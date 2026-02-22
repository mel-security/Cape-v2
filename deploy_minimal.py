#!/usr/bin/env python3
"""
deploy_minimal.py - Deploy a minimal "windows-minimal" VM for CAPEv2
on an existing QEMU/KVM + libvirt installation.

ZERO-IMPACT: never modifies or deletes the existing VM, its snapshots,
or the libvirt network.  Non-destructive, safe-by-default.

Usage:
    sudo python3 deploy_minimal.py              # normal run
    sudo python3 deploy_minimal.py --dry-run    # preview only
    sudo python3 deploy_minimal.py --force      # auto-suffix if name collision
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
NEW_VM_NAME = "windows-minimal"
IMAGE_DIR = Path("/var/lib/libvirt/images")
KVM_CONF = Path("/opt/CAPEv2/conf/kvm.conf")
TIMESTAMP = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d_%H%M%S")
LOG_PATH = Path(f"/tmp/windows-minimal-deploy.{TIMESTAMP}.log")

# ---------------------------------------------------------------------------
# Logging helper
# ---------------------------------------------------------------------------
_log_lines: List[str] = []


def log(msg: str, *, level: str = "INFO") -> None:
    line = f"[{level}] {msg}"
    _log_lines.append(line)
    prefix = {"INFO": "\033[34m[INFO]\033[0m",
              "WARN": "\033[33m[WARN]\033[0m",
              "ERROR": "\033[31m[ERROR]\033[0m",
              "OK": "\033[32m[ OK ]\033[0m",
              "DRY": "\033[35m[DRY ]\033[0m"}.get(level, f"[{level}]")
    print(f"{prefix} {msg}", flush=True)


def flush_log() -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_PATH.write_text("\n".join(_log_lines) + "\n", encoding="utf-8")
    log(f"Log written to {LOG_PATH}", level="OK")


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------
def run(cmd: str | list, *, check: bool = True, capture: bool = True,
        dry_run: bool = False, dry_label: str = "") -> subprocess.CompletedProcess:
    if isinstance(cmd, list):
        display = " ".join(cmd)
    else:
        display = cmd
    if dry_run:
        log(f"[would run] {dry_label or display}", level="DRY")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    log(f"Running: {display}")
    result = subprocess.run(
        cmd, shell=isinstance(cmd, str), capture_output=capture,
        text=True, timeout=600,
    )
    if check and result.returncode != 0:
        log(f"Command failed (rc={result.returncode}): {display}", level="ERROR")
        if result.stderr:
            log(f"  stderr: {result.stderr.strip()}", level="ERROR")
        raise SystemExit(1)
    return result


def sha256_of(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
def detect_source_domain() -> str:
    """Find an existing Windows domain in libvirt (prefer 'window')."""
    result = run("virsh list --all --name", check=False)
    domains = [d.strip() for d in result.stdout.splitlines() if d.strip()]
    if not domains:
        log("No libvirt domains found.", level="ERROR")
        raise SystemExit(1)
    # Prefer "window" (the known CAPEv2 default)
    if "window" in domains:
        return "window"
    # Otherwise pick the first domain whose name hints at Windows
    for d in domains:
        if "win" in d.lower():
            return d
    # Last resort: first domain
    log(f"No Windows-ish domain found; using first domain: {domains[0]}", level="WARN")
    return domains[0]


def get_domain_xml(name: str) -> str:
    result = run(["virsh", "dumpxml", name])
    return result.stdout


def find_disk_source(xml_str: str) -> str:
    """Return the path of the first disk <source file='...'> in the domain XML."""
    root = ET.fromstring(xml_str)
    for disk in root.iter("disk"):
        if disk.get("device") == "disk":
            src = disk.find("source")
            if src is not None and src.get("file"):
                return src.get("file")
    log("Cannot find disk source in domain XML.", level="ERROR")
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# XML rewriting for the minimal profile
# ---------------------------------------------------------------------------
def rewrite_xml(xml_str: str, new_name: str, new_disk_path: str) -> str:
    """
    Create a new domain XML based on the source, with:
    - new <name>
    - new disk path
    - removed: <watchdog>, <redirdev>, <redirfilter>, tablet input
    - removed: <uuid> (libvirt will generate a new one)
    """
    root = ET.fromstring(xml_str)

    # --- Name ---
    name_el = root.find("name")
    if name_el is not None:
        name_el.text = new_name

    # --- Remove UUID so libvirt generates a new one ---
    uuid_el = root.find("uuid")
    if uuid_el is not None:
        root.remove(uuid_el)

    # --- Disk: replace source path ---
    for disk in root.iter("disk"):
        if disk.get("device") == "disk":
            src = disk.find("source")
            if src is not None and src.get("file"):
                src.set("file", new_disk_path)
                break

    # --- Devices: remove unwanted elements ---
    devices = root.find("devices")
    if devices is not None:
        to_remove = []
        for child in devices:
            tag = child.tag
            # Remove all watchdog elements
            if tag == "watchdog":
                to_remove.append(child)
            # Remove all redirdev elements
            elif tag == "redirdev":
                to_remove.append(child)
            # Remove redirfilter
            elif tag == "redirfilter":
                to_remove.append(child)
            # Remove USB tablet input
            elif tag == "input":
                if child.get("type") == "tablet" and child.get("bus") == "usb":
                    to_remove.append(child)
        for el in to_remove:
            devices.remove(el)
            log(f"  Removed <{el.tag}> from XML")

    # --- Serialize ---
    return ET.tostring(root, encoding="unicode", xml_declaration=False)


# ---------------------------------------------------------------------------
# Image / overlay creation
# ---------------------------------------------------------------------------
def resolve_image_path(name: str) -> Path:
    """Return a non-colliding path under IMAGE_DIR."""
    p = IMAGE_DIR / name
    if not p.exists():
        return p
    stamped = IMAGE_DIR / f"{Path(name).stem}.{TIMESTAMP}{Path(name).suffix}"
    log(f"  Path {p} exists, using timestamped: {stamped}", level="WARN")
    return stamped


def create_base_image(source_disk: str, dest: Path, dry_run: bool) -> None:
    """Clone the source disk into a standalone qcow2 (Option A: full clone)."""
    log(f"Creating base image: {dest}")
    log(f"  Source: {source_disk}")
    run(
        ["qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", "-p", str(source_disk), str(dest)],
        dry_run=dry_run,
        dry_label=f"qemu-img convert {source_disk} -> {dest}",
    )


def create_overlay(backing: Path, dest: Path, dry_run: bool) -> None:
    """Create a qcow2 overlay backed by `backing`."""
    log(f"Creating overlay: {dest}")
    log(f"  Backing: {backing}")
    run(
        ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
         "-b", str(backing), str(dest)],
        dry_run=dry_run,
        dry_label=f"qemu-img create overlay {dest} <- {backing}",
    )


# ---------------------------------------------------------------------------
# Libvirt domain definition
# ---------------------------------------------------------------------------
def domain_exists(name: str) -> bool:
    r = run(["virsh", "dominfo", name], check=False)
    return r.returncode == 0


def define_domain(xml_str: str, dry_run: bool) -> None:
    if dry_run:
        log("[would define domain from rewritten XML]", level="DRY")
        return
    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(xml_str)
        tmp = f.name
    try:
        run(["virsh", "define", tmp])
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# kvm.conf update
# ---------------------------------------------------------------------------
def update_kvm_conf(snapshot_name: str, dry_run: bool) -> List[str]:
    """
    In-place update of kvm.conf:
    - machines = ... window ... -> ... windows-minimal ...
    - [window] -> [windows-minimal]
    - label = window -> label = windows-minimal
    - snapshot = <old> -> snapshot = <snapshot_name>

    Returns list of change descriptions.
    """
    changes: List[str] = []

    if not KVM_CONF.exists():
        log(f"{KVM_CONF} does not exist, skipping kvm.conf update.", level="WARN")
        changes.append("kvm.conf not found - skipped")
        return changes

    original = KVM_CONF.read_text(encoding="utf-8")
    lines = original.splitlines(keepends=True)
    new_lines: List[str] = []

    for line in lines:
        orig_line = line

        # --- machines = ... line ---
        if re.match(r"^\s*machines\s*=", line):
            # Replace the exact token "window" but not "windows-minimal" etc.
            # Use word-boundary matching
            new_line = re.sub(r'\bwindow\b', NEW_VM_NAME, line)
            # Prevent duplication if already present
            if new_line.count(NEW_VM_NAME) > 1:
                # Deduplicate: split, unique, rejoin
                m = re.match(r"^(\s*machines\s*=\s*)(.*)", new_line)
                if m:
                    prefix = m.group(1)
                    tokens = m.group(2).strip().split()
                    seen = set()
                    deduped = []
                    for t in tokens:
                        t_clean = t.strip().rstrip(",")
                        if t_clean not in seen:
                            seen.add(t_clean)
                            deduped.append(t_clean)
                    new_line = prefix + ", ".join(deduped) + "\n"
            if new_line != orig_line:
                changes.append(f"machines line: '{orig_line.strip()}' -> '{new_line.strip()}'")
            line = new_line

        # --- Section header [window] ---
        elif re.match(r"^\s*\[window\]\s*$", line):
            line = line.replace("[window]", f"[{NEW_VM_NAME}]")
            changes.append(f"Section header: [window] -> [{NEW_VM_NAME}]")

        # --- label = window ---
        elif re.match(r"^\s*label\s*=\s*window\s*$", line):
            line = re.sub(r"(label\s*=\s*)window", rf"\1{NEW_VM_NAME}", line)
            changes.append(f"label: window -> {NEW_VM_NAME}")

        # --- snapshot = ... ---
        elif re.match(r"^\s*snapshot\s*=", line):
            old_val = line.split("=", 1)[1].strip()
            line = re.sub(r"(snapshot\s*=\s*)\S+", rf"\1{snapshot_name}", line)
            if old_val != snapshot_name:
                changes.append(f"snapshot: {old_val} -> {snapshot_name}")

        new_lines.append(line)

    new_content = "".join(new_lines)

    if not changes:
        log("kvm.conf: no changes needed.", level="INFO")
        return changes

    if dry_run:
        log("kvm.conf changes (dry-run):", level="DRY")
        for c in changes:
            log(f"  {c}", level="DRY")
        return changes

    # Backup
    backup = KVM_CONF.with_name(f"kvm.conf.bak.{TIMESTAMP}")
    shutil.copy2(str(KVM_CONF), str(backup))
    log(f"kvm.conf backup: {backup}", level="OK")

    # Atomic write via tempfile + rename
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=str(KVM_CONF.parent), prefix="kvm.conf.tmp.", suffix=".tmp"
    )
    try:
        os.write(tmp_fd, new_content.encode("utf-8"))
        os.close(tmp_fd)
        os.chmod(tmp_path, os.stat(str(KVM_CONF)).st_mode)
        os.rename(tmp_path, str(KVM_CONF))
        log(f"kvm.conf updated atomically.", level="OK")
    except Exception:
        os.close(tmp_fd) if not os.get_inheritable(tmp_fd) else None
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise

    return changes


# ---------------------------------------------------------------------------
# Post-operation verification
# ---------------------------------------------------------------------------
def verify(source_domain: str, source_xml_hash: str,
           base_img: Path, chrome_img: Path,
           dry_run: bool) -> None:
    log("=" * 60)
    log("POST-DEPLOY VERIFICATION")
    log("=" * 60)

    if dry_run:
        log("Skipping verification in dry-run mode.", level="DRY")
        return

    # 1. New domain should be clean
    log("Checking new domain XML for removed elements...")
    r = run(f"virsh dumpxml {NEW_VM_NAME} | grep -ciE 'watchdog|redirdev|redirfilter|type=.tablet.'",
            check=False)
    count = int(r.stdout.strip()) if r.stdout.strip().isdigit() else 0
    if count == 0:
        log("  No watchdog/redirdev/tablet found in new domain.", level="OK")
    else:
        log(f"  WARNING: {count} unwanted element(s) still present!", level="WARN")

    # 2. Source domain unchanged
    log(f"Verifying source domain '{source_domain}' is unchanged...")
    current_xml = get_domain_xml(source_domain)
    current_hash = sha256_of(current_xml)
    if current_hash == source_xml_hash:
        log(f"  Source domain XML hash matches (before={source_xml_hash}, after={current_hash}).", level="OK")
    else:
        log(f"  WARNING: Source domain XML hash changed! before={source_xml_hash}, after={current_hash}", level="WARN")

    # 3. Images exist
    for img in [base_img, chrome_img]:
        if img.exists():
            log(f"  Image exists: {img}", level="OK")
        else:
            log(f"  Image MISSING: {img}", level="WARN")

    # 4. Backing chain depth
    log("Checking backing chain depth of chrome overlay...")
    r = run(["qemu-img", "info", "--backing-chain", str(chrome_img)], check=False)
    chain_depth = r.stdout.count("backing file:")
    log(f"  Backing chain depth: {chain_depth} (max recommended: 2)")
    if chain_depth <= 2:
        log("  Chain depth OK.", level="OK")
    else:
        log("  Chain depth too deep!", level="WARN")

    # 5. kvm.conf checks
    if KVM_CONF.exists():
        conf = KVM_CONF.read_text(encoding="utf-8")
        checks = [
            (NEW_VM_NAME in conf, f"'{NEW_VM_NAME}' found in machines line"),
            (f"[{NEW_VM_NAME}]" in conf, f"Section [{NEW_VM_NAME}] found"),
            (f"label = {NEW_VM_NAME}" in conf, f"label = {NEW_VM_NAME} found"),
        ]
        for ok, desc in checks:
            if ok:
                log(f"  kvm.conf: {desc}", level="OK")
            else:
                log(f"  kvm.conf: MISSING - {desc}", level="WARN")
    else:
        log("  kvm.conf not found, skipping conf checks.", level="WARN")


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def print_report(source_domain: str, source_disk: str,
                 base_img: Path, chrome_img: Path,
                 kvm_changes: List[str]) -> None:
    log("")
    log("=" * 60)
    log("DEPLOYMENT REPORT")
    log("=" * 60)
    log(f"Source domain        : {source_domain}")
    log(f"Source disk           : {source_disk}")
    log(f"New domain            : {NEW_VM_NAME}")
    log(f"Base image            : {base_img}")
    log(f"Chrome overlay        : {chrome_img}")
    log(f"kvm.conf changes      : {len(kvm_changes)}")
    for c in kvm_changes:
        log(f"  - {c}")
    log("")
    log("Verification commands:")
    log(f"  virsh dumpxml {NEW_VM_NAME} | grep -ciE 'watchdog|redirdev|type=.tablet.'")
    log(f"  qemu-img info --backing-chain {chrome_img}")
    if KVM_CONF.exists():
        log(f"  grep -E 'machines|\\[{NEW_VM_NAME}\\]|label|snapshot' {KVM_CONF}")
    log("")
    log("Rollback (manual):")
    if KVM_CONF.exists():
        log(f"  cp {KVM_CONF}.bak.{TIMESTAMP} {KVM_CONF}")
    log(f"  virsh undefine {NEW_VM_NAME}")
    log(f"  rm -f {base_img} {chrome_img}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Deploy a minimal 'windows-minimal' VM for CAPEv2.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              sudo python3 deploy_minimal.py              # deploy
              sudo python3 deploy_minimal.py --dry-run    # preview only
              sudo python3 deploy_minimal.py --force      # auto-suffix on collision
        """),
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be done without making changes.")
    parser.add_argument("--force", action="store_true",
                        help="If 'windows-minimal' already exists, use a timestamped suffix.")
    parser.add_argument("--no-kvmconf", action="store_true",
                        help="Skip kvm.conf update (deploy VM only).")
    args = parser.parse_args()

    dry_run = args.dry_run

    log(f"deploy_minimal.py started at {TIMESTAMP}")
    log(f"  dry_run={dry_run}  force={args.force}  no_kvmconf={args.no_kvmconf}")

    # --- Must be root ---
    if os.geteuid() != 0 and not dry_run:
        log("This script must be run as root (sudo).", level="ERROR")
        raise SystemExit(1)

    # --- Determine final VM name ---
    vm_name = NEW_VM_NAME
    if domain_exists(vm_name):
        if args.force:
            vm_name = f"{NEW_VM_NAME}-{TIMESTAMP}"
            log(f"Domain '{NEW_VM_NAME}' exists, using '{vm_name}' (--force).", level="WARN")
        elif not dry_run:
            log(f"Domain '{NEW_VM_NAME}' already exists. Use --force to auto-suffix.", level="ERROR")
            raise SystemExit(1)
        else:
            log(f"Domain '{NEW_VM_NAME}' already exists (dry-run continues).", level="WARN")

    # --- Detect source domain ---
    source_domain = detect_source_domain()
    log(f"Source domain: {source_domain}", level="OK")

    # --- Capture source XML and hash (for integrity check) ---
    source_xml = get_domain_xml(source_domain)
    source_xml_hash = sha256_of(source_xml)
    log(f"Source XML hash: {source_xml_hash}")

    # --- Find source disk ---
    source_disk = find_disk_source(source_xml)
    log(f"Source disk: {source_disk}", level="OK")

    if not Path(source_disk).exists() and not dry_run:
        log(f"Source disk does not exist: {source_disk}", level="ERROR")
        raise SystemExit(1)

    # --- Plan image paths ---
    base_name = f"{vm_name}.base.qcow2"
    chrome_name = f"{vm_name}.chrome.qcow2"
    base_img = resolve_image_path(base_name)
    chrome_img = resolve_image_path(chrome_name)

    # Snapshot name for kvm.conf (the overlay CAPE will revert to)
    snapshot_chrome_name = f"{vm_name}_chrome"

    log(f"Base image  : {base_img}")
    log(f"Chrome overlay: {chrome_img}")
    log(f"Snapshot name : {snapshot_chrome_name}")

    # --- Step 1: Create base image (full clone) ---
    log("")
    log("=" * 60)
    log("STEP 1: Create base image (qemu-img convert / full clone)")
    log("=" * 60)
    create_base_image(source_disk, base_img, dry_run)

    # --- Step 2: Create chrome overlay ---
    log("")
    log("=" * 60)
    log("STEP 2: Create chrome overlay")
    log("=" * 60)
    create_overlay(base_img, chrome_img, dry_run)

    # --- Step 3: Rewrite XML and define domain ---
    log("")
    log("=" * 60)
    log("STEP 3: Define libvirt domain")
    log("=" * 60)
    new_xml = rewrite_xml(source_xml, vm_name, str(chrome_img))
    if dry_run:
        log("Rewritten XML (first 40 lines):", level="DRY")
        for i, l in enumerate(new_xml.splitlines()[:40]):
            log(f"  {l}", level="DRY")

    define_domain(new_xml, dry_run)
    if not dry_run:
        log(f"Domain '{vm_name}' defined.", level="OK")

    # --- Step 4: Create libvirt snapshot metadata ---
    log("")
    log("=" * 60)
    log("STEP 4: Create libvirt snapshot for CAPE revert")
    log("=" * 60)
    if not dry_run:
        # Create an internal snapshot name that CAPE can revert to.
        # CAPE uses `virsh snapshot-revert <domain> <snapshot>`.
        # We create a snapshot of the *current* (shut-off) state.
        r = run(["virsh", "snapshot-create-as", vm_name,
                 "--name", snapshot_chrome_name,
                 "--description", "Clean chrome state for CAPE analysis",
                 "--atomic"], check=False)
        if r.returncode == 0:
            log(f"Snapshot '{snapshot_chrome_name}' created.", level="OK")
        else:
            # If domain is shut off, try without --atomic
            log("Retrying snapshot without --atomic (domain may be shut off)...", level="WARN")
            r2 = run(["virsh", "snapshot-create-as", vm_name,
                      "--name", snapshot_chrome_name,
                      "--description", "Clean chrome state for CAPE analysis"],
                     check=False)
            if r2.returncode == 0:
                log(f"Snapshot '{snapshot_chrome_name}' created.", level="OK")
            else:
                log(f"Could not create snapshot. You may need to create it manually:", level="WARN")
                log(f"  virsh snapshot-create-as {vm_name} --name {snapshot_chrome_name}", level="WARN")
    else:
        log(f"[would create snapshot '{snapshot_chrome_name}']", level="DRY")

    # --- Step 5: Update kvm.conf ---
    kvm_changes: List[str] = []
    if not args.no_kvmconf:
        log("")
        log("=" * 60)
        log("STEP 5: Update kvm.conf")
        log("=" * 60)
        kvm_changes = update_kvm_conf(snapshot_chrome_name, dry_run)
    else:
        log("Skipping kvm.conf update (--no-kvmconf).", level="INFO")
        kvm_changes.append("skipped (--no-kvmconf)")

    # --- Step 6: Verification ---
    log("")
    verify(source_domain, source_xml_hash, base_img, chrome_img, dry_run)

    # --- Report ---
    print_report(source_domain, source_disk, base_img, chrome_img, kvm_changes)

    # --- Flush log ---
    flush_log()

    log("")
    if dry_run:
        log("DRY RUN complete. No changes were made.", level="OK")
    else:
        log("Deployment complete.", level="OK")


if __name__ == "__main__":
    main()
