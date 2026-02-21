#!/usr/bin/env python3
"""
CAPE/Cuckoo all-in-one triage and safe remediation helper.
"""

from __future__ import annotations

import argparse
import configparser
import dataclasses
import datetime as dt
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Dict, List, Optional, Sequence

# Minimum VM RAM (MiB) for modern browser workloads.
MIN_VM_RAM_MIB = 4096
# Minimum host free RAM (MiB) to safely run a VM with a modern browser.
MIN_HOST_FREE_MIB = 2048
# Minimum VRAM (MiB) for browser rendering.
MIN_VRAM_MIB = 128


@dataclasses.dataclass
class CmdResult:
    command: str
    rc: int
    stdout: str
    stderr: str
    started_at: str
    ended_at: str


@dataclasses.dataclass
class Finding:
    severity: str
    symptom: str
    evidence: List[str]
    probable_causes: List[str]
    recommendations: List[str]


class CapeDoctor:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.hostname = socket.gethostname()
        self.timestamp = dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        default_out = Path.cwd() / f"cape_triage_{self.timestamp}"
        self.out_dir = Path(args.out_dir or default_out).resolve()
        self.logs_dir = self.out_dir / "logs"
        self.cmd_dir = self.out_dir / "commands"
        self.cfg_dir = self.out_dir / "configs"
        self.meta_dir = self.out_dir / "metadata"
        self.findings: List[Finding] = []
        self.inventory: Dict[str, str] = {}
        self.detected: Dict[str, str] = {}
        self.vm_meta: Dict[str, str] = {}
        self.logger = logging.getLogger("cape_doctor")

        for d in [self.out_dir, self.logs_dir, self.cmd_dir, self.cfg_dir, self.meta_dir]:
            d.mkdir(parents=True, exist_ok=True)

        log_file = self.out_dir / "cape_doctor.log"
        logging.basicConfig(
            level=logging.DEBUG if args.verbose else logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
            handlers=[logging.FileHandler(log_file), logging.StreamHandler(sys.stdout)],
        )

        self.known_config_files = [
            "conf/cuckoo.conf",
            "conf/auxiliary.conf",
            "conf/machinery.conf",
            "conf/routing.conf",
            "conf/processing.conf",
            "conf/reporting.conf",
            "conf/web.conf",
        ]

    @staticmethod
    def _mask_public_ip(text: str) -> str:
        def repl(match: re.Match[str]) -> str:
            ip = match.group(0)
            try:
                parts = [int(p) for p in ip.split(".")]
                if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
                    return ip
                private = (
                    parts[0] == 10
                    or (parts[0] == 172 and 16 <= parts[1] <= 31)
                    or (parts[0] == 192 and parts[1] == 168)
                    or parts[0] == 127
                    or (parts[0] == 169 and parts[1] == 254)
                )
                if private:
                    return ip
                return "x.x.x.x"
            except ValueError:
                return ip

        return re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", repl, text)

    @staticmethod
    def _mask_secrets(text: str) -> str:
        patterns = [
            (r"(?i)(password\s*[=:]\s*)([^\s,;]+)", r"\1***"),
            (r"(?i)(token\s*[=:]\s*)([^\s,;]+)", r"\1***"),
            (r"(?i)(secret\s*[=:]\s*)([^\s,;]+)", r"\1***"),
            (r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----", "***PRIVATE_KEY_REDACTED***"),
        ]
        output = text
        for pat, repl in patterns:
            output = re.sub(pat, repl, output)
        return CapeDoctor._mask_public_ip(output)

    def run_cmd(self, command: str, name: str, timeout: int = 30) -> CmdResult:
        started = dt.datetime.utcnow().isoformat() + "Z"
        self.logger.debug("Running command [%s]: %s", name, command)
        try:
            proc = subprocess.run(
                command,
                shell=True,
                text=True,
                capture_output=True,
                timeout=timeout,
            )
            rc = proc.returncode
            out = proc.stdout
            err = proc.stderr
        except subprocess.TimeoutExpired as exc:
            rc = 124
            out = exc.stdout or ""
            err = (exc.stderr or "") + "\nTIMEOUT"
        ended = dt.datetime.utcnow().isoformat() + "Z"
        result = CmdResult(command, rc, out, err, started, ended)
        content = {
            "command": command,
            "rc": rc,
            "started_at": started,
            "ended_at": ended,
            "stdout": self._mask_secrets(out),
            "stderr": self._mask_secrets(err),
        }
        (self.cmd_dir / f"{name}.json").write_text(json.dumps(content, indent=2), encoding="utf-8")
        return result

    def detect_environment(self) -> None:
        os_release = self.run_cmd("cat /etc/os-release", "os_release")
        uname = self.run_cmd("uname -a", "uname")
        cpu = self.run_cmd("lscpu", "lscpu")
        virt = self.run_cmd("egrep -c '(vmx|svm)' /proc/cpuinfo", "cpu_virt_flags")

        self.inventory["hostname"] = self.hostname
        self.inventory["kernel"] = uname.stdout.strip().split("\n")[0] if uname.stdout else "unknown"
        self.inventory["os_release"] = (os_release.stdout.strip().split("\n")[0] if os_release.stdout else "unknown")
        self.inventory["virt_flags_count"] = virt.stdout.strip() or "0"

        capepaths = [Path("/opt/CAPEv2"), Path("/opt/CAPE"), Path.home() / ".cuckoo", Path.home() / "cuckoo", Path("/etc/cuckoo")]
        repo = ""
        for p in capepaths:
            if p.exists():
                repo = str(p)
                break
        self.detected["cape_root"] = repo or "not_found"

        kind = "unknown"
        if repo and "cape" in repo.lower():
            kind = "cape"
        elif repo:
            kind = "cuckoo"
        self.detected["framework"] = kind

        if shutil.which("systemctl"):
            self.detected["service_manager"] = "systemd"
        elif shutil.which("supervisorctl"):
            self.detected["service_manager"] = "supervisord"
        else:
            self.detected["service_manager"] = "unknown"

        hv = self.args.hypervisor
        if hv == "auto":
            if shutil.which("virsh"):
                hv = "kvm"
            elif shutil.which("VBoxManage"):
                hv = "virtualbox"
            else:
                hv = "unknown"
        self.detected["hypervisor"] = hv

        (self.meta_dir / "environment.json").write_text(json.dumps({"inventory": self.inventory, "detected": self.detected}, indent=2), encoding="utf-8")

        if cpu.stdout and not re.search(r"\b(vmx|svm)\b", cpu.stdout):
            self.findings.append(
                Finding(
                    "high",
                    "Virtualization flags missing",
                    ["No vmx/svm flags found in lscpu/proc cpuinfo"],
                    ["Host CPU virtualization disabled in BIOS/UEFI"],
                    ["Enable Intel VT-x or AMD-V in BIOS/UEFI and reboot host."],
                )
            )

    def collect_versions_and_packages(self) -> None:
        cmds = {
            "python_version": "python3 --version",
            "pip_version": "python3 -m pip --version",
            "dpkg_packages": "dpkg -l | egrep 'qemu|libvirt|virtualbox|tcpdump|redis|mongo|postgres|nginx|apache2|cape|cuckoo' || true",
            "rpm_packages": "rpm -qa | egrep 'qemu|libvirt|virtualbox|tcpdump|redis|mongo|postgres|nginx|httpd|cape|cuckoo' || true",
        }
        for name, cmd in cmds.items():
            self.run_cmd(cmd, name)

        root = self.detected.get("cape_root")
        if root and root != "not_found":
            self.run_cmd(f"cd {shlex_quote(root)} && git rev-parse --short HEAD", "cape_git_rev")
            self.run_cmd(f"cd {shlex_quote(root)} && git status --short", "cape_git_status")

    def collect_service_status(self) -> None:
        services = [
            "cape",
            "cuckoo",
            "cape-web",
            "cape-api",
            "nginx",
            "apache2",
            "httpd",
            "redis",
            "redis-server",
            "mongodb",
            "mongod",
            "postgresql",
            "mysql",
            "mariadb",
            "libvirtd",
            "virtqemud",
            "vboxdrv",
        ]
        if self.detected.get("service_manager") == "systemd":
            for svc in services:
                self.run_cmd(f"systemctl status {svc} --no-pager -l", f"svc_{svc}", timeout=15)
        elif self.detected.get("service_manager") == "supervisord":
            self.run_cmd("supervisorctl status", "supervisor_status")

        self.run_cmd("ss -ltnup", "listening_ports")

    def _possible_roots(self) -> List[Path]:
        roots = [Path("/opt/CAPEv2"), Path("/opt/CAPE"), Path.home() / ".cuckoo", Path.home() / "cuckoo", Path("/etc/cuckoo")]
        detected_root = self.detected.get("cape_root")
        if detected_root and detected_root != "not_found":
            roots.insert(0, Path(detected_root))
        unique: List[Path] = []
        for r in roots:
            if r not in unique:
                unique.append(r)
        return unique

    def parse_configs(self) -> Dict[str, str]:
        key_patterns = [
            "machinery", "interface", "route", "resultserver", "ip", "port", "timeout", "browser", "proxy", "dns", "suricata", "yara",
        ]
        parsed: Dict[str, str] = {}
        for root in self._possible_roots():
            for rel in self.known_config_files:
                f = root / rel
                if not f.exists():
                    continue
                dst = self.cfg_dir / f"{root.name}_{rel.replace('/', '_')}"
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                    dst.write_text(self._mask_secrets(content), encoding="utf-8")
                    lines = []
                    for ln in content.splitlines():
                        if any(k in ln.lower() for k in key_patterns) and not ln.strip().startswith("#"):
                            lines.append(ln.strip())
                    parsed[str(f)] = "\n".join(lines[:200])
                except Exception as exc:
                    parsed[str(f)] = f"ERROR: {exc}"
        (self.meta_dir / "parsed_configs.json").write_text(json.dumps(parsed, indent=2), encoding="utf-8")
        return parsed

    def collect_network(self) -> None:
        net_cmds = {
            "ip_addr": "ip a",
            "ip_route": "ip route",
            "resolv_conf": "cat /etc/resolv.conf",
            "nm_state": "nmcli general status || true",
            "sysctl_ipfwd": "sysctl net.ipv4.ip_forward",
            "sysctl_rpf": "sysctl net.ipv4.conf.all.rp_filter",
            "iptables_nat": "iptables -t nat -S || true",
            "iptables_filter": "iptables -S || true",
            "nft_ruleset": "nft list ruleset || true",
            "arp_table": "ip neigh",
        }
        for name, cmd in net_cmds.items():
            self.run_cmd(cmd, name)

        if self.args.online:
            self.run_cmd("getent hosts example.com", "online_dns_test")
            self.run_cmd("ping -c 2 -W 2 1.1.1.1", "online_ping_test")
            self.run_cmd("curl -I --max-time 5 https://example.com || true", "online_https_test")

    def collect_hypervisor(self) -> None:
        hv = self.detected.get("hypervisor")
        vm = self.args.vm_name
        if hv == "kvm":
            self.run_cmd("virsh list --all", "virsh_list_all")
            if vm:
                self.run_cmd(f"virsh dominfo {shlex_quote(vm)}", "virsh_dominfo")
                self.run_cmd(f"virsh domifaddr {shlex_quote(vm)}", "virsh_domifaddr")
            self.run_cmd("journalctl -u libvirtd -n 300 --no-pager || true", "journal_libvirtd")
            self.run_cmd("journalctl -u virtqemud -n 300 --no-pager || true", "journal_virtqemud")
        elif hv == "virtualbox":
            self.run_cmd("VBoxManage list vms", "vbox_list_vms")
            self.run_cmd("VBoxManage list runningvms", "vbox_running_vms")
            if vm:
                self.run_cmd(f"VBoxManage showvminfo {shlex_quote(vm)} --details", "vbox_showvminfo")
                vm_log_glob = Path.home() / "VirtualBox VMs" / vm / "Logs"
                if vm_log_glob.exists():
                    for idx, logfile in enumerate(sorted(vm_log_glob.glob("VBox*.log"))[:5]):
                        try:
                            data = logfile.read_text(encoding="utf-8", errors="ignore")
                            (self.logs_dir / f"vbox_{idx}_{logfile.name}").write_text(self._mask_secrets(data[-120000:]), encoding="utf-8")
                        except Exception:
                            continue
        else:
            self.findings.append(
                Finding(
                    "medium",
                    "Hypervisor not auto-detected",
                    ["Neither virsh nor VBoxManage was available in PATH."],
                    ["Hypervisor binaries not installed or PATH not configured."],
                    ["Run with --hypervisor kvm|virtualbox, install required CLI tools and retry."],
                )
            )

    # ------------------------------------------------------------------
    # Deep VM configuration inspection (browser-crash focused)
    # ------------------------------------------------------------------

    def collect_vm_config(self) -> None:
        """Inspect VM definition for RAM, video adapter, CPU model,
        Hyper-V enlightenments, and other settings that affect modern
        browser stability."""
        hv = self.detected.get("hypervisor")
        vm = self.args.vm_name
        if not vm:
            return

        if hv == "kvm":
            self._inspect_kvm_vm(vm)
        elif hv == "virtualbox":
            self._inspect_vbox_vm(vm)

    def _inspect_kvm_vm(self, vm: str) -> None:
        # Dump full XML definition
        xml_res = self.run_cmd(f"virsh dumpxml {shlex_quote(vm)}", "virsh_dumpxml", timeout=15)
        xml = xml_res.stdout

        # -- RAM --
        mem_match = re.search(r"<memory[^>]*>(\d+)</memory>", xml)
        mem_unit_match = re.search(r"<memory\s+unit=['\"](\w+)['\"]", xml)
        if mem_match:
            raw_val = int(mem_match.group(1))
            unit = mem_unit_match.group(1) if mem_unit_match else "KiB"
            mem_mib = self._to_mib(raw_val, unit)
            self.vm_meta["ram_mib"] = str(mem_mib)
            if mem_mib < MIN_VM_RAM_MIB:
                self.findings.append(Finding(
                    "high",
                    f"VM RAM too low for modern browsers ({mem_mib} MiB < {MIN_VM_RAM_MIB} MiB)",
                    [f"virsh dumpxml reports {mem_mib} MiB allocated to VM '{vm}'."],
                    [
                        "Chrome/Edge multi-process architecture consumes 2-3 GB alone.",
                        "Low VM RAM causes GPU process crash, tab crash, or full VM freeze.",
                    ],
                    [
                        f"Increase VM RAM to at least {MIN_VM_RAM_MIB} MiB: virsh edit {vm} -> <memory>.",
                        "If host RAM is limited, reduce concurrent analysis count in CAPE config.",
                    ],
                ))

        # -- Video adapter --
        video_match = re.search(r"<video>.*?</video>", xml, re.DOTALL)
        if video_match:
            video_block = video_match.group(0)
            model_match = re.search(r"<model\s+type=['\"](\w+)['\"]", video_block)
            vram_match = re.search(r"vram=['\"](\d+)['\"]", video_block)
            accel3d_match = re.search(r"accel3d=['\"](\w+)['\"]", video_block)
            adapter = model_match.group(1) if model_match else "unknown"
            self.vm_meta["video_adapter"] = adapter
            if vram_match:
                self.vm_meta["video_vram_kib"] = vram_match.group(1)

            # virtio-gpu and VGA cause crashes with modern browsers
            if adapter.lower() in ("vga", "virtio", "bochs", "ramfb"):
                self.findings.append(Finding(
                    "high",
                    f"KVM video adapter '{adapter}' incompatible with modern browsers",
                    [f"<model type='{adapter}'> in VM XML."],
                    [
                        f"'{adapter}' adapter lacks stable 2D/3D acceleration for Chrome/Edge.",
                        "Browser GPU process crashes immediately on launch.",
                    ],
                    [
                        "Switch to QXL adapter: virsh edit -> <model type='qxl'/>.",
                        "Install QXL guest drivers (qxl-wddm-dod) in Windows guest.",
                        "If using '--fix', this will be corrected automatically.",
                    ],
                ))

            # Check VRAM too low
            if vram_match:
                vram_kib = int(vram_match.group(1))
                vram_mib = vram_kib // 1024 if vram_kib > 1024 else vram_kib
                if vram_mib < MIN_VRAM_MIB:
                    self.findings.append(Finding(
                        "medium",
                        f"VM VRAM low ({vram_mib} MiB) for browser rendering",
                        [f"Video RAM set to {vram_mib} MiB in VM XML."],
                        ["Low VRAM causes rendering failures and GPU process crashes in browsers."],
                        [f"Increase VRAM to at least {MIN_VRAM_MIB} MiB in VM video configuration."],
                    ))

            # 3D accel enabled in KVM = unstable
            if accel3d_match and accel3d_match.group(1).lower() == "yes":
                self.findings.append(Finding(
                    "high",
                    "KVM 3D acceleration enabled - likely crash cause",
                    ["accel3d='yes' found in VM video configuration."],
                    [
                        "3D acceleration in KVM/QEMU (virgl) is experimental.",
                        "Chrome/Edge GPU process crashes when 3D is enabled without proper drivers.",
                    ],
                    [
                        "Disable 3D acceleration: remove accel3d='yes' from VM XML.",
                        "Browsers should use software rendering (SwiftShader/WARP) in analysis VMs.",
                    ],
                ))

        # -- CPU model & Hyper-V enlightenments --
        hyperv_features = re.findall(r"<(\w+)\s+state=['\"]on['\"]", xml)
        hv_expected = {"relaxed", "vapic", "spinlocks"}
        hv_present = {f.lower() for f in hyperv_features} & {"relaxed", "vapic", "spinlocks", "vpindex", "synic", "stimer"}
        missing_hv = hv_expected - hv_present
        self.vm_meta["hyperv_enlightenments"] = ",".join(sorted(hv_present)) or "none"
        if missing_hv:
            self.findings.append(Finding(
                "medium",
                f"Missing Hyper-V enlightenments: {', '.join(sorted(missing_hv))}",
                [f"VM XML hyperv section missing: {', '.join(sorted(missing_hv))}."],
                [
                    "Missing Hyper-V enlightenments cause Windows timer/scheduler instability.",
                    "This leads to sporadic guest freezes especially under heavy browser load.",
                ],
                [
                    "Add to VM XML <features><hyperv>: <relaxed state='on'/> <vapic state='on'/> <spinlocks state='on' retries='8191'/>.",
                    "Use '--fix' to apply these automatically.",
                ],
            ))

        # -- Snapshot list --
        snap = self.run_cmd(f"virsh snapshot-list {shlex_quote(vm)}", "virsh_snapshots", timeout=15)
        if snap.stdout:
            self.vm_meta["snapshot_count"] = str(len([l for l in snap.stdout.strip().splitlines() if l.strip() and not l.startswith("---") and "Name" not in l]))

        # -- QEMU process command line --
        qemu_proc = self.run_cmd(
            f"ps aux | grep -E 'qemu.*{re.escape(vm)}' | grep -v grep || true",
            "qemu_process", timeout=10,
        )
        if qemu_proc.stdout.strip():
            self.vm_meta["qemu_running"] = "yes"
            cmdline = qemu_proc.stdout
            # Check for missing -cpu host or missing hv flags in cmdline
            if "-cpu" in cmdline and "host" not in cmdline:
                self.findings.append(Finding(
                    "medium",
                    "QEMU not using '-cpu host' passthrough",
                    ["QEMU process running with custom CPU model instead of host passthrough."],
                    ["Missing CPU features can cause browser JIT/WASM crashes."],
                    ["Set CPU model to 'host' in VM XML: <cpu mode='host-passthrough'/>."],
                ))

        # -- AppArmor/SELinux blocking QEMU --
        self.run_cmd("aa-status 2>/dev/null || true", "apparmor_status", timeout=10)
        self.run_cmd("getenforce 2>/dev/null || true", "selinux_status", timeout=10)
        audit = self.run_cmd(
            "journalctl -n 200 --no-pager | grep -iE 'apparmor.*denied.*qemu|avc.*denied.*qemu' || true",
            "security_denials", timeout=10,
        )
        if audit.stdout.strip():
            self.findings.append(Finding(
                "high",
                "AppArmor/SELinux blocking QEMU operations",
                ["Denied audit entries found for qemu process."],
                [
                    "Mandatory access control policy blocking QEMU memory/device access.",
                    "This can cause immediate VM crash on browser launch (memory mapping denied).",
                ],
                [
                    "Review AppArmor/SELinux audit logs: journalctl | grep denied.*qemu.",
                    "Set libvirt AppArmor profile to complain mode: aa-complain /etc/apparmor.d/usr.sbin.libvirtd.",
                    "Or adjust policy to allow required accesses.",
                ],
            ))

    def _inspect_vbox_vm(self, vm: str) -> None:
        info = self.run_cmd(f"VBoxManage showvminfo {shlex_quote(vm)} --machinereadable", "vbox_machinereadable", timeout=15)
        data = info.stdout

        # -- RAM --
        mem_match = re.search(r'memory=(\d+)', data)
        if mem_match:
            mem_mib = int(mem_match.group(1))
            self.vm_meta["ram_mib"] = str(mem_mib)
            if mem_mib < MIN_VM_RAM_MIB:
                self.findings.append(Finding(
                    "high",
                    f"VM RAM too low for modern browsers ({mem_mib} MiB < {MIN_VM_RAM_MIB} MiB)",
                    [f"VBoxManage reports {mem_mib} MiB allocated to VM '{vm}'."],
                    [
                        "Chrome/Edge multi-process architecture needs 2-3 GB alone.",
                        "Low VM RAM causes GPU process crash, tab crash, or full VM freeze.",
                    ],
                    [
                        f"Increase VM RAM: VBoxManage modifyvm {vm} --memory {MIN_VM_RAM_MIB}.",
                        "If host RAM is limited, reduce concurrent analysis count.",
                    ],
                ))

        # -- Graphics controller --
        gfx_match = re.search(r'graphicscontrollertypestr="([^"]+)"', data, re.IGNORECASE)
        if not gfx_match:
            gfx_match = re.search(r'GraphicsControllerType="([^"]+)"', data, re.IGNORECASE)
        if gfx_match:
            gfx = gfx_match.group(1)
            self.vm_meta["graphics_controller"] = gfx
            if gfx.lower() in ("vmsvga", "vboxsvga"):
                self.findings.append(Finding(
                    "high",
                    f"VirtualBox graphics controller '{gfx}' unstable with modern browsers",
                    [f"Graphics controller set to '{gfx}'."],
                    [
                        f"'{gfx}' with 3D acceleration causes Chrome/Edge GPU process crash.",
                        "VBoxSVGA/VMSVGA 3D support is experimental and triggers browser sandbox violations.",
                    ],
                    [
                        f"Switch to VBoxVGA: VBoxManage modifyvm {vm} --graphicscontroller vboxvga.",
                        "Disable 3D acceleration alongside.",
                        "Browsers will fall back to software rendering (stable).",
                    ],
                ))

        # -- VRAM --
        vram_match = re.search(r'vram=(\d+)', data)
        if vram_match:
            vram_mib = int(vram_match.group(1))
            self.vm_meta["vram_mib"] = str(vram_mib)
            if vram_mib < MIN_VRAM_MIB:
                self.findings.append(Finding(
                    "medium",
                    f"VirtualBox VRAM too low ({vram_mib} MiB < {MIN_VRAM_MIB} MiB)",
                    [f"Video memory set to {vram_mib} MiB."],
                    ["Low VRAM causes rendering failures and GPU process crashes."],
                    [f"Increase VRAM: VBoxManage modifyvm {vm} --vram {MIN_VRAM_MIB}."],
                ))

        # -- 3D acceleration --
        accel3d_match = re.search(r'accelerate3d="(\w+)"', data, re.IGNORECASE)
        if accel3d_match and accel3d_match.group(1).lower() == "on":
            self.vm_meta["3d_acceleration"] = "on"
            self.findings.append(Finding(
                "high",
                "VirtualBox 3D acceleration enabled - primary browser crash cause",
                ["accelerate3d=\"on\" in VM configuration."],
                [
                    "3D acceleration in VirtualBox causes Chrome/Edge GPU process to crash.",
                    "The browser GPU sandbox cannot operate with VirtualBox's 3D passthrough.",
                ],
                [
                    f"Disable: VBoxManage modifyvm {vm} --accelerate3d off.",
                    "Use '--fix' to apply automatically.",
                ],
            ))

        # -- 2D acceleration (legacy, can cause issues) --
        accel2d_match = re.search(r'accelerate2dvideo="(\w+)"', data, re.IGNORECASE)
        if accel2d_match and accel2d_match.group(1).lower() == "on":
            self.vm_meta["2d_acceleration"] = "on"

        # -- Nested VT-x/AMD-V (browser sandbox may need it) --
        nested_match = re.search(r'nestedpaging="(\w+)"', data, re.IGNORECASE)
        hwvirtex_match = re.search(r'hwvirtex="(\w+)"', data, re.IGNORECASE)
        if hwvirtex_match and hwvirtex_match.group(1).lower() != "on":
            self.findings.append(Finding(
                "high",
                "VirtualBox hardware virtualization (VT-x/AMD-V) disabled for VM",
                ["hwvirtex is not 'on' in VM config."],
                ["VM runs in software emulation mode, causing extreme slowness and crashes."],
                [f"Enable: VBoxManage modifyvm {vm} --hwvirtex on --nestedpaging on."],
            ))

    @staticmethod
    def _to_mib(value: int, unit: str) -> int:
        """Convert libvirt memory value to MiB."""
        unit = unit.lower().replace("i", "")
        if unit in ("kb", "kib"):
            return value // 1024
        if unit in ("b", "bytes"):
            return value // (1024 * 1024)
        if unit in ("gb", "gib"):
            return value * 1024
        return value  # already MiB

    # ------------------------------------------------------------------
    # Host memory pressure analysis
    # ------------------------------------------------------------------

    def check_host_memory(self) -> None:
        """Analyse host free memory to detect pressure that would crash
        a VM running a modern browser."""
        free_res = self.run_cmd("free -m", "free_mem_mib")
        for line in free_res.stdout.splitlines():
            if line.lower().startswith("mem:"):
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        total = int(parts[1])
                        available = int(parts[6]) if len(parts) >= 7 else int(parts[3])
                        self.vm_meta["host_ram_total_mib"] = str(total)
                        self.vm_meta["host_ram_available_mib"] = str(available)
                        if available < MIN_HOST_FREE_MIB:
                            self.findings.append(Finding(
                                "high",
                                f"Host RAM critically low ({available} MiB free of {total} MiB)",
                                [f"free -m shows {available} MiB available."],
                                [
                                    "Kernel OOM-killer will target qemu/VirtualBox process.",
                                    "VM crash on browser launch is the direct consequence.",
                                ],
                                [
                                    "Free host RAM: stop unused services, reduce concurrent CAPE tasks.",
                                    "Add swap: fallocate -l 4G /swapfile && mkswap /swapfile && swapon /swapfile.",
                                    "Increase host physical RAM.",
                                ],
                            ))
                    except (ValueError, IndexError):
                        pass

        # -- Huge pages / KSM --
        self.run_cmd("cat /sys/kernel/mm/transparent_hugepage/enabled || true", "thp_status")
        ksm = self.run_cmd("cat /sys/kernel/mm/ksm/run 2>/dev/null || true", "ksm_status")
        if ksm.stdout.strip() == "0":
            self.findings.append(Finding(
                "low",
                "KSM (Kernel Same-page Merging) disabled",
                ["KSM is not running (/sys/kernel/mm/ksm/run = 0)."],
                ["Enabling KSM can save 10-30% RAM with multiple similar Windows VMs."],
                ["Enable: echo 1 > /sys/kernel/mm/ksm/run (or use '--fix')."],
            ))

    # ------------------------------------------------------------------
    # CAPE analysis failures collection
    # ------------------------------------------------------------------

    def collect_failed_analyses(self) -> None:
        """Scan recent CAPE/Cuckoo analyses for failures, especially
        browser-related crashes."""
        storage_paths = []
        for root in self._possible_roots():
            for candidate in [root / "storage" / "analyses", root / "storage"]:
                if candidate.is_dir():
                    storage_paths.append(candidate)

        if not storage_paths:
            self.logger.info("No analysis storage directory found, skipping failed analyses scan.")
            return

        fail_dir = self.out_dir / "failed_analyses"
        fail_dir.mkdir(exist_ok=True)
        browser_crash_count = 0
        total_failures = 0

        for storage in storage_paths:
            # Look at the last 20 analysis dirs (sorted numerically descending)
            try:
                analysis_dirs = sorted(
                    [d for d in storage.iterdir() if d.is_dir() and d.name.isdigit()],
                    key=lambda d: int(d.name),
                    reverse=True,
                )[:20]
            except Exception:
                continue

            for adir in analysis_dirs:
                task_log = adir / "task.json"
                debug_log = adir / "logs" / "analysis.log"
                report_json = adir / "reports" / "report.json"

                # Check for failure markers
                is_failure = False
                is_browser_crash = False

                for logfile in [task_log, debug_log, report_json]:
                    if not logfile.exists():
                        continue
                    try:
                        content = logfile.read_text(encoding="utf-8", errors="ignore")[:500_000]
                    except Exception:
                        continue

                    if re.search(r'"errors":\s*\[.+\]|"status":\s*"failed"|CriticalError|guest_error', content, re.IGNORECASE):
                        is_failure = True

                    if re.search(
                        r"chrome\.exe.*crash|msedge\.exe.*crash|firefox\.exe.*crash"
                        r"|browser.*crash|gpu[_-]?process.*crash"
                        r"|STATUS_ACCESS_VIOLATION.*chrome|STATUS_ACCESS_VIOLATION.*msedge"
                        r"|renderer.*crash|broker.*crash|utility.*crash"
                        r"|WerFault.*chrome|WerFault.*msedge|WerFault.*firefox",
                        content, re.IGNORECASE,
                    ):
                        is_browser_crash = True
                        is_failure = True

                if is_failure:
                    total_failures += 1
                    if is_browser_crash:
                        browser_crash_count += 1
                    # Copy key logs for the failed analysis
                    target = fail_dir / adir.name
                    target.mkdir(exist_ok=True)
                    for src in [task_log, debug_log]:
                        if src.exists():
                            try:
                                data = src.read_text(encoding="utf-8", errors="ignore")
                                (target / src.name).write_text(self._mask_secrets(data[-100_000:]), encoding="utf-8")
                            except Exception:
                                pass

        self.vm_meta["recent_failures"] = str(total_failures)
        self.vm_meta["browser_crash_failures"] = str(browser_crash_count)

        if browser_crash_count > 0:
            self.findings.append(Finding(
                "high",
                f"Browser crash detected in {browser_crash_count}/{total_failures} recent failed analyses",
                [
                    f"{browser_crash_count} analyses show browser process crash signatures.",
                    "Check failed_analyses/ in the bundle for details.",
                ],
                [
                    "Chrome/Edge GPU process crash due to VM graphics/memory configuration.",
                    "CAPE monitor DLL injection conflict with browser multi-process sandbox.",
                    "Missing VC++ redistributables or .NET in guest.",
                ],
                [
                    "Check VM video adapter and RAM (see other findings).",
                    "In guest, install latest VC++ Redistributables (2015-2022 x86+x64).",
                    "Test browser with --disable-gpu --no-sandbox flags (see CAPE package options).",
                    "If CAPE monitor injection crashes the browser, set options=free=yes in the analysis.",
                ],
            ))

    # ------------------------------------------------------------------
    # CAPE package / browser options check
    # ------------------------------------------------------------------

    def check_cape_browser_config(self) -> None:
        """Verify that CAPE browser package is configured with the right
        options for modern browsers in a VM."""
        found_package_config = False
        browser_options_ok = False

        for root in self._possible_roots():
            # Check for custom package options in conf
            for conf_name in ("web.conf", "cuckoo.conf", "auxiliary.conf"):
                conf_path = root / "conf" / conf_name
                if not conf_path.exists():
                    continue
                try:
                    content = conf_path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                if "browser" in content.lower() or "package" in content.lower():
                    found_package_config = True

            # Check custom package definitions
            pkg_dir = root / "analyzer" / "windows" / "modules" / "packages"
            if not pkg_dir.is_dir():
                pkg_dir = root / "modules" / "packages"
            if pkg_dir.is_dir():
                for pkg_file in pkg_dir.glob("*.py"):
                    try:
                        pkg_content = pkg_file.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue
                    if re.search(r"class\s+\w*[Bb]rowser|class\s+\w*[Cc]hrome|class\s+\w*[Ee]dge", pkg_content):
                        found_package_config = True
                        if re.search(r"disable.gpu|no.sandbox|disable-gpu|no-sandbox", pkg_content):
                            browser_options_ok = True
                        # Save a copy for analysis
                        (self.cfg_dir / f"package_{pkg_file.name}").write_text(
                            self._mask_secrets(pkg_content), encoding="utf-8"
                        )

        if found_package_config and not browser_options_ok:
            self.findings.append(Finding(
                "high",
                "CAPE browser package missing --disable-gpu / --no-sandbox flags",
                [
                    "Browser package found but no --disable-gpu or --no-sandbox in launch args.",
                    "Without these flags, Chrome/Edge require GPU acceleration which crashes in VMs.",
                ],
                [
                    "Chrome/Edge GPU process cannot initialize in a VM without proper GPU drivers.",
                    "The browser sandbox (seccomp/win32k lockdown) conflicts with CAPE instrumentation.",
                ],
                [
                    "Add to browser package start_args: --disable-gpu --disable-software-rasterizer --no-sandbox --disable-dev-shm-usage.",
                    "Or set options in CAPE analysis submission: options=browser_args=--disable-gpu,--no-sandbox.",
                    "Test manually: launch Chrome in guest with these flags to confirm stability.",
                ],
            ))

        # Check if clock server / NTP is configured (cert validation needs correct time)
        for root in self._possible_roots():
            aux_conf = root / "conf" / "auxiliary.conf"
            if aux_conf.exists():
                try:
                    content = aux_conf.read_text(encoding="utf-8", errors="ignore")
                    cp = configparser.ConfigParser()
                    cp.read_string(content)
                    # Check MITM / sniffer which can break certs
                    if cp.has_section("mitm") and cp.get("mitm", "enabled", fallback="no").lower() in ("yes", "true", "1"):
                        self.vm_meta["mitm_enabled"] = "yes"
                    if cp.has_section("sniffer") and cp.get("sniffer", "enabled", fallback="no").lower() in ("yes", "true", "1"):
                        self.vm_meta["sniffer_enabled"] = "yes"
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Clock drift detection
    # ------------------------------------------------------------------

    def check_clock_drift(self) -> None:
        """Detect significant clock drift between host and any known
        guest time reference. Large drift breaks TLS cert validation."""
        # Host NTP status
        ntp_res = self.run_cmd("timedatectl status 2>/dev/null || true", "timedatectl")
        if ntp_res.stdout:
            if re.search(r"NTP synchronized:\s*no|System clock synchronized:\s*no", ntp_res.stdout, re.IGNORECASE):
                self.findings.append(Finding(
                    "medium",
                    "Host NTP not synchronized",
                    ["timedatectl shows NTP synchronized: no."],
                    [
                        "If host clock drifts, guest clock drifts too (KVM/VBox inherit host RTC).",
                        "Clock drift > 5 min causes TLS certificate validation failures in browsers.",
                        "All HTTPS sites appear as 'certificate not yet valid' or 'expired'.",
                    ],
                    [
                        "Enable NTP: timedatectl set-ntp true.",
                        "Or install chrony/ntpd.",
                    ],
                ))

        # Check hwclock vs system clock drift
        hw = self.run_cmd("hwclock --show 2>/dev/null || true", "hwclock")
        self.run_cmd("date -u '+%Y-%m-%dT%H:%M:%SZ'", "system_clock")

    def collect_resources_and_runtime_logs(self) -> None:
        resource_cmds = {
            "free_mem": "free -h",
            "swap": "swapon --show || true",
            "disk_usage": "df -h",
            "dmesg_tail": "dmesg -T | tail -n 300",
            "oom_journal": "journalctl -k -n 500 --no-pager | egrep -i 'oom|killed process|out of memory|qemu|virtualbox|vbox' || true",
            "syslog_tail": "tail -n 300 /var/log/syslog 2>/dev/null || tail -n 300 /var/log/messages 2>/dev/null || true",
        }
        for name, cmd in resource_cmds.items():
            self.run_cmd(cmd, name)

        log_candidates = [
            Path("/var/log/cape"),
            Path("/var/log/cuckoo"),
            Path.home() / ".cuckoo" / "log",
            Path.home() / ".cuckoo" / "logs",
        ]
        for base in log_candidates:
            if not base.exists():
                continue
            for lf in sorted(base.glob("**/*.log"))[:60]:
                rel = str(lf).replace("/", "_")
                try:
                    content = lf.read_text(encoding="utf-8", errors="ignore")
                    (self.logs_dir / f"{rel}.tail.log").write_text(self._mask_secrets(content[-200000:]), encoding="utf-8")
                except Exception:
                    continue

    def collect_guest(self) -> None:
        method = self.args.guest_creds
        guest_dir = self.out_dir / "guest"
        guest_dir.mkdir(exist_ok=True)

        shared_candidates = [
            Path("/tmp"),
            Path("/var/lib/libvirt/images"),
            Path.home() / ".cuckoo" / "storage" / "analyses",
        ]
        for cand in shared_candidates:
            if not cand.exists():
                continue
            for pattern in ["agent.log", "analyzer.log", "*browser*.log", "*.dmp"]:
                for fp in cand.glob(f"**/{pattern}"):
                    if fp.is_file():
                        target = guest_dir / f"{str(fp).replace('/', '_')}"
                        try:
                            content = fp.read_bytes()
                            target.write_bytes(content[:2_000_000])
                        except Exception:
                            continue

        if method == "winrm":
            self._collect_winrm(guest_dir)

    def _collect_winrm(self, guest_dir: Path) -> None:
        host = self.args.guest_host
        user = self.args.guest_user
        pwd = self.args.guest_password
        if not (host and user and pwd):
            self.findings.append(
                Finding(
                    "medium",
                    "WinRM collection requested but missing credentials",
                    ["--guest-creds=winrm used without --guest-host/--guest-user/--guest-password"],
                    ["Insufficient authentication data"],
                    ["Provide WinRM target and credentials through CLI/env vars."],
                )
            )
            return

        if not _python_module_available("winrm"):
            self.findings.append(
                Finding(
                    "medium",
                    "WinRM Python module not installed",
                    ["import winrm failed"],
                    ["pywinrm missing from host Python environment"],
                    ["Install pywinrm offline package if available and rerun."],
                )
            )
            return

        script = (
            "Get-WinEvent -LogName System -MaxEvents 200 | "
            "Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | Format-List"
        )
        py = (
            "import winrm,sys;"
            f"s=winrm.Session('http://{host}:5985/wsman',auth=('{user}','{pwd}'));"
            f"r=s.run_ps({script!r});"
            "sys.stdout.write(r.std_out.decode(errors='ignore'));"
            "sys.stderr.write(r.std_err.decode(errors='ignore'));"
            "sys.exit(r.status_code)"
        )
        res = self.run_cmd(f"python3 -c \"{py}\"", "winrm_system_events", timeout=90)
        (guest_dir / "winrm_system_events.txt").write_text(self._mask_secrets(res.stdout + "\n" + res.stderr), encoding="utf-8")

    def correlate(self) -> None:
        command_files = list(self.cmd_dir.glob("*.json"))
        corpus = ""
        for f in command_files:
            corpus += f.read_text(encoding="utf-8", errors="ignore") + "\n"

        # Also scan collected logs
        for lf in self.logs_dir.glob("*"):
            if lf.is_file():
                try:
                    corpus += lf.read_text(encoding="utf-8", errors="ignore")[:200_000] + "\n"
                except Exception:
                    pass

        def has(pattern: str) -> bool:
            return re.search(pattern, corpus, re.IGNORECASE) is not None

        # --- OOM / memory kill ---
        if has(r"oom|out of memory|killed process.*qemu|killed process.*virtualbox"):
            self.findings.append(
                Finding(
                    "high",
                    "VM process likely killed by OOM",
                    ["OOM/kill signatures found in kernel or journal logs."],
                    ["Insufficient host RAM/swap for modern browser workload in guest."],
                    ["Increase host RAM or VM RAM; reduce concurrent analyses; add swap; disable heavy browser features."],
                )
            )

        # --- Networking / NAT ---
        if has(r"FORWARD DROP|Chain FORWARD .*policy DROP") and not has(r"MASQUERADE"):
            self.findings.append(
                Finding(
                    "high",
                    "Potential routing/NAT breakage",
                    ["FORWARD policy appears DROP with no clear MASQUERADE rule."],
                    ["Guest egress blocked causing browser/package failures."],
                    ["Enable ip_forward and add NAT MASQUERADE on outbound interface."],
                )
            )

        # --- Resultserver ---
        if has(r"resultserver") and has(r"timeout|refused|unreachable|mismatch"):
            self.findings.append(
                Finding(
                    "high",
                    "Resultserver communication issue",
                    ["Resultserver errors/timeouts seen in runtime logs."],
                    ["Resultserver IP/port mismatch after host IP change; firewall block."],
                    ["Align resultserver IP/port in routing/machinery configs and open firewall path."],
                )
            )

        # --- VirtualBox 3D (generic, for cases without --vm-name) ---
        if has(r"3D|VMSVGA|VBoxSVGA|gpu|ANGLE|d3d|dxgi|opengl") and self.detected.get("hypervisor") == "virtualbox":
            # Only add if not already flagged by deep inspection
            if not any("3D acceleration" in f.symptom for f in self.findings):
                self.findings.append(
                    Finding(
                        "medium",
                        "Potential browser crash from VirtualBox 3D/GPU acceleration",
                        ["Graphics acceleration references found with modern browser crash context."],
                        ["VirtualBox guest graphics/3D instability."],
                        ["Disable 3D acceleration for analysis VM and test with software rendering."],
                    )
                )

        # --- QEMU/KVM errors specific to VM crash ---
        if has(r"kvm run failed|KVM_EXIT_INTERNAL_ERROR|KVM_EXIT_SHUTDOWN|invalid opcode|triple fault"):
            self.findings.append(Finding(
                "high",
                "KVM internal error / triple fault detected",
                ["KVM_EXIT_INTERNAL_ERROR or triple fault in qemu/libvirt logs."],
                [
                    "Guest hit a CPU-level fault (invalid opcode, EPT violation, or triple fault).",
                    "Common with modern browsers that use advanced CPU instructions (AVX, SSE4).",
                ],
                [
                    "Use CPU host passthrough: <cpu mode='host-passthrough'/> in VM XML.",
                    "Check BIOS for EPT (Extended Page Tables) / NPT support.",
                    "Verify guest Windows is not corrupted (run sfc /scannow).",
                ],
            ))

        # --- QEMU device errors ---
        if has(r"qxl.*error|spice.*error|display.*error|virtio.*gpu.*error|cirrus.*error"):
            self.findings.append(Finding(
                "medium",
                "QEMU display device errors detected",
                ["Display/GPU device error messages in qemu or libvirt logs."],
                ["Video adapter driver issue in guest or incompatible adapter type."],
                [
                    "Switch video adapter type (try QXL with QXL WDDM driver in guest).",
                    "Disable 3D acceleration.",
                ],
            ))

        # --- Browser process crash signatures ---
        if has(r"STATUS_ACCESS_VIOLATION.*(?:chrome|msedge|firefox)"
               r"|gpu_process_host.*crash|GpuProcessHost.*OnProcessCrashed"
               r"|Gpu process exited|EXCEPTION_ACCESS_VIOLATION.*browser"
               r"|chrome\.exe.*has stopped|msedge\.exe.*has stopped"):
            if not any("Browser crash" in f.symptom for f in self.findings):
                self.findings.append(Finding(
                    "high",
                    "Browser process crash signatures in logs",
                    ["STATUS_ACCESS_VIOLATION or GPU process crash for Chrome/Edge found."],
                    [
                        "Browser GPU process fails to initialize in VM environment.",
                        "Missing GPU drivers, 3D acceleration misconfigured, or CAPE monitor conflict.",
                    ],
                    [
                        "Launch browser with: --disable-gpu --no-sandbox --disable-dev-shm-usage.",
                        "Check VM video adapter type and VRAM.",
                        "Install VC++ Redistributables 2015-2022 (x86+x64) in guest.",
                        "If CAPE monitor conflicts, test with options=free=yes.",
                    ],
                ))

        # --- CAPE monitor / injection failures ---
        if has(r"injection failed|inject.*error|monitor.*fail|cuckoomon.*error|capemon.*error"
               r"|inject_dll.*fail|loader.*error.*inject"):
            self.findings.append(Finding(
                "high",
                "CAPE monitor injection failure",
                ["DLL injection or monitor initialization errors in analysis logs."],
                [
                    "CAPE monitor (capemon/cuckoomon) DLL injection into browser process failed.",
                    "Modern browsers (Chrome/Edge) have strict sandbox policies that block injection.",
                    "Browser multi-process architecture: injection into broker/GPU/renderer child fails.",
                ],
                [
                    "Test analysis with options=free=yes to confirm if injection is the root cause.",
                    "Update CAPE to latest version for improved browser injection support.",
                    "Consider using 'browser' package type which handles multi-process browsers.",
                    "Set options=injection=0 as a workaround if behavioral analysis is not needed.",
                ],
            ))

        # --- TLS / cert / IE false positives ---
        if has(r"certificate|tls|ssl|smartscreen|defender|proxy|sinkhole|block page|captive"):
            self.findings.append(
                Finding(
                    "medium",
                    "IE marking all URLs may be policy/TLS/proxy artifact",
                    ["TLS/cert/proxy/smartscreen-like indicators found in logs/config."],
                    ["MITM cert trust issue, sinkhole DNS/proxy block page classified as malicious."],
                    ["Validate root cert chain in guest, proxy settings, SmartScreen/Defender policy for controlled lab mode."],
                )
            )

        # --- Snapshot corruption indicators ---
        if has(r"snapshot.*error|snapshot.*corrupt|snapshot.*fail|could not restore|restore.*fail"
               r"|domain.*not found|cannot restore|virDomainSnapshotRestore"):
            self.findings.append(Finding(
                "high",
                "VM snapshot restore failure",
                ["Snapshot error/corruption messages found in logs."],
                [
                    "Corrupted snapshot causes VM to crash immediately after restore.",
                    "If snapshot was taken while browser/GPU was active, the restored state is unstable.",
                ],
                [
                    "Delete current snapshot and create a fresh one with VM at idle (desktop visible, no apps open).",
                    "Ensure guest has finished booting and all services are started before taking snapshot.",
                    "For KVM: virsh snapshot-delete <vm> <snap> && virsh snapshot-create-as <vm> <snap>.",
                ],
            ))

        # --- Agent communication ---
        if has(r"agent.*timeout|agent.*error|agent.*unreachable|guest.*not.*respond"
               r"|connection refused.*2042|connection refused.*8000"):
            self.findings.append(Finding(
                "high",
                "CAPE agent in guest not responding",
                ["Agent timeout or connection refused errors found."],
                [
                    "Guest agent (agent.py/agent.pyw) not running or blocked by guest firewall.",
                    "VM network misconfigured: resultserver cannot reach guest or vice versa.",
                ],
                [
                    "Verify agent.pyw is in Startup folder or scheduled at boot in guest.",
                    "Check guest Windows Firewall allows inbound on agent port (default 8000).",
                    "Verify resultserver IP matches host IP on guest-facing interface.",
                ],
            ))

        # --- IP forward disabled ---
        if has(r"net\.ipv4\.ip_forward\s*=\s*0"):
            self.findings.append(Finding(
                "high",
                "IP forwarding disabled on host",
                ["sysctl net.ipv4.ip_forward = 0."],
                ["Guest VM has no outbound internet access through host routing."],
                [
                    "Enable: sysctl -w net.ipv4.ip_forward=1.",
                    "Persist: echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.d/cape.conf.",
                    "Use '--fix' to apply automatically.",
                ],
            ))

        if not self.findings:
            self.findings.append(
                Finding(
                    "low",
                    "No obvious hard failure signatures",
                    ["Checks completed without deterministic blocker."],
                    ["Issue may be intermittent or guest-specific."],
                    ["Run targeted single-task analysis with verbose CAPE logging and collect guest event logs."],
                )
            )

    def apply_fixes(self) -> None:
        if not self.args.fix:
            return
        self.logger.info("Applying safe fixes (--fix enabled)")
        vm = self.args.vm_name
        hv = self.detected.get("hypervisor")

        # --- Network fixes ---
        self.run_cmd("sysctl -w net.ipv4.ip_forward=1", "fix_enable_ip_forward")

        route = self.run_cmd("ip route show default | awk '{print $5}' | head -n1", "default_iface")
        iface = route.stdout.strip()
        if iface:
            check = self.run_cmd(f"iptables -t nat -S | grep -F -- '-A POSTROUTING -o {iface} -j MASQUERADE'", "check_masquerade")
            if check.rc != 0:
                self.run_cmd(f"iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE", "fix_add_masquerade")

        # --- Permission fixes ---
        for d in [Path("/var/log/cape"), Path("/var/log/cuckoo"), Path.home() / ".cuckoo" / "log"]:
            if d.exists():
                self.run_cmd(f"chmod -R u+rwX {shlex_quote(str(d))}", f"fix_perm_{d.name}")

        # --- KSM ---
        ksm_path = Path("/sys/kernel/mm/ksm/run")
        if ksm_path.exists():
            try:
                if ksm_path.read_text().strip() == "0":
                    self.run_cmd("echo 1 > /sys/kernel/mm/ksm/run", "fix_enable_ksm")
            except Exception:
                pass

        # --- KVM-specific browser crash fixes ---
        if hv == "kvm" and vm:
            self._fix_kvm_browser_crash(vm)

        # --- VirtualBox-specific browser crash fixes ---
        if hv == "virtualbox" and vm:
            self._fix_vbox_browser_crash(vm)

        # --- Service restarts (last, after config changes) ---
        if self.detected.get("service_manager") == "systemd":
            for svc in ["cape", "cuckoo", "libvirtd", "virtqemud"]:
                self.run_cmd(f"systemctl restart {svc}", f"fix_restart_{svc}")

    def _fix_kvm_browser_crash(self, vm: str) -> None:
        """Apply KVM-specific fixes for modern browser crashes."""
        xml_res = self.run_cmd(f"virsh dumpxml {shlex_quote(vm)}", "fix_kvm_read_xml", timeout=15)
        xml = xml_res.stdout
        if not xml:
            return

        changes_made = []

        # Fix 1: Video adapter -> QXL if currently VGA/virtio/bochs
        video_model = re.search(r"<model\s+type=['\"](\w+)['\"]", xml)
        if video_model and video_model.group(1).lower() in ("vga", "virtio", "bochs", "ramfb"):
            old_adapter = video_model.group(1)
            # Replace video model type with qxl and set vram
            new_xml = re.sub(
                r"(<model\s+type=['\"])\w+(['\"])",
                r"\1qxl\2",
                xml,
                count=1,
            )
            # Ensure VRAM is adequate
            if "vram=" in new_xml:
                new_xml = re.sub(r"vram=['\"](\d+)['\"]", f"vram='{MIN_VRAM_MIB * 1024}'", new_xml, count=1)
            # Remove accel3d if present
            new_xml = re.sub(r"\s*accel3d=['\"]yes['\"]", "", new_xml)
            changes_made.append(f"video adapter {old_adapter} -> qxl")
            xml = new_xml

        # Fix 2: Disable 3D acceleration if enabled
        if re.search(r"accel3d=['\"]yes['\"]", xml):
            xml = re.sub(r"accel3d=['\"]yes['\"]", "accel3d='no'", xml)
            changes_made.append("disabled 3D acceleration")

        # Fix 3: Add Hyper-V enlightenments if missing
        hv_section = re.search(r"<hyperv>(.*?)</hyperv>", xml, re.DOTALL)
        needed_hv = {
            "relaxed": "<relaxed state='on'/>",
            "vapic": "<vapic state='on'/>",
            "spinlocks": "<spinlocks state='on' retries='8191'/>",
        }
        if hv_section:
            existing = hv_section.group(1)
            additions = ""
            for feat, tag in needed_hv.items():
                if feat not in existing:
                    additions += f"\n      {tag}"
                    changes_made.append(f"added hyperv {feat}")
            if additions:
                xml = xml.replace(hv_section.group(0), f"<hyperv>{existing}{additions}\n    </hyperv>")
        else:
            # Insert hyperv block into <features>
            features_match = re.search(r"(<features>)", xml)
            if features_match:
                hv_block = "\n    <hyperv>\n"
                for feat, tag in needed_hv.items():
                    hv_block += f"      {tag}\n"
                    changes_made.append(f"added hyperv {feat}")
                hv_block += "    </hyperv>"
                xml = xml.replace(features_match.group(0), f"<features>{hv_block}")

        # Fix 4: CPU host-passthrough if not set
        cpu_match = re.search(r"<cpu[^>]*mode=['\"]([^'\"]+)['\"]", xml)
        if not cpu_match or cpu_match.group(1) != "host-passthrough":
            if re.search(r"<cpu[^>]*>", xml):
                xml = re.sub(r"<cpu[^>]*mode=['\"][^'\"]+['\"]", "<cpu mode='host-passthrough'", xml)
            else:
                # Insert before </domain>
                xml = xml.replace("</domain>", "  <cpu mode='host-passthrough'/>\n</domain>")
            changes_made.append("set CPU mode to host-passthrough")

        # Fix 5: Increase RAM if below minimum
        ram_mib_str = self.vm_meta.get("ram_mib", "0")
        try:
            ram_mib = int(ram_mib_str)
        except ValueError:
            ram_mib = 0
        if 0 < ram_mib < MIN_VM_RAM_MIB:
            new_kib = MIN_VM_RAM_MIB * 1024
            xml = re.sub(r"<memory[^>]*>\d+</memory>", f"<memory unit='KiB'>{new_kib}</memory>", xml)
            xml = re.sub(r"<currentMemory[^>]*>\d+</currentMemory>", f"<currentMemory unit='KiB'>{new_kib}</currentMemory>", xml)
            changes_made.append(f"increased RAM {ram_mib} -> {MIN_VM_RAM_MIB} MiB")

        if changes_made:
            self.logger.info("KVM fixes to apply: %s", "; ".join(changes_made))
            xml_path = self.out_dir / "fixed_vm.xml"
            xml_path.write_text(xml, encoding="utf-8")
            # VM must be shut off to redefine
            self.run_cmd(f"virsh destroy {shlex_quote(vm)} 2>/dev/null || true", "fix_kvm_shutoff")
            res = self.run_cmd(f"virsh define {shlex_quote(str(xml_path))}", "fix_kvm_redefine", timeout=30)
            if res.rc == 0:
                self.logger.info("VM redefined successfully with fixes: %s", "; ".join(changes_made))
                # Snapshot needs to be recreated after XML change
                self.findings.append(Finding(
                    "medium",
                    "VM XML was modified by --fix: snapshot must be recreated",
                    [f"Applied: {'; '.join(changes_made)}."],
                    ["Old snapshot references previous VM configuration."],
                    [
                        f"1. Start VM: virsh start {vm}",
                        "2. Wait for guest to fully boot and reach desktop.",
                        "3. Install QXL drivers if video adapter was changed (virtio-win ISO).",
                        f"4. Create new snapshot: virsh snapshot-create-as {vm} clean --atomic.",
                    ],
                ))
            else:
                self.logger.warning("Failed to redefine VM: %s", res.stderr)

    def _fix_vbox_browser_crash(self, vm: str) -> None:
        """Apply VirtualBox-specific fixes for modern browser crashes."""
        changes_made = []
        qvm = shlex_quote(vm)

        # Must power off VM first
        self.run_cmd(f"VBoxManage controlvm {qvm} poweroff 2>/dev/null || true", "fix_vbox_poweroff")

        # Fix 1: Disable 3D acceleration
        if self.vm_meta.get("3d_acceleration") == "on":
            self.run_cmd(f"VBoxManage modifyvm {qvm} --accelerate3d off", "fix_vbox_disable_3d")
            changes_made.append("disabled 3D acceleration")

        # Fix 2: Switch graphics controller to VBoxVGA (most stable)
        gfx = self.vm_meta.get("graphics_controller", "").lower()
        if gfx in ("vmsvga", "vboxsvga"):
            self.run_cmd(f"VBoxManage modifyvm {qvm} --graphicscontroller vboxvga", "fix_vbox_gfx_controller")
            changes_made.append(f"graphics controller {gfx} -> vboxvga")

        # Fix 3: Increase VRAM
        vram_str = self.vm_meta.get("vram_mib", "0")
        try:
            vram = int(vram_str)
        except ValueError:
            vram = 0
        if 0 < vram < MIN_VRAM_MIB:
            self.run_cmd(f"VBoxManage modifyvm {qvm} --vram {MIN_VRAM_MIB}", "fix_vbox_vram")
            changes_made.append(f"VRAM {vram} -> {MIN_VRAM_MIB} MiB")

        # Fix 4: Increase RAM if below minimum
        ram_str = self.vm_meta.get("ram_mib", "0")
        try:
            ram = int(ram_str)
        except ValueError:
            ram = 0
        if 0 < ram < MIN_VM_RAM_MIB:
            self.run_cmd(f"VBoxManage modifyvm {qvm} --memory {MIN_VM_RAM_MIB}", "fix_vbox_memory")
            changes_made.append(f"RAM {ram} -> {MIN_VM_RAM_MIB} MiB")

        # Fix 5: Ensure hardware virt is on
        if self.vm_meta.get("hwvirtex") == "off":
            self.run_cmd(f"VBoxManage modifyvm {qvm} --hwvirtex on --nestedpaging on", "fix_vbox_hwvirt")
            changes_made.append("enabled hardware virtualization + nested paging")

        if changes_made:
            self.logger.info("VirtualBox fixes applied: %s", "; ".join(changes_made))
            self.findings.append(Finding(
                "medium",
                "VirtualBox VM was modified by --fix: snapshot must be recreated",
                [f"Applied: {'; '.join(changes_made)}."],
                ["Old snapshot references previous VM configuration."],
                [
                    f"1. Start VM: VBoxManage startvm {vm} --type headless",
                    "2. Wait for guest to fully boot and reach desktop.",
                    f"3. Take new snapshot: VBoxManage snapshot {vm} take clean --live.",
                ],
            ))

    def write_report(self) -> Path:
        report = self.out_dir / "report.md"
        lines: List[str] = []
        lines.append(f"# CAPE/Cuckoo Triage Report\n")
        lines.append(f"- Generated: {dt.datetime.utcnow().isoformat()}Z")
        lines.append(f"- Host: {self.hostname}")
        lines.append(f"- Framework: {self.detected.get('framework', 'unknown')}")
        lines.append(f"- Hypervisor: {self.detected.get('hypervisor', 'unknown')}")
        lines.append(f"- Service manager: {self.detected.get('service_manager', 'unknown')}\n")

        lines.append("## Inventory")
        for k, v in sorted(self.inventory.items()):
            lines.append(f"- **{k}**: `{self._mask_secrets(v)}`")

        if self.vm_meta:
            lines.append("\n## VM Configuration")
            for k, v in sorted(self.vm_meta.items()):
                lines.append(f"- **{k}**: `{self._mask_secrets(v)}`")

        lines.append("\n## Key Checks")
        for jf in sorted(self.cmd_dir.glob("*.json")):
            try:
                data = json.loads(jf.read_text(encoding="utf-8"))
                icon = "PASS" if data["rc"] == 0 else "WARN"
                lines.append(f"- [{icon}] `{data['command']}` (rc={data['rc']}) -> `{jf.name}`")
            except Exception:
                continue

        lines.append("\n## Findings")
        for idx, f in enumerate(self.findings, start=1):
            lines.append(f"### {idx}. {f.symptom} ({f.severity.upper()})")
            lines.append("**Indices**")
            for e in f.evidence:
                lines.append(f"- {e}")
            lines.append("**Causes probables**")
            for c in f.probable_causes:
                lines.append(f"- {c}")
            lines.append("**Actions correctives**")
            for r in f.recommendations:
                lines.append(f"- {r}")

        lines.append("\n## Recommended Next Steps")
        lines.extend(
            [
                "1. Re-run one controlled URL task with detailed logging enabled.",
                "2. Compare guest browser crash timestamps with host hypervisor/kernel logs.",
                "3. Validate resultserver reachability from guest subnet.",
                "4. If IE marks all URLs malicious, inspect TLS chain/proxy/DNS sinkhole behavior in guest.",
            ]
        )

        report.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return report

    def create_archive(self) -> Path:
        archive = self.out_dir.parent / f"cape_triage_{self.hostname}_{self.timestamp}.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(self.out_dir, arcname=self.out_dir.name)
        return archive

    def print_summary(self, report: Path, archive: Path) -> None:
        sev_rank = {"high": 3, "medium": 2, "low": 1}
        top = sorted(self.findings, key=lambda x: sev_rank.get(x.severity, 0), reverse=True)[:5]
        print("\n=== CAPE Doctor Summary ===")
        for f in top:
            color = "\033[91m" if f.severity == "high" else "\033[93m" if f.severity == "medium" else "\033[92m"
            end = "\033[0m"
            print(f"{color}[{f.severity.upper()}]{end} {f.symptom}")
        print(f"Report: {report}")
        print(f"Bundle: {archive}")


def _python_module_available(mod: str) -> bool:
    try:
        __import__(mod)
        return True
    except Exception:
        return False


def shlex_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CAPE/Cuckoo all-in-one diagnostics and safe remediation")
    p.add_argument("--out-dir", help="Output directory (default: ./cape_triage_<ts>)")
    p.add_argument("--vm-name", help="Guest VM name if autodetection fails")
    p.add_argument("--hypervisor", choices=["auto", "kvm", "virtualbox"], default="auto")
    p.add_argument("--fix", action="store_true", help="Apply safe remediations")
    p.add_argument("--online", action="store_true", help="Allow online checks (dns/ping/https)")
    p.add_argument("--guest-creds", choices=["none", "winrm", "ssh", "manual"], default="none")
    p.add_argument("--guest-host", help="Guest host/IP for remote collection (winrm/ssh)")
    p.add_argument("--guest-user", help="Guest username for remote collection")
    p.add_argument("--guest-password", help="Guest password for remote collection (prefer env/secret store)")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    doctor = CapeDoctor(args)
    try:
        doctor.detect_environment()
        doctor.collect_versions_and_packages()
        doctor.collect_service_status()
        doctor.parse_configs()
        doctor.collect_network()
        doctor.collect_hypervisor()
        doctor.collect_vm_config()
        doctor.check_host_memory()
        doctor.check_cape_browser_config()
        doctor.check_clock_drift()
        doctor.collect_resources_and_runtime_logs()
        doctor.collect_failed_analyses()
        doctor.collect_guest()
        doctor.correlate()
        doctor.apply_fixes()
        report = doctor.write_report()
        archive = doctor.create_archive()
        doctor.print_summary(report, archive)
        return 0
    except Exception as exc:
        logging.exception("Unhandled error: %s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
