#!/usr/bin/env python3
"""
CAPE/Cuckoo all-in-one triage and safe remediation helper.
"""

from __future__ import annotations

import argparse
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
import xml.etree.ElementTree as ET


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


@dataclasses.dataclass
class VMInfo:
    name: str
    state: str
    id: str = "-"
    vcpus: str = "?"
    max_memory_kb: str = "?"
    machine_type: str = "?"
    cpu_mode: str = "?"
    graphics_type: str = "none"
    video_model: str = "none"
    watchdog: bool = False
    watchdog_action: str = ""
    redirdev_count: int = 0
    has_spice_channel: bool = False
    has_spice_audio: bool = False
    has_tablet: bool = False
    disk_path: str = ""
    backing_chain_depth: int = 0


@dataclasses.dataclass
class DeviceIssue:
    device: str
    severity: str
    message: str
    recommendation: str
    risk_points: int = 1


class CapeDoctor:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.hostname = socket.gethostname()
        self.timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d_%H%M%S")
        default_out = Path.cwd() / f"cape_triage_{self.timestamp}"
        self.out_dir = Path(args.out_dir or default_out).resolve()
        self.logs_dir = self.out_dir / "logs"
        self.cmd_dir = self.out_dir / "commands"
        self.cfg_dir = self.out_dir / "configs"
        self.meta_dir = self.out_dir / "metadata"
        self.findings: List[Finding] = []
        self.inventory: Dict[str, str] = {}
        self.detected: Dict[str, str] = {}
        self.vm_infos: List[VMInfo] = []
        self.vm_device_issues: Dict[str, List[DeviceIssue]] = {}
        self.runtime_secrets: List[str] = [args.guest_password] if args.guest_password else []
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
        started = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
        self.logger.debug("Running command [%s]: %s", name, self._mask_runtime_secrets(command))
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
        ended = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
        result = CmdResult(command, rc, out, err, started, ended)
        content = {
            "command": self._mask_runtime_secrets(command),
            "rc": rc,
            "started_at": started,
            "ended_at": ended,
            "stdout": self._mask_runtime_secrets(out),
            "stderr": self._mask_runtime_secrets(err),
        }
        (self.cmd_dir / f"{name}.json").write_text(json.dumps(content, indent=2), encoding="utf-8")
        return result

    def _mask_runtime_secrets(self, text: str) -> str:
        masked = self._mask_secrets(text)
        for secret in self.runtime_secrets:
            if secret and secret in masked:
                masked = masked.replace(secret, "***")
        return masked

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
    # VM diagnostics (libvirt / QEMU)
    # ------------------------------------------------------------------

    def _parse_virsh_list(self, output: str) -> List[Dict[str, str]]:
        """Parse ``virsh list --all`` output into list of dicts."""
        vms: List[Dict[str, str]] = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("Id") or line.startswith("--"):
                continue
            parts = line.split(None, 2)
            if len(parts) >= 3:
                vms.append({"id": parts[0], "name": parts[1], "state": parts[2]})
            elif len(parts) == 2:
                vms.append({"id": parts[0], "name": parts[1], "state": "unknown"})
        return vms

    def _collect_qemu_log(self, vm_name: str) -> str:
        """Tail the QEMU log for *vm_name* and return its content."""
        log_path = f"/var/log/libvirt/qemu/{vm_name}.log"
        result = self.run_cmd(
            f"tail -n 200 {shlex_quote(log_path)}", f"qemu_log_{vm_name}", timeout=10,
        )
        if result.rc == 0 and result.stdout:
            dst = self.logs_dir / f"qemu_{vm_name}.log"
            dst.write_text(self._mask_secrets(result.stdout), encoding="utf-8")
            return result.stdout
        return ""

    def _check_stopped_by_libvirt(self, vm_name: str, log_content: str) -> Optional[Finding]:
        """Detect STOPPED_BY_LIBVIRT from QEMU log content."""
        if not log_content:
            return None
        has_signal15 = bool(
            re.search(r"terminating on signal 15.*(/usr/sbin/libvirtd|from pid)", log_content),
        )
        has_destroyed = "reason=destroyed" in log_content

        if not (has_signal15 or has_destroyed):
            return None

        evidence: List[str] = []
        for line in log_content.splitlines():
            if "terminating on signal 15" in line:
                evidence.append(f"`{line.strip()}`")
                break
        for line in log_content.splitlines():
            if "reason=destroyed" in line:
                evidence.append(f"`{line.strip()}`")
                break
        evidence.append(f"Log: `/var/log/libvirt/qemu/{vm_name}.log`")
        return Finding(
            severity="high",
            symptom=f"STOPPED_BY_LIBVIRT: VM '{vm_name}' killed by libvirtd",
            evidence=evidence,
            probable_causes=[
                "libvirtd sent SIGTERM (signal 15) to the QEMU process",
                "Possible triggers: libvirtd restart, virsh destroy, cgroup OOM, or watchdog action",
                "This is NOT a proven guest crash (BSOD/freeze) — the VM was externally terminated",
            ],
            recommendations=[
                "Check journalctl -u libvirtd for the event that triggered the destroy",
                "Verify watchdog is not triggering resets/poweroffs",
                "Check for OOM events: journalctl -k | grep -i oom",
                "Remove watchdog from VM XML or set action='none'",
                "Run with --fix --fix-vm-xml to clean up risky devices",
            ],
        )

    def _check_qemu_monitor_lost(self, journal_content: str) -> Optional[Finding]:
        """Detect QEMU_MONITOR_LOST from libvirtd journal."""
        if not journal_content:
            return None
        has_null_monitor = "monitor must not be NULL" in journal_content
        has_eof = (
            "End of file while reading data" in journal_content
            and "Input/output error" in journal_content
        )
        if not (has_null_monitor or has_eof):
            return None

        evidence: List[str] = []
        for line in journal_content.splitlines():
            if "monitor must not be NULL" in line or "End of file while reading data" in line:
                evidence.append(f"`{line.strip()}`")
                if len(evidence) >= 3:
                    break
        evidence.append("Source: `journalctl -u libvirtd`")
        return Finding(
            severity="high",
            symptom="QEMU_MONITOR_LOST: libvirtd lost QEMU monitor connection",
            evidence=evidence,
            probable_causes=[
                "QEMU process died unexpectedly (OOM, device emulation error)",
                "QEMU Unix socket closed before libvirtd could detach cleanly",
                "Unstable SPICE/USB redirection causing QEMU abort",
                "libvirtd / virtqemud version mismatch or bug",
            ],
            recommendations=[
                "Remove SPICE and USB redirection devices (common cause of QEMU instability)",
                "Check /var/log/libvirt/qemu/<vm>.log for QEMU errors before the monitor disconnect",
                "Ensure libvirtd and qemu-kvm versions are compatible",
                "Switch to VNC (headless) instead of SPICE for sandbox VMs",
                "Run with --fix --fix-vm-xml --fix-spice-to-vnc to harden VM config",
            ],
        )

    @staticmethod
    def _parse_vm_xml(xml_str: str) -> Optional[ET.Element]:
        """Parse ``virsh dumpxml`` output. Returns root Element or ``None``."""
        try:
            return ET.fromstring(xml_str)
        except ET.ParseError:
            return None

    def _lint_vm_xml(self, vm_name: str, root: ET.Element) -> List[DeviceIssue]:
        """Detect problematic devices in VM XML for sandbox use."""
        issues: List[DeviceIssue] = []
        devices = root.find("devices")
        if devices is None:
            return issues

        # SPICE graphics
        for graphics in devices.findall("graphics"):
            if graphics.get("type") == "spice":
                issues.append(DeviceIssue(
                    device="graphics[type=spice]",
                    severity="medium",
                    message="SPICE display enabled — unnecessary for headless sandbox",
                    recommendation="Switch to VNC (type='vnc') or remove graphics entirely",
                ))

        # spicevmc channels
        for channel in devices.findall("channel"):
            if channel.get("type") == "spicevmc":
                issues.append(DeviceIssue(
                    device="channel[type=spicevmc]",
                    severity="medium",
                    message="SPICE vmc channel — only needed with SPICE display",
                    recommendation="Remove this channel when switching away from SPICE",
                ))

        # USB redirection (spicevmc)
        redir_count = sum(1 for r in devices.findall("redirdev") if r.get("type") == "spicevmc")
        if redir_count > 0:
            issues.append(DeviceIssue(
                device=f"redirdev[type=spicevmc] x{redir_count}",
                severity="high",
                message=(
                    f"{redir_count} USB redirection device(s) via SPICE — known source of "
                    "'usb-redir connection broken' QEMU warnings and instability"
                ),
                recommendation="Remove all redirdev elements (--fix --fix-vm-xml)",
                risk_points=2 * redir_count,
            ))

        # SPICE audio
        for audio in devices.findall("audio"):
            if audio.get("type") == "spice":
                issues.append(DeviceIssue(
                    device="audio[type=spice]",
                    severity="low",
                    message="SPICE audio backend — unnecessary in sandbox",
                    recommendation="Remove audio element or set type='none'",
                ))

        # Watchdog
        for watchdog in devices.findall("watchdog"):
            action = watchdog.get("action", "")
            model = watchdog.get("model", "")
            if action in ("reset", "poweroff", "shutdown"):
                issues.append(DeviceIssue(
                    device=f"watchdog[model={model}, action={action}]",
                    severity="high",
                    message=f"Watchdog with action='{action}' can cause unexpected VM resets during analysis",
                    recommendation="Remove watchdog or set action='none'",
                    risk_points=2,
                ))
            else:
                issues.append(DeviceIssue(
                    device=f"watchdog[model={model}, action={action or 'default'}]",
                    severity="low",
                    message="Watchdog present (benign action) — verify intent",
                    recommendation="Consider removing watchdog entirely for sandbox VMs",
                    risk_points=0,
                ))

        # USB tablet
        has_ps2 = any(i.get("bus") == "ps2" for i in devices.findall("input"))
        for inp in devices.findall("input"):
            if inp.get("type") == "tablet" and inp.get("bus") == "usb":
                extra = " — PS/2 input also present, tablet redundant" if has_ps2 else ""
                issues.append(DeviceIssue(
                    device="input[type=tablet, bus=usb]",
                    severity="low",
                    message=f"USB tablet (absolute mouse) present{extra}",
                    recommendation="Remove USB tablet if PS/2 input devices exist",
                ))

        # QXL video
        for video in devices.findall("video"):
            model_el = video.find("model")
            if model_el is not None and model_el.get("type") == "qxl":
                issues.append(DeviceIssue(
                    device="video[model=qxl]",
                    severity="medium",
                    message="QXL video (SPICE-optimized) — use VGA or virtio for headless sandbox",
                    recommendation="Switch video model to 'vga' or 'virtio'",
                ))

        return issues

    @staticmethod
    def _get_disk_path_from_xml(root: ET.Element) -> Optional[str]:
        """Extract the primary disk image path from VM XML."""
        devices = root.find("devices")
        if devices is None:
            return None
        for disk in devices.findall("disk"):
            if disk.get("device") == "disk":
                source = disk.find("source")
                if source is not None:
                    return source.get("file") or source.get("dev")
        return None

    def _extract_vm_info_from_xml(self, vm_name: str, state: str, vm_id: str,
                                  root: ET.Element) -> VMInfo:
        """Build a :class:`VMInfo` from parsed XML."""
        info = VMInfo(name=vm_name, state=state, id=vm_id)

        vcpu_el = root.find("vcpu")
        if vcpu_el is not None and vcpu_el.text:
            info.vcpus = vcpu_el.text.strip()

        mem_el = root.find("memory")
        if mem_el is not None and mem_el.text:
            info.max_memory_kb = mem_el.text.strip()

        os_el = root.find("os")
        if os_el is not None:
            type_el = os_el.find("type")
            if type_el is not None:
                info.machine_type = type_el.get("machine", "?")

        cpu_el = root.find("cpu")
        if cpu_el is not None:
            info.cpu_mode = cpu_el.get("mode", "?")

        devices = root.find("devices")
        if devices is not None:
            for g in devices.findall("graphics"):
                info.graphics_type = g.get("type", "none")
                break
            for v in devices.findall("video"):
                m = v.find("model")
                if m is not None:
                    info.video_model = m.get("type", "?")
                break
            wd = devices.find("watchdog")
            if wd is not None:
                info.watchdog = True
                info.watchdog_action = wd.get("action", "")
            info.redirdev_count = sum(
                1 for r in devices.findall("redirdev") if r.get("type") == "spicevmc"
            )
            info.has_spice_channel = any(
                c.get("type") == "spicevmc" for c in devices.findall("channel")
            )
            info.has_spice_audio = any(
                a.get("type") == "spice" for a in devices.findall("audio")
            )
            info.has_tablet = any(
                i.get("type") == "tablet" and i.get("bus") == "usb"
                for i in devices.findall("input")
            )
            info.disk_path = self._get_disk_path_from_xml(root) or ""

        return info

    def _check_backing_chain(self, disk_path: str, vm_name: str) -> Dict:
        """Check qcow2 backing chain depth."""
        result = self.run_cmd(
            f"qemu-img info --backing-chain {shlex_quote(disk_path)}",
            f"qemu_backing_chain_{vm_name}",
            timeout=30,
        )
        depth = 0
        if result.rc == 0 and result.stdout:
            image_lines = [ln for ln in result.stdout.splitlines() if ln.startswith("image:")]
            depth = len(image_lines)
        return {
            "depth": depth,
            "output": result.stdout[:2000] if result.stdout else "",
            "rc": result.rc,
            "error": result.stderr[:500] if result.stderr else "",
        }

    def _fix_vm_xml(self, vm_name: str, xml_str: str, root: ET.Element) -> bool:
        """Apply sandbox-minimal XML fixes. Returns ``True`` if changes were applied."""
        devices = root.find("devices")
        if devices is None:
            self.logger.warning("No <devices> section in XML for %s", vm_name)
            return False

        changed = False
        removed: List[str] = []

        # Remove USB redirdev (spicevmc)
        for redirdev in list(devices.findall("redirdev")):
            if redirdev.get("type") == "spicevmc":
                devices.remove(redirdev)
                removed.append("redirdev[type=spicevmc]")
                changed = True

        # Remove redirfilter
        for rf in list(devices.findall("redirfilter")):
            devices.remove(rf)
            removed.append("redirfilter")
            changed = True

        # Remove watchdog
        for wd in list(devices.findall("watchdog")):
            devices.remove(wd)
            removed.append(f"watchdog[model={wd.get('model', '?')}, action={wd.get('action', '?')}]")
            changed = True

        # Remove USB tablet if PS/2 inputs exist
        inputs = devices.findall("input")
        has_ps2 = any(i.get("bus") == "ps2" for i in inputs)
        if has_ps2:
            for inp in list(inputs):
                if inp.get("type") == "tablet" and inp.get("bus") == "usb":
                    devices.remove(inp)
                    removed.append("input[type=tablet, bus=usb]")
                    changed = True

        # Optional: SPICE -> VNC and QXL -> VGA
        if getattr(self.args, "fix_spice_to_vnc", False):
            for graphics in list(devices.findall("graphics")):
                if graphics.get("type") == "spice":
                    for child in list(graphics):
                        graphics.remove(child)
                    graphics.set("type", "vnc")
                    graphics.set("port", "-1")
                    graphics.set("autoport", "yes")
                    graphics.set("listen", "127.0.0.1")
                    removed.append("graphics[spice->vnc]")
                    changed = True

            for video in devices.findall("video"):
                model_el = video.find("model")
                if model_el is not None and model_el.get("type") == "qxl":
                    model_el.set("type", "vga")
                    for attr in ("ram", "vram", "vgamem"):
                        if attr in model_el.attrib:
                            del model_el.attrib[attr]
                    removed.append("video[qxl->vga]")
                    changed = True

            for channel in list(devices.findall("channel")):
                if channel.get("type") == "spicevmc":
                    devices.remove(channel)
                    removed.append("channel[type=spicevmc]")
                    changed = True

            for audio in list(devices.findall("audio")):
                if audio.get("type") == "spice":
                    devices.remove(audio)
                    removed.append("audio[type=spice]")
                    changed = True

        if not changed:
            self.logger.info("No changes needed for VM '%s'", vm_name)
            return False

        self.logger.info("Changes for VM '%s': %s", vm_name, removed)
        tmp_xml = f"/tmp/cape_doctor_fixed_{vm_name}.xml"
        try:
            tree = ET.ElementTree(root)
            tree.write(tmp_xml, encoding="unicode", xml_declaration=True)

            result = self.run_cmd(
                f"virsh define {shlex_quote(tmp_xml)}", f"virsh_define_{vm_name}", timeout=30,
            )
            if result.rc != 0:
                self.logger.error("virsh define failed for %s: %s", vm_name, result.stderr)
                self.findings.append(Finding(
                    severity="medium",
                    symptom=f"Failed to apply XML fix for VM '{vm_name}'",
                    evidence=[f"virsh define rc={result.rc}", result.stderr[:200]],
                    probable_causes=["XML syntax error after patch", "VM locked or running"],
                    recommendations=[f"Manually check {tmp_xml} and run: virsh define {tmp_xml}"],
                ))
                return False

            self.findings.append(Finding(
                severity="low",
                symptom=f"FIX APPLIED: VM '{vm_name}' XML updated (sandbox minimal profile)",
                evidence=[
                    f"Removed: {', '.join(removed)}",
                    f"Backup: /tmp/cape_doctor_backup_{vm_name}.xml",
                    f"Fixed XML: {tmp_xml}",
                ],
                probable_causes=["--fix --fix-vm-xml requested by operator"],
                recommendations=[
                    f"Verify VM starts correctly: virsh start {vm_name}",
                    f"Review with: virsh dumpxml {vm_name}",
                ],
            ))
            return True
        except Exception as exc:
            self.logger.error("Failed to write/apply fixed XML for %s: %s", vm_name, exc)
            return False

    def diagnose_vms(self) -> None:
        """Orchestrate all VM-level diagnostics for KVM/libvirt."""
        hv = self.detected.get("hypervisor")
        if hv != "kvm":
            return

        list_result = self.run_cmd("virsh list --all", "virsh_list_vms_diag", timeout=15)
        vm_list = self._parse_virsh_list(list_result.stdout or "")

        if not vm_list:
            self.logger.info("No VMs found via virsh list --all")
            return

        # Determine which VMs to diagnose
        target_vm = self.args.vm_name
        all_vms = getattr(self.args, "all_vms", False)
        if all_vms or not target_vm:
            vms_to_check = vm_list
        else:
            vms_to_check = [v for v in vm_list if v["name"] == target_vm]
            if not vms_to_check:
                self.logger.warning("VM '%s' not found in virsh list, checking all VMs", target_vm)
                vms_to_check = vm_list

        # Collect libvirtd journal once (shared across VMs)
        journal_result = self.run_cmd(
            "journalctl -u libvirtd --no-pager -n 500 2>/dev/null || true",
            "journal_libvirtd_vmdiag", timeout=30,
        )
        journal_content = journal_result.stdout or ""

        journal_vq = self.run_cmd(
            "journalctl -u virtqemud --no-pager -n 500 2>/dev/null || true",
            "journal_virtqemud_vmdiag", timeout=30,
        )
        journal_content += "\n" + (journal_vq.stdout or "")

        # Kernel logs (best-effort)
        self.run_cmd(
            "journalctl -k --no-pager -n 300 2>/dev/null || true",
            "journal_kernel_vmdiag", timeout=30,
        )

        # Global check: QEMU_MONITOR_LOST
        monitor_finding = self._check_qemu_monitor_lost(journal_content)
        if monitor_finding:
            self.findings.append(monitor_finding)

        # Per-VM diagnostics
        threshold = getattr(self.args, "backing_chain_threshold", 5)
        for vm in vms_to_check:
            vm_name = vm["name"]
            vm_state = vm["state"]
            vm_id = vm["id"]

            self.logger.info("Diagnosing VM: %s (state: %s)", vm_name, vm_state)

            # dominfo
            self.run_cmd(
                f"virsh dominfo {shlex_quote(vm_name)}",
                f"virsh_dominfo_{vm_name}", timeout=15,
            )

            # domstate
            self.run_cmd(
                f"virsh domstate {shlex_quote(vm_name)}",
                f"virsh_domstate_{vm_name}", timeout=15,
            )

            # dumpxml
            xml_result = self.run_cmd(
                f"virsh dumpxml {shlex_quote(vm_name)}",
                f"virsh_dumpxml_{vm_name}", timeout=15,
            )
            xml_str = xml_result.stdout or ""

            if xml_str:
                (self.cfg_dir / f"vm_{vm_name}.xml").write_text(xml_str, encoding="utf-8")

            root = self._parse_vm_xml(xml_str) if xml_str else None

            # Extract VM info
            if root is not None:
                vm_info = self._extract_vm_info_from_xml(vm_name, vm_state, vm_id, root)
            else:
                vm_info = VMInfo(name=vm_name, state=vm_state, id=vm_id)

            # Collect & check QEMU log
            qemu_log = self._collect_qemu_log(vm_name)
            if qemu_log:
                stopped_finding = self._check_stopped_by_libvirt(vm_name, qemu_log)
                if stopped_finding:
                    self.findings.append(stopped_finding)

            # Lint XML devices
            if root is not None:
                issues = self._lint_vm_xml(vm_name, root)
                self.vm_device_issues[vm_name] = issues

                if issues:
                    risk_score = sum(i.risk_points for i in issues)
                    risk_level = (
                        "high" if risk_score >= 5
                        else "medium" if risk_score >= 3
                        else "low"
                    )
                    evidence_lines = [f"Risk score: {risk_score} ({risk_level})"] + [
                        f"[{i.severity.upper()}] {i.device}: {i.message}" for i in issues
                    ]
                    recommendations = list(dict.fromkeys(i.recommendation for i in issues))
                    recommendations += [
                        "Run with --fix --fix-vm-xml to remove risky devices automatically",
                        "Add --fix-spice-to-vnc to also switch SPICE->VNC and QXL->VGA",
                    ]
                    self.findings.append(Finding(
                        severity=risk_level,
                        symptom=f"DEVICE_LINT: VM '{vm_name}' has {len(issues)} risky device(s)",
                        evidence=evidence_lines,
                        probable_causes=[
                            "SPICE/USB redirection devices cause QEMU instability in headless sandbox",
                            "Watchdog with reset action can interrupt long analyses",
                            "QXL/USB tablet unnecessary in non-interactive sandbox",
                        ],
                        recommendations=recommendations,
                    ))

            # Check backing chain depth
            if vm_info.disk_path:
                chain_info = self._check_backing_chain(vm_info.disk_path, vm_name)
                vm_info.backing_chain_depth = chain_info["depth"]
                if chain_info["depth"] > threshold:
                    self.findings.append(Finding(
                        severity="medium",
                        symptom=f"BACKING_CHAIN_DEPTH: VM '{vm_name}' chain depth={chain_info['depth']} (threshold={threshold})",
                        evidence=[
                            f"Disk: `{vm_info.disk_path}`",
                            f"Chain depth: {chain_info['depth']} images",
                            f"Threshold: {threshold}",
                        ],
                        probable_causes=[
                            "Long snapshot chain (qcow2 backing store) accumulated over time",
                            "Each backing layer adds I/O overhead and potential timeout risk",
                        ],
                        recommendations=[
                            "Plan a disk flatten/commit to reduce chain depth",
                            "DO NOT auto-flatten without stopping the VM and creating a backup first",
                            f"Manual: qemu-img convert -O qcow2 {vm_info.disk_path} <flat.qcow2>",
                        ],
                    ))

            self.vm_infos.append(vm_info)

            # Apply XML fix if requested
            if self.args.fix and getattr(self.args, "fix_vm_xml", False) and root is not None:
                backup_path = f"/tmp/cape_doctor_backup_{vm_name}.xml"
                try:
                    Path(backup_path).write_text(xml_str, encoding="utf-8")
                    self.logger.info("XML backup for '%s' saved to %s", vm_name, backup_path)
                except Exception as exc:
                    self.logger.warning("Failed to backup XML for %s: %s", vm_name, exc)
                self._fix_vm_xml(vm_name, xml_str, root)

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

        def has(pattern: str) -> bool:
            return re.search(pattern, corpus, re.IGNORECASE) is not None

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

        if has(r"3D|VMSVGA|VBoxSVGA|gpu|ANGLE|d3d|dxgi|opengl") and self.detected.get("hypervisor") == "virtualbox":
            self.findings.append(
                Finding(
                    "medium",
                    "Potential browser crash from VirtualBox 3D/GPU acceleration",
                    ["Graphics acceleration references found with modern browser crash context."],
                    ["VirtualBox guest graphics/3D instability."],
                    ["Disable 3D acceleration for analysis VM and test with software rendering."],
                )
            )

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
        self.run_cmd("sysctl -w net.ipv4.ip_forward=1", "fix_enable_ip_forward")

        route = self.run_cmd("ip route show default | awk '{print $5}' | head -n1", "default_iface")
        iface = route.stdout.strip()
        if iface:
            check = self.run_cmd(f"iptables -t nat -S | grep -F -- '-A POSTROUTING -o {iface} -j MASQUERADE'", "check_masquerade")
            if check.rc != 0:
                self.run_cmd(f"iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE", "fix_add_masquerade")

        for d in [Path("/var/log/cape"), Path("/var/log/cuckoo"), Path.home() / ".cuckoo" / "log"]:
            if d.exists():
                self.run_cmd(f"chmod -R u+rwX {shlex_quote(str(d))}", f"fix_perm_{d.name}")

        if self.detected.get("service_manager") == "systemd":
            for svc in ["cape", "cuckoo", "libvirtd", "virtqemud"]:
                self.run_cmd(f"systemctl restart {svc}", f"fix_restart_{svc}")

        if self.detected.get("hypervisor") == "virtualbox" and self.args.vm_name:
            self.run_cmd(f"VBoxManage modifyvm {shlex_quote(self.args.vm_name)} --accelerate3d off", "fix_vbox_disable_3d")

    def write_report(self) -> Path:
        report = self.out_dir / "report.md"
        lines: List[str] = []
        lines.append(f"# CAPE/Cuckoo Triage Report\n")
        lines.append(f"- Generated: {dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')}")
        lines.append(f"- Host: {self.hostname}")
        lines.append(f"- Framework: {self.detected.get('framework', 'unknown')}")
        lines.append(f"- Hypervisor: {self.detected.get('hypervisor', 'unknown')}")
        lines.append(f"- Service manager: {self.detected.get('service_manager', 'unknown')}\n")

        lines.append("## Inventory")
        for k, v in sorted(self.inventory.items()):
            lines.append(f"- **{k}**: `{self._mask_secrets(v)}`")

        lines.append("\n## Key Checks")
        for jf in sorted(self.cmd_dir.glob("*.json")):
            try:
                data = json.loads(jf.read_text(encoding="utf-8"))
                icon = "PASS" if data["rc"] == 0 else "WARN"
                lines.append(f"- [{icon}] `{data['command']}` (rc={data['rc']}) -> `{jf.name}`")
            except Exception:
                continue

        # VM Inventory section
        if self.vm_infos:
            lines.append("\n## VM Inventory")
            lines.append(
                "| Name | State | ID | vCPU | RAM (KiB) | Machine | CPU Mode "
                "| Graphics | Video | Watchdog | Redirdev | Chain Depth |"
            )
            lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
            for vm in self.vm_infos:
                wd_str = vm.watchdog_action if vm.watchdog else "none"
                lines.append(
                    f"| `{vm.name}` | {vm.state} | {vm.id} | {vm.vcpus} "
                    f"| {vm.max_memory_kb} | {vm.machine_type} | {vm.cpu_mode} "
                    f"| {vm.graphics_type} | {vm.video_model} | {wd_str} "
                    f"| {vm.redirdev_count} | {vm.backing_chain_depth} |"
                )

        # VM Device Analysis section
        if self.vm_device_issues:
            lines.append("\n## VM Device Analysis")
            for vm_name, issues in self.vm_device_issues.items():
                if not issues:
                    lines.append(f"\n### {vm_name}: No risky devices detected")
                    continue
                risk_score = sum(i.risk_points for i in issues)
                risk_level = (
                    "HIGH" if risk_score >= 5
                    else "MEDIUM" if risk_score >= 3
                    else "LOW"
                )
                lines.append(f"\n### {vm_name}: Risk Score {risk_score} ({risk_level})")
                lines.append("| Device | Severity | Issue | Recommendation |")
                lines.append("|---|---|---|---|")
                for issue in issues:
                    lines.append(
                        f"| `{issue.device}` | {issue.severity.upper()} "
                        f"| {issue.message} | {issue.recommendation} |"
                    )

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
                "5. Review VM XML for unnecessary SPICE/USB/watchdog devices (use --fix --fix-vm-xml).",
                "6. Check qcow2 backing chain depth and plan flatten if needed.",
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
    p.add_argument("--all-vms", action="store_true",
                   help="Diagnose all VMs (not just --vm-name)")
    p.add_argument("--fix-vm-xml", action="store_true",
                   help="Remove risky VM devices from XML (requires --fix)")
    p.add_argument("--fix-spice-to-vnc", action="store_true",
                   help="Also switch SPICE->VNC and QXL->VGA (requires --fix --fix-vm-xml)")
    p.add_argument("--backing-chain-threshold", type=int, default=5,
                   help="Alert threshold for qcow2 backing chain depth (default: 5)")
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
        doctor.diagnose_vms()
        doctor.collect_resources_and_runtime_logs()
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
