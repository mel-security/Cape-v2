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
