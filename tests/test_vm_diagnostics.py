"""Unit tests for cape_doctor VM diagnostics (libvirt/QEMU)."""

from __future__ import annotations

import sys
import textwrap
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cape_doctor import CapeDoctor, DeviceIssue, Finding, VMInfo, parse_args


def _make_doctor(tmp_path, extra_args=None):
    """Create a CapeDoctor instance pointing to *tmp_path*."""
    args_list = ["--out-dir", str(tmp_path)]
    if extra_args:
        args_list.extend(extra_args)
    args = parse_args(args_list)
    return CapeDoctor(args)


# ------------------------------------------------------------------ #
# _parse_virsh_list
# ------------------------------------------------------------------ #

class TestParseVirshList:
    def test_normal_output(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        output = textwrap.dedent("""\
             Id   Name          State
            -----------------------------------------
             1    win10-cape    running
             -    win7-cape     shut off
        """)
        result = doctor._parse_virsh_list(output)
        assert len(result) == 2
        assert result[0] == {"id": "1", "name": "win10-cape", "state": "running"}
        assert result[1] == {"id": "-", "name": "win7-cape", "state": "shut off"}

    def test_empty_output(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        assert doctor._parse_virsh_list("") == []

    def test_header_only(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        output = " Id   Name   State\n-----------\n"
        assert doctor._parse_virsh_list(output) == []


# ------------------------------------------------------------------ #
# _check_stopped_by_libvirt
# ------------------------------------------------------------------ #

class TestCheckStoppedByLibvirt:
    SIGNAL15_LOG = textwrap.dedent("""\
        2024-01-15 10:23:45.123+0000: starting up libvirt version: 8.0.0
        2024-01-15 10:30:12.456+0000: qemu-system-x86_64: terminating on signal 15 from pid 12345 (/usr/sbin/libvirtd)
        2024-01-15 10:30:12.457+0000: shutting down, reason=destroyed
    """)

    DESTROYED_ONLY = "2024-01-15 10:30:12.457+0000: shutting down, reason=destroyed\n"

    CLEAN_LOG = textwrap.dedent("""\
        2024-01-15 10:23:45.123+0000: starting up libvirt version: 8.0.0
        2024-01-15 10:30:00.000+0000: QEMU process has exited
    """)

    def test_signal15_detected(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        finding = doctor._check_stopped_by_libvirt("win10", self.SIGNAL15_LOG)
        assert finding is not None
        assert finding.severity == "high"
        assert "STOPPED_BY_LIBVIRT" in finding.symptom
        assert "'win10'" in finding.symptom

    def test_reason_destroyed_detected(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        finding = doctor._check_stopped_by_libvirt("win10", self.DESTROYED_ONLY)
        assert finding is not None
        assert "STOPPED_BY_LIBVIRT" in finding.symptom

    def test_clean_log_returns_none(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        assert doctor._check_stopped_by_libvirt("win10", self.CLEAN_LOG) is None

    def test_empty_log_returns_none(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        assert doctor._check_stopped_by_libvirt("win10", "") is None


# ------------------------------------------------------------------ #
# _check_qemu_monitor_lost
# ------------------------------------------------------------------ #

class TestCheckQemuMonitorLost:
    NULL_MONITOR = textwrap.dedent("""\
        Jan 15 10:30:12 host libvirtd[1234]: error: internal error: invalid argument: monitor must not be NULL
        Jan 15 10:30:12 host libvirtd[1234]: error: Failed to connect to QEMU
    """)

    EOF_ERROR = (
        "Jan 15 10:30:12 host libvirtd[1234]: error: Failed to read from monitor: "
        "End of file while reading data: Input/output error\n"
    )

    CLEAN_JOURNAL = "Jan 15 10:30:12 host libvirtd[1234]: info: Starting VM win10\n"

    def test_null_monitor(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        finding = doctor._check_qemu_monitor_lost(self.NULL_MONITOR)
        assert finding is not None
        assert "QEMU_MONITOR_LOST" in finding.symptom

    def test_eof_error(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        finding = doctor._check_qemu_monitor_lost(self.EOF_ERROR)
        assert finding is not None
        assert "QEMU_MONITOR_LOST" in finding.symptom

    def test_clean_journal(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        assert doctor._check_qemu_monitor_lost(self.CLEAN_JOURNAL) is None

    def test_empty_string(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        assert doctor._check_qemu_monitor_lost("") is None


# ------------------------------------------------------------------ #
# _lint_vm_xml
# ------------------------------------------------------------------ #

SPICE_VM_XML = textwrap.dedent("""\
    <domain type='kvm'>
      <devices>
        <graphics type='spice' port='-1' autoport='yes'>
          <listen type='address'/>
          <image compression='off'/>
        </graphics>
        <channel type='spicevmc'>
          <target type='virtio' name='com.redhat.spice.0'/>
        </channel>
        <redirdev bus='usb' type='spicevmc'/>
        <redirdev bus='usb' type='spicevmc'/>
        <audio id='1' type='spice'/>
        <watchdog model='itco' action='reset'/>
        <input type='tablet' bus='usb'/>
        <input type='keyboard' bus='ps2'/>
        <input type='mouse' bus='ps2'/>
        <video>
          <model type='qxl' ram='65536' vram='65536' vgamem='16384' heads='1' primary='yes'/>
        </video>
      </devices>
    </domain>
""")

MINIMAL_VM_XML = textwrap.dedent("""\
    <domain type='kvm'>
      <devices>
        <graphics type='vnc' port='-1'/>
        <video>
          <model type='vga' vram='16384' heads='1' primary='yes'/>
        </video>
        <input type='keyboard' bus='ps2'/>
        <input type='mouse' bus='ps2'/>
      </devices>
    </domain>
""")


class TestLintVmXml:
    def test_spice_vm_reports_issues(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        root = ET.fromstring(SPICE_VM_XML)
        issues = doctor._lint_vm_xml("win10", root)
        assert len(issues) > 0
        devices_found = [i.device for i in issues]
        assert any("redirdev" in d for d in devices_found)
        assert any("watchdog" in d for d in devices_found)
        assert any("qxl" in d for d in devices_found)
        assert any("spice" in d for d in devices_found)

    def test_minimal_vm_no_issues(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        root = ET.fromstring(MINIMAL_VM_XML)
        issues = doctor._lint_vm_xml("win10", root)
        assert issues == []

    def test_risk_score_high_for_spice_vm(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        root = ET.fromstring(SPICE_VM_XML)
        issues = doctor._lint_vm_xml("win10", root)
        risk_score = sum(i.risk_points for i in issues)
        assert risk_score >= 5, f"Expected high risk (>=5), got {risk_score}"

    def test_redirdev_counted(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        root = ET.fromstring(SPICE_VM_XML)
        issues = doctor._lint_vm_xml("win10", root)
        redir_issues = [i for i in issues if "redirdev" in i.device]
        assert len(redir_issues) == 1
        assert "x2" in redir_issues[0].device

    def test_watchdog_reset_is_high(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        root = ET.fromstring(SPICE_VM_XML)
        issues = doctor._lint_vm_xml("win10", root)
        wd = [i for i in issues if "watchdog" in i.device]
        assert len(wd) == 1
        assert wd[0].severity == "high"
        assert wd[0].risk_points == 2

    def test_watchdog_none_is_low(self, tmp_path):
        xml = '<domain><devices><watchdog model="itco" action="none"/></devices></domain>'
        doctor = _make_doctor(tmp_path)
        root = ET.fromstring(xml)
        issues = doctor._lint_vm_xml("win10", root)
        wd = [i for i in issues if "watchdog" in i.device]
        assert len(wd) == 1
        assert wd[0].severity == "low"
        assert wd[0].risk_points == 0


# ------------------------------------------------------------------ #
# _get_disk_path_from_xml
# ------------------------------------------------------------------ #

class TestGetDiskPath:
    DISK_XML = textwrap.dedent("""\
        <domain>
          <devices>
            <disk type='file' device='disk'>
              <driver name='qemu' type='qcow2'/>
              <source file='/var/lib/libvirt/images/win10.qcow2'/>
              <target dev='vda' bus='virtio'/>
            </disk>
            <disk type='file' device='cdrom'>
              <source file='/tmp/drivers.iso'/>
              <target dev='sda' bus='sata'/>
            </disk>
          </devices>
        </domain>
    """)

    NO_DISK_XML = "<domain><devices></devices></domain>"

    def test_finds_disk_path(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        root = ET.fromstring(self.DISK_XML)
        assert doctor._get_disk_path_from_xml(root) == "/var/lib/libvirt/images/win10.qcow2"

    def test_no_disk_returns_none(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        root = ET.fromstring(self.NO_DISK_XML)
        assert doctor._get_disk_path_from_xml(root) is None

    def test_skips_cdrom(self, tmp_path):
        xml = textwrap.dedent("""\
            <domain><devices>
              <disk type='file' device='cdrom'>
                <source file='/tmp/cd.iso'/>
              </disk>
            </devices></domain>
        """)
        doctor = _make_doctor(tmp_path)
        root = ET.fromstring(xml)
        assert doctor._get_disk_path_from_xml(root) is None


# ------------------------------------------------------------------ #
# _extract_vm_info_from_xml
# ------------------------------------------------------------------ #

class TestExtractVmInfo:
    FULL_XML = textwrap.dedent("""\
        <domain type='kvm'>
          <vcpu placement='static'>4</vcpu>
          <memory unit='KiB'>4194304</memory>
          <os>
            <type arch='x86_64' machine='pc-q35-6.2'>hvm</type>
          </os>
          <cpu mode='host-passthrough' check='none'/>
          <devices>
            <graphics type='spice' port='-1'/>
            <video><model type='qxl'/></video>
            <watchdog model='itco' action='reset'/>
            <redirdev bus='usb' type='spicevmc'/>
            <redirdev bus='usb' type='spicevmc'/>
            <channel type='spicevmc'/>
            <audio id='1' type='spice'/>
            <input type='tablet' bus='usb'/>
            <disk type='file' device='disk'>
              <source file='/images/win10.qcow2'/>
            </disk>
          </devices>
        </domain>
    """)

    def test_all_fields(self, tmp_path):
        doctor = _make_doctor(tmp_path)
        root = ET.fromstring(self.FULL_XML)
        info = doctor._extract_vm_info_from_xml("win10", "running", "1", root)
        assert info.name == "win10"
        assert info.state == "running"
        assert info.vcpus == "4"
        assert info.max_memory_kb == "4194304"
        assert info.machine_type == "pc-q35-6.2"
        assert info.cpu_mode == "host-passthrough"
        assert info.graphics_type == "spice"
        assert info.video_model == "qxl"
        assert info.watchdog is True
        assert info.watchdog_action == "reset"
        assert info.redirdev_count == 2
        assert info.has_spice_channel is True
        assert info.has_spice_audio is True
        assert info.has_tablet is True
        assert info.disk_path == "/images/win10.qcow2"


# ------------------------------------------------------------------ #
# _parse_vm_xml
# ------------------------------------------------------------------ #

class TestParseVmXml:
    def test_valid_xml(self, tmp_path):
        root = CapeDoctor._parse_vm_xml("<domain><name>test</name></domain>")
        assert root is not None
        assert root.tag == "domain"

    def test_invalid_xml_returns_none(self, tmp_path):
        assert CapeDoctor._parse_vm_xml("not xml at all <<<") is None

    def test_empty_string(self, tmp_path):
        assert CapeDoctor._parse_vm_xml("") is None


# ------------------------------------------------------------------ #
# _fix_vm_xml (XML manipulation, without virsh call)
# ------------------------------------------------------------------ #

class TestFixVmXml:
    def test_removes_redirdev_and_watchdog(self, tmp_path):
        doctor = _make_doctor(tmp_path, ["--fix", "--fix-vm-xml"])
        root = ET.fromstring(SPICE_VM_XML)
        devices = root.find("devices")

        # Patch run_cmd to simulate successful virsh define
        original_run = doctor.run_cmd
        def fake_run(cmd, name, timeout=30):
            if "virsh define" in cmd:
                from cape_doctor import CmdResult
                return CmdResult(cmd, 0, "Domain win10 defined", "", "", "")
            return original_run(cmd, name, timeout)
        doctor.run_cmd = fake_run

        result = doctor._fix_vm_xml("win10", SPICE_VM_XML, root)
        assert result is True

        # Verify redirdev removed
        assert len(devices.findall("redirdev")) == 0
        # Verify watchdog removed
        assert devices.find("watchdog") is None
        # Verify USB tablet removed (PS/2 exists)
        tablets = [i for i in devices.findall("input")
                   if i.get("type") == "tablet" and i.get("bus") == "usb"]
        assert len(tablets) == 0

    def test_spice_to_vnc_when_flag_set(self, tmp_path):
        doctor = _make_doctor(tmp_path, ["--fix", "--fix-vm-xml", "--fix-spice-to-vnc"])
        root = ET.fromstring(SPICE_VM_XML)
        devices = root.find("devices")

        original_run = doctor.run_cmd
        def fake_run(cmd, name, timeout=30):
            if "virsh define" in cmd:
                from cape_doctor import CmdResult
                return CmdResult(cmd, 0, "Domain win10 defined", "", "", "")
            return original_run(cmd, name, timeout)
        doctor.run_cmd = fake_run

        doctor._fix_vm_xml("win10", SPICE_VM_XML, root)

        graphics = devices.find("graphics")
        assert graphics is not None
        assert graphics.get("type") == "vnc"

        video_model = devices.find("video/model")
        assert video_model is not None
        assert video_model.get("type") == "vga"
        assert "ram" not in video_model.attrib

        # SPICE channels and audio removed
        assert len([c for c in devices.findall("channel") if c.get("type") == "spicevmc"]) == 0
        assert len([a for a in devices.findall("audio") if a.get("type") == "spice"]) == 0

    def test_no_changes_on_minimal_vm(self, tmp_path):
        doctor = _make_doctor(tmp_path, ["--fix", "--fix-vm-xml"])
        root = ET.fromstring(MINIMAL_VM_XML)
        result = doctor._fix_vm_xml("win10", MINIMAL_VM_XML, root)
        assert result is False


# ------------------------------------------------------------------ #
# _check_backing_chain (mocked)
# ------------------------------------------------------------------ #

class TestCheckBackingChain:
    CHAIN_OUTPUT = textwrap.dedent("""\
        image: /var/lib/libvirt/images/win10.qcow2
        file format: qcow2
        backing file: /var/lib/libvirt/images/snap3.qcow2

        image: /var/lib/libvirt/images/snap3.qcow2
        file format: qcow2
        backing file: /var/lib/libvirt/images/snap2.qcow2

        image: /var/lib/libvirt/images/snap2.qcow2
        file format: qcow2
        backing file: /var/lib/libvirt/images/snap1.qcow2

        image: /var/lib/libvirt/images/snap1.qcow2
        file format: qcow2
        backing file: /var/lib/libvirt/images/base.qcow2

        image: /var/lib/libvirt/images/base.qcow2
        file format: qcow2
    """)

    def test_counts_depth(self, tmp_path):
        from cape_doctor import CmdResult
        doctor = _make_doctor(tmp_path)
        original_run = doctor.run_cmd
        def fake_run(cmd, name, timeout=30):
            if "qemu-img info" in cmd:
                return CmdResult(cmd, 0, self.CHAIN_OUTPUT, "", "", "")
            return original_run(cmd, name, timeout)
        doctor.run_cmd = fake_run

        info = doctor._check_backing_chain("/images/win10.qcow2", "win10")
        assert info["depth"] == 5
        assert info["rc"] == 0

    def test_single_image(self, tmp_path):
        from cape_doctor import CmdResult
        doctor = _make_doctor(tmp_path)
        single = "image: /images/win10.qcow2\nfile format: qcow2\nvirtual size: 60 GiB\n"
        def fake_run(cmd, name, timeout=30):
            if "qemu-img info" in cmd:
                return CmdResult(cmd, 0, single, "", "", "")
            return doctor.run_cmd(cmd, name, timeout)
        doctor.run_cmd = fake_run

        info = doctor._check_backing_chain("/images/win10.qcow2", "win10")
        assert info["depth"] == 1


# ------------------------------------------------------------------ #
# VMInfo and DeviceIssue dataclasses
# ------------------------------------------------------------------ #

class TestDataclasses:
    def test_vminfo_defaults(self):
        vm = VMInfo(name="test", state="running")
        assert vm.id == "-"
        assert vm.vcpus == "?"
        assert vm.redirdev_count == 0
        assert vm.backing_chain_depth == 0

    def test_device_issue_defaults(self):
        issue = DeviceIssue(
            device="test", severity="low", message="msg", recommendation="rec",
        )
        assert issue.risk_points == 1
