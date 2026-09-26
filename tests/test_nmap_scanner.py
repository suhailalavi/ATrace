import os
import subprocess
import pytest
from unittest.mock import patch, MagicMock
from alavitrace.core.models import Target
from alavitrace.scanners.nmap_scanner import (
    NmapScanner,
    NmapNotFoundError,
    NmapExecutionError,
    NmapTimeoutError
)

@pytest.fixture
def valid_target():
    return Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4", is_valid=True)

@pytest.fixture
def invalid_target():
    return Target(raw_input="invalid_target", normalized="invalid_target", target_type="Invalid", is_valid=False, error_message="Invalid target format")

def test_nmap_scanner_check_nmap_installed_success():
    with patch("shutil.which", return_value="C:\\Program Files (x86)\\Nmap\\nmap.exe"):
        scanner = NmapScanner()
        path = scanner.check_nmap_installed()
        assert path == "C:\\Program Files (x86)\\Nmap\\nmap.exe"

def test_nmap_scanner_check_nmap_installed_missing():
    with patch("shutil.which", return_value=None):
        scanner = NmapScanner()
        with pytest.raises(NmapNotFoundError):
            scanner.check_nmap_installed()

def test_nmap_scanner_run_scan_invalid_target(invalid_target):
    scanner = NmapScanner()
    with pytest.raises(ValueError, match="Cannot scan invalid target"):
        scanner.run_scan(invalid_target)

def test_nmap_scanner_successful_run(valid_target):
    scanner = NmapScanner()

    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = "Nmap done"

    def fake_subprocess_run(cmd, **kwargs):
        assert kwargs.get("shell") is False
        assert cmd[0] == "nmap"
        assert cmd[1] == "-sV"
        assert cmd[2] == "-oX"
        xml_file = cmd[3]
        # Write dummy content to xml file path
        with open(xml_file, "w") as f:
            f.write("<nmaprun></nmaprun>")
        return mock_process

    with patch("shutil.which", return_value="/usr/bin/nmap"), \
         patch("subprocess.run", side_effect=fake_subprocess_run):
        xml_path, cmd = scanner.run_scan(valid_target)
        assert os.path.exists(xml_path)
        assert cmd == ["nmap", "-sV", "-oX", xml_path, "192.168.56.106"]
        NmapScanner.cleanup_xml(xml_path)
        assert not os.path.exists(xml_path)

def test_nmap_scanner_execution_error(valid_target):
    scanner = NmapScanner()
    mock_process = MagicMock()
    mock_process.returncode = 1
    mock_process.stderr = "Failed to parse target"

    with patch("shutil.which", return_value="/usr/bin/nmap"), \
         patch("subprocess.run", return_value=mock_process):
        with pytest.raises(NmapExecutionError):
            scanner.run_scan(valid_target)

def test_nmap_scanner_timeout_error(valid_target):
    scanner = NmapScanner(timeout_seconds=1)

    with patch("shutil.which", return_value="/usr/bin/nmap"), \
         patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["nmap"], timeout=1)):
        with pytest.raises(NmapTimeoutError):
            scanner.run_scan(valid_target)
