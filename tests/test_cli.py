import pytest
from unittest.mock import patch, MagicMock
from alavitrace.cli import run_pipeline, parse_args
from alavitrace.core.models import Target

def test_parse_args():
    args = parse_args(["-t", "192.168.56.106", "--pn", "-v", "--owasp"])
    assert args.target == "192.168.56.106"
    assert args.pn is True
    assert args.verbose is True
    assert args.owasp is True

    args_no_owasp = parse_args(["-t", "192.168.56.106", "--no-owasp"])
    assert args_no_owasp.owasp is False

    args_injection = parse_args(["-t", "192.168.56.106", "--injection", "--max-injection-requests", "30"])
    assert args_injection.injection is True
    assert args_injection.max_injection_requests == 30

    args_no_injection = parse_args(["-t", "192.168.56.106", "--no-injection"])
    assert args_no_injection.injection is False

    args_misconfig = parse_args(["-t", "192.168.56.106", "--misconfig"])
    assert args_misconfig.misconfig is True

def test_run_pipeline_invalid_target():
    exit_code = run_pipeline("invalid_target_123!!!")
    assert exit_code == 1

def test_run_pipeline_successful_flow(tmp_path):
    # Mock NmapScanner scan result using static XML fixture
    fixture_xml = tmp_path / "test.xml"
    fixture_xml.write_text("""<?xml version="1.0"?>
    <nmaprun scanner="nmap" args="nmap">
      <host>
        <status state="up"/>
        <address addr="192.168.56.106" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="21">
            <state state="open"/>
            <service name="ftp" product="pyftpdlib" version="1.5.5"/>
          </port>
        </ports>
      </host>
    </nmaprun>""")

    with patch("alavitrace.scanners.nmap_scanner.NmapScanner.run_scan", return_value=(str(fixture_xml), ["nmap", "-sV"])):
        exit_code = run_pipeline("192.168.56.106", output_dir=str(tmp_path), skip_vuln_check=True, skip_ai=True)
        assert exit_code == 0

def test_run_pipeline_with_owasp_flag(tmp_path):
    fixture_xml = tmp_path / "test_owasp.xml"
    fixture_xml.write_text("""<?xml version="1.0"?>
    <nmaprun scanner="nmap" args="nmap">
      <host>
        <status state="up"/>
        <address addr="192.168.56.106" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="21">
            <state state="open"/>
            <service name="ftp" product="pyftpdlib" version="1.5.5"/>
          </port>
        </ports>
      </host>
    </nmaprun>""")

    with patch("alavitrace.scanners.nmap_scanner.NmapScanner.run_scan", return_value=(str(fixture_xml), ["nmap", "-sV"])):
        exit_code = run_pipeline("192.168.56.106", enable_owasp=True, output_dir=str(tmp_path), skip_vuln_check=True, skip_ai=True)
        assert exit_code == 0
