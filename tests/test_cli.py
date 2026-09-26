import pytest
from unittest.mock import patch, MagicMock
from alavitrace.cli import run_pipeline, parse_args
from alavitrace.core.models import Target

def test_parse_args():
    args = parse_args(["-t", "192.168.56.106", "--pn", "-v"])
    assert args.target == "192.168.56.106"
    assert args.pn is True
    assert args.verbose is True

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
        exit_code = run_pipeline("192.168.56.106")
        assert exit_code == 0
