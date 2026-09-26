import os
import pytest
from alavitrace.parsers.nmap_parser import NmapParser, NmapParseError, classify_service
from alavitrace.core.validator import validate_target

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

def get_fixture_path(filename: str) -> str:
    return os.path.join(FIXTURES_DIR, filename)

def test_basic_scan_parsing():
    xml_path = get_fixture_path("basic_scan.xml")
    target = validate_target("192.168.56.106")
    scan_result = NmapParser.parse_xml_file(xml_path, target)

    assert scan_result is not None
    assert len(scan_result.hosts) == 1

    host = scan_result.hosts[0]
    assert host.ipv4 == "192.168.56.106"
    assert host.state == "up"
    assert host.hostname == "sunset.local"
    assert "Linux 4.15 - 5.8" in host.os_matches
    assert "cpe:/o:linux:linux_kernel" in host.cpes

    assert len(host.open_ports) == 2

    # Port 21
    ftp_service = host.open_ports[0]
    assert ftp_service.port == 21
    assert ftp_service.protocol == "tcp"
    assert ftp_service.state == "open"
    assert ftp_service.name == "FTP"
    assert ftp_service.product == "pyftpdlib"
    assert ftp_service.version == "1.5.5"
    assert "cpe:/a:giorgio_gould:pyftpdlib:1.5.5" in ftp_service.cpes

    # Port 22
    ssh_service = host.open_ports[1]
    assert ssh_service.port == 22
    assert ssh_service.protocol == "tcp"
    assert ssh_service.state == "open"
    assert ssh_service.name == "SSH"
    assert ssh_service.product == "OpenSSH"
    assert ssh_service.version == "7.9p1"
    assert ssh_service.extra_info == "Debian 10"

def test_multiple_hosts_parsing():
    xml_path = get_fixture_path("multiple_hosts.xml")
    scan_result = NmapParser.parse_xml_file(xml_path)

    assert len(scan_result.hosts) == 2

    h1 = scan_result.hosts[0]
    assert h1.ipv4 == "192.168.56.101"
    assert h1.hostname == "host1.lab"
    assert len(h1.open_ports) == 1
    assert h1.open_ports[0].port == 80
    assert h1.open_ports[0].product == "Apache httpd"

    h2 = scan_result.hosts[1]
    assert h2.ipv4 == "192.168.56.102"
    assert h2.hostname == "host2.lab"
    assert len(h2.open_ports) == 1
    assert h2.open_ports[0].port == 445
    assert h2.open_ports[0].product == "Samba"

def test_missing_version_and_non_open_ports_filtered():
    xml_path = get_fixture_path("missing_version.xml")
    scan_result = NmapParser.parse_xml_file(xml_path)

    assert len(scan_result.hosts) == 1
    host = scan_result.hosts[0]
    assert host.hostname is None
    assert len(host.cpes) == 0

    # Port 9999 is filtered, so only open port 22 should be in open_ports
    assert len(host.open_ports) == 1
    ssh_port = host.open_ports[0]
    assert ssh_port.port == 22
    assert ssh_port.state == "open"
    assert ssh_port.name == "SSH"
    assert ssh_port.product == "Unknown"
    assert ssh_port.version == "Unknown"

def test_no_open_ports_parsing():
    xml_path = get_fixture_path("no_open_ports.xml")
    target = validate_target("192.168.56.200")
    scan_result = NmapParser.parse_xml_file(xml_path, target)

    assert len(scan_result.hosts) == 1
    host = scan_result.hosts[0]
    assert host.ipv4 == "192.168.56.200"
    assert len(host.open_ports) == 0

def test_no_hosts_and_no_target_error(tmp_path):
    no_hosts_xml = tmp_path / "no_hosts.xml"
    no_hosts_xml.write_text('<?xml version="1.0"?><nmaprun></nmaprun>')
    with pytest.raises(NmapParseError, match="No hosts discovered in Nmap XML and no target was supplied"):
        NmapParser.parse_xml_file(str(no_hosts_xml))

def test_ipv6_addrtype_handling(tmp_path):
    ipv6_xml = tmp_path / "ipv6.xml"
    ipv6_xml.write_text('''<?xml version="1.0"?>
    <nmaprun scanner="nmap" args="nmap">
      <host>
        <status state="up"/>
        <address addr="fe80::1" addrtype="ipv6"/>
        <hostnames><hostname name="ipv6host.local"/></hostnames>
        <ports>
          <port protocol="tcp" portid="80"><state state="open"/></port>
        </ports>
      </host>
    </nmaprun>''')

    scan_result = NmapParser.parse_xml_file(str(ipv6_xml))
    host = scan_result.hosts[0]
    assert host.ipv4 is None
    assert host.hostname == "ipv6host.local"

def test_malformed_xml_error():
    xml_path = get_fixture_path("malformed.xml")
    with pytest.raises(NmapParseError, match="Malformed Nmap XML structure"):
        NmapParser.parse_xml_file(xml_path)

def test_empty_xml_error(tmp_path):
    empty_file = tmp_path / "empty.xml"
    empty_file.write_text("")
    with pytest.raises(NmapParseError, match="XML file is empty"):
        NmapParser.parse_xml_file(str(empty_file))

def test_missing_file_error():
    with pytest.raises(NmapParseError, match="XML file not found"):
        NmapParser.parse_xml_file("non_existent_file.xml")

def test_service_classification_helper():
    assert classify_service(80, "http") == "HTTP"
    assert classify_service(80, "unknown") == "HTTP"
    assert classify_service(22, None) == "SSH"
    assert classify_service(12345, "custom-service") == "CUSTOM-SERVICE"
    assert classify_service(9999, None) == "UNKNOWN"
