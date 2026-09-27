import os
import xml.etree.ElementTree as ET
import logging
from typing import List, Optional, Dict
from alavitrace.core.models import Target, Host, Service, ScanResult
from alavitrace.core.validator import validate_target

logger = logging.getLogger("ATrace")

COMMON_PORT_SERVICES: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS/SMB",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP Alternate",
}

class NmapParseError(Exception):
    """Exception raised when Nmap XML output cannot be parsed."""
    pass

def classify_service(port: int, nmap_service_name: Optional[str] = None) -> str:
    """
    Classifies a service based on Nmap XML output or common port numbers.
    Prefer Nmap detected service name, fallback to standard port lookup.
    """
    if nmap_service_name and nmap_service_name.strip() and nmap_service_name.lower() != "unknown":
        return nmap_service_name.strip().upper()
    return COMMON_PORT_SERVICES.get(port, "UNKNOWN")

class NmapParser:
    """
    Parses machine-readable Nmap XML files into ATrace Host, Service, and ScanResult models.
    """

    @staticmethod
    def parse_xml_file(xml_path: str, target: Optional[Target] = None) -> ScanResult:
        """
        Parses an Nmap XML file and extracts all host, port, service, OS, and CPE details.

        Args:
            xml_path: Path to Nmap XML output file.
            target: Optional target context.

        Returns:
            ScanResult containing structured hosts and open services.
        """
        if not os.path.exists(xml_path):
            raise NmapParseError(f"XML file not found: {xml_path}")

        if os.path.getsize(xml_path) == 0:
            raise NmapParseError(f"XML file is empty: {xml_path}")

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
        except ET.ParseError as e:
            raise NmapParseError(f"Malformed Nmap XML structure in '{xml_path}': {e}")

        if root.tag != "nmaprun":
            raise NmapParseError(f"Invalid XML root tag '{root.tag}'. Expected 'nmaprun'.")

        scan_args = root.attrib.get("args", "").split()
        hosts: List[Host] = []

        # Iterate through all host elements (supporting multi-host scans)
        for host_elem in root.findall("host"):
            parsed_host = NmapParser._parse_host(host_elem, target)
            if parsed_host:
                hosts.append(parsed_host)

        if not hosts and not target:
            raise NmapParseError("No hosts discovered in Nmap XML and no target was supplied.")

        fallback_target = target or hosts[0].target
        return ScanResult(
            target=fallback_target,
            hosts=hosts,
            raw_xml_path=xml_path,
            scan_args=scan_args
        )

    @staticmethod
    def _parse_host(host_elem: ET.Element, default_target: Optional[Target] = None) -> Optional[Host]:
        """Parses a single <host> XML element."""
        # 1. Host status
        status_elem = host_elem.find("status")
        host_state = status_elem.attrib.get("state", "unknown") if status_elem is not None else "unknown"

        # 2. IP Address & Hostnames
        ipv4_addr: Optional[str] = None
        for addr_elem in host_elem.findall("address"):
            if addr_elem.attrib.get("addrtype") == "ipv4":
                ipv4_addr = addr_elem.attrib.get("addr")
                break

        hostnames: List[str] = []
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            for hn_elem in hostnames_elem.findall("hostname"):
                name = hn_elem.attrib.get("name")
                if name:
                    hostnames.append(name)

        primary_hostname = hostnames[0] if hostnames else None

        # Build Host target
        target_str = ipv4_addr or primary_hostname or "unknown"
        target_obj = default_target if (default_target and default_target.is_valid) else validate_target(target_str)

        # 3. OS Matches and Host-level CPEs
        os_matches: List[str] = []
        host_cpes: List[str] = []
        os_elem = host_elem.find("os")
        if os_elem is not None:
            for osmatch_elem in os_elem.findall("osmatch"):
                name = osmatch_elem.attrib.get("name")
                if name:
                    os_matches.append(name)
            for cpe_elem in os_elem.findall(".//cpe"):
                if cpe_elem.text:
                    host_cpes.append(cpe_elem.text.strip())

        # 4. Open Ports / Services (only state == 'open')
        open_services: List[Service] = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                service = NmapParser._parse_port(port_elem)
                if service and service.state == "open":
                    open_services.append(service)

        return Host(
            target=target_obj,
            state=host_state,
            ipv4=ipv4_addr,
            hostname=primary_hostname,
            hostnames=hostnames,
            open_ports=open_services,
            os_matches=os_matches,
            cpes=host_cpes
        )

    @staticmethod
    def _parse_port(port_elem: ET.Element) -> Optional[Service]:
        """Parses a single <port> XML element."""
        try:
            port_num = int(port_elem.attrib.get("portid", "0"))
        except ValueError:
            return None

        protocol = port_elem.attrib.get("protocol", "tcp")

        # Port state (open, closed, filtered)
        state_elem = port_elem.find("state")
        port_state = state_elem.attrib.get("state", "unknown") if state_elem is not None else "unknown"

        # Service details
        service_elem = port_elem.find("service")
        service_name = "unknown"
        product = "Unknown"
        version = "Unknown"
        extra_info = ""
        service_cpes: List[str] = []

        if service_elem is not None:
            raw_name = service_elem.attrib.get("name")
            if raw_name:
                service_name = raw_name
            product = service_elem.attrib.get("product", "Unknown")
            version = service_elem.attrib.get("version", "Unknown")
            extra_info = service_elem.attrib.get("extrainfo", "")

            for cpe_elem in service_elem.findall("cpe"):
                if cpe_elem.text:
                    service_cpes.append(cpe_elem.text.strip())

        classified_name = classify_service(port_num, service_name)

        # Script outputs
        scripts_output: Dict[str, str] = {}
        for script_elem in port_elem.findall("script"):
            script_id = script_elem.attrib.get("id")
            script_out = script_elem.attrib.get("output", "")
            if script_id:
                scripts_output[script_id] = script_out

        return Service(
            port=port_num,
            protocol=protocol,
            state=port_state,
            name=classified_name,
            product=product,
            version=version,
            extra_info=extra_info,
            cpes=service_cpes,
            scripts_output=scripts_output
        )
