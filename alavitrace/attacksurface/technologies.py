import re
import logging
from typing import List, Dict, Optional, Any, Tuple
from alavitrace.core.models import Confidence, ScanResult, HttpResult
from alavitrace.attacksurface.models import Technology

logger = logging.getLogger("AlaviTrace")

def _parse_software_version(header_value: str) -> List[Tuple[str, Optional[str]]]:
    """
    Parses banner strings like 'Apache/2.4.41 (Ubuntu) PHP/7.4.3' or 'WordPress 6.2' into [(name, version)].
    """
    results: List[Tuple[str, Optional[str]]] = []
    tokens = header_value.split()
    idx = 0
    while idx < len(tokens):
        token = tokens[idx].strip(";,()")
        if "/" in token:
            parts = token.split("/", 1)
            name = parts[0].strip()
            ver = parts[1].strip()
            if name:
                results.append((name, ver))
            idx += 1
        elif token and not token.startswith("("):
            # Check if next token is a version string (starts with a digit)
            if idx + 1 < len(tokens):
                next_token = tokens[idx + 1].strip(";,()")
                if re.match(r"^[0-9]+(\.[0-9a-zA-Z_-]+)*$", next_token):
                    results.append((token, next_token))
                    idx += 2
                    continue
            results.append((token, None))
            idx += 1
        else:
            idx += 1
    return results

class TechnologyFingerprinter:
    """
    Deterministic technology fingerprinting engine.
    Extracts server software, language runtimes, web frameworks, and application identifiers
    from HTTP headers, cookies, HTML generators, and Nmap service detections.
    """

    KNOWN_COOKIES = {
        "phpsessid": ("PHP", None, Confidence.PROBABLE),
        "jsessionid": ("Java / Servlet Container", None, Confidence.PROBABLE),
        "csrftoken": ("Django", None, Confidence.PROBABLE),
        "sessionid": ("Django / Python", None, Confidence.PROBABLE),
        "laravel_session": ("Laravel", None, Confidence.PROBABLE),
        "connect.sid": ("Express.js / Node.js", None, Confidence.PROBABLE),
        "wp-settings": ("WordPress", None, Confidence.PROBABLE),
        "wordpress_logged_in": ("WordPress", None, Confidence.PROBABLE),
        "rack.session": ("Ruby on Rails / Rack", None, Confidence.PROBABLE),
        "cfduid": ("Cloudflare", None, Confidence.PROBABLE)
    }

    @classmethod
    def identify(
        cls,
        http_results: List[HttpResult],
        scan_result: Optional[ScanResult] = None,
        meta_generators: Optional[List[str]] = None
    ) -> List[Technology]:
        """
        Consolidates technology evidence across all available deterministic sources.
        Deduplicates by (name, version).
        """
        tech_map: Dict[str, Technology] = {}

        def add_tech(name: str, version: Optional[str], source: str, conf: Confidence):
            key = f"{name.lower()}::{version or ''}"
            if key not in tech_map:
                tech_map[key] = Technology(name=name, version=version, source=source, confidence=conf)
            else:
                # Upgrade confidence if new source has higher confidence
                existing = tech_map[key]
                if conf == Confidence.CONFIRMED:
                    existing.confidence = Confidence.CONFIRMED
                    existing.source = f"{existing.source}, {source}"

        # 1. Inspect HTTP Results
        for hr in http_results:
            # A. Server header
            if hr.server_header:
                for s_name, s_ver in _parse_software_version(hr.server_header):
                    conf = Confidence.CONFIRMED if s_ver else Confidence.PROBABLE
                    add_tech(s_name, s_ver, "Server header", conf)

            # B. X-Powered-By header
            if hr.powered_by_header:
                for p_name, p_ver in _parse_software_version(hr.powered_by_header):
                    conf = Confidence.CONFIRMED if p_ver else Confidence.PROBABLE
                    add_tech(p_name, p_ver, "X-Powered-By header", conf)

            # C. Framework headers
            for hdr_name, hdr_val in hr.framework_headers.items():
                hdr_lower = hdr_name.lower()
                if "aspnet" in hdr_lower:
                    add_tech("ASP.NET", hdr_val, f"{hdr_name} header", Confidence.CONFIRMED)
                elif "django" in hdr_lower:
                    add_tech("Django", hdr_val, f"{hdr_name} header", Confidence.CONFIRMED)
                elif "generator" in hdr_lower:
                    for g_name, g_ver in _parse_software_version(hdr_val):
                        add_tech(g_name, g_ver, f"{hdr_name} header", Confidence.CONFIRMED)

            # D. Cookies
            for cookie in hr.cookies:
                c_name = cookie.get("name", "").lower()
                for known_k, (t_name, t_ver, t_conf) in cls.KNOWN_COOKIES.items():
                    if known_k in c_name:
                        add_tech(t_name, t_ver, f"Cookie ({cookie.get('name')})", t_conf)

        # 2. Meta generator tags from HTML
        if meta_generators:
            for gen in meta_generators:
                for g_name, g_ver in _parse_software_version(gen):
                    conf = Confidence.CONFIRMED if g_ver else Confidence.PROBABLE
                    add_tech(g_name, g_ver, "HTML meta generator", conf)

        # 3. Correlate Nmap Discovered Services
        if scan_result:
            for host in scan_result.hosts:
                for s in host.open_ports:
                    if s.product and s.product != "Unknown":
                        ver = s.version if s.version != "Unknown" else None
                        conf = Confidence.CONFIRMED if ver else Confidence.PROBABLE
                        source_str = f"Nmap Service Detection (Port {s.port}/{s.protocol})"
                        add_tech(s.product, ver, source_str, conf)

        return list(tech_map.values())
