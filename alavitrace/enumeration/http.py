import logging
import time
import requests
from typing import List, Tuple, Optional, Dict
from alavitrace.core.models import Host, Service, HttpResult

logger = logging.getLogger("AlaviTrace")

# Standard HTTP security headers evaluated during passive reconnaissance
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Recognized non-web network services to avoid probing with HTTP requests
KNOWN_NON_WEB_SERVICES = {
    "SSH", "FTP", "TELNET", "SMTP", "POP3", "IMAP", "DOMAIN", "DNS",
    "MYSQL", "POSTGRESQL", "ORACLE", "REDIS", "MONGODB", "SMB", "NETBIOS",
    "SNMP", "RDP", "VNC", "NTP", "DHCP", "LDAP", "KERBEROS", "BGP", "IRC"
}

# Recognized web software/framework signatures in Nmap product metadata
KNOWN_WEB_PRODUCTS = [
    "apache", "nginx", "gophish", "node.js", "express", "tornado", "werkzeug",
    "flask", "django", "tomcat", "jetty", "iis", "lighttpd", "caddy", "kestrel",
    "puma", "unicorn", "uvicorn", "starlette", "fastapi", "httpd", "web"
]

def identify_http_service(
    target_addr: str,
    service: Service,
    allow_probe: bool = True,
    timeout_seconds: float = 3.0
) -> Tuple[bool, bool]:
    """
    Deterministically identifies if an open port hosts an HTTP or HTTPS service using
    multi-source evidence: Nmap metadata (service names, product signatures, CPEs)
    and, when ambiguous, safe non-destructive network probing.

    Args:
        target_addr: IP address or hostname of the target host.
        service: Service model instance for the target port.
        allow_probe: Whether active safe probing is permitted for ambiguous services.
        timeout_seconds: Timeout for active safe probing.

    Returns:
        Tuple[bool, bool]: (is_http, is_https)
            (True, False)  -> Valid HTTP service
            (True, True)   -> Valid HTTPS service
            (False, False) -> Not an HTTP/HTTPS service
    """
    svc_name = (service.name or "").strip().upper()
    product = (service.product or "").lower()
    extra_info = (service.extra_info or "").lower()

    # 1. Standard ports with explicit or default service names
    if service.port == 80 and svc_name in ["", "HTTP", "UNKNOWN"]:
        return (True, False)
    if service.port == 443 and svc_name in ["", "HTTPS", "SSL/HTTP", "UNKNOWN"]:
        return (True, True)

    # 2. Explicit Nmap service name evidence
    if svc_name == "HTTPS" or svc_name == "SSL/HTTP" or svc_name == "HTTPS-ALT" or "HTTPS" in svc_name:
        return (True, True)
    if "HTTP" in svc_name or svc_name in ["HTTP-PROXY", "HTTP-ALT", "WWW", "WEBSOCKET", "CALDAV", "CARDDAV"]:
        is_tls = "SSL" in svc_name or "ssl" in extra_info or service.port in [443, 8443, 9443]
        return (True, is_tls)

    # 3. Known web product / server signatures in Nmap metadata
    has_web_product = any(wp in product for wp in KNOWN_WEB_PRODUCTS)
    if has_web_product:
        is_tls = (
            service.port in [443, 8443, 9443]
            or "ssl" in svc_name.lower()
            or "ssl" in extra_info
        )
        return (True, is_tls)

    # 4. Explicit non-web service exclusion (do not probe SSH, MySQL, FTP, etc.)
    if svc_name in KNOWN_NON_WEB_SERVICES and not has_web_product:
        return (False, False)

    # 5. Common alternate ports if probing is disabled
    if not allow_probe:
        if service.port in [8080, 8000, 8888, 5000]:
            return (True, False)
        if service.port in [8443, 9443]:
            return (True, True)
        return (False, False)

    # 6. Ambiguous open port: Safe, non-destructive HTTP/HTTPS probing
    probe_url = f"http://{target_addr}:{service.port}/"
    headers = {"User-Agent": "AlaviTrace-Recon/1.0"}

    try:
        requests.packages.urllib3.disable_warnings()
        resp = requests.get(
            probe_url,
            headers=headers,
            timeout=timeout_seconds,
            allow_redirects=False,
            verify=False
        )

        if 100 <= resp.status_code < 600:
            body_text = (resp.text or "").lower()
            # If server indicates plain HTTP was sent to an HTTPS port
            if (
                "plain http request was sent to https" in body_text
                or "http request to an https server" in body_text
                or "sent an http request to an https server" in body_text
            ):
                return (True, True)
            return (True, False)

    except requests.exceptions.SSLError:
        # Port is speaking TLS, confirm with HTTPS probe
        https_url = f"https://{target_addr}:{service.port}/"
        try:
            resp_https = requests.get(
                https_url,
                headers=headers,
                timeout=timeout_seconds,
                allow_redirects=False,
                verify=False
            )
            if 100 <= resp_https.status_code < 600:
                return (True, True)
        except Exception:
            # SSLError on plain HTTP already strongly confirms TLS
            return (True, True)

    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        # Service is unreachable, rejected connection, or timed out
        return (False, False)
    except Exception as e:
        logger.debug(f"HTTP probe encountered exception for {probe_url}: {e}")
        return (False, False)

    return (False, False)

def build_http_urls(
    host: Host,
    allow_probe: bool = True,
    timeout_seconds: float = 3.0
) -> List[Tuple[int, str]]:
    """
    Constructs HTTP/HTTPS URLs for discovered web services across standard
    and arbitrary non-standard ports.

    Args:
        host: Host instance containing open services.
        allow_probe: Whether to allow active probing of ambiguous services.
        timeout_seconds: Timeout for safe HTTP probing.

    Returns:
        List of tuples: (port_number, url_string)
    """
    urls: List[Tuple[int, str]] = []
    target_addr = host.ipv4 or host.hostname or host.target.normalized

    for service in host.open_ports:
        is_http, is_https = identify_http_service(
            target_addr=target_addr,
            service=service,
            allow_probe=allow_probe,
            timeout_seconds=timeout_seconds
        )

        if is_http:
            scheme = "https" if is_https else "http"
            if (scheme == "http" and service.port == 80) or (scheme == "https" and service.port == 443):
                url = f"{scheme}://{target_addr}"
            else:
                url = f"{scheme}://{target_addr}:{service.port}"

            urls.append((service.port, url))

            # If service name was ambiguous, update it to HTTP/HTTPS for downstream consistency
            if service.name.upper() in ["UNKNOWN", "PPP", "UNRESOLVED", "TCPWRAPPED"]:
                service.name = "HTTPS" if is_https else "HTTP"

    return urls

class HttpEnumerator:
    """
    Performs non-intrusive passive HTTP/HTTPS response inspection and security header analysis.
    """

    def __init__(self, user_agent: str = "AlaviTrace-Recon/0.1", timeout_seconds: int = 10):
        self.user_agent = user_agent
        self.timeout_seconds = timeout_seconds

    def enumerate(self, url: str) -> HttpResult:
        """
        Executes a single passive HTTP GET request and extracts server/security metadata.
        """
        logger.info(f"Starting passive HTTP enumeration: {url}")
        headers = {"User-Agent": self.user_agent}

        start_time = time.time()
        try:
            # Disable SSL warnings for self-signed certificates in lab environments
            requests.packages.urllib3.disable_warnings()
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout_seconds,
                allow_redirects=True,
                verify=False
            )
            elapsed_ms = round((time.time() - start_time) * 1000, 2)

            # 1. Status and Redirect Chain
            status_code = response.status_code
            final_url = response.url
            redirect_chain = [r.url for r in response.history]
            if redirect_chain:
                redirect_chain.append(final_url)

            # 2. Server and Technology Headers
            server_header = response.headers.get("Server")
            powered_by_header = response.headers.get("X-Powered-By")
            content_type = response.headers.get("Content-Type")

            content_len_header = response.headers.get("Content-Length")
            content_length = int(content_len_header) if (content_len_header and content_len_header.isdigit()) else len(response.content)

            technologies: List[str] = []
            if server_header:
                technologies.append(f"Server: {server_header}")
            if powered_by_header:
                technologies.append(f"X-Powered-By: {powered_by_header}")

            # 3. Security Header Analysis
            present_sec_headers: Dict[str, str] = {}
            missing_sec_headers: List[str] = []

            resp_headers_lower = {k.lower(): v for k, v in response.headers.items()}

            for sec_header in SECURITY_HEADERS:
                header_lower = sec_header.lower()
                if header_lower in resp_headers_lower:
                    present_sec_headers[sec_header] = resp_headers_lower[header_lower]
                else:
                    missing_sec_headers.append(sec_header)

            # 4. Cookie Parsing
            cookies: List[Dict[str, Any]] = []
            for c in response.cookies:
                httponly = bool(c.has_nonstandard_attr('HttpOnly') or c.has_nonstandard_attr('httponly'))
                samesite = c.get_nonstandard_attr('SameSite') or c.get_nonstandard_attr('samesite')
                if hasattr(c, '_rest') and c._rest:
                    rest_lower = {str(k).lower(): v for k, v in c._rest.items()}
                    if 'httponly' in rest_lower:
                        httponly = True
                    if 'samesite' in rest_lower and not samesite:
                        samesite = rest_lower['samesite']
                cookies.append({
                    "name": c.name,
                    "value": c.value,
                    "secure": bool(c.secure),
                    "httponly": httponly,
                    "samesite": samesite
                })

            # 5. HTML and Parameter Extraction
            body_sample: Optional[str] = None
            forms: List[Dict[str, Any]] = []
            insecure_resources: List[str] = []
            observed_parameters: List[str] = []

            try:
                raw_text = response.text or ""
                body_sample = raw_text[:2000] if raw_text else ""

                # Query parameters from final URL
                import urllib.parse
                parsed_url = urllib.parse.urlparse(final_url)
                params_set = set()
                if parsed_url.query:
                    for p in urllib.parse.parse_qs(parsed_url.query).keys():
                        params_set.add(p)

                # HTML feature parsing if text/html
                content_type_lower = (content_type or "").lower()
                if "text/html" in content_type_lower or "<html" in body_sample.lower():
                    from html.parser import HTMLParser

                    class _PageParser(HTMLParser):
                        def __init__(self, base: str):
                            super().__init__()
                            self.base = base
                            self.page_forms: List[Dict[str, Any]] = []
                            self.page_insecure: List[str] = []
                            self.page_params: set = set()
                            self._current: Optional[Dict[str, Any]] = None

                        def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
                            attr_dict = {k.lower(): (v or "") for k, v in attrs}
                            if tag == "script":
                                src = attr_dict.get("src", "")
                                integrity = attr_dict.get("integrity", "")
                                if src:
                                    if self.base.lower().startswith("https://") and src.lower().startswith("http://"):
                                        self.page_insecure.append(f"Mixed Content script: {src}")
                                    if (src.startswith("http://") or src.startswith("https://") or src.startswith("//")) and not integrity:
                                        self.page_insecure.append(f"External script missing SRI: {src}")
                            elif tag == "link":
                                href = attr_dict.get("href", "")
                                if self.base.lower().startswith("https://") and href.lower().startswith("http://"):
                                    self.page_insecure.append(f"Mixed Content link: {href}")
                            elif tag == "form":
                                action = attr_dict.get("action", "")
                                resolved_action = urllib.parse.urljoin(self.base, action) if action else self.base
                                method = attr_dict.get("method", "GET").upper()
                                self._current = {
                                    "action": resolved_action,
                                    "method": method,
                                    "inputs": [],
                                    "has_csrf_token": False,
                                    "has_password": False
                                }
                                self.page_forms.append(self._current)
                            elif tag == "input" and self._current is not None:
                                inp_name = attr_dict.get("name", "")
                                inp_type = attr_dict.get("type", "text").lower()
                                inp_val = attr_dict.get("value", "")
                                if inp_name:
                                    self.page_params.add(inp_name)
                                    name_lower = inp_name.lower()
                                    if any(tok in name_lower for tok in ["csrf", "xsrf", "token", "authenticity_token", "nonce"]):
                                        self._current["has_csrf_token"] = True
                                if inp_type == "password":
                                    self._current["has_password"] = True
                                self._current["inputs"].append({
                                    "name": inp_name,
                                    "type": inp_type,
                                    "value": inp_val
                                })

                        def handle_endtag(self, tag: str):
                            if tag == "form":
                                self._current = None

                    parser = _PageParser(base=final_url)
                    parser.feed(raw_text[:50000])
                    forms = parser.page_forms
                    insecure_resources = parser.page_insecure
                    params_set.update(parser.page_params)

                observed_parameters = sorted(list(params_set))
            except Exception as e:
                logger.debug(f"Non-critical error extracting HTML features from {url}: {e}")

            logger.info(f"HTTP enumeration succeeded for {url} (Status: {status_code}, {elapsed_ms}ms)")

            # Extract framework & version disclosure headers
            framework_headers: Dict[str, str] = {}
            for h_key, h_val in response.headers.items():
                h_lower = h_key.lower()
                if h_lower in ["x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime", "x-version", "x-powered-cms"]:
                    framework_headers[h_key] = h_val
                    technologies.append(f"{h_key}: {h_val}")

            # Check if Allow header was sent in response
            options_methods: List[str] = []
            if "allow" in resp_headers_lower:
                options_methods = [m.strip().upper() for m in resp_headers_lower["allow"].split(",") if m.strip()]

            return HttpResult(
                url=url,
                status_code=status_code,
                final_url=final_url,
                response_time_ms=elapsed_ms,
                server_header=server_header,
                powered_by_header=powered_by_header,
                content_type=content_type,
                content_length=content_length,
                redirect_chain=redirect_chain,
                security_headers=present_sec_headers,
                missing_security_headers=missing_sec_headers,
                technologies=technologies,
                error_message=None,
                cookies=cookies,
                body_sample=body_sample,
                forms=forms,
                insecure_resources=insecure_resources,
                observed_parameters=observed_parameters,
                options_methods=options_methods,
                tls_cert_info=None,
                robots_txt_disallowed=[],
                security_txt_found=False,
                framework_headers=framework_headers,
                raw_body=raw_text
            )

        except requests.exceptions.Timeout:
            logger.warning(f"HTTP enumeration timed out for {url}")
            return HttpResult(url=url, error_message=f"Request timed out after {self.timeout_seconds} seconds.")
        except requests.exceptions.SSLError as e:
            logger.warning(f"SSL/TLS error during HTTP enumeration for {url}: {e}")
            return HttpResult(url=url, error_message=f"SSL/TLS handshake error: {e}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"HTTP enumeration failed for {url}: {e}")
            return HttpResult(url=url, error_message=f"HTTP connection failed: {e}")

    def check_options(self, url: str) -> List[str]:
        """
        Executes a safe, non-destructive HTTP OPTIONS request to discover advertised HTTP methods.
        Returns list of allowed methods (e.g. ['GET', 'POST', 'TRACE']).
        """
        try:
            requests.packages.urllib3.disable_warnings()
            resp = requests.options(
                url,
                headers={"User-Agent": self.user_agent},
                timeout=min(5, self.timeout_seconds),
                verify=False
            )
            allow_header = resp.headers.get("Allow", "")
            if allow_header:
                return [m.strip().upper() for m in allow_header.split(",") if m.strip()]
        except Exception as e:
            logger.debug(f"OPTIONS request failed for {url}: {e}")
        return []

    def check_safe_paths(self, base_url: str) -> Tuple[List[str], bool]:
        """
        Inspects a strictly bounded set of approved safe, public files (/robots.txt, /security.txt).
        Does NOT harvest sensitive files (.env, .git, /etc/passwd).
        Returns tuple of (disallowed_paths, security_txt_found).
        """
        from alavitrace.analysis.misconfiguration import check_robots_txt
        disallowed: List[str] = []
        security_txt_found = False
        base = base_url.rstrip("/")

        # 1. Safe /robots.txt check
        try:
            r = requests.get(
                f"{base}/robots.txt",
                headers={"User-Agent": self.user_agent},
                timeout=min(4, self.timeout_seconds),
                verify=False
            )
            if r.status_code == 200 and r.text:
                disallowed = check_robots_txt(r.text)
        except Exception as e:
            logger.debug(f"robots.txt check error on {base}: {e}")

        # 2. Safe /.well-known/security.txt check
        try:
            r_sec = requests.get(
                f"{base}/.well-known/security.txt",
                headers={"User-Agent": self.user_agent},
                timeout=min(4, self.timeout_seconds),
                verify=False
            )
            if r_sec.status_code == 200 and "contact:" in (r_sec.text or "").lower():
                security_txt_found = True
        except Exception as e:
            logger.debug(f"security.txt check error on {base}: {e}")

        return disallowed, security_txt_found
