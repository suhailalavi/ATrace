import logging
import time
import requests
from typing import List, Tuple, Optional, Dict
from alavitrace.core.models import Host, Service, HttpResult

logger = logging.getLogger("ATrace")

# Standard HTTP security headers evaluated during passive reconnaissance
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

def build_http_urls(host: Host) -> List[Tuple[int, str]]:
    """
    Constructs HTTP/HTTPS URLs for discovered web services.

    Returns:
        List of tuples: (port_number, url_string)
    """
    urls: List[Tuple[int, str]] = []
    target_addr = host.ipv4 or host.hostname or host.target.normalized

    for service in host.open_ports:
        service_name = service.name.upper()
        if "HTTP" in service_name or service.port in [80, 443, 8080, 8443]:
            is_https = service_name == "HTTPS" or service.port in [443, 8443]
            scheme = "https" if is_https else "http"

            # Omit port if standard HTTP (80) or HTTPS (443)
            if (scheme == "http" and service.port == 80) or (scheme == "https" and service.port == 443):
                url = f"{scheme}://{target_addr}"
            else:
                url = f"{scheme}://{target_addr}:{service.port}"

            urls.append((service.port, url))

    return urls

class HttpEnumerator:
    """
    Performs non-intrusive passive HTTP/HTTPS response inspection and security header analysis.
    """

    def __init__(self, user_agent: str = "ATrace-Recon/0.1", timeout_seconds: int = 10):
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

            logger.info(f"HTTP enumeration succeeded for {url} (Status: {status_code}, {elapsed_ms}ms)")

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
                error_message=None
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
