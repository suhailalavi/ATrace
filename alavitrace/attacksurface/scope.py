import logging
from typing import Optional, Set
from urllib.parse import urlparse, urljoin, urlunparse
from alavitrace.attacksurface.models import RedirectEntry

logger = logging.getLogger("AlaviTrace")

class ScopeController:
    """
    Enforces strict target scope boundaries on discovered URLs and redirects.
    Prevents off-scope web crawling, unintended SSRF-like behavior, and following third-party links.
    """

    DISALLOWED_SCHEMES = {"javascript", "mailto", "data", "file", "ftp", "tel", "ssh"}

    def __init__(self, authorized_target: str, allowed_ports: Optional[Set[int]] = None):
        self.raw_target = authorized_target
        self.allowed_hosts: Set[str] = set()
        self.allowed_ports: Optional[Set[int]] = allowed_ports

        self._initialize_scope(authorized_target)

    def _initialize_scope(self, target_str: str) -> None:
        """Parses target into normalized allowed hostnames/IPs."""
        candidate = target_str.strip()
        if "://" not in candidate:
            candidate = f"http://{candidate}"

        parsed = urlparse(candidate)
        hostname = (parsed.hostname or target_str).lower().strip()

        if hostname:
            self.allowed_hosts.add(hostname)
            # If domain like example.com, also permit www.example.com and vice versa
            if hostname.startswith("www."):
                self.allowed_hosts.add(hostname[4:])
            else:
                self.allowed_hosts.add(f"www.{hostname}")

        if parsed.port and self.allowed_ports is None:
            self.allowed_ports = {parsed.port}

    def normalize_url(self, base_url: str, candidate_url: str) -> Optional[str]:
        """
        Normalizes relative and absolute URLs against base_url.
        Strips fragments (#), rejects non-HTTP schemes, and cleans redundant path slashes.
        """
        if not candidate_url:
            return None

        candidate = candidate_url.strip()
        if not candidate or candidate.startswith("#"):
            return None

        # Check scheme before joining
        colon_idx = candidate.find(":")
        if colon_idx != -1:
            scheme_candidate = candidate[:colon_idx].lower()
            if scheme_candidate in self.DISALLOWED_SCHEMES:
                return None

        # Resolve relative URLs
        try:
            resolved = urljoin(base_url, candidate)
            parsed = urlparse(resolved)

            if parsed.scheme.lower() not in ["http", "https"]:
                return None

            # Remove fragment
            clean = parsed._replace(fragment="")

            # Normalize path: collapse /./ and remove duplicate trailing slashes
            path = clean.path or "/"
            if "//" in path:
                import re
                path = re.sub(r"/+", "/", path)
            clean = clean._replace(path=path)

            return urlunparse(clean)
        except Exception as e:
            logger.debug(f"Failed to normalize candidate URL '{candidate_url}': {e}")
            return None

    def is_in_scope(self, url: str) -> bool:
        """
        Validates whether a candidate URL belongs strictly to the authorized target scope.
        """
        if not url:
            return False

        try:
            parsed = urlparse(url)
            if parsed.scheme.lower() not in ["http", "https"]:
                return False

            cand_host = (parsed.hostname or "").lower().strip()
            if not cand_host:
                return False

            if cand_host in self.allowed_hosts:
                return True

            # If target was an IP without www, exact match only
            return False
        except Exception:
            return False

    def check_redirect(self, source_url: str, target_url: str, status_code: Optional[int] = None) -> RedirectEntry:
        """
        Evaluates a redirect target against scope.
        Marks out-of-scope redirects with OUT_OF_SCOPE_REDIRECT flag.
        """
        normalized_target = self.normalize_url(source_url, target_url) or target_url
        in_scope = self.is_in_scope(normalized_target)

        if not in_scope:
            logger.info(f"Detected out-of-scope redirect: {source_url} -> {target_url} (Flag: OUT_OF_SCOPE_REDIRECT)")
            return RedirectEntry(
                source_url=source_url,
                target_url=normalized_target,
                status_code=status_code,
                is_out_of_scope=True,
                flag="OUT_OF_SCOPE_REDIRECT"
            )

        return RedirectEntry(
            source_url=source_url,
            target_url=normalized_target,
            status_code=status_code,
            is_out_of_scope=False,
            flag=None
        )
