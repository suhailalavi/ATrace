import re
import logging
from typing import List, Dict, Set, Tuple, Optional, Any
from urllib.parse import urlparse, parse_qs
from html.parser import HTMLParser

logger = logging.getLogger("AlaviTrace")

SENSITIVE_PARAM_NAMES = {
    "password", "pass", "pwd", "passwd",
    "token", "csrf", "xsrf", "authenticity_token",
    "secret", "api_key", "apikey", "authorization",
    "auth", "access_token", "private_key"
}

class _PageHTMLParser(HTMLParser):
    """
    Standard library HTMLParser that extracts links, forms, input fields, and meta generator tags.
    Fault-tolerant against broken, malformed, or incomplete HTML markup.
    """

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self.meta_generators: List[str] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): (v or "").strip() for k, v in attrs if k}

        # 1. Links
        if tag in ["a", "link"]:
            href = attr_dict.get("href")
            if href:
                self.links.add(href)

        # 2. Meta generator tag
        elif tag == "meta":
            name = attr_dict.get("name", "").lower()
            if name == "generator":
                content = attr_dict.get("content", "").strip()
                if content:
                    self.meta_generators.append(content)

        # 3. Forms
        elif tag == "form":
            action = attr_dict.get("action", "")
            method = attr_dict.get("method", "GET").upper()
            self._current_form = {
                "action": action,
                "method": method if method in ["GET", "POST", "PUT", "DELETE"] else "GET",
                "inputs": [],
                "parameters": []
            }
            self.forms.append(self._current_form)

        # 4. Form inputs, textareas, selects
        elif tag in ["input", "textarea", "select"] and self._current_form is not None:
            inp_name = attr_dict.get("name")
            inp_type = attr_dict.get("type", "text").lower()
            if inp_name:
                self._current_form["parameters"].append(inp_name)
                # Sensitive parameter check
                is_sensitive = inp_name.lower() in SENSITIVE_PARAM_NAMES or inp_type == "password"
                self._current_form["inputs"].append({
                    "name": inp_name,
                    "type": inp_type,
                    "is_sensitive": is_sensitive
                })

    def handle_endtag(self, tag: str):
        if tag == "form":
            self._current_form = None


class HTMLExtractor:
    """
    Extracts structured links, forms, parameters, and technology indicators from HTML responses.
    """

    @classmethod
    def extract_from_html(cls, html_content: str, base_url: str) -> Dict[str, Any]:
        """
        Parses HTML string and returns raw links, forms, parameters, and meta tags.
        """
        if not html_content:
            return {
                "links": [],
                "forms": [],
                "meta_generators": []
            }

        parser = _PageHTMLParser(base_url=base_url)
        try:
            parser.feed(html_content)
        except Exception as e:
            logger.debug(f"HTMLParser warning on content from {base_url}: {e}")

        return {
            "links": list(parser.links),
            "forms": parser.forms,
            "meta_generators": parser.meta_generators
        }


class RobotsExtractor:
    """
    Extracts referenced paths and sitemap URLs from /robots.txt content.
    """

    @staticmethod
    def extract_paths(robots_content: str) -> Dict[str, List[str]]:
        """
        Parses robots.txt and extracts Disallow, Allow, and Sitemap directives.
        """
        disallow_paths: List[str] = []
        allow_paths: List[str] = []
        sitemaps: List[str] = []

        if not robots_content:
            return {"disallow": [], "allow": [], "sitemaps": []}

        for line in robots_content.splitlines():
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue

            lower = clean.lower()
            if lower.startswith("disallow:"):
                val = clean[len("disallow:"):].strip()
                if val:
                    disallow_paths.append(val)
            elif lower.startswith("allow:"):
                val = clean[len("allow:"):].strip()
                if val:
                    allow_paths.append(val)
            elif lower.startswith("sitemap:"):
                val = clean[len("sitemap:"):].strip()
                if val:
                    sitemaps.append(val)

        return {
            "disallow": disallow_paths,
            "allow": allow_paths,
            "sitemaps": sitemaps
        }


class SitemapExtractor:
    """
    Extracts URLs from standard sitemap.xml documents using fault-tolerant regex.
    """

    @staticmethod
    def extract_urls(sitemap_content: str) -> List[str]:
        """
        Extracts URLs from <loc>...</loc> tags in sitemap.xml.
        """
        if not sitemap_content:
            return []

        # Use regex to avoid XML parsing failures on slightly malformed sitemaps
        urls = re.findall(r"<loc>(https?://[^<]+)</loc>", sitemap_content, re.IGNORECASE)
        return [u.strip() for u in urls if u.strip()]


def extract_query_parameters(url: str) -> List[str]:
    """
    Extracts query parameter names from a URL string.
    """
    if not url:
        return []
    try:
        parsed = urlparse(url)
        if not parsed.query:
            return []
        qs = parse_qs(parsed.query, keep_blank_values=True)
        return list(qs.keys())
    except Exception:
        return []
