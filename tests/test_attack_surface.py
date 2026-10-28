import os
import json
import socket
from unittest.mock import MagicMock, patch
import pytest
import requests

from alavitrace.core.models import (
    Target,
    ScanResult,
    Host,
    Service,
    HttpResult,
    Confidence
)
from alavitrace.analysis.prioritization import PrioritizationResult
from alavitrace.attacksurface.models import (
    Technology,
    Parameter,
    Endpoint,
    RedirectEntry,
    AttackSurface
)
from alavitrace.attacksurface.scope import ScopeController
from alavitrace.attacksurface.extractor import (
    HTMLExtractor,
    RobotsExtractor,
    SitemapExtractor,
    extract_query_parameters,
    SENSITIVE_PARAM_NAMES
)
from alavitrace.attacksurface.technologies import TechnologyFingerprinter
from alavitrace.attacksurface.mapper import AttackSurfaceMapper
from alavitrace.ai.analyst import SecurityAnalyst
from alavitrace.reporting.json_report import generate_json_report
from alavitrace.reporting.markdown_report import generate_markdown_report
from alavitrace.reporting.html_report import generate_html_report
from alavitrace.cli import parse_args, render_attack_surface_summary

# ---------------------------------------------------------------------------
# FIXTURES
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_target():
    return Target(raw_input="192.168.56.101", normalized="192.168.56.101", target_type="IPv4")

@pytest.fixture
def sample_html():
    return """<!DOCTYPE html>
<html>
<head>
    <title>Authorized Test Portal</title>
    <meta name="generator" content="WordPress 6.2">
    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
    <header>
        <a href="/about.php">About Us</a>
        <a href="contact.html">Contact</a>
        <a href="../docs/api.html">Docs</a>
        <a href="http://192.168.56.101/admin/dashboard">Admin Dashboard</a>
        <a href="https://external-malicious.org/phish">External Link</a>
        <a href="javascript:alert(1)">XSS Link</a>
        <a href="mailto:admin@test.local">Email</a>
        <a href="#top">Anchor</a>
    </header>
    <main>
        <form action="/login.php" method="POST">
            <input type="text" name="username" value="admin">
            <input type="password" name="password" value="secret123">
            <input type="hidden" name="csrf_token" value="xyz987">
            <button type="submit">Sign In</button>
        </form>
        <form action="/search" method="GET">
            <input type="text" name="q">
            <input type="text" name="category">
        </form>
    </main>
</body>
</html>
"""

@pytest.fixture
def sample_http_result(sample_html):
    return HttpResult(
        url="http://192.168.56.101:80/",
        status_code=200,
        server_header="Apache/2.4.41 (Ubuntu)",
        powered_by_header="PHP/7.4.3",
        content_type="text/html; charset=UTF-8",
        content_length=len(sample_html),
        cookies=[{"name": "PHPSESSID", "value": "session_secret_abc123"}],
        options_methods=["GET", "POST", "OPTIONS", "HEAD"],
        body_sample=sample_html[:200],
        raw_body=sample_html
    )

# ---------------------------------------------------------------------------
# UNIT TESTS
# ---------------------------------------------------------------------------

def test_relative_url_extraction(sample_html):
    """Test 1: Extraction and resolution of relative URLs."""
    extracted = HTMLExtractor.extract_from_html(sample_html, "http://192.168.56.101/")
    links = extracted["links"]
    assert "/about.php" in links
    assert "contact.html" in links
    assert "../docs/api.html" in links

    scope = ScopeController("192.168.56.101")
    resolved_about = scope.normalize_url("http://192.168.56.101/", "/about.php")
    assert resolved_about == "http://192.168.56.101/about.php"

    resolved_contact = scope.normalize_url("http://192.168.56.101/dir/", "contact.html")
    assert resolved_contact == "http://192.168.56.101/dir/contact.html"

def test_absolute_url_extraction(sample_html):
    """Test 2: Extraction and resolution of same-host absolute URLs."""
    extracted = HTMLExtractor.extract_from_html(sample_html, "http://192.168.56.101/")
    assert "http://192.168.56.101/admin/dashboard" in extracted["links"]

    scope = ScopeController("192.168.56.101")
    norm = scope.normalize_url("http://192.168.56.101/", "http://192.168.56.101/admin/dashboard")
    assert norm == "http://192.168.56.101/admin/dashboard"
    assert scope.is_in_scope(norm) is True

def test_html_link_extraction(sample_html):
    """Test 3: Extraction of <a> and <link> tags from HTML."""
    extracted = HTMLExtractor.extract_from_html(sample_html, "http://192.168.56.101/")
    links = extracted["links"]
    assert "/static/style.css" in links
    assert "/about.php" in links

def test_html_form_extraction(sample_html):
    """Test 4: Extraction of forms, methods, action endpoints, and input parameters."""
    extracted = HTMLExtractor.extract_from_html(sample_html, "http://192.168.56.101/")
    forms = extracted["forms"]
    assert len(forms) == 2

    post_form = next(f for f in forms if f["method"] == "POST")
    assert post_form["action"] == "/login.php"
    assert "username" in post_form["parameters"]
    assert "password" in post_form["parameters"]
    assert "csrf_token" in post_form["parameters"]

    get_form = next(f for f in forms if f["method"] == "GET")
    assert get_form["action"] == "/search"
    assert "q" in get_form["parameters"]
    assert "category" in get_form["parameters"]

def test_query_parameter_extraction():
    """Test 5: Extraction of query parameters from candidate URLs."""
    url = "http://192.168.56.101/search?q=cybersecurity&category=books&sort=asc"
    params = extract_query_parameters(url)
    assert params == ["q", "category", "sort"]

    url_no_params = "http://192.168.56.101/static/app.js"
    assert extract_query_parameters(url_no_params) == []

def test_technology_detection_headers_and_cookies(sample_http_result):
    """Test 6: Detection of technologies from Server, X-Powered-By, and Cookies."""
    techs = TechnologyFingerprinter.identify(http_results=[sample_http_result])
    tech_names = [t.name for t in techs]

    assert "Apache" in tech_names
    apache_tech = next(t for t in techs if t.name == "Apache")
    assert apache_tech.version == "2.4.41"
    assert apache_tech.confidence == Confidence.CONFIRMED

    assert "PHP" in tech_names
    php_tech = next(t for t in techs if t.name == "PHP")
    assert php_tech.version == "7.4.3"

def test_technology_detection_meta_and_nmap(mock_target):
    """Test 7: Detection of technologies from meta generators and Nmap scan results."""
    scan = ScanResult(
        target=mock_target,
        hosts=[
            Host(
                target=mock_target,
                ipv4="192.168.56.101",
                state="up",
                open_ports=[
                    Service(
                        port=80,
                        protocol="tcp",
                        state="open",
                        name="http",
                        product="nginx",
                        version="1.18.0",
                        cpes=["cpe:/a:igor_sysoev:nginx:1.18.0"]
                    )
                ]
            )
        ]
    )

    techs = TechnologyFingerprinter.identify(
        http_results=[],
        scan_result=scan,
        meta_generators=["WordPress 6.2"]
    )
    tech_names = [t.name for t in techs]

    assert "WordPress" in tech_names
    wp_tech = next(t for t in techs if t.name == "WordPress")
    assert wp_tech.version == "6.2"

    assert "nginx" in tech_names
    nginx_tech = next(t for t in techs if t.name == "nginx")
    assert nginx_tech.version == "1.18.0"

def test_in_scope_redirect_handling():
    """Test 8: In-scope redirect tracking."""
    scope = ScopeController("192.168.56.101")
    redirect = scope.check_redirect("http://192.168.56.101/", "http://192.168.56.101/index.php", status_code=301)

    assert redirect.is_out_of_scope is False
    assert redirect.flag is None
    assert redirect.source_url == "http://192.168.56.101/"
    assert redirect.target_url == "http://192.168.56.101/index.php"

def test_out_of_scope_redirect_flagged_and_not_requested():
    """Test 9: Out-of-scope redirect flagged as OUT_OF_SCOPE_REDIRECT and never requested."""
    scope = ScopeController("192.168.56.101")
    redirect = scope.check_redirect("http://192.168.56.101/out", "https://external-target.com/login", status_code=302)

    assert redirect.is_out_of_scope is True
    assert redirect.flag == "OUT_OF_SCOPE_REDIRECT"

    mapper = AttackSurfaceMapper("192.168.56.101")
    with patch("requests.get") as mock_get:
        resp = mapper._fetch_url("https://external-target.com/login")
        assert resp is None
        mock_get.assert_not_called()

def test_external_domain_link_rejection(sample_html):
    """Test 10: External links rejected and excluded from crawling."""
    scope = ScopeController("192.168.56.101")
    extracted = HTMLExtractor.extract_from_html(sample_html, "http://192.168.56.101/")
    ext_link = "https://external-malicious.org/phish"
    assert ext_link in extracted["links"]
    assert scope.is_in_scope(ext_link) is False

def test_maximum_depth_enforcement(mock_target, sample_http_result):
    """Test 11: Depth limits (max_depth=0 discovers no crawled endpoints beyond root)."""
    mapper_depth_0 = AttackSurfaceMapper("192.168.56.101", max_depth=0)
    with patch.object(mapper_depth_0, "_fetch_url") as mock_fetch:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = ""
        mock_fetch.return_value = mock_resp

        surface_0 = mapper_depth_0.map_surface(mock_target, [sample_http_result])
        # In depth 0, no secondary crawl requests are made for discovered HTML links
        fetched_urls = [c.args[0] for c in mock_fetch.call_args_list if c.args]
        assert not any("about.php" in u or "contact" in u for u in fetched_urls)
        assert surface_0.metadata["max_depth"] == 0

def test_maximum_request_limit_enforcement(mock_target, sample_http_result):
    """Test 12: Request limit enforcement and REQUEST_LIMIT_REACHED status."""
    mapper = AttackSurfaceMapper("192.168.56.101", max_depth=1, max_requests=2)

    def mock_get(url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<html><body><a href='/sub'>Sub</a></body></html>"
        resp.content = b"<html><body><a href='/sub'>Sub</a></body></html>"
        resp.headers = {"Content-Type": "text/html"}
        resp.history = []
        return resp

    with patch("requests.get", side_effect=mock_get):
        surface = mapper.map_surface(mock_target, [sample_http_result])
        assert mapper.requests_sent <= 2
        assert surface.metadata["requests_sent"] <= 2
        assert surface.metadata["request_limit_reached"] is True
        assert surface.metadata["status"] == "REQUEST_LIMIT_REACHED"

def test_robots_txt_parsing():
    """Test 13: Parsing robots.txt disallow/allow paths and sitemap references."""
    robots_content = """User-agent: *
Disallow: /admin/
Disallow: /private/api
Allow: /public/
Sitemap: http://192.168.56.101/sitemap.xml
"""
    parsed = RobotsExtractor.extract_paths(robots_content)
    assert "/admin/" in parsed["disallow"]
    assert "/private/api" in parsed["disallow"]
    assert "/public/" in parsed["allow"]
    assert "http://192.168.56.101/sitemap.xml" in parsed["sitemaps"]

def test_sitemap_xml_parsing():
    """Test 14: Parsing XML sitemaps for <loc> URL endpoints."""
    sitemap_content = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>http://192.168.56.101/page1</loc>
    </url>
    <url>
        <loc>http://192.168.56.101/page2</loc>
    </url>
</urlset>
"""
    urls = SitemapExtractor.extract_urls(sitemap_content)
    assert urls == ["http://192.168.56.101/page1", "http://192.168.56.101/page2"]

def test_duplicate_endpoint_removal(mock_target):
    """Test 15: Deduplication of endpoints with identical method and path."""
    html = """<html><body>
        <a href="/contact">Contact</a>
        <a href="/contact">Contact Again</a>
        <a href="./contact">Contact Relative</a>
    </body></html>"""

    hr = HttpResult(
        url="http://192.168.56.101/",
        status_code=200,
        raw_body=html
    )

    mapper = AttackSurfaceMapper("192.168.56.101", max_depth=0)
    surface = mapper.map_surface(mock_target, [hr])

    contact_endpoints = [e for e in surface.endpoints if e.path == "/contact"]
    assert len(contact_endpoints) == 1

def test_url_normalization():
    """Test 16: Removal of fragments, collapsing multiple slashes, and rejecting invalid schemes."""
    scope = ScopeController("192.168.56.101")

    # Fragment removal
    assert scope.normalize_url("http://192.168.56.101/", "/page.html#section1") == "http://192.168.56.101/page.html"

    # Redundant slash collapse
    assert scope.normalize_url("http://192.168.56.101/", "///api//v1///users") == "http://192.168.56.101/api/v1/users"

    # Scheme rejections
    assert scope.normalize_url("http://192.168.56.101/", "javascript:void(0)") is None
    assert scope.normalize_url("http://192.168.56.101/", "mailto:admin@example.com") is None
    assert scope.normalize_url("http://192.168.56.101/", "tel:+123456789") is None

def test_http_timeout_handling():
    """Test 17: Graceful handling of HTTP timeouts without crashing."""
    mapper = AttackSurfaceMapper("192.168.56.101")
    with patch("requests.get", side_effect=requests.exceptions.Timeout("Connection timed out")):
        resp = mapper._fetch_url("http://192.168.56.101/timeout")
        assert resp is None

def test_connection_error_handling():
    """Test 18: Graceful handling of network connection failures."""
    mapper = AttackSurfaceMapper("192.168.56.101")
    with patch("requests.get", side_effect=requests.exceptions.ConnectionError("Connection refused")):
        resp = mapper._fetch_url("http://192.168.56.101/down")
        assert resp is None

def test_malformed_html_handling():
    """Test 19: Graceful parsing of truncated/malformed HTML without throwing errors."""
    malformed = "<a href='/valid'>Valid</a><form action='/broken'<input name='foo'<<>>>"
    extracted = HTMLExtractor.extract_from_html(malformed, "http://192.168.56.101/")
    assert "/valid" in extracted["links"]
    assert isinstance(extracted["forms"], list)

def test_empty_response_handling(mock_target):
    """Test 20: Handling of empty string body and None responses."""
    hr = HttpResult(
        url="http://192.168.56.101/",
        status_code=204,
        raw_body=""
    )
    mapper = AttackSurfaceMapper("192.168.56.101", max_depth=0)
    surface = mapper.map_surface(mock_target, [hr])
    assert len(surface.endpoints) == 1
    assert surface.endpoints[0].status_code == 204

def test_sensitive_parameter_redaction():
    """Test 21: Verification that sensitive parameter names are identified in SENSITIVE_PARAM_NAMES."""
    sensitive_samples = ["password", "token", "secret", "api_key", "authorization", "passwd", "access_token"]
    for s in sensitive_samples:
        assert s in SENSITIVE_PARAM_NAMES

    # HTMLExtractor only extracts input names, not secret values
    html = '<form action="/auth" method="POST"><input name="password" value="SuperSecretValue123"/></form>'
    extracted = HTMLExtractor.extract_from_html(html, "http://192.168.56.101/")
    form = extracted["forms"][0]
    assert form["parameters"] == ["password"]
    # Verify raw values are not leaked in parameters list
    assert "SuperSecretValue123" not in form["parameters"]

def test_cli_argument_parsing():
    """Test 22: CLI argument parsing for Phase 10 options."""
    args = parse_args(["-t", "192.168.56.101", "--attack-surface", "--max-depth", "2", "--max-requests", "50"])
    assert args.attack_surface is True
    assert args.max_depth == 2
    assert args.max_requests == 50

    default_args = parse_args(["-t", "192.168.56.101"])
    assert default_args.attack_surface is False
    assert default_args.max_depth == 1
    assert default_args.max_requests == 20

def test_json_report_attack_surface(mock_target, tmp_path):
    """Test 23: JSON report includes structured attack surface payload."""
    scan = ScanResult(target=mock_target, hosts=[])
    surface = AttackSurface(
        target=mock_target.normalized,
        base_urls=["http://192.168.56.101/"],
        endpoints=[
            Endpoint(url="http://192.168.56.101/login", path="/login", method="POST", parameters=["username", "password"])
        ],
        technologies=[
            Technology(name="Apache", version="2.4.41", source="Server header", confidence=Confidence.CONFIRMED)
        ],
        parameters=[
            Parameter(name="username", location="form_body", endpoint="http://192.168.56.101/login")
        ],
        methods=["GET", "POST"],
        metadata={"status": "COMPLETED"}
    )
    p_result = PrioritizationResult(total_correlated=0, prioritized_count=0, all_findings=[], prioritized_findings=[])

    report_path = generate_json_report(
        scan_result=scan,
        http_results=[],
        prioritization_result=p_result,
        ai_analysis=None,
        output_dir=str(tmp_path),
        attack_surface=surface
    )

    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "attack_surface" in data
    assert data["attack_surface"]["target"] == "192.168.56.101"
    assert data["attack_surface"]["total_endpoints"] == 1
    assert data["attack_surface"]["endpoints"][0]["path"] == "/login"
    assert data["attack_surface"]["technologies"][0]["name"] == "Apache"

def test_markdown_report_attack_surface(mock_target, tmp_path):
    """Test 24: Markdown report includes attack surface section and tables."""
    scan = ScanResult(target=mock_target, hosts=[])
    surface = AttackSurface(
        target=mock_target.normalized,
        base_urls=["http://192.168.56.101/"],
        endpoints=[
            Endpoint(url="http://192.168.56.101/api", path="/api", method="GET", status_code=200)
        ],
        technologies=[
            Technology(name="nginx", version="1.18.0", source="Nmap Service Detection", confidence=Confidence.CONFIRMED)
        ],
        parameters=[],
        methods=["GET"],
        metadata={"status": "COMPLETED"}
    )
    p_result = PrioritizationResult(total_correlated=0, prioritized_count=0, all_findings=[], prioritized_findings=[])

    md_path = generate_markdown_report(
        scan_result=scan,
        http_results=[],
        prioritization_result=p_result,
        ai_analysis=None,
        output_dir=str(tmp_path),
        attack_surface=surface
    )

    with open(md_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "Attack Surface & Web Endpoint Discovery" in content
    assert "/api" in content
    assert "nginx" in content

def test_html_report_attack_surface(mock_target, tmp_path):
    """Test 25: HTML report includes attack surface card, badge styling, and table."""
    scan = ScanResult(target=mock_target, hosts=[])
    surface = AttackSurface(
        target=mock_target.normalized,
        base_urls=["http://192.168.56.101/"],
        endpoints=[
            Endpoint(url="http://192.168.56.101/profile", path="/profile", method="GET", status_code=200, depth=1)
        ],
        technologies=[
            Technology(name="PHP", version="7.4.3", source="X-Powered-By header", confidence=Confidence.CONFIRMED)
        ],
        parameters=[
            Parameter(name="id", location="query", endpoint="http://192.168.56.101/profile")
        ],
        methods=["GET"],
        metadata={"status": "COMPLETED"}
    )
    p_result = PrioritizationResult(total_correlated=0, prioritized_count=0, all_findings=[], prioritized_findings=[])

    html_path = generate_html_report(
        scan_result=scan,
        http_results=[],
        prioritization_result=p_result,
        ai_analysis=None,
        output_dir=str(tmp_path),
        attack_surface=surface
    )

    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    assert "Attack Surface" in html_content
    assert "/profile" in html_content
    assert "PHP" in html_content

def test_ai_input_serialization_attack_surface(mock_target):
    """Test 26: AI input serialization includes attack surface summary without hallucinations."""
    scan = ScanResult(target=mock_target, hosts=[])
    surface = AttackSurface(
        target=mock_target.normalized,
        base_urls=["http://192.168.56.101/"],
        endpoints=[
            Endpoint(url="http://192.168.56.101/admin", path="/admin", method="GET", status_code=403)
        ],
        technologies=[
            Technology(name="Apache", version="2.4.41", source="Server header", confidence=Confidence.CONFIRMED)
        ],
        parameters=[
            Parameter(name="user", location="query", endpoint="http://192.168.56.101/admin")
        ],
        methods=["GET"],
        metadata={"status": "COMPLETED"}
    )
    p_result = PrioritizationResult(total_correlated=0, prioritized_count=0, all_findings=[], prioritized_findings=[])

    mock_provider = MagicMock()
    analyst = SecurityAnalyst(provider=mock_provider)

    payload = analyst.prepare_structured_input(
        scan_result=scan,
        http_results=[],
        prioritization_result=p_result,
        attack_surface=surface
    )

    assert "attack_surface" in payload
    assert payload["attack_surface"]["total_endpoints"] == 1
    assert len(payload["attack_surface"]["parameters"]) == 1
    assert len(payload["attack_surface"]["technologies"]) == 1
    assert payload["attack_surface"]["endpoints"][0]["path"] == "/admin"

def test_zero_outbound_network_calls(mock_target, sample_html):
    """Test 27: Zero real network sockets are opened during mocked attack surface mapping."""
    hr = HttpResult(
        url="http://192.168.56.101/",
        status_code=200,
        raw_body=sample_html
    )

    mapper = AttackSurfaceMapper("192.168.56.101", max_depth=1, max_requests=5)

    def guard_connect(*args, **kwargs):
        raise RuntimeError("Forbidden real network socket opened during offline test!")

    with patch.object(socket.socket, "connect", side_effect=guard_connect):
        with patch.object(mapper, "_fetch_url") as mock_fetch:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "<html><body>Clean</body></html>"
            mock_resp.content = b"<html><body>Clean</body></html>"
            mock_resp.headers = {"Content-Type": "text/html"}
            mock_resp.history = []
            mock_fetch.return_value = mock_resp

            surface = mapper.map_surface(mock_target, [hr])
            assert len(surface.endpoints) >= 1
            assert surface.metadata["requests_sent"] == 0 or mock_fetch.called
