import pytest
from unittest.mock import patch, MagicMock
import requests

from alavitrace.core.models import Target, Host, Service
from alavitrace.enumeration.http import (
    identify_http_service,
    build_http_urls,
    KNOWN_NON_WEB_SERVICES,
    KNOWN_WEB_PRODUCTS
)
from alavitrace.assessment.models import AssessmentContext
from alavitrace.core.models import ScanResult, HttpResult

@pytest.fixture
def base_target():
    return Target(raw_input="192.168.56.103", normalized="192.168.56.103", target_type="IPv4")

def test_standard_http_port_80(base_target):
    """Scenario 1: Standard HTTP on port 80 detected as http://target without probing."""
    svc = Service(port=80, protocol="tcp", state="open", name="http")
    is_http, is_https = identify_http_service(base_target.normalized, svc, allow_probe=False)
    assert is_http is True
    assert is_https is False

    host = Host(target=base_target, ipv4="192.168.56.103", open_ports=[svc])
    urls = build_http_urls(host, allow_probe=False)
    assert urls == [(80, "http://192.168.56.103")]

def test_standard_https_port_443(base_target):
    """Scenario 2: Standard HTTPS on port 443 detected as https://target without probing."""
    svc = Service(port=443, protocol="tcp", state="open", name="https")
    is_http, is_https = identify_http_service(base_target.normalized, svc, allow_probe=False)
    assert is_http is True
    assert is_https is True

    host = Host(target=base_target, ipv4="192.168.56.103", open_ports=[svc])
    urls = build_http_urls(host, allow_probe=False)
    assert urls == [(443, "https://192.168.56.103")]

def test_non_standard_port_3000_ppp_detected_via_safe_probe(base_target):
    """
    Scenario 3: Port 3000 where Nmap classified service as 'PPP'.
    Safe probe issues GET http://target:3000/ and receives HTTP 200,
    confirming HTTP on port 3000 and updating service name to HTTP.
    """
    svc = Service(port=3000, protocol="tcp", state="open", name="ppp", product="Unknown")
    host = Host(target=base_target, ipv4="192.168.56.103", open_ports=[svc])

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "<html><title>OWASP Juice Shop</title></html>"

    with patch("requests.get", return_value=mock_resp) as mock_get:
        urls = build_http_urls(host, allow_probe=True)
        assert mock_get.called
        assert mock_get.call_args[0][0] == "http://192.168.56.103:3000/"

    assert urls == [(3000, "http://192.168.56.103:3000")]
    assert svc.name == "HTTP"

def test_arbitrary_non_standard_port_8080(base_target):
    """Scenario 4: HTTP on arbitrary non-standard port 8080 detected."""
    svc = Service(port=8080, protocol="tcp", state="open", name="http-proxy")
    host = Host(target=base_target, ipv4="192.168.56.103", open_ports=[svc])

    urls = build_http_urls(host, allow_probe=False)
    assert urls == [(8080, "http://192.168.56.103:8080")]

def test_unrelated_tcp_service_ssh_not_classified_as_http(base_target):
    """
    Scenario 5: Unrelated TCP services (e.g. port 22 SSH with OpenSSH) must NOT be
    classified as HTTP and must NEVER be probed with HTTP requests.
    """
    svc = Service(port=22, protocol="tcp", state="open", name="ssh", product="OpenSSH", version="10.2p1")
    host = Host(target=base_target, ipv4="192.168.56.103", open_ports=[svc])

    with patch("requests.get") as mock_get:
        is_http, is_https = identify_http_service(base_target.normalized, svc, allow_probe=True)
        assert is_http is False
        assert is_https is False
        assert not mock_get.called  # Probing strictly skipped for confirmed SSH

        urls = build_http_urls(host, allow_probe=True)
        assert len(urls) == 0
        assert not mock_get.called

def test_ambiguous_service_port_5000_identified_via_probe(base_target):
    """Scenario 6: Ambiguous service name (e.g. UNKNOWN on port 5000) identified when safe probe returns valid HTTP."""
    svc = Service(port=5000, protocol="tcp", state="open", name="unknown")
    host = Host(target=base_target, ipv4="192.168.56.103", open_ports=[svc])

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"status": "ok"}'

    with patch("requests.get", return_value=mock_resp):
        urls = build_http_urls(host, allow_probe=True)

    assert urls == [(5000, "http://192.168.56.103:5000")]
    assert svc.name == "HTTP"

def test_non_standard_https_detection_plain_to_https_banner(base_target):
    """
    Scenario 7: Non-standard port (e.g. 8443 or custom 9443) where plain HTTP probe
    returns 400 Bad Request with 'The plain HTTP request was sent to HTTPS port'.
    Correctly identifies service as HTTPS and formats URL with https://.
    """
    svc = Service(port=8443, protocol="tcp", state="open", name="unknown")
    host = Host(target=base_target, ipv4="192.168.56.103", open_ports=[svc])

    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.text = "<html><body><h1>400 Bad Request</h1><p>The plain HTTP request was sent to HTTPS port</p></body></html>"

    with patch("requests.get", return_value=mock_resp):
        urls = build_http_urls(host, allow_probe=True)

    assert urls == [(8443, "https://192.168.56.103:8443")]
    assert svc.name == "HTTPS"

def test_non_standard_https_detection_via_ssl_error(base_target):
    """
    Scenario 7b: Non-standard port raising SSLError on plain HTTP probe,
    subsequently verified via HTTPS probe.
    """
    svc = Service(port=9001, protocol="tcp", state="open", name="unknown")
    host = Host(target=base_target, ipv4="192.168.56.103", open_ports=[svc])

    def mock_get_side_effect(url, *args, **kwargs):
        if url.startswith("http://"):
            raise requests.exceptions.SSLError("Wrong version number / TLS handshake")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "OK"
        return mock_resp

    with patch("requests.get", side_effect=mock_get_side_effect):
        urls = build_http_urls(host, allow_probe=True)

    assert urls == [(9001, "https://192.168.56.103:9001")]
    assert svc.name == "HTTPS"

def test_multiple_web_ports_on_same_host_kept_separate(base_target):
    """
    Scenario 8: Multiple web ports on the same host (e.g. port 80, port 3000, port 8443)
    must remain completely distinct endpoints without merging.
    """
    svc80 = Service(port=80, protocol="tcp", state="open", name="http", product="Gophish httpd")
    svc3000 = Service(port=3000, protocol="tcp", state="open", name="ppp", product="Unknown")
    svc8443 = Service(port=8443, protocol="tcp", state="open", name="https-alt")
    svc22 = Service(port=22, protocol="tcp", state="open", name="ssh", product="OpenSSH")

    host = Host(target=base_target, ipv4="192.168.56.103", open_ports=[svc22, svc80, svc3000, svc8443])

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "Juice Shop"

    with patch("requests.get", return_value=mock_resp):
        urls = build_http_urls(host, allow_probe=True)

    assert len(urls) == 3
    assert (80, "http://192.168.56.103") in urls
    assert (3000, "http://192.168.56.103:3000") in urls
    assert (8443, "https://192.168.56.103:8443") in urls

def test_probe_failure_handled_gracefully(base_target):
    """
    Scenario 9: If safe probe encounters connection error or timeout on an ambiguous port,
    it must handle it gracefully, return (False, False), and not crash.
    """
    svc = Service(port=9999, protocol="tcp", state="open", name="unknown")
    host = Host(target=base_target, ipv4="192.168.56.103", open_ports=[svc])

    with patch("requests.get", side_effect=requests.exceptions.ConnectionError("Connection refused")):
        urls = build_http_urls(host, allow_probe=True)

    assert len(urls) == 0

    with patch("requests.get", side_effect=requests.exceptions.Timeout("Timeout")):
        urls = build_http_urls(host, allow_probe=True)

    assert len(urls) == 0

def test_assessment_context_recognizes_non_standard_ports(base_target):
    """
    Scenario 10: AssessmentContext.get_open_web_ports() and has_http_service()
    accurately recognize non-standard ports from http_results.
    """
    scan_result = ScanResult(
        target=base_target,
        hosts=[
            Host(
                target=base_target,
                ipv4="192.168.56.103",
                open_ports=[
                    Service(port=22, protocol="tcp", state="open", name="ssh"),
                    Service(port=80, protocol="tcp", state="open", name="http"),
                    Service(port=3000, protocol="tcp", state="open", name="ppp")
                ]
            )
        ]
    )

    http_results = [
        HttpResult(url="http://192.168.56.103", status_code=200),
        HttpResult(url="http://192.168.56.103:3000", status_code=200)
    ]

    context = AssessmentContext(
        target=base_target,
        scan_result=scan_result,
        http_results=http_results
    )

    assert context.has_http_service() is True
    web_ports = context.get_open_web_ports()
    assert 80 in web_ports
    assert 3000 in web_ports
    assert 22 not in web_ports
