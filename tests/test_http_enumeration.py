import pytest
from unittest.mock import patch, MagicMock
import requests
from alavitrace.core.models import Target, Host, Service
from alavitrace.enumeration.http import build_http_urls, HttpEnumerator

def test_build_http_urls():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    host = Host(
        target=target,
        ipv4="192.168.56.106",
        open_ports=[
            Service(port=80, protocol="tcp", state="open", name="HTTP"),
            Service(port=443, protocol="tcp", state="open", name="HTTPS"),
            Service(port=8080, protocol="tcp", state="open", name="HTTP ALTERNATE"),
            Service(port=22, protocol="tcp", state="open", name="SSH"),
        ]
    )

    urls = build_http_urls(host)
    assert len(urls) == 3
    assert urls[0] == (80, "http://192.168.56.106")
    assert urls[1] == (443, "https://192.168.56.106")
    assert urls[2] == (8080, "http://192.168.56.106:8080")

def test_http_enumerator_success_200():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = "http://192.168.56.106"
    mock_resp.history = []
    mock_resp.content = b"<html>Test</html>"
    mock_resp.headers = {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
        "Content-Type": "text/html; charset=UTF-8",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY"
    }

    with patch("requests.get", return_value=mock_resp):
        enumerator = HttpEnumerator()
        result = enumerator.enumerate("http://192.168.56.106")

        assert result.url == "http://192.168.56.106"
        assert result.status_code == 200
        assert result.server_header == "Apache/2.4.41 (Ubuntu)"
        assert result.powered_by_header == "PHP/7.4.3"
        assert result.content_type == "text/html; charset=UTF-8"
        assert "X-Content-Type-Options" in result.security_headers
        assert "X-Frame-Options" in result.security_headers
        assert "Content-Security-Policy" in result.missing_security_headers
        assert result.error_message is None

def test_http_enumerator_redirect():
    mock_hist = MagicMock()
    mock_hist.url = "http://192.168.56.106"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = "https://192.168.56.106"
    mock_resp.history = [mock_hist]
    mock_resp.content = b"Redirected"
    mock_resp.headers = {"Server": "nginx"}

    with patch("requests.get", return_value=mock_resp):
        enumerator = HttpEnumerator()
        result = enumerator.enumerate("http://192.168.56.106")

        assert result.status_code == 200
        assert result.final_url == "https://192.168.56.106"
        assert result.redirect_chain == ["http://192.168.56.106", "https://192.168.56.106"]

def test_http_enumerator_timeout():
    with patch("requests.get", side_effect=requests.exceptions.Timeout()):
        enumerator = HttpEnumerator(timeout_seconds=1)
        result = enumerator.enumerate("http://192.168.56.106")

        assert result.url == "http://192.168.56.106"
        assert result.status_code is None
        assert "Request timed out" in result.error_message

def test_http_enumerator_connection_error():
    with patch("requests.get", side_effect=requests.exceptions.ConnectionError("Refused")):
        enumerator = HttpEnumerator()
        result = enumerator.enumerate("http://192.168.56.106")

        assert result.status_code is None
        assert "HTTP connection failed" in result.error_message
