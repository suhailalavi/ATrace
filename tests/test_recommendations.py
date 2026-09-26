import pytest
from alavitrace.core.models import HttpResult, Severity, Confidence
from alavitrace.analysis.recommendations import RecommendationEngine

def test_recommendation_engine_missing_headers():
    http_result = HttpResult(
        url="https://192.168.56.106",
        status_code=200,
        final_url="https://192.168.56.106",
        missing_security_headers=[
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security"
        ],
        server_header="Apache/2.4.41"
    )

    findings = RecommendationEngine.analyze_http_result(http_result)
    assert len(findings) == 5

    titles = [f.title for f in findings]
    assert "Missing X-Content-Type-Options Header" in titles
    assert "Missing Content-Security-Policy (CSP) Header" in titles
    assert "Missing X-Frame-Options Header" in titles
    assert "Missing Strict-Transport-Security (HSTS) Header" in titles
    assert "Detailed Server Version Disclosure" in titles

    # Verify severity and confidence
    csp_finding = next(f for f in findings if f.title == "Missing Content-Security-Policy (CSP) Header")
    assert csp_finding.severity == Severity.LOW
    assert csp_finding.confidence == Confidence.CONFIRMED

def test_recommendation_engine_http_redirect():
    http_result = HttpResult(
        url="http://192.168.56.106",
        status_code=200,
        final_url="https://192.168.56.106",
        redirect_chain=["http://192.168.56.106", "https://192.168.56.106"],
        missing_security_headers=[]
    )

    findings = RecommendationEngine.analyze_http_result(http_result)
    assert len(findings) == 1
    assert findings[0].title == "HTTP to HTTPS Redirection Enabled"
    assert findings[0].severity == Severity.INFO
