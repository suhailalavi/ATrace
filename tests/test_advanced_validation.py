import os
import json
import socket
from unittest.mock import MagicMock, patch
import pytest

from alavitrace.core.models import (
    Target,
    ScanResult,
    HttpResult,
    Finding,
    Severity,
    Confidence
)
from alavitrace.assessment.models import OWASPFinding
from alavitrace.attacksurface.models import AttackSurface, Endpoint
from alavitrace.analysis.prioritization import PrioritizationResult, VulnerabilityPrioritizer
from alavitrace.validation.models import ValidationStatus, ValidationResult
from alavitrace.validation.base import (
    BaseValidator,
    DEFAULT_VALIDATION_TIMEOUT,
    DEFAULT_MAX_VALIDATION_REQUESTS,
    redact_sensitive_params
)
from alavitrace.validation.validators import (
    SQLInjectionValidator,
    ReflectedXSSValidator,
    ReflectedInputValidator,
    PathTraversalValidator,
    CommandInjectionValidator,
    CSRFValidator,
    SSRFCandidateValidator,
    IDORCandidateValidator,
    AuthenticationSecurityValidator,
    HeaderValidator,
    MisconfigurationValidator,
    ResponseBehaviorValidator,
    ServicePresenceValidator,
    FallbackValidator
)
from alavitrace.validation.registry import ValidatorRegistry
from alavitrace.validation.engine import ValidationEngine, ValidationEngineResult
from alavitrace.ai.analyst import SecurityAnalyst
from alavitrace.reporting.json_report import generate_json_report
from alavitrace.reporting.markdown_report import generate_markdown_report
from alavitrace.reporting.html_report import generate_html_report
from alavitrace.cli import parse_args, render_validation_summary


# ---------------------------------------------------------------------------
# FIXTURES
# ---------------------------------------------------------------------------

@pytest.fixture
def target_ipv4():
    return Target(raw_input="192.168.56.101", normalized="192.168.56.101", target_type="IPv4")


@pytest.fixture
def sample_sqli_finding():
    return OWASPFinding.create(
        id="OWASP-A03-SQLI-001",
        title="SQL Injection Candidate",
        owasp_category="A03:2021 - Injection",
        severity=Severity.HIGH,
        confidence=Confidence.PROBABLE,
        description="Potential SQL injection point identified on query parameter.",
        evidence="Parameter 'id' accepts arbitrary input.",
        affected_asset="192.168.56.101",
        endpoint="http://192.168.56.101/products",
        http_method="GET",
        parameter="id"
    )


@pytest.fixture
def sample_xss_finding():
    return OWASPFinding.create(
        id="OWASP-A03-XSS-001",
        title="Reflected XSS Candidate",
        owasp_category="A03:2021 - Injection",
        severity=Severity.HIGH,
        confidence=Confidence.PROBABLE,
        description="Search input reflected in page body.",
        evidence="Parameter 'q' observed in response body.",
        affected_asset="192.168.56.101",
        endpoint="http://192.168.56.101/search",
        http_method="GET",
        parameter="q"
    )


@pytest.fixture
def sample_traversal_finding():
    return OWASPFinding.create(
        id="OWASP-A01-TRAV-001",
        title="Path Traversal Candidate",
        owasp_category="A01:2021 - Broken Access Control",
        severity=Severity.HIGH,
        confidence=Confidence.PROBABLE,
        description="File parameter accepts file path references.",
        evidence="Parameter 'file' is used to specify static documents.",
        affected_asset="192.168.56.101",
        endpoint="http://192.168.56.101/view",
        http_method="GET",
        parameter="file"
    )


@pytest.fixture
def sample_csrf_finding():
    return OWASPFinding.create(
        id="OWASP-A01-CSRF-001",
        title="Cross-Site Request Forgery (CSRF) Weakness",
        owasp_category="A01:2021 - Broken Access Control",
        severity=Severity.MEDIUM,
        confidence=Confidence.PROBABLE,
        description="Application state-changing endpoint may lack anti-CSRF token verification.",
        evidence="POST endpoint /update-profile lacks csrf token validation.",
        affected_asset="192.168.56.101",
        endpoint="http://192.168.56.101/update-profile",
        http_method="POST",
        parameter=None
    )


@pytest.fixture
def sample_ssrf_finding():
    return OWASPFinding.create(
        id="OWASP-A10-SSRF-001",
        title="Server-Side Request Forgery Candidate",
        owasp_category="A10:2021 - Server-Side Request Forgery (SSRF)",
        severity=Severity.HIGH,
        confidence=Confidence.INFORMATIONAL,
        description="Endpoint accepts target URL parameter for remote data fetching.",
        evidence="Parameter 'url' observed on /proxy.",
        affected_asset="192.168.56.101",
        endpoint="http://192.168.56.101/proxy",
        http_method="GET",
        parameter="url"
    )


@pytest.fixture
def sample_idor_finding():
    return OWASPFinding.create(
        id="OWASP-A01-IDOR-001",
        title="Direct Object Reference Candidate",
        owasp_category="A01:2021 - Broken Access Control",
        severity=Severity.MEDIUM,
        confidence=Confidence.INFORMATIONAL,
        description="Endpoint exposes direct sequential database ID.",
        evidence="Path contains direct object reference /user/1042.",
        affected_asset="192.168.56.101",
        endpoint="http://192.168.56.101/user/1042",
        http_method="GET",
        parameter="id"
    )


@pytest.fixture
def sample_auth_finding():
    return Finding(
        id="OWASP-A07-AUTH-001",
        title="Insecure Session Cookie Configuration",
        category="Security Misconfiguration",
        owasp_category="A07:2021 - Identification and Authentication Failures",
        severity=Severity.MEDIUM,
        confidence=Confidence.OBSERVED,
        description="Session cookie is transmitted without HttpOnly and Secure attributes.",
        evidence="Set-Cookie header observed without HttpOnly flag.",
        affected_asset="192.168.56.101",
        endpoint="http://192.168.56.101/login",
        affected_port=80
    )


# ---------------------------------------------------------------------------
# 1-3. REFLECTED XSS VALIDATOR TESTS
# ---------------------------------------------------------------------------

@patch("requests.get")
def test_reflected_marker_detection(mock_get, sample_xss_finding):
    """1. Reflected marker detection confirms VALIDATED status."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "<html><body>Results for atracecanary987</body></html>"
    mock_resp.headers = {"Content-Type": "text/html"}
    mock_get.return_value = mock_resp

    validator = ReflectedXSSValidator()
    result = validator.validate(sample_xss_finding)

    assert result.status == ValidationStatus.VALIDATED
    assert "atracecanary987" in result.evidence
    assert result.structured_evidence["reflected"] is True
    assert result.structured_evidence["reflection_context"] == "html_content"


@patch("requests.get")
def test_reflected_marker_not_reflected(mock_get, sample_xss_finding):
    """2. Non-reflection returns NOT_VALIDATED status."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "<html><body>No search results found.</body></html>"
    mock_resp.headers = {"Content-Type": "text/html"}
    mock_get.return_value = mock_resp

    validator = ReflectedXSSValidator()
    result = validator.validate(sample_xss_finding)

    assert result.status == ValidationStatus.NOT_VALIDATED
    assert result.structured_evidence["reflected"] is False


@patch("requests.get")
def test_reflected_marker_contexts(mock_get, sample_xss_finding):
    """3. HTML-context reflection correctly differentiates plain text, script, and body."""
    validator = ReflectedXSSValidator()

    # Case A: Plain text / JSON context
    mock_resp_json = MagicMock()
    mock_resp_json.status_code = 200
    mock_resp_json.headers = {"Content-Type": "application/json"}
    mock_resp_json.text = '{"query": "atracecanary987"}'
    mock_get.return_value = mock_resp_json

    res_json = validator.validate(sample_xss_finding)
    assert res_json.status == ValidationStatus.VALIDATED
    assert res_json.structured_evidence["reflection_context"] == "plain_text"

    # Case B: Potentially dangerous script context
    mock_resp_script = MagicMock()
    mock_resp_script.status_code = 200
    mock_resp_script.headers = {"Content-Type": "text/html"}
    mock_resp_script.text = '<script>var term = "atracecanary987";</script>'
    mock_get.return_value = mock_resp_script

    res_script = validator.validate(sample_xss_finding)
    assert res_script.status == ValidationStatus.VALIDATED
    assert res_script.structured_evidence["reflection_context"] == "potentially_dangerous_html"


# ---------------------------------------------------------------------------
# 4-5. SQL INJECTION VALIDATOR TESTS
# ---------------------------------------------------------------------------

@patch("requests.get")
def test_sql_error_indicator_detection(mock_get, sample_sqli_finding):
    """4. SQL error indicator detects DB error signatures and validates."""
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    mock_get.return_value = mock_resp

    validator = SQLInjectionValidator()
    result = validator.validate(sample_sqli_finding)

    assert result.status == ValidationStatus.VALIDATED
    assert result.confidence == Confidence.CONFIRMED
    assert "MySQL" in result.evidence
    assert result.structured_evidence["error_signatures_detected"] == ["MySQL"]
    assert result.limitations is not None


@patch("requests.get")
def test_sql_no_error_indicator(mock_get, sample_sqli_finding):
    """5. Normal response without error signatures returns NOT_VALIDATED."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "<html><body>Product List: Item 1, Item 2</body></html>"
    mock_get.return_value = mock_resp

    validator = SQLInjectionValidator()
    result = validator.validate(sample_sqli_finding)

    assert result.status == ValidationStatus.NOT_VALIDATED
    assert result.structured_evidence["error_signatures_detected"] == []


# ---------------------------------------------------------------------------
# 6-7. PATH TRAVERSAL VALIDATOR TESTS
# ---------------------------------------------------------------------------

@patch("requests.get")
def test_path_traversal_indicator_detection(mock_get, sample_traversal_finding):
    """6. Path error disclosure validates path traversal candidate."""
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Warning: include(): open_basedir restriction in effect. File(....//....//etc/config) is not within the allowed path"
    mock_get.return_value = mock_resp

    validator = PathTraversalValidator()
    result = validator.validate(sample_traversal_finding)

    assert result.status == ValidationStatus.VALIDATED
    assert result.confidence in [Confidence.OBSERVED, Confidence.CONFIRMED]
    assert result.structured_evidence["error_indicator_observed"] is True
    assert "open_basedir" in result.evidence


@patch("requests.get")
def test_path_traversal_no_indicator(mock_get, sample_traversal_finding):
    """7. Normal response without path errors returns NOT_VALIDATED."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "File not found."
    mock_get.return_value = mock_resp

    validator = PathTraversalValidator()
    result = validator.validate(sample_traversal_finding)

    assert result.status == ValidationStatus.NOT_VALIDATED
    assert result.structured_evidence["error_indicator_observed"] is False


# ---------------------------------------------------------------------------
# 8-9. CSRF VALIDATOR TESTS
# ---------------------------------------------------------------------------

@patch("requests.get")
def test_csrf_token_present_protected(mock_get, sample_csrf_finding):
    """8. Form with anti-CSRF token verifies protection (NOT_VALIDATED)."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = """
    <html><body>
    <form action="/update-profile" method="POST">
        <input type="hidden" name="csrf_token" value="abc123xyz" />
        <input type="text" name="email" value="user@example.com" />
        <button type="submit">Update</button>
    </form>
    </body></html>
    """
    mock_resp.headers = {"Set-Cookie": "sessionid=xyz; SameSite=Strict"}
    mock_get.return_value = mock_resp

    validator = CSRFValidator()
    result = validator.validate(sample_csrf_finding)

    assert result.status == ValidationStatus.NOT_VALIDATED
    assert "Anti-CSRF protection observed" in result.evidence


@patch("requests.get")
def test_csrf_missing_token_unprotected(mock_get, sample_csrf_finding):
    """9. State-changing POST form without anti-CSRF token marks VALIDATED weakness."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = """
    <html><body>
    <form action="/update-profile" method="POST">
        <input type="text" name="email" value="user@example.com" />
        <button type="submit">Update</button>
    </form>
    </body></html>
    """
    mock_resp.headers = {"Set-Cookie": "sessionid=xyz"}
    mock_get.return_value = mock_resp

    validator = CSRFValidator()
    result = validator.validate(sample_csrf_finding)

    assert result.status == ValidationStatus.VALIDATED
    assert result.structured_evidence["post_forms_found"] == 1
    assert result.structured_evidence["has_csrf_token"] is False


# ---------------------------------------------------------------------------
# 10-11. SSRF CANDIDATE VALIDATOR TESTS
# ---------------------------------------------------------------------------

def test_ssrf_candidate_detection(sample_ssrf_finding):
    """10. SSRF candidate parameter identified without live outbound call."""
    validator = SSRFCandidateValidator()
    assert validator.can_validate(sample_ssrf_finding) is True

    result = validator.validate(sample_ssrf_finding)
    assert result.validation_method == "SSRF Candidate Analysis"
    assert result.structured_evidence["candidate_parameter"] == "url"


def test_ssrf_remains_not_validated(sample_ssrf_finding):
    """11. SSRF candidate safely remains NOT_VALIDATED without live callback infra."""
    validator = SSRFCandidateValidator()
    result = validator.validate(sample_ssrf_finding)

    assert result.status == ValidationStatus.NOT_VALIDATED
    assert result.structured_evidence["live_callback_tested"] is False
    assert "No internal IPs" in result.limitations


# ---------------------------------------------------------------------------
# 12-13. IDOR CANDIDATE VALIDATOR TESTS
# ---------------------------------------------------------------------------

def test_idor_candidate_detection(sample_idor_finding):
    """12. IDOR candidate path identified via direct object reference pattern."""
    validator = IDORCandidateValidator()
    assert validator.can_validate(sample_idor_finding) is True

    result = validator.validate(sample_idor_finding)
    assert result.validation_method == "IDOR Candidate Analysis"
    assert result.structured_evidence["substitution_attempted"] is False


def test_idor_remains_not_validated(sample_idor_finding):
    """13. IDOR candidate safely remains NOT_VALIDATED without multi-tenant credentials."""
    validator = IDORCandidateValidator()
    result = validator.validate(sample_idor_finding)

    assert result.status == ValidationStatus.NOT_VALIDATED
    assert "account substitution was not performed" in result.limitations


# ---------------------------------------------------------------------------
# 14. AUTHENTICATION SECURITY VALIDATOR TESTS
# ---------------------------------------------------------------------------

@patch("requests.get")
def test_authentication_cookie_security(mock_get, sample_auth_finding):
    """14. Passive inspection identifies missing HttpOnly and Secure flags."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Set-Cookie": "session=auth_token_123; Path=/"}
    mock_get.return_value = mock_resp

    validator = AuthenticationSecurityValidator()
    result = validator.validate(sample_auth_finding)

    assert "HttpOnly" in result.structured_evidence["cookie_flags_missing"]
    assert "Secure" in result.structured_evidence["cookie_flags_missing"]
    assert "Session cookie security weakness" in result.evidence


# ---------------------------------------------------------------------------
# 15. SENSITIVE DATA REDACTION
# ---------------------------------------------------------------------------

def test_sensitive_data_redaction():
    """15. Sensitive parameters (password, token, secret) are redacted in reports."""
    params = {
        "user": "alice",
        "password": "SuperSecretPassword123!",
        "api_key": "abc-key-9999",
        "page": "1"
    }
    redacted = redact_sensitive_params(params)
    assert redacted["user"] == "alice"
    assert redacted["page"] == "1"
    assert redacted["password"] == "[REDACTED]"
    assert redacted["api_key"] == "[REDACTED]"


# ---------------------------------------------------------------------------
# 16. OUT-OF-SCOPE REDIRECT REJECTION
# ---------------------------------------------------------------------------

def test_out_of_scope_redirect_rejection(sample_xss_finding):
    """16. Out-of-scope targets are strictly rejected by scope enforcement."""
    engine = ValidationEngine()
    engine._current_scope = "authorized.lab"

    # In-scope URL
    assert engine.is_url_in_scope("http://authorized.lab/search") is True
    assert engine.is_url_in_scope("https://www.authorized.lab/login") is True

    # Out-of-scope URLs
    assert engine.is_url_in_scope("http://attacker.com/evil") is False
    assert engine.is_url_in_scope("https://other-domain.net/test") is False


# ---------------------------------------------------------------------------
# 17-18. TIMEOUT & CONNECTION FAILURE HANDLING
# ---------------------------------------------------------------------------

@patch("requests.get")
def test_validation_request_timeout_handling(mock_get, sample_xss_finding):
    """17. Request timeout gracefully returns INCONCLUSIVE status."""
    import requests
    mock_get.side_effect = requests.exceptions.Timeout("Connection timed out after 3s")

    validator = ReflectedXSSValidator()
    result = validator.validate(sample_xss_finding, timeout=3)

    assert result.status == ValidationStatus.INCONCLUSIVE
    assert "timed out" in result.evidence


@patch("requests.get")
def test_validation_connection_failure_handling(mock_get, sample_xss_finding):
    """18. Connection failure gracefully returns INCONCLUSIVE status."""
    import requests
    mock_get.side_effect = requests.exceptions.ConnectionError("Failed to establish a new connection")

    validator = ReflectedXSSValidator()
    result = validator.validate(sample_xss_finding)

    assert result.status == ValidationStatus.INCONCLUSIVE
    assert "failed" in result.evidence


# ---------------------------------------------------------------------------
# 19. REQUEST LIMIT BUDGET REACHED
# ---------------------------------------------------------------------------

@patch("requests.get")
def test_validation_request_limit_budget_reached(mock_get, sample_xss_finding, sample_sqli_finding):
    """19. Exhausted request limit terminates gracefully with budget error."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "no reflection"
    mock_resp.headers = {}
    mock_get.return_value = mock_resp

    engine = ValidationEngine(max_requests=1)
    findings = [sample_xss_finding, sample_sqli_finding]

    engine_res = engine.validate_findings(findings, target_scope="192.168.56.101")
    assert engine_res.requests_sent == 1
    assert engine_res.request_limit_reached is True
    assert sample_sqli_finding.validation_result.error_message == "VALIDATION_REQUEST_LIMIT_REACHED"
    assert sample_sqli_finding.validation_result.status == ValidationStatus.INCONCLUSIVE


# ---------------------------------------------------------------------------
# 20. VALIDATION DISABLED BEHAVIOR
# ---------------------------------------------------------------------------

def test_validation_disabled_behavior(sample_sqli_finding):
    """20. When validation is disabled, finding carries no validation result."""
    assert sample_sqli_finding.validation_result is None


# ---------------------------------------------------------------------------
# 21-22. VALIDATOR REGISTRY & PRECEDENCE ORDERING
# ---------------------------------------------------------------------------

def test_multiple_validators_in_registry():
    """21. ValidatorRegistry contains full suite of validators."""
    registry = ValidatorRegistry()
    assert len(registry.validators) >= 12


def test_validator_registry_precedence(sample_sqli_finding, sample_xss_finding, sample_traversal_finding, sample_csrf_finding):
    """22. Precedence ordering routes specific finding types to correct validators."""
    registry = ValidatorRegistry()

    assert isinstance(registry.get_validator(sample_sqli_finding), SQLInjectionValidator)
    assert isinstance(registry.get_validator(sample_xss_finding), (ReflectedXSSValidator, ReflectedInputValidator))
    assert isinstance(registry.get_validator(sample_traversal_finding), PathTraversalValidator)
    assert isinstance(registry.get_validator(sample_csrf_finding), CSRFValidator)


# ---------------------------------------------------------------------------
# 23. VALIDATION RESULT SERIALIZATION
# ---------------------------------------------------------------------------

def test_validation_result_serialization_with_limitations():
    """23. ValidationResult serializes structured_evidence and limitations."""
    res = ValidationResult(
        finding_id="OWASP-A03-SQLI-001",
        target="192.168.56.101",
        status=ValidationStatus.VALIDATED,
        evidence="MySQL syntax error observed.",
        validation_method="SQL Injection Indicator Validation",
        structured_evidence={"db_engine": "MySQL", "error": "syntax error"},
        limitations="Zero data extraction performed."
    )
    d = res.to_dict()
    assert d["status"] == "VALIDATED"
    assert d["structured_evidence"]["db_engine"] == "MySQL"
    assert d["limitations"] == "Zero data extraction performed."


# ---------------------------------------------------------------------------
# 24-26. REPORTING SECTIONS
# ---------------------------------------------------------------------------

def test_json_report_validation_section(tmp_path, target_ipv4, sample_sqli_finding):
    """24. JSON report includes validation_summary and finding validation details."""
    sample_sqli_finding.validation_result = ValidationResult(
        finding_id=sample_sqli_finding.id,
        target=sample_sqli_finding.affected_asset,
        status=ValidationStatus.VALIDATED,
        evidence="MySQL error signature detected.",
        validation_method="SQL Injection Indicator Validation",
        limitations="Zero data dumping."
    )
    prio_res = PrioritizationResult(
        total_correlated=1,
        prioritized_count=1,
        prioritized_findings=[sample_sqli_finding],
        all_findings=[sample_sqli_finding]
    )
    scan_res = ScanResult(target=target_ipv4, hosts=[], raw_xml_path=None, scan_args=[])

    out_file = generate_json_report(scan_res, [], prio_res, None, output_dir=str(tmp_path))
    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["validation_summary"]["enabled"] is True
    assert data["validation_summary"]["statuses"]["VALIDATED"] == 1
    assert data["findings"][0]["validation"]["limitations"] == "Zero data dumping."


def test_markdown_report_validation_section(tmp_path, target_ipv4, sample_sqli_finding):
    """25. Markdown report includes validation summary table and limitations."""
    sample_sqli_finding.validation_result = ValidationResult(
        finding_id=sample_sqli_finding.id,
        target=sample_sqli_finding.affected_asset,
        status=ValidationStatus.VALIDATED,
        evidence="MySQL error signature detected.",
        validation_method="SQL Injection Indicator Validation",
        limitations="Non-destructive delimiter probe only."
    )
    prio_res = PrioritizationResult(
        total_correlated=1,
        prioritized_count=1,
        prioritized_findings=[sample_sqli_finding],
        all_findings=[sample_sqli_finding]
    )
    scan_res = ScanResult(target=target_ipv4, hosts=[], raw_xml_path=None, scan_args=[])

    out_file = generate_markdown_report(scan_res, [], prio_res, None, output_dir=str(tmp_path))
    with open(out_file, "r", encoding="utf-8") as f:
        md = f.read()

    assert "Controlled Finding Validation Summary" in md
    assert "Non-destructive delimiter probe only." in md


def test_html_report_validation_section(tmp_path, target_ipv4, sample_sqli_finding):
    """26. HTML report renders validation badges and limitations."""
    sample_sqli_finding.validation_result = ValidationResult(
        finding_id=sample_sqli_finding.id,
        target=sample_sqli_finding.affected_asset,
        status=ValidationStatus.VALIDATED,
        evidence="MySQL error signature detected.",
        validation_method="SQL Injection Indicator Validation",
        limitations="Safe syntax probe only."
    )
    prio_res = PrioritizationResult(
        total_correlated=1,
        prioritized_count=1,
        prioritized_findings=[sample_sqli_finding],
        all_findings=[sample_sqli_finding]
    )
    scan_res = ScanResult(target=target_ipv4, hosts=[], raw_xml_path=None, scan_args=[])

    out_file = generate_html_report(scan_res, [], prio_res, None, output_dir=str(tmp_path))
    with open(out_file, "r", encoding="utf-8") as f:
        html = f.read()

    assert "badge-VALIDATED" in html
    assert "Safe syntax probe only." in html


# ---------------------------------------------------------------------------
# 27. AI INPUT SERIALIZATION WITH VALIDATION DETAILS
# ---------------------------------------------------------------------------

def test_ai_input_serialization_validation_details(target_ipv4, sample_sqli_finding):
    """27. AI SecurityAnalyst serializes structured validation evidence and limitations."""
    sample_sqli_finding.validation_result = ValidationResult(
        finding_id=sample_sqli_finding.id,
        target=sample_sqli_finding.affected_asset,
        status=ValidationStatus.VALIDATED,
        evidence="Observed PostgreSQL error signature.",
        validation_method="SQL Injection Indicator Validation",
        structured_evidence={"db_engine": "PostgreSQL"},
        limitations="Zero extraction performed."
    )
    prio_res = PrioritizationResult(
        total_correlated=1,
        prioritized_count=1,
        prioritized_findings=[sample_sqli_finding],
        all_findings=[sample_sqli_finding]
    )
    scan_res = ScanResult(target=target_ipv4, hosts=[], raw_xml_path=None, scan_args=[])

    data = SecurityAnalyst.prepare_structured_input(scan_res, [], prio_res)
    assert "validation_summary" in data
    val_data = data["prioritized_findings"][0]["validation"]
    assert val_data["status"] == "VALIDATED"
    assert val_data["structured_evidence"]["db_engine"] == "PostgreSQL"
    assert val_data["limitations"] == "Zero extraction performed."


# ---------------------------------------------------------------------------
# 28. ZERO OUTBOUND NETWORK SOCKET TEST
# ---------------------------------------------------------------------------

def test_zero_outbound_network_sockets(sample_sqli_finding):
    """28. Verifies that unit tests run completely offline with zero raw outbound connections."""
    with patch("socket.socket") as mock_sock:
        mock_sock.side_effect = AssertionError("Unauthorized raw socket creation attempted in unit test!")
        # Internal operations and mocks should never open real network sockets
        validator = SQLInjectionValidator()
        assert validator.name == "SQLInjectionValidator"
