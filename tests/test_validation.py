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
from alavitrace.analysis.prioritization import PrioritizationResult
from alavitrace.validation.models import ValidationStatus, ValidationResult
from alavitrace.validation.base import (
    BaseValidator,
    DEFAULT_VALIDATION_TIMEOUT,
    DEFAULT_MAX_VALIDATION_REQUESTS
)
from alavitrace.validation.validators import (
    HeaderValidator,
    ResponseBehaviorValidator,
    ReflectedInputValidator,
    MisconfigurationValidator,
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
def mock_target():
    return Target(raw_input="192.168.56.101", normalized="192.168.56.101", target_type="IPv4")

@pytest.fixture
def mock_scan_result(mock_target):
    return ScanResult(target=mock_target, hosts=[])

@pytest.fixture
def sample_header_finding():
    return Finding(
        id="REC-HTTP-001",
        title="Missing Strict-Transport-Security Header",
        category="Deterministic Security Recommendations",
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        description="The HTTP response does not include the HSTS security header.",
        evidence="Header 'Strict-Transport-Security' missing from response.",
        affected_asset="192.168.56.101",
        affected_port=80,
        endpoint="http://192.168.56.101:80/"
    )

@pytest.fixture
def sample_reflection_finding():
    return OWASPFinding.create(
        id="OWASP-A03-REFL-001",
        title="Reflected Parameter Candidate",
        owasp_category="A03:2021 - Injection",
        severity=Severity.HIGH,
        confidence=Confidence.PROBABLE,
        description="Search parameter input reflected in page body.",
        evidence="Parameter 'q' observed reflecting input.",
        affected_asset="192.168.56.101",
        endpoint="http://192.168.56.101/search",
        parameter="q"
    )

@pytest.fixture
def sample_misconfig_finding():
    return Finding(
        id="OWASP-A05-DIR-001",
        title="Directory Listing Enabled",
        category="Security Misconfiguration",
        severity=Severity.MEDIUM,
        confidence=Confidence.OBSERVED,
        description="Directory browsing is permitted on the web server.",
        evidence="Endpoint /uploads/ discloses directory listing.",
        affected_asset="192.168.56.101",
        endpoint="http://192.168.56.101/uploads/"
    )

@pytest.fixture
def sample_cve_finding():
    return Finding(
        id="CVE-2021-41773",
        title="CVE-2021-41773 - Apache HTTP Server Path Traversal",
        category="Vulnerability Intelligence",
        severity=Severity.CRITICAL,
        confidence=Confidence.PROBABLE,
        description="Path traversal flaw in Apache 2.4.49.",
        evidence="Observed Apache 2.4.49 on port 80 (CVSS 9.8).",
        affected_asset="192.168.56.101",
        affected_port=80,
        affected_service="http"
    )

# ---------------------------------------------------------------------------
# MODEL TESTS
# ---------------------------------------------------------------------------

def test_validation_status_enum():
    assert ValidationStatus.VALIDATED.value == "VALIDATED"
    assert ValidationStatus.NOT_VALIDATED.value == "NOT_VALIDATED"
    assert ValidationStatus.INCONCLUSIVE.value == "INCONCLUSIVE"
    assert ValidationStatus.NOT_APPLICABLE.value == "NOT_APPLICABLE"
    assert ValidationStatus.ERROR.value == "ERROR"

def test_validation_result_serialization():
    res = ValidationResult(
        finding_id="F-01",
        target="192.168.56.101",
        port=80,
        service="HTTP",
        vulnerability_id="CVE-2021-41773",
        owasp_category="A06:2021 - Vulnerable Components",
        status=ValidationStatus.VALIDATED,
        confidence=Confidence.CONFIRMED,
        evidence="Port 80 confirmed open and responsive.",
        validation_method="Non-Destructive TCP Service Handshake"
    )
    d = res.to_dict()
    assert d["finding_id"] == "F-01"
    assert d["target"] == "192.168.56.101"
    assert d["status"] == "VALIDATED"
    assert d["confidence"] == "Confirmed"
    assert "evidence" in d
    assert d["validation_method"] == "Non-Destructive TCP Service Handshake"

def test_finding_carries_validation_result(sample_header_finding):
    assert sample_header_finding.validation_result is None
    res = ValidationResult(
        finding_id=sample_header_finding.id,
        target=sample_header_finding.affected_asset,
        status=ValidationStatus.VALIDATED,
        evidence="Header confirmed missing."
    )
    sample_header_finding.validation_result = res
    assert sample_header_finding.validation_result.status == ValidationStatus.VALIDATED

def test_owasp_finding_to_dict_includes_validation(sample_reflection_finding):
    res = ValidationResult(
        finding_id=sample_reflection_finding.id,
        target=sample_reflection_finding.affected_asset,
        status=ValidationStatus.VALIDATED,
        evidence="Canary reflection observed."
    )
    sample_reflection_finding.validation_result = res
    d = sample_reflection_finding.to_dict()
    assert "validation" in d
    assert d["validation"]["status"] == "VALIDATED"

# ---------------------------------------------------------------------------
# REGISTRY TESTS
# ---------------------------------------------------------------------------

def test_validator_registry_dispatch(sample_header_finding, sample_reflection_finding, sample_misconfig_finding, sample_cve_finding):
    registry = ValidatorRegistry()
    assert isinstance(registry.get_validator(sample_header_finding), HeaderValidator)
    assert isinstance(registry.get_validator(sample_reflection_finding), ReflectedInputValidator)
    assert isinstance(registry.get_validator(sample_misconfig_finding), MisconfigurationValidator)
    assert isinstance(registry.get_validator(sample_cve_finding), ServicePresenceValidator)

    # Unknown finding category falls back to FallbackValidator
    unknown_finding = Finding(
        id="UNK-01",
        title="Theoretical Flaw",
        category="General",
        severity=Severity.LOW,
        confidence=Confidence.POTENTIAL,
        description="N/A",
        evidence="N/A",
        affected_asset="192.168.56.101"
    )
    assert isinstance(registry.get_validator(unknown_finding), FallbackValidator)

# ---------------------------------------------------------------------------
# VALIDATOR UNIT TESTS (MOCKED NETWORK)
# ---------------------------------------------------------------------------

@patch("requests.get")
def test_header_validator_still_missing_validated(mock_get, sample_header_finding):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Server": "Apache/2.4.41", "Content-Type": "text/html"}
    mock_get.return_value = mock_resp

    validator = HeaderValidator()
    result = validator.validate(sample_header_finding, timeout=2)

    assert result.status == ValidationStatus.VALIDATED
    assert "Strict-Transport-Security" in result.evidence
    assert result.confidence == Confidence.CONFIRMED

@patch("requests.get")
def test_header_validator_now_present_not_validated(mock_get, sample_header_finding):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}
    mock_get.return_value = mock_resp

    validator = HeaderValidator()
    result = validator.validate(sample_header_finding, timeout=2)

    assert result.status == ValidationStatus.NOT_VALIDATED
    assert "observed present" in result.evidence

@patch("requests.get")
def test_header_validator_timeout_inconclusive(mock_get, sample_header_finding):
    import requests
    mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")

    validator = HeaderValidator()
    result = validator.validate(sample_header_finding, timeout=2)

    assert result.status == ValidationStatus.INCONCLUSIVE
    assert "timed out" in result.error_message

@patch("requests.get")
def test_reflected_input_validator_canary_reflected(mock_get, sample_reflection_finding):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    # Include the canary token in body
    mock_resp.text = "<html><body>Results for atracecanary987</body></html>"
    mock_get.return_value = mock_resp

    validator = ReflectedInputValidator()
    result = validator.validate(sample_reflection_finding, timeout=2)

    assert result.status == ValidationStatus.VALIDATED
    assert "atracecanary987" in result.evidence
    # Verify request query parameter was safe
    mock_get.assert_called_once()
    _, kwargs = mock_get.call_args
    assert kwargs["params"] == {"q": "atracecanary987"}

@patch("requests.get")
def test_reflected_input_validator_canary_not_reflected(mock_get, sample_reflection_finding):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "<html><body>No search results found.</body></html>"
    mock_get.return_value = mock_resp

    validator = ReflectedInputValidator()
    result = validator.validate(sample_reflection_finding, timeout=2)

    assert result.status == ValidationStatus.NOT_VALIDATED

@patch("requests.get")
def test_misconfiguration_validator_directory_listing_found(mock_get, sample_misconfig_finding):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1></body></html>"
    mock_get.return_value = mock_resp

    validator = MisconfigurationValidator()
    result = validator.validate(sample_misconfig_finding, timeout=2)

    assert result.status == ValidationStatus.VALIDATED
    assert "Directory listing signature confirmed" in result.evidence

@patch("requests.request")
def test_misconfiguration_validator_trace_method_accepted(mock_request):
    finding = Finding(
        id="A05-TRACE",
        title="HTTP TRACE Method Enabled",
        category="Security Misconfiguration",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        description="Server responds to TRACE requests.",
        evidence="TRACE method enabled.",
        affected_asset="192.168.56.101"
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_request.return_value = mock_resp

    validator = MisconfigurationValidator()
    result = validator.validate(finding, timeout=2)

    assert result.status == ValidationStatus.VALIDATED
    assert "status 200 OK" in result.evidence

@patch("socket.socket")
def test_service_presence_validator_port_open(mock_socket_cls, sample_cve_finding):
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = 0  # 0 indicates connection succeeded
    mock_socket_cls.return_value = mock_sock

    validator = ServicePresenceValidator()
    result = validator.validate(sample_cve_finding, timeout=2)

    assert result.status == ValidationStatus.VALIDATED
    assert "confirmed actively open" in result.evidence
    mock_sock.connect_ex.assert_called_once_with(("192.168.56.101", 80))

@patch("socket.socket")
def test_service_presence_validator_port_closed(mock_socket_cls, sample_cve_finding):
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = 111  # ECONNREFUSED
    mock_socket_cls.return_value = mock_sock

    validator = ServicePresenceValidator()
    result = validator.validate(sample_cve_finding, timeout=2)

    assert result.status == ValidationStatus.NOT_VALIDATED
    assert "not reachable" in result.evidence

def test_fallback_validator():
    f = Finding(
        id="RCE-001",
        title="Remote Code Execution",
        category="Remote Exploit",
        severity=Severity.CRITICAL,
        confidence=Confidence.POTENTIAL,
        description="N/A",
        evidence="N/A",
        affected_asset="192.168.56.101"
    )
    validator = FallbackValidator()
    res = validator.validate(f)
    assert res.status == ValidationStatus.NOT_APPLICABLE
    assert "Non-Destructive Policy" in res.validation_method

# ---------------------------------------------------------------------------
# VALIDATION ENGINE TESTS
# ---------------------------------------------------------------------------

@patch("socket.socket")
@patch("requests.get")
def test_validation_engine_execution(mock_get, mock_socket_cls, sample_header_finding, sample_cve_finding):
    # Mock header response
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Server": "Apache"}
    mock_get.return_value = mock_resp

    # Mock socket
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = 0
    mock_socket_cls.return_value = mock_sock

    engine = ValidationEngine()
    findings = [sample_header_finding, sample_cve_finding]
    result = engine.validate_findings(findings, target_scope="192.168.56.101")

    assert isinstance(result, ValidationEngineResult)
    assert result.total_candidates == 2
    assert result.validated_count == 2
    assert sample_header_finding.validation_result.status == ValidationStatus.VALIDATED
    assert sample_cve_finding.validation_result.status == ValidationStatus.VALIDATED

def test_validation_engine_scope_filtering(sample_header_finding):
    # Scope mismatch: authorized is 10.0.0.1, finding is on 192.168.56.101
    engine = ValidationEngine()
    result = engine.validate_findings([sample_header_finding], target_scope="10.0.0.1")

    assert result.not_applicable_count == 1
    assert sample_header_finding.validation_result.status == ValidationStatus.NOT_APPLICABLE
    assert "scope boundary" in sample_header_finding.validation_result.evidence

# ---------------------------------------------------------------------------
# AI INTEGRATION & SERIALIZATION
# ---------------------------------------------------------------------------

def test_ai_analyst_serializes_validation_results(mock_scan_result, sample_header_finding):
    res = ValidationResult(
        finding_id=sample_header_finding.id,
        target=sample_header_finding.affected_asset,
        status=ValidationStatus.VALIDATED,
        evidence="Confirmed HSTS header absent from response.",
        validation_method="Fresh HTTP Header Inspection"
    )
    sample_header_finding.validation_result = res

    prio_result = PrioritizationResult(
        total_correlated=1,
        prioritized_count=1,
        prioritized_findings=[sample_header_finding],
        all_findings=[sample_header_finding]
    )

    analyst = SecurityAnalyst(provider=MagicMock())
    payload = analyst.prepare_structured_input(mock_scan_result, [], prio_result)

    assert "validation_summary" in payload
    assert payload["validation_summary"]["total_candidates"] == 1
    assert payload["validation_summary"]["statuses"]["VALIDATED"] == 1

    finding_entry = payload["prioritized_findings"][0]
    assert "validation" in finding_entry
    assert finding_entry["validation"]["status"] == "VALIDATED"
    assert finding_entry["validation"]["method"] == "Fresh HTTP Header Inspection"

# ---------------------------------------------------------------------------
# REPORTING TESTS
# ---------------------------------------------------------------------------

def test_reports_with_validation_results(tmp_path, mock_scan_result, sample_header_finding):
    res = ValidationResult(
        finding_id=sample_header_finding.id,
        target=sample_header_finding.affected_asset,
        status=ValidationStatus.VALIDATED,
        evidence="Confirmed HSTS header absent.",
        validation_method="Fresh HTTP Header Inspection"
    )
    sample_header_finding.validation_result = res

    prio_result = PrioritizationResult(
        total_correlated=1,
        prioritized_count=1,
        prioritized_findings=[sample_header_finding],
        all_findings=[sample_header_finding]
    )

    out_dir = str(tmp_path)

    # 1. JSON Report
    json_path = generate_json_report(mock_scan_result, [], prio_result, None, output_dir=out_dir)
    assert os.path.exists(json_path)
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "validation_summary" in data
    assert data["validation_summary"]["enabled"] is True
    assert data["findings"][0]["validation"]["status"] == "VALIDATED"

    # 2. Markdown Report
    md_path = generate_markdown_report(mock_scan_result, [], prio_result, None, output_dir=out_dir)
    assert os.path.exists(md_path)
    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()
    assert "Controlled Finding Validation Summary (Phase 9)" in md_text
    assert "VALIDATED" in md_text

    # 3. HTML Report
    html_path = generate_html_report(mock_scan_result, [], prio_result, None, output_dir=out_dir)
    assert os.path.exists(html_path)
    with open(html_path, "r", encoding="utf-8") as f:
        html_text = f.read()
    assert "badge-VALIDATED" in html_text
    assert "Validation Status" in html_text

# ---------------------------------------------------------------------------
# CLI ARGUMENT TESTS
# ---------------------------------------------------------------------------

def test_cli_validate_arguments():
    args = parse_args(["-t", "192.168.56.101", "--validate", "--validation-timeout", "3", "--max-validation-requests", "5"])
    assert args.validate is True
    assert args.validation_timeout == 3
    assert args.max_validation_requests == 5

def test_cli_default_validate_flag_is_false():
    args = parse_args(["-t", "192.168.56.101"])
    assert args.validate is False
    assert args.validation_timeout == 5
    assert args.max_validation_requests == 10

def test_render_validation_summary_output(capsys):
    engine_result = ValidationEngineResult(total_candidates=1)
    res = ValidationResult(
        finding_id="REC-001",
        target="192.168.56.101",
        status=ValidationStatus.VALIDATED,
        evidence="Header missing.",
        validation_method="Fresh HTTP Header Inspection"
    )
    engine_result.results["REC-001"] = res

    render_validation_summary(engine_result)
    captured = capsys.readouterr()
    assert "CONTROLLED FINDING VALIDATION (PHASE 9)" in captured.out
    assert "VALIDATED: 1" in captured.out
    assert "REC-001" in captured.out

# ---------------------------------------------------------------------------
# ZERO OUTBOUND NETWORK SOCKET SAFETY INTERCEPTOR
# ---------------------------------------------------------------------------

def test_zero_outbound_network_calls_during_unit_tests():
    """
    Verifies that all validation unit tests operate strictly offline via mocks
    and do not attempt real socket connections to external networks.
    """
    real_connect = socket.socket.connect

    def blocked_connect(self, *args, **kwargs):
        raise AssertionError("Unauthorized outbound network connection attempted during test!")

    with patch.object(socket.socket, "connect", blocked_connect):
        # Instantiate validators and execute offline check
        v = FallbackValidator()
        res = v.validate(Finding(
            id="T-01",
            title="Offline Check",
            category="Test",
            severity=Severity.INFO,
            confidence=Confidence.INFORMATIONAL,
            description="N/A",
            evidence="N/A",
            affected_asset="127.0.0.1"
        ))
        assert res.status == ValidationStatus.NOT_APPLICABLE
