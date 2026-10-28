import json
import pytest
from unittest.mock import patch, MagicMock

from alavitrace.core.models import (
    Target,
    Host,
    Service,
    ScanResult,
    HttpResult,
    Finding,
    Severity,
    Confidence
)
from alavitrace.assessment.models import (
    OwaspCategory,
    DetectionType,
    AssessmentContext,
    AssessmentResult,
    OWASPFinding
)
from alavitrace.assessment.base import BaseAssessmentCheck
from alavitrace.assessment.registry import CheckRegistry
from alavitrace.assessment.engine import (
    AssessmentEngine,
    generate_finding_fingerprint,
    deduplicate_findings
)
from alavitrace.analysis.prioritization import VulnerabilityPrioritizer
from alavitrace.reporting.json_report import generate_json_report
from alavitrace.reporting.markdown_report import generate_markdown_report
from alavitrace.reporting.html_report import generate_html_report
from alavitrace.ai.analyst import SecurityAnalyst

class MockHeaderCheck(BaseAssessmentCheck):
    category = OwaspCategory.A05_2021
    name = "MockHeaderCheck"
    description = "Generates mock CSP finding"
    detection_type = DetectionType.PASSIVE

    def check(self, context: AssessmentContext):
        return [
            OWASPFinding.create(
                id="OWASP-TEST-001",
                title="Missing Content-Security-Policy",
                owasp_category=OwaspCategory.A05_2021.value,
                severity=Severity.MEDIUM,
                confidence=Confidence.OBSERVED,
                description="CSP header is absent.",
                evidence="Content-Security-Policy header was missing",
                affected_asset="http://192.168.56.106",
                endpoint="http://192.168.56.106/",
                detection_type=DetectionType.PASSIVE.value
            )
        ]

class MockFailingCheck(BaseAssessmentCheck):
    category = OwaspCategory.A03_2021
    name = "MockFailingCheck"
    description = "Check that raises an unexpected exception"
    detection_type = DetectionType.ACTIVE

    def check(self, context: AssessmentContext):
        raise RuntimeError("Simulated network socket failure")

def test_engine_skips_when_http_unavailable():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    # Only FTP and SSH open - representative of Sunset lab target
    host = Host(
        target=target,
        ipv4="192.168.56.106",
        open_ports=[
            Service(port=21, protocol="tcp", state="open", name="ftp"),
            Service(port=22, protocol="tcp", state="open", name="ssh")
        ]
    )
    scan_result = ScanResult(target=target, hosts=[host])
    context = AssessmentContext(target=target, scan_result=scan_result, http_results=[])

    registry = CheckRegistry()
    registry.register(MockHeaderCheck())

    engine = AssessmentEngine(registry=registry)
    result = engine.execute(context)

    assert result.is_http_available is False
    assert result.findings == []
    assert result.executed_checks == []
    assert "No HTTP/HTTPS service detected" in result.message

def test_engine_executes_checks_when_http_available():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    host = Host(
        target=target,
        ipv4="192.168.56.106",
        open_ports=[Service(port=80, protocol="tcp", state="open", name="http")]
    )
    http_res = HttpResult(url="http://192.168.56.106", status_code=200)
    context = AssessmentContext(
        target=target,
        scan_result=ScanResult(target=target, hosts=[host]),
        http_results=[http_res]
    )

    registry = CheckRegistry()
    registry.register(MockHeaderCheck())

    engine = AssessmentEngine(registry=registry)
    result = engine.execute(context)

    assert result.is_http_available is True
    assert len(result.findings) == 1
    assert result.executed_checks == ["MockHeaderCheck"]
    assert result.findings[0].id == "OWASP-TEST-001"
    assert result.findings[0].owasp_category == OwaspCategory.A05_2021.value

def test_engine_handles_check_exception_gracefully():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    http_res = HttpResult(url="http://192.168.56.106", status_code=200)
    context = AssessmentContext(
        target=target,
        scan_result=ScanResult(target=target),
        http_results=[http_res]
    )

    registry = CheckRegistry()
    registry.register(MockHeaderCheck())
    registry.register(MockFailingCheck())

    engine = AssessmentEngine(registry=registry)
    result = engine.execute(context)

    assert result.is_http_available is True
    assert len(result.findings) == 1  # Header check succeeded
    assert "MockHeaderCheck" in result.executed_checks
    assert any("MockFailingCheck" in note for note in result.notes)

def test_finding_fingerprint_normalization():
    f1 = Finding(
        id="FIND-1",
        title="Missing Content-Security-Policy (CSP) Header",
        category="Web Security Configuration",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        description="Missing CSP",
        evidence="No CSP",
        affected_asset="http://192.168.56.106/"
    )
    f2 = OWASPFinding.create(
        id="OWASP-1",
        title="Missing Content-Security-Policy",
        owasp_category="A05:2021 - Security Misconfiguration",
        severity=Severity.MEDIUM,
        confidence=Confidence.OBSERVED,
        description="Missing CSP",
        evidence="No CSP",
        affected_asset="http://192.168.56.106",
        endpoint="http://192.168.56.106/"
    )

    fp1 = generate_finding_fingerprint(f1)
    fp2 = generate_finding_fingerprint(f2)

    # Both represent missing CSP at http://192.168.56.106 and should share a fingerprint
    assert fp1 == fp2

def test_deduplication_between_phase3_and_owasp():
    phase3_finding = Finding(
        id="FIND-SEC-HEADER-CSP-123456",
        title="Missing Content-Security-Policy (CSP) Header",
        category="Web Security Configuration",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        description="No CSP",
        evidence="No CSP found",
        affected_asset="http://192.168.56.106"
    )

    owasp_finding = OWASPFinding.create(
        id="OWASP-A05-001",
        title="Missing Content-Security-Policy",
        owasp_category="A05:2021 - Security Misconfiguration",
        severity=Severity.MEDIUM,
        confidence=Confidence.OBSERVED,
        description="No CSP",
        evidence="Content-Security-Policy missing",
        affected_asset="http://192.168.56.106",
        endpoint="http://192.168.56.106",
        detection_type="passive"
    )

    existing = [phase3_finding]
    new_findings = [owasp_finding]

    deduped = deduplicate_findings(new_findings, existing)

    # The duplicate should be suppressed from the new findings list
    assert len(deduped) == 0

    # And the existing finding is enriched with OWASP metadata
    assert phase3_finding.owasp_category == "A05:2021 - Security Misconfiguration"
    assert phase3_finding.detection_type == "passive"
    assert phase3_finding.endpoint == "http://192.168.56.106"

def test_prioritization_compatibility_with_owasp():
    prioritizer = VulnerabilityPrioritizer()

    owasp_finding = OWASPFinding.create(
        id="OWASP-TEST-001",
        title="Missing Content-Security-Policy",
        owasp_category="A05:2021 - Security Misconfiguration",
        severity=Severity.MEDIUM,
        confidence=Confidence.OBSERVED,
        description="No CSP header",
        evidence="Header missing (no CVSS)",
        affected_asset="http://192.168.56.106",
        endpoint="http://192.168.56.106/"
    )

    # 1. Test score calculation
    score, rationale = prioritizer.calculate_priority_score(owasp_finding)
    # Severity MEDIUM = 50, Confidence OBSERVED = 45, CVSS = 0, Exposed endpoint = 20 -> 115
    assert score == 115
    assert "CVSS 0.0: 0pts" in rationale

    # 2. Test prioritize list
    p_result = prioritizer.prioritize([owasp_finding], max_findings=5)
    assert len(p_result.prioritized_findings) == 1
    assert p_result.prioritized_findings[0].id == "OWASP-TEST-001"

def test_reporting_compatibility_with_owasp(tmp_path):
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    scan_result = ScanResult(target=target)
    owasp_finding = OWASPFinding.create(
        id="OWASP-TEST-001",
        title="Missing Content-Security-Policy",
        owasp_category="A05:2021 - Security Misconfiguration",
        severity=Severity.MEDIUM,
        confidence=Confidence.OBSERVED,
        description="No CSP",
        evidence="No CSP found",
        affected_asset="http://192.168.56.106",
        endpoint="http://192.168.56.106"
    )
    prioritization_result = VulnerabilityPrioritizer().prioritize([owasp_finding])
    owasp_result = AssessmentResult(
        is_http_available=True,
        findings=[owasp_finding],
        executed_checks=["MockHeaderCheck"],
        supported_categories=["A05:2021 - Security Misconfiguration"]
    )

    # 1. JSON Report
    json_path = generate_json_report(
        scan_result, [], prioritization_result, None,
        output_dir=str(tmp_path), owasp_result=owasp_result
    )
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "owasp_assessment" in data
    assert data["owasp_assessment"]["is_http_available"] is True
    assert len(data["owasp_assessment"]["findings"]) == 1

    # 2. Markdown Report
    md_path = generate_markdown_report(
        scan_result, [], prioritization_result, None,
        output_dir=str(tmp_path), owasp_result=owasp_result
    )
    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()
    assert "OWASP Web Security Assessment" in md_text
    assert "Missing Content-Security-Policy" in md_text

    # 3. HTML Report
    html_path = generate_html_report(
        scan_result, [], prioritization_result, None,
        output_dir=str(tmp_path), owasp_result=owasp_result
    )
    with open(html_path, "r", encoding="utf-8") as f:
        html_text = f.read()
    assert "OWASP Web Security Assessment" in html_text
    assert "Missing Content-Security-Policy" in html_text

def test_ai_input_serialization_with_owasp():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    scan_result = ScanResult(target=target)
    owasp_finding = OWASPFinding.create(
        id="OWASP-TEST-001",
        title="Missing Content-Security-Policy",
        owasp_category="A05:2021 - Security Misconfiguration",
        severity=Severity.MEDIUM,
        confidence=Confidence.OBSERVED,
        description="No CSP",
        evidence="No CSP found",
        affected_asset="http://192.168.56.106",
        endpoint="http://192.168.56.106"
    )
    prioritization_result = VulnerabilityPrioritizer().prioritize([owasp_finding])
    owasp_result = AssessmentResult(
        is_http_available=True,
        findings=[owasp_finding],
        executed_checks=["MockHeaderCheck"]
    )

    ai_input = SecurityAnalyst.prepare_structured_input(
        scan_result, [], prioritization_result, owasp_result=owasp_result
    )

    assert "owasp_assessment" in ai_input
    assert ai_input["owasp_assessment"]["enabled"] is True
    assert ai_input["owasp_assessment"]["findings_count"] == 1
    assert ai_input["owasp_assessment"]["findings"][0]["owasp_category"] == "A05:2021 - Security Misconfiguration"
