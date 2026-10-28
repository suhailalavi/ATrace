import os
import json
import pytest
from alavitrace.core.models import Target, Host, Service, ScanResult, Finding, Severity, Confidence, HttpResult
from alavitrace.ai.models import AIAnalysisResult
from alavitrace.reporting.json_report import generate_json_report
from alavitrace.reporting.markdown_report import generate_markdown_report
from alavitrace.reporting.html_report import generate_html_report

@pytest.fixture
def sample_scan_data(tmp_path):
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    host = Host(
        target=target,
        ipv4="192.168.56.106",
        state="up",
        open_ports=[Service(port=22, protocol="tcp", state="open", name="SSH", product="OpenSSH", version="7.9p1")]
    )
    scan_result = ScanResult(target=target, hosts=[host])

    http_results = [
        HttpResult(
            url="http://192.168.56.106",
            status_code=200,
            server_header="Apache/2.4.41",
            missing_security_headers=["Content-Security-Policy"]
        )
    ]

    findings = [
        Finding(
            id="FIND-TEST-001",
            title="Known CVE Associated with OpenSSH 7.9p1 (CVE-2019-6111)",
            category="Vulnerability Intelligence",
            severity=Severity.MEDIUM,
            confidence=Confidence.PROBABLE,
            description="OpenSSH flaw.",
            evidence="Service OpenSSH 7.9p1 matched CVE-2019-6111.",
            affected_asset="192.168.56.106",
            recommendation="Review advisory."
        )
    ]

    ai_analysis = AIAnalysisResult(
        executive_summary="Target has 1 open SSH service.",
        attack_surface_summary="Port 22 SSH exposed.",
        key_observations=["OpenSSH 7.9p1 detected."],
        investigation_priorities=["Check OpenSSH patch status."],
        remediation_summary=["Apply vendor patch."],
        limitations=["Reconnaissance only."]
    )

    return scan_result, http_results, findings, ai_analysis

def test_json_report_generation(tmp_path, sample_scan_data):
    scan_result, http_results, findings, ai_analysis = sample_scan_data
    filepath = generate_json_report(scan_result, http_results, findings, ai_analysis, output_dir=str(tmp_path))

    assert os.path.exists(filepath)
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["metadata"]["target"] == "192.168.56.106"
    assert len(data["reconnaissance"]["hosts"]) == 1
    assert data["reconnaissance"]["hosts"][0]["open_ports"][0]["product"] == "OpenSSH"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["id"] == "FIND-TEST-001"
    assert data["ai_analysis"]["executive_summary"] == "Target has 1 open SSH service."

def test_markdown_report_generation(tmp_path, sample_scan_data):
    scan_result, http_results, findings, ai_analysis = sample_scan_data
    filepath = generate_markdown_report(scan_result, http_results, findings, ai_analysis, output_dir=str(tmp_path))

    assert os.path.exists(filepath)
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    assert "# AlaviTrace Security Assessment Report" in content
    assert "`192.168.56.106`" in content
    assert "OpenSSH" in content
    assert "CVE-2019-6111" in content
    assert "Target has 1 open SSH service." in content

def test_html_report_generation(tmp_path, sample_scan_data):
    scan_result, http_results, findings, ai_analysis = sample_scan_data
    filepath = generate_html_report(scan_result, http_results, findings, ai_analysis, output_dir=str(tmp_path))

    assert os.path.exists(filepath)
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    assert "AlaviTrace Security Assessment" in content
    assert "192.168.56.106" in content
    assert "badge-MEDIUM" in content
    assert "CVE-2019-6111" in content

def test_reports_without_ai(tmp_path, sample_scan_data):
    scan_result, http_results, findings, _ = sample_scan_data
    json_path = generate_json_report(scan_result, http_results, findings, ai_analysis=None, output_dir=str(tmp_path))
    md_path = generate_markdown_report(scan_result, http_results, findings, ai_analysis=None, output_dir=str(tmp_path))
    html_path = generate_html_report(scan_result, http_results, findings, ai_analysis=None, output_dir=str(tmp_path))

    assert os.path.exists(json_path)
    assert os.path.exists(md_path)
    assert os.path.exists(html_path)

def test_reports_with_owasp_a05_and_a06(tmp_path, sample_scan_data):
    from alavitrace.assessment.models import AssessmentResult, OWASPFinding, OwaspCategory
    scan_result, http_results, findings, ai_analysis = sample_scan_data

    a05_f = OWASPFinding.create(
        id="OWASP-A05-TEST-1",
        title="Missing Content-Security-Policy (CSP) Header",
        owasp_category=OwaspCategory.A05_2021.value,
        severity=Severity.MEDIUM,
        confidence=Confidence.CONFIRMED,
        description="Missing CSP header.",
        evidence="CSP header was absent.",
        affected_asset="http://192.168.56.106",
        endpoint="http://192.168.56.106/"
    )
    a06_f = OWASPFinding.create(
        id="OWASP-A06-TEST-1",
        title="Outdated Component: OpenSSH (CVE-2019-6111)",
        owasp_category=OwaspCategory.A06_2021.value,
        severity=Severity.HIGH,
        confidence=Confidence.PROBABLE,
        description="Outdated OpenSSH component.",
        evidence="Service OpenSSH 7.9p1 matched CVE-2019-6111.",
        affected_asset="192.168.56.106",
        endpoint="192.168.56.106:22"
    )

    owasp_result = AssessmentResult(
        is_http_available=True,
        findings=[a05_f, a06_f],
        executed_checks=["A05", "A06"],
        supported_categories=["A05:2021", "A06:2021"]
    )

    # 1. JSON
    json_path = generate_json_report(scan_result, http_results, findings, ai_analysis, output_dir=str(tmp_path), owasp_result=owasp_result)
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "a05_misconfiguration" in data["owasp_assessment"]
    assert data["owasp_assessment"]["a05_misconfiguration"]["total_count"] == 1
    assert "a06_vulnerable_components" in data["owasp_assessment"]
    assert data["owasp_assessment"]["a06_vulnerable_components"]["total_count"] == 1

    # 2. Markdown
    md_path = generate_markdown_report(scan_result, http_results, findings, ai_analysis, output_dir=str(tmp_path), owasp_result=owasp_result)
    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()
    assert "### A05:2021 Security Misconfiguration Summary" in md_text
    assert "### A06:2021 Vulnerable and Outdated Components Summary" in md_text

    # 3. HTML
    html_path = generate_html_report(scan_result, http_results, findings, ai_analysis, output_dir=str(tmp_path), owasp_result=owasp_result)
    with open(html_path, "r", encoding="utf-8") as f:
        html_text = f.read()
    assert "A05 Misconfigurations" in html_text
    assert "A06 Outdated Components" in html_text

