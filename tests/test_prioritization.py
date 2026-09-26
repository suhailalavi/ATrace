import json
import pytest
from alavitrace.core.models import Finding, Severity, Confidence, ScanResult, Target, Host, Service
from alavitrace.analysis.prioritization import VulnerabilityPrioritizer, PrioritizationResult
from alavitrace.reporting.json_report import generate_json_report
from alavitrace.reporting.markdown_report import generate_markdown_report
from alavitrace.reporting.html_report import generate_html_report
from alavitrace.ai.analyst import SecurityAnalyst

@pytest.fixture
def sample_findings():
    return [
        Finding(
            id="FIND-001",
            title="Known CVE Associated with OpenSSH 7.9p1 (CVE-2019-6111)",
            category="Vulnerability Intelligence",
            severity=Severity.MEDIUM,
            confidence=Confidence.PROBABLE,
            description="OpenSSH flaw.",
            evidence="Service OpenSSH 7.9p1 detected on port 22/tcp matched vulnerability record CVE-2019-6111 (CVSS 5.8).",
            affected_asset="192.168.56.106",
            affected_port=22
        ),
        Finding(
            id="FIND-002",
            title="Known CVE Associated with OpenSSH 7.9p1 (CVE-2023-38408)",
            category="Vulnerability Intelligence",
            severity=Severity.CRITICAL,
            confidence=Confidence.PROBABLE,
            description="OpenSSH PKCS#11 flaw.",
            evidence="Service OpenSSH 7.9p1 detected on port 22/tcp matched vulnerability record CVE-2023-38408 (CVSS 9.8).",
            affected_asset="192.168.56.106",
            affected_port=22
        ),
        Finding(
            id="FIND-003",
            title="Known CVE Associated with OpenSSH 7.9p1 (CVE-2021-41617)",
            category="Vulnerability Intelligence",
            severity=Severity.HIGH,
            confidence=Confidence.PROBABLE,
            description="OpenSSH privilege escalation.",
            evidence="Service OpenSSH 7.9p1 detected on port 22/tcp matched vulnerability record CVE-2021-41617 (CVSS 7.0).",
            affected_asset="192.168.56.106",
            affected_port=22
        ),
        Finding(
            id="FIND-004",
            title="Known CVE Associated with pyftpdlib 1.5.5 (CVE-2020-10001)",
            category="Vulnerability Intelligence",
            severity=Severity.LOW,
            confidence=Confidence.POTENTIAL,
            description="pyftpdlib flaw.",
            evidence="Service pyftpdlib 1.5.5 detected on port 21/tcp matched vulnerability record CVE-2020-10001 (CVSS 3.3).",
            affected_asset="192.168.56.106",
            affected_port=21
        ),
        Finding(
            id="FIND-005",
            title="Known CVE Associated with pyftpdlib 1.5.5 (CVE-2020-10002)",
            category="Vulnerability Intelligence",
            severity=Severity.INFO,
            confidence=Confidence.POTENTIAL,
            description="pyftpdlib minor info disclosure.",
            evidence="Service pyftpdlib 1.5.5 detected on port 21/tcp matched vulnerability record CVE-2020-10002 (CVSS N/A).",
            affected_asset="192.168.56.106",
            affected_port=21
        ),
        Finding(
            id="FIND-006",
            title="Known CVE Associated with pyftpdlib 1.5.5 (CVE-2020-10003)",
            category="Vulnerability Intelligence",
            severity=Severity.MEDIUM,
            confidence=Confidence.POTENTIAL,
            description="pyftpdlib medium flaw.",
            evidence="Service pyftpdlib 1.5.5 detected on port 21/tcp matched vulnerability record CVE-2020-10003 (CVSS 5.0).",
            affected_asset="192.168.56.106",
            affected_port=21
        ),
        Finding(
            id="FIND-007",
            title="Missing X-Content-Type-Options Header",
            category="Web Security Configuration",
            severity=Severity.LOW,
            confidence=Confidence.CONFIRMED,
            description="Missing nosniff header.",
            evidence="Header X-Content-Type-Options missing.",
            affected_asset="http://192.168.56.106"
        )
    ]

def test_prioritization_default_top_5(sample_findings):
    prioritizer = VulnerabilityPrioritizer()
    res = prioritizer.prioritize(sample_findings, max_findings=5)

    assert res.total_correlated == 6
    assert res.prioritized_count == 5

    # Critical finding (CVE-2023-38408) should be #1
    top_vuln = [f for f in res.prioritized_findings if f.category == "Vulnerability Intelligence"]
    assert len(top_vuln) == 5
    assert top_vuln[0].id == "FIND-002"
    assert "CVE-2023-38408" in top_vuln[0].title

    # Retained all findings dataset in all_findings
    assert len(res.all_findings) == 7

def test_prioritization_custom_max_findings(sample_findings):
    prioritizer = VulnerabilityPrioritizer()
    res = prioritizer.prioritize(sample_findings, max_findings=2)

    assert res.total_correlated == 6
    assert res.prioritized_count == 2
    top_vuln = [f for f in res.prioritized_findings if f.category == "Vulnerability Intelligence"]
    assert len(top_vuln) == 2

def test_prioritization_invalid_max_findings(sample_findings):
    prioritizer = VulnerabilityPrioritizer()
    with pytest.raises(ValueError, match="max_findings must be at least 1"):
        prioritizer.prioritize(sample_findings, max_findings=0)

def test_cve_deduplication_same_cve_multi_port():
    duplicate_findings = [
        Finding(
            id="FIND-001a",
            title="Known CVE Associated with OpenSSH (CVE-2023-38408)",
            category="Vulnerability Intelligence",
            severity=Severity.CRITICAL,
            confidence=Confidence.PROBABLE,
            description="OpenSSH flaw.",
            evidence="Service OpenSSH detected on port 22/tcp matched CVE-2023-38408 (CVSS 9.8).",
            affected_asset="192.168.56.106",
            affected_port=22
        ),
        Finding(
            id="FIND-001b",
            title="Known CVE Associated with OpenSSH (CVE-2023-38408)",
            category="Vulnerability Intelligence",
            severity=Severity.CRITICAL,
            confidence=Confidence.PROBABLE,
            description="OpenSSH flaw.",
            evidence="Service OpenSSH detected on port 2222/tcp matched CVE-2023-38408 (CVSS 9.8).",
            affected_asset="192.168.56.106",
            affected_port=2222
        )
    ]

    prioritizer = VulnerabilityPrioritizer()
    res = prioritizer.prioritize(duplicate_findings, max_findings=5)

    assert res.total_correlated == 1
    assert "Observed across ports: 22, 2222" in res.prioritized_findings[0].evidence

def test_cpe_vs_keyword_confidence_scoring():
    f_cpe = Finding(
        id="FIND-CPE",
        title="Known CVE Associated with Software (CVE-2022-0001)",
        category="Vulnerability Intelligence",
        severity=Severity.HIGH,
        confidence=Confidence.PROBABLE,
        description="CPE match.",
        evidence="CPE match (CVSS 7.5).",
        affected_asset="192.168.56.106",
        affected_port=80
    )
    f_kw = Finding(
        id="FIND-KW",
        title="Known CVE Associated with Software (CVE-2022-0002)",
        category="Vulnerability Intelligence",
        severity=Severity.HIGH,
        confidence=Confidence.POTENTIAL,
        description="Keyword match.",
        evidence="Keyword match (CVSS 7.5).",
        affected_asset="192.168.56.106",
        affected_port=80
    )

    prioritizer = VulnerabilityPrioritizer()
    res = prioritizer.prioritize([f_kw, f_cpe], max_findings=5)

    # Probable CPE match should score higher than Potential Keyword match
    top_vuln = [f for f in res.prioritized_findings if f.category == "Vulnerability Intelligence"]
    assert top_vuln[0].id == "FIND-CPE"

def test_reporting_data_retention(tmp_path, sample_findings):
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    host = Host(target=target, ipv4="192.168.56.106", open_ports=[Service(port=22, protocol="tcp", state="open", name="SSH")])
    scan_result = ScanResult(target=target, hosts=[host])

    prioritizer = VulnerabilityPrioritizer()
    p_result = prioritizer.prioritize(sample_findings, max_findings=3)

    json_path = generate_json_report(scan_result, [], p_result, ai_analysis=None, output_dir=str(tmp_path))
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    vuln_sec = data["vulnerability_intelligence"]
    assert vuln_sec["total_correlated"] == 6
    assert vuln_sec["prioritized_count"] == 3
    assert len(vuln_sec["prioritized_vulnerabilities"]) == 3
    assert len(vuln_sec["all_correlated_vulnerabilities"]) == 6

def test_ai_input_uses_prioritized_findings(sample_findings):
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    host = Host(target=target, ipv4="192.168.56.106", open_ports=[Service(port=22, protocol="tcp", state="open", name="SSH")])
    scan_result = ScanResult(target=target, hosts=[host])

    prioritizer = VulnerabilityPrioritizer()
    p_result = prioritizer.prioritize(sample_findings, max_findings=2)

    ai_input = SecurityAnalyst.prepare_structured_input(scan_result, [], p_result)

    vuln_summary = ai_input["vulnerability_summary"]
    assert vuln_summary["total_unique_cves_correlated"] == 6
    assert vuln_summary["prioritized_candidates_count"] == 2
    assert vuln_summary["additional_correlated_cves_retained_in_json"] == 4

    # AI input findings list contains only prioritized findings (2 vulns + 1 header recommendation = 3 findings total)
    assert len(ai_input["prioritized_findings"]) == 3
