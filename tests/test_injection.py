import pytest
from unittest.mock import patch, MagicMock

from alavitrace.core.models import (
    Target,
    Host,
    Service,
    ScanResult,
    HttpResult,
    Severity,
    Confidence
)
from alavitrace.assessment.models import (
    OwaspCategory,
    AssessmentContext,
    OWASPFinding
)
from alavitrace.assessment.injection_payloads import (
    PayloadType,
    SafePayload,
    get_sqli_payloads,
    generate_xss_canary,
    COMMAND_PARAM_CANDIDATES
)
from alavitrace.assessment.http_probe import (
    InjectionTarget,
    ProbeResponse,
    HttpProber
)
from alavitrace.assessment.response_analysis import (
    XssContext,
    detect_db_error,
    detect_sqli_error_difference,
    classify_xss_context,
    analyze_xss_reflection
)
from alavitrace.assessment.injection_engine import (
    discover_injection_targets,
    ControlledInjectionDetector,
    InjectionAssessmentResult
)
from alavitrace.assessment.base import InjectionCheck
from alavitrace.assessment.engine import AssessmentEngine
from alavitrace.analysis.prioritization import VulnerabilityPrioritizer
from alavitrace.reporting.json_report import generate_json_report
from alavitrace.reporting.markdown_report import generate_markdown_report
from alavitrace.reporting.html_report import generate_html_report

# ============================================================================
# 1. Parameter Discovery Tests
# ============================================================================

def test_discover_injection_targets_from_query():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    http_res = HttpResult(
        url="http://192.168.56.106/search?q=cyber&cat=news",
        status_code=200
    )
    context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[http_res])
    targets = discover_injection_targets(context, max_targets=5)

    assert len(targets) == 2
    param_names = [t.parameter_name for t in targets]
    assert "q" in param_names
    assert "cat" in param_names
    for t in targets:
        assert t.url == "http://192.168.56.106/search"
        assert t.parameter_location == "query"
        assert t.http_method == "GET"

def test_discover_injection_targets_from_forms():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    http_res = HttpResult(
        url="http://192.168.56.106/profile",
        status_code=200,
        forms=[{
            "action": "http://192.168.56.106/profile/update",
            "method": "POST",
            "inputs": [
                {"name": "username", "type": "text", "value": "john"},
                {"name": "bio", "type": "text", "value": "security"},
                {"name": "csrf_token", "type": "hidden", "value": "secret123"},
                {"name": "submit", "type": "submit", "value": "Save"}
            ]
        }]
    )
    context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[http_res])
    targets = discover_injection_targets(context, max_targets=5)

    # CSRF token and submit button should be filtered out
    assert len(targets) == 2
    param_names = [t.parameter_name for t in targets]
    assert "username" in param_names
    assert "bio" in param_names
    assert "csrf_token" not in param_names
    assert "submit" not in param_names
    for t in targets:
        assert t.url == "http://192.168.56.106/profile/update"
        assert t.parameter_location == "form"
        assert t.http_method == "POST"

def test_discover_injection_targets_empty():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    http_res = HttpResult(url="http://192.168.56.106/index.html", status_code=200)
    context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[http_res])
    targets = discover_injection_targets(context)
    assert targets == []

# ============================================================================
# 2. HTTP Prober & Safety Limits Tests
# ============================================================================

def test_prober_budget_exhaustion():
    prober = HttpProber(max_requests=3, delay_seconds=0)
    inj_target = InjectionTarget(url="http://192.168.56.106/api", http_method="GET", parameter_name="id")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"OK"
    mock_resp.text = "OK"
    mock_resp.headers = {}
    mock_resp.url = "http://192.168.56.106/api"

    with patch("requests.request", return_value=mock_resp) as mock_req:
        resp1 = prober.get_baseline(inj_target)
        resp2 = prober.send_probe(inj_target, "'")
        resp3 = prober.send_probe(inj_target, '"')
        # 4th request should be blocked by budget
        resp4 = prober.send_probe(inj_target, r"\'")

        assert mock_req.call_count == 3
        assert prober.budget_exhausted is True
        assert resp4.error_message is not None
        assert "budget exhausted" in resp4.error_message.lower()

def test_prober_handles_429_rate_limiting():
    prober = HttpProber(max_requests=10, delay_seconds=0)
    inj_target = InjectionTarget(url="http://192.168.56.106/api", http_method="GET", parameter_name="id")

    mock_resp_429 = MagicMock()
    mock_resp_429.status_code = 429
    mock_resp_429.content = b"Too Many Requests"
    mock_resp_429.text = "Too Many Requests"
    mock_resp_429.headers = {}
    mock_resp_429.url = "http://192.168.56.106/api"

    with patch("requests.request", return_value=mock_resp_429):
        resp1 = prober.get_baseline(inj_target)
        assert resp1.status_code == 429
        assert prober.rate_limited is True

        # Subsequent requests must be immediately blocked
        resp2 = prober.send_probe(inj_target, "'")
        assert "Rate limit" in resp2.error_message

def test_prober_handles_connection_timeout():
    import requests
    prober = HttpProber(max_requests=5, timeout=2, delay_seconds=0)
    inj_target = InjectionTarget(url="http://192.168.56.106/api", http_method="GET", parameter_name="id")

    with patch("requests.request", side_effect=requests.exceptions.Timeout("Read timeout")):
        resp = prober.get_baseline(inj_target)
        assert resp.status_code is None
        assert "timed out" in resp.error_message.lower()

# ============================================================================
# 3. Response Analysis & False-Positive Elimination Tests
# ============================================================================

def test_detect_db_error_signatures():
    mysql_text = "Error: You have an error in your SQL syntax near '1' at line 1"
    pg_text = "Server Error: pg_query(): syntax error at or near 'admin'"
    mssql_text = "System.Data.SqlClient.SqlException: Unclosed quotation mark after the character string."
    sqlite_text = "Warning: SQLite3::query(): unrecognized token: \"'\""
    oracle_text = "ORA-00933: SQL command not properly ended"
    clean_text = "Search results for: ' OR 1=1 -- Found 0 items."

    assert detect_db_error(mysql_text)["database"] == "MySQL"
    assert detect_db_error(pg_text)["database"] == "PostgreSQL"
    assert detect_db_error(mssql_text)["database"] == "Microsoft SQL Server"
    assert detect_db_error(sqlite_text)["database"] == "SQLite"
    assert detect_db_error(oracle_text)["database"] == "Oracle"
    assert detect_db_error(clean_text) is None

def test_sqli_difference_eliminates_baseline_errors():
    # If a page contains a preexisting database error in the baseline response,
    # mutating an input should NOT trigger a false positive SQLi finding.
    baseline = "Welcome! Note: MySQL server version 8.0.28 is active. (SQL syntax error checking enabled)"
    test_body = "Search results: Note: MySQL server version 8.0.28 is active. (SQL syntax error checking enabled)"

    diff = detect_sqli_error_difference(baseline, test_body)
    assert diff is None

def test_sqli_difference_detects_genuine_mutation_error():
    baseline = "<html><body>Search Results: No items found</body></html>"
    test_body = "<html><body>Database Error: You have an error in your SQL syntax near '' at line 1</body></html>"

    diff = detect_sqli_error_difference(baseline, test_body)
    assert diff is not None
    assert diff["database"] == "MySQL"
    assert "error in your sql syntax" in diff["matched_snippet"]

# ============================================================================
# 4. XSS Reflection & Context Classification Tests
# ============================================================================

def test_xss_context_classification_script():
    canary = "ATRACE_CANARY_abc123"
    body = f"<html><head><script>var user = '{canary}';</script></head><body>Hello</body></html>"
    context, is_encoded = classify_xss_context(body, canary)
    assert context == XssContext.SCRIPT
    assert is_encoded is False

def test_xss_context_classification_attribute():
    canary = "ATRACE_CANARY_def456"
    body = f"<html><body><input type='text' name='q' value='{canary}'></body></html>"
    context, is_encoded = classify_xss_context(body, canary)
    assert context == XssContext.ATTRIBUTE
    assert is_encoded is False

def test_xss_context_classification_url_attribute():
    canary = "ATRACE_CANARY_url789"
    body = f"<html><body><a href='http://target/redirect?to={canary}'>Next</a></body></html>"
    context, is_encoded = classify_xss_context(body, canary)
    assert context == XssContext.URL
    assert is_encoded is False

def test_xss_context_classification_text():
    canary = "ATRACE_CANARY_txt000"
    body = f"<html><body><p>You searched for: {canary}</p></body></html>"
    context, is_encoded = classify_xss_context(body, canary)
    assert context == XssContext.TEXT
    assert is_encoded is False

def test_xss_reflection_requires_absence_in_baseline():
    canary = "ATRACE_CANARY_111111"
    # Preexisting in baseline -> must return None
    baseline = f"Preexisting canary: {canary}"
    test_body = f"Preexisting canary: {canary}"
    res = analyze_xss_reflection(baseline, test_body, canary)
    assert res is None

# ============================================================================
# 5. Controlled Injection Detector Integration Tests
# ============================================================================

def test_controlled_injection_detector_sqli_finding():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    http_res = HttpResult(url="http://192.168.56.106/view?id=10", status_code=200)
    context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[http_res])

    detector = ControlledInjectionDetector(max_requests=10, delay_seconds=0)

    # Mock baseline and probe responses
    def mock_request(method, url, params=None, data=None, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        resp.url = url
        # If single quote tested, return database error
        if params and params.get("id") == "'":
            resp.content = b"Database error: You have an error in your SQL syntax near ''"
            resp.text = "Database error: You have an error in your SQL syntax near ''"
        else:
            resp.content = b"User Profile: ID 10"
            resp.text = "User Profile: ID 10"
        return resp

    with patch("requests.request", side_effect=mock_request):
        result = detector.execute(context)

    assert result.is_executed is True
    assert result.sqli_candidates == 1
    sqli_finding = next((f for f in result.findings if "SQL Injection" in f.title), None)
    assert sqli_finding is not None
    assert sqli_finding.severity == Severity.HIGH
    assert sqli_finding.confidence == Confidence.PROBABLE
    assert sqli_finding.owasp_category == OwaspCategory.A03_2021.value
    assert sqli_finding.parameter == "id"
    assert "No data extraction" in sqli_finding.limitations

def test_controlled_injection_detector_xss_finding():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    http_res = HttpResult(url="http://192.168.56.106/search?q=test", status_code=200)
    context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[http_res])

    detector = ControlledInjectionDetector(max_requests=10, delay_seconds=0)

    def mock_request(method, url, params=None, data=None, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        resp.url = url
        # If canary string sent, reflect it inside HTML attribute
        q_val = params.get("q", "") if params else ""
        if "ATRACE_CANARY" in q_val:
            resp.content = f"<html><body><input name='q' value='{q_val}'></body></html>".encode()
            resp.text = f"<html><body><input name='q' value='{q_val}'></body></html>"
        else:
            resp.content = b"<html><body>Search Results</body></html>"
            resp.text = "<html><body>Search Results</body></html>"
        return resp

    with patch("requests.request", side_effect=mock_request):
        result = detector.execute(context)

    assert result.is_executed is True
    assert result.xss_candidates == 1
    xss_finding = next((f for f in result.findings if "XSS" in f.title), None)
    assert xss_finding is not None
    assert xss_finding.severity == Severity.MEDIUM
    assert xss_finding.confidence == Confidence.PROBABLE
    assert "ATTRIBUTE" in xss_finding.evidence
    assert "Browser script execution was not performed" in xss_finding.limitations

def test_command_injection_heuristic():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    http_res = HttpResult(url="http://192.168.56.106/tools?cmd=status", status_code=200)
    context = AssessmentContext(target=target, scan_result=ScanResult(target=target), http_results=[http_res])

    detector = ControlledInjectionDetector(max_requests=10, delay_seconds=0)

    def mock_request(method, url, params=None, data=None, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        resp.url = url
        resp.content = b"Command status: healthy"
        resp.text = "Command status: healthy"
        return resp

    with patch("requests.request", side_effect=mock_request):
        result = detector.execute(context)

    cmd_finding = next((f for f in result.findings if "Command Injection" in f.title), None)
    assert cmd_finding is not None
    assert cmd_finding.severity == Severity.LOW
    assert cmd_finding.confidence == Confidence.POTENTIAL
    assert "No command execution payloads were tested" in cmd_finding.limitations

# ============================================================================
# 6. Check & Engine Integration Tests
# ============================================================================

def test_injection_check_with_enable_injection_option():
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    http_res = HttpResult(url="http://192.168.56.106/items?cat=tech", status_code=200)
    context = AssessmentContext(
        target=target,
        scan_result=ScanResult(target=target),
        http_results=[http_res],
        options={"enable_injection": True, "max_injection_requests": 10}
    )

    check = InjectionCheck()

    def mock_request(method, url, params=None, data=None, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        resp.url = url
        if params and params.get("cat") == "'":
            resp.content = b"Error: valid postgresql result syntax error at or near '''"
            resp.text = "Error: valid postgresql result syntax error at or near '''"
        else:
            resp.content = b"Tech items"
            resp.text = "Tech items"
        return resp

    with patch("requests.request", side_effect=mock_request):
        findings = check.check(context)

    assert len(findings) >= 1
    assert any("SQL Injection" in f.title for f in findings)
    assert findings[0].owasp_category == OwaspCategory.A03_2021.value

def test_injection_findings_prioritize_and_report(tmp_path):
    target = Target(raw_input="192.168.56.106", normalized="192.168.56.106", target_type="IPv4")
    scan_result = ScanResult(target=target)

    sqli_finding = OWASPFinding.create(
        id="OWASP-A03-SQLI-TEST",
        title="Potential SQL Injection",
        owasp_category=OwaspCategory.A03_2021.value,
        severity=Severity.HIGH,
        confidence=Confidence.PROBABLE,
        description="SQL syntax error produced by quote mutation.",
        evidence="MySQL syntax error observed.",
        affected_asset="http://192.168.56.106/search",
        endpoint="http://192.168.56.106/search",
        parameter="q",
        detection_type="active"
    )

    prioritizer = VulnerabilityPrioritizer()
    p_result = prioritizer.prioritize([sqli_finding], max_findings=5)
    assert len(p_result.prioritized_findings) == 1

    from alavitrace.assessment.models import AssessmentResult
    owasp_result = AssessmentResult(
        is_http_available=True,
        findings=[sqli_finding],
        executed_checks=["InjectionCheck"]
    )

    # 1. JSON Report
    json_path = generate_json_report(scan_result, [], p_result, None, output_dir=str(tmp_path), owasp_result=owasp_result)
    import json
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "a03_injection" in data
    assert data["a03_injection"]["total_candidates"] == 1
    assert data["a03_injection"]["sqli_candidates"] == 1

    # 2. Markdown Report
    md_path = generate_markdown_report(scan_result, [], p_result, None, output_dir=str(tmp_path), owasp_result=owasp_result)
    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()
    assert "A03:2021 Injection Assessment Summary" in md_text
    assert "SQL Injection Candidates" in md_text

    # 3. HTML Report
    html_path = generate_html_report(scan_result, [], p_result, None, output_dir=str(tmp_path), owasp_result=owasp_result)
    with open(html_path, "r", encoding="utf-8") as f:
        html_text = f.read()
    assert "A03 Injection Candidates" in html_text
