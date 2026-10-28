import re
import socket
import logging
import uuid
from typing import Optional, Any, Dict, List
from urllib.parse import urlparse
import requests

from alavitrace.core.models import Finding, Confidence
from alavitrace.validation.models import ValidationStatus, ValidationResult
from alavitrace.validation.base import (
    BaseValidator,
    DEFAULT_VALIDATION_TIMEOUT,
    DEFAULT_VALIDATION_USER_AGENT,
    redact_sensitive_params
)

logger = logging.getLogger("AlaviTrace")

def _resolve_url(finding: Finding) -> str:
    """Helper to resolve a well-formed HTTP URL for a finding."""
    candidate = finding.endpoint or finding.affected_asset
    if candidate.startswith("http://") or candidate.startswith("https://"):
        return candidate
    port = finding.affected_port or 80
    scheme = "https" if port in [443, 8443] else "http"
    return f"{scheme}://{candidate}:{port}/"

def _send_request(
    engine: Optional[Any],
    method: str,
    url: str,
    timeout: int = DEFAULT_VALIDATION_TIMEOUT,
    **kwargs: Any
) -> Optional[requests.Response]:
    """
    Routes HTTP request through ValidationEngine controller if available,
    or falls back to direct requests.request.
    """
    if engine and hasattr(engine, "execute_request"):
        return engine.execute_request(method, url, timeout=timeout, **kwargs)

    headers = kwargs.pop("headers", {})
    if "User-Agent" not in headers:
        headers["User-Agent"] = DEFAULT_VALIDATION_USER_AGENT
    requests.packages.urllib3.disable_warnings()
    req_m = method.upper()
    if req_m == "GET":
        return requests.get(url, timeout=timeout, verify=False, headers=headers, **kwargs)
    elif req_m == "POST":
        return requests.post(url, timeout=timeout, verify=False, headers=headers, **kwargs)
    elif req_m == "HEAD":
        return requests.head(url, timeout=timeout, verify=False, headers=headers, **kwargs)
    elif req_m == "OPTIONS":
        return requests.options(url, timeout=timeout, verify=False, headers=headers, **kwargs)
    else:
        return requests.request(
            method=req_m,
            url=url,
            timeout=timeout,
            verify=False,
            headers=headers,
            **kwargs
        )


# ---------------------------------------------------------------------------
# 1. SQL INJECTION INDICATOR VALIDATOR
# ---------------------------------------------------------------------------

class SQLInjectionValidator(BaseValidator):
    """
    Validates potential SQL injection indicators using conservative delimiter syntax checks
    and database error signature analysis across MySQL, PostgreSQL, MSSQL, SQLite, and Oracle.
    STRICT SAFETY: Zero data extraction, zero table enumeration, zero stacked queries, zero data modification.
    """
    name = "SQLInjectionValidator"
    description = "Validates potential SQL injection indicators using conservative delimiter syntax checks"

    DB_ERROR_PATTERNS = {
        "MySQL": [
            r"you have an error in your sql syntax",
            r"check the manual that corresponds to your mysql server version",
            r"warning: mysql_",
            r"valid mysql result",
            r"mysqldb\."
        ],
        "PostgreSQL": [
            r"psql:",
            r"syntax error at or near",
            r"pg_query\(\)",
            r"pg_exec\(\)",
            r"unterminated quoted string at or near",
            r"pg_dump"
        ],
        "SQLite": [
            r"sqlite3::",
            r"unrecognized token:",
            r"operationalerror: near",
            r"sqlite error",
            r"sqlite3\.operationalerror"
        ],
        "MSSQL": [
            r"microsoft sql server",
            r"unclosed quotation mark after the character string",
            r"driver\] \[sql server\]",
            r"odbc sql server driver"
        ],
        "Oracle": [
            r"ora-01756",
            r"ora-00933",
            r"ora-00907",
            r"quoted string not properly terminated"
        ]
    }

    def can_validate(self, finding: Finding) -> bool:
        if finding.category == "Vulnerability Intelligence" and not finding.parameter and not finding.endpoint:
            return False
        title_lower = finding.title.lower()
        owasp_cat = (finding.owasp_category or "").lower()
        if "sql" in title_lower or "sqli" in title_lower or "database" in title_lower:
            return True
        if "a03" in owasp_cat and ("sql" in title_lower or "injection" in title_lower):
            if "xss" not in title_lower and "command" not in title_lower:
                return True
        return False

    def validate(
        self,
        finding: Finding,
        context: Optional[Any] = None,
        timeout: int = DEFAULT_VALIDATION_TIMEOUT,
        **kwargs: Any
    ) -> ValidationResult:
        engine = kwargs.get("engine")
        url = _resolve_url(finding)
        param = finding.parameter or "id"
        method = (finding.http_method or "GET").upper()

        result = ValidationResult(
            finding_id=finding.id,
            target=finding.affected_asset,
            port=finding.affected_port,
            service=finding.affected_service or "HTTP",
            vulnerability_id=finding.id,
            owasp_category=finding.owasp_category or "A03:2021-Injection",
            validation_method="SQL Injection Indicator Validation (Benign Delimiter Probe)",
            confidence=finding.confidence,
            limitations="Zero data extraction, stacked queries, or table enumeration attempted. Bounded delimiter probe only."
        )

        test_input = "'"
        try:
            if method == "POST":
                resp = _send_request(engine, "POST", url, data={param: test_input}, timeout=timeout, allow_redirects=False)
            else:
                resp = _send_request(engine, "GET", url, params={param: test_input}, timeout=timeout, allow_redirects=False)

            if resp is None:
                if engine and getattr(engine, "request_limit_reached", False):
                    result.status = ValidationStatus.INCONCLUSIVE
                    result.evidence = f"Validation request limit reached ({engine.max_requests}). Request halted."
                    result.error_message = "VALIDATION_REQUEST_LIMIT_REACHED"
                else:
                    result.status = ValidationStatus.INCONCLUSIVE
                    result.evidence = "Target request could not be completed; validation inconclusive."
                return result

            body_lower = resp.text.lower()
            matched_engine = None
            matched_pattern = None

            for db_name, patterns in self.DB_ERROR_PATTERNS.items():
                for pat in patterns:
                    if re.search(pat, body_lower):
                        matched_engine = db_name
                        matched_pattern = pat
                        break
                if matched_engine:
                    break

            if matched_engine:
                result.status = ValidationStatus.VALIDATED
                result.confidence = Confidence.CONFIRMED
                result.evidence = (
                    f"Parameter '{param}' produced a database-error response ({matched_engine}) "
                    f"when supplied with a controlled test value. This is a candidate SQL injection indicator "
                    f"requiring further manual validation."
                )
                result.structured_evidence = {
                    "endpoint": url,
                    "parameter": param,
                    "test_input": test_input,
                    "response_status": resp.status_code,
                    "database_engine": matched_engine,
                    "error_signatures_detected": [matched_engine],
                    "matched_pattern": matched_pattern
                }
            elif resp.status_code == 500:
                result.status = ValidationStatus.VALIDATED
                result.confidence = Confidence.OBSERVED
                result.evidence = (
                    f"Parameter '{param}' triggered HTTP 500 Internal Server Error when supplied with "
                    f"controlled delimiter input. Candidate server-side syntax anomaly observed."
                )
                result.structured_evidence = {
                    "endpoint": url,
                    "parameter": param,
                    "test_input": test_input,
                    "error_signatures_detected": ["Internal Server Error 500"],
                    "response_status": resp.status_code
                }
            else:
                result.status = ValidationStatus.NOT_VALIDATED
                result.evidence = (
                    f"Parameter '{param}' handled test input without producing observable database "
                    f"error signatures or server anomalies (Status: {resp.status_code})."
                )
                result.structured_evidence = {
                    "endpoint": url,
                    "parameter": param,
                    "response_status": resp.status_code,
                    "database_error": False,
                    "error_signatures_detected": []
                }

        except requests.exceptions.Timeout:
            result.status = ValidationStatus.INCONCLUSIVE
            result.error_message = f"Request to '{url}' timed out after {timeout}s during SQL injection check"
            result.evidence = "Target timed out during SQL injection test."
        except requests.exceptions.RequestException as e:
            result.status = ValidationStatus.INCONCLUSIVE
            result.error_message = f"Connection failed to '{url}': {str(e)}"
            result.evidence = "Target unreachable during SQL injection check."
        except Exception as e:
            logger.exception("Unexpected error in SQLInjectionValidator")
            result.status = ValidationStatus.ERROR
            result.error_message = str(e)
            result.evidence = "Internal error encountered during SQL injection validation."

        return result


# ---------------------------------------------------------------------------
# 2. REFLECTED XSS INDICATOR VALIDATOR
# ---------------------------------------------------------------------------

class ReflectedXSSValidator(BaseValidator):
    """
    Validates parameter reflection and context using benign, unique alphanumeric canary tokens.
    STRICT SAFETY: Zero XSS payloads, zero quotes, zero script execution, zero browser execution.
    """
    name = "ReflectedXSSValidator"
    description = "Validates parameter reflection using benign, unique alphanumeric canary markers"

    def can_validate(self, finding: Finding) -> bool:
        if finding.category == "Vulnerability Intelligence" and not finding.parameter and not finding.endpoint:
            return False
        title_lower = finding.title.lower()
        owasp_cat = (finding.owasp_category or "").lower()

        if "xss" in title_lower or "cross-site scripting" in title_lower:
            return True
        if "reflected" in title_lower or "reflection" in title_lower:
            return True
        if getattr(finding, "detection_type", None) == "reflected_parameter":
            return True
        if "a03" in owasp_cat and "xss" in title_lower:
            return True
        if finding.parameter is not None and "sql" not in title_lower and "command" not in title_lower and "traversal" not in title_lower:
            return True
        return False

    def validate(
        self,
        finding: Finding,
        context: Optional[Any] = None,
        timeout: int = DEFAULT_VALIDATION_TIMEOUT,
        **kwargs: Any
    ) -> ValidationResult:
        engine = kwargs.get("engine")
        url = _resolve_url(finding)
        param = finding.parameter or "q"
        method = (finding.http_method or "GET").upper()

        result = ValidationResult(
            finding_id=finding.id,
            target=finding.affected_asset,
            port=finding.affected_port,
            service=finding.affected_service or "HTTP",
            vulnerability_id=finding.id,
            owasp_category=finding.owasp_category or "A03:2021-Injection",
            validation_method="Reflected XSS Indicator Validation (Benign Alphanumeric Marker)",
            confidence=finding.confidence,
            limitations="Browser-side JavaScript execution was not attempted. Probed with benign alphanumeric token only."
        )

        canary_token = f"atracecanary987"

        try:
            if method == "POST":
                resp = _send_request(engine, "POST", url, data={param: canary_token}, timeout=timeout, allow_redirects=True)
            else:
                resp = _send_request(engine, "GET", url, params={param: canary_token}, timeout=timeout, allow_redirects=True)

            if resp is None:
                if engine and getattr(engine, "request_limit_reached", False):
                    result.status = ValidationStatus.INCONCLUSIVE
                    result.evidence = f"Validation request limit reached ({engine.max_requests}). Request halted."
                    result.error_message = "VALIDATION_REQUEST_LIMIT_REACHED"
                else:
                    result.status = ValidationStatus.INCONCLUSIVE
                    result.evidence = "Target request could not be completed; validation inconclusive."
                return result

            text = resp.text
            content_type = resp.headers.get("Content-Type", "").lower()

            if canary_token not in text:
                result.status = ValidationStatus.NOT_VALIDATED
                result.evidence = (
                    f"Controlled marker '{canary_token}' was not reflected in HTTP response for parameter '{param}' "
                    f"(Status: {resp.status_code})."
                )
                result.structured_evidence = {
                    "endpoint": url,
                    "parameter": param,
                    "test_marker": canary_token,
                    "response_status": resp.status_code,
                    "reflected": False
                }
            else:
                result.status = ValidationStatus.VALIDATED

                if "application/json" in content_type or "text/plain" in content_type:
                    reflection_ctx = "plain_text"
                    result.confidence = Confidence.OBSERVED
                    result.evidence = (
                        f"Controlled marker '{canary_token}' was reflected in plain text / JSON non-HTML response content "
                        f"for parameter '{param}' (Status: {resp.status_code})."
                    )
                else:
                    script_pattern = re.compile(rf"<script[^>]*>[^<]*?{re.escape(canary_token)}[^<]*?</script>", re.IGNORECASE | re.DOTALL)
                    handler_pattern = re.compile(rf'on\w+\s*=\s*["\']?[^"\'>]*?{re.escape(canary_token)}', re.IGNORECASE)

                    if script_pattern.search(text) or handler_pattern.search(text):
                        reflection_ctx = "potentially_dangerous_html"
                        result.confidence = Confidence.CONFIRMED
                        result.evidence = (
                            f"Controlled marker '{canary_token}' was reflected inside an executable HTML script or event handler "
                            f"attribute context for parameter '{param}' (Status: {resp.status_code}). "
                            f"High indicator requiring manual output encoding review."
                        )
                    else:
                        reflection_ctx = "html_content"
                        result.confidence = Confidence.CONFIRMED
                        result.evidence = (
                            f"Controlled marker '{canary_token}' was reflected inside HTML response content for parameter '{param}' "
                            f"(Status: {resp.status_code}). Output encoding review recommended."
                        )

                result.structured_evidence = {
                    "endpoint": url,
                    "parameter": param,
                    "test_marker": canary_token,
                    "response_status": resp.status_code,
                    "reflected": True,
                    "reflection_context": reflection_ctx
                }

        except requests.exceptions.Timeout:
            result.status = ValidationStatus.INCONCLUSIVE
            result.error_message = f"Request to '{url}' timed out after {timeout}s during reflection check"
            result.evidence = "Target timed out during reflection test."
        except requests.exceptions.RequestException as e:
            result.status = ValidationStatus.INCONCLUSIVE
            result.error_message = f"Connection failed to '{url}': {str(e)}"
            result.evidence = f"Connection failed to '{url}': Target unreachable during reflection check."
        except Exception as e:
            logger.exception("Unexpected error in ReflectedXSSValidator")
            result.status = ValidationStatus.ERROR
            result.error_message = str(e)
            result.evidence = "Internal error encountered during reflection validation."

        return result

# Alias for backward compatibility with Phase 9 tests
ReflectedInputValidator = ReflectedXSSValidator


# ---------------------------------------------------------------------------
# 3. PATH TRAVERSAL INDICATOR VALIDATOR
# ---------------------------------------------------------------------------

class PathTraversalValidator(BaseValidator):
    """
    Validates candidate path traversal parameters using harmless relative indicators
    and observable path error signature detection.
    STRICT SAFETY: Zero sensitive file extraction. Never accesses /etc/passwd, SSH keys, or private files.
    """
    name = "PathTraversalValidator"
    description = "Validates candidate path traversal parameters using harmless relative indicators"

    TRAVERSAL_PARAMS = {
        "file", "path", "page", "doc", "document", "folder",
        "template", "include", "view", "filename", "read", "load", "filepath"
    }

    PATH_ERROR_PATTERNS = [
        r"open_basedir restriction in effect",
        r"failed to open stream",
        r"no such file or directory",
        r"java\.io\.filenotfoundexception",
        r"cannot find the file specified",
        r"directory traversal",
        r"invalid path characters"
    ]

    def can_validate(self, finding: Finding) -> bool:
        if finding.category == "Vulnerability Intelligence" and not finding.parameter and not finding.endpoint:
            return False
        title_lower = finding.title.lower()
        if "path traversal" in title_lower or "directory traversal" in title_lower or "file inclusion" in title_lower or "lfi" in title_lower:
            return True
        if finding.parameter and finding.parameter.lower() in self.TRAVERSAL_PARAMS:
            return True
        return False

    def validate(
        self,
        finding: Finding,
        context: Optional[Any] = None,
        timeout: int = DEFAULT_VALIDATION_TIMEOUT,
        **kwargs: Any
    ) -> ValidationResult:
        engine = kwargs.get("engine")
        url = _resolve_url(finding)
        param = finding.parameter or "file"
        method = (finding.http_method or "GET").upper()

        result = ValidationResult(
            finding_id=finding.id,
            target=finding.affected_asset,
            port=finding.affected_port,
            service=finding.affected_service or "HTTP",
            vulnerability_id=finding.id,
            owasp_category=finding.owasp_category or "A01:2021-Broken Access Control",
            validation_method="Path Traversal Indicator Validation (Harmless Relative Probe)",
            confidence=finding.confidence,
            limitations="No operating system, credential, or sensitive private files were accessed. Evaluated using benign traversal syntax only."
        )

        test_input = "....//atrace_traversal_canary_test"

        try:
            if method == "POST":
                resp = _send_request(engine, "POST", url, data={param: test_input}, timeout=timeout, allow_redirects=False)
            else:
                resp = _send_request(engine, "GET", url, params={param: test_input}, timeout=timeout, allow_redirects=False)

            if resp is None:
                if engine and getattr(engine, "request_limit_reached", False):
                    result.status = ValidationStatus.INCONCLUSIVE
                    result.evidence = f"Validation request limit reached ({engine.max_requests}). Request halted."
                    result.error_message = "VALIDATION_REQUEST_LIMIT_REACHED"
                else:
                    result.status = ValidationStatus.INCONCLUSIVE
                    result.evidence = "Target request could not be completed; validation inconclusive."
                return result

            body_lower = resp.text.lower()
            matched_err = None
            for pat in self.PATH_ERROR_PATTERNS:
                if re.search(pat, body_lower):
                    matched_err = pat
                    break

            if matched_err:
                result.status = ValidationStatus.VALIDATED
                result.confidence = Confidence.OBSERVED
                result.evidence = (
                    f"Parameter '{param}' produced observable path/file error signature ('{matched_err}') "
                    f"when supplied with controlled traversal indicator (Status: {resp.status_code})."
                )
                result.structured_evidence = {
                    "endpoint": url,
                    "parameter": param,
                    "test_input": test_input,
                    "matched_error": matched_err,
                    "error_indicator_observed": True,
                    "response_status": resp.status_code
                }
            else:
                result.status = ValidationStatus.NOT_VALIDATED
                result.evidence = (
                    f"Parameter '{param}' handled traversal input without producing observable path "
                    f"error disclosures or response divergence (Status: {resp.status_code})."
                )
                result.structured_evidence = {
                    "endpoint": url,
                    "parameter": param,
                    "response_status": resp.status_code,
                    "error_indicator_observed": False,
                    "traversal_observed": False
                }

        except requests.exceptions.Timeout:
            result.status = ValidationStatus.INCONCLUSIVE
            result.error_message = f"Request to '{url}' timed out after {timeout}s"
            result.evidence = "Target timed out during path traversal check."
        except requests.exceptions.RequestException as e:
            result.status = ValidationStatus.INCONCLUSIVE
            result.error_message = f"Connection failed to '{url}': {str(e)}"
            result.evidence = "Target unreachable during path traversal check."
        except Exception as e:
            logger.exception("Unexpected error in PathTraversalValidator")
            result.status = ValidationStatus.ERROR
            result.error_message = str(e)
            result.evidence = "Internal error encountered during path traversal validation."

        return result


# ---------------------------------------------------------------------------
# 4. COMMAND INJECTION INDICATOR VALIDATOR
# ---------------------------------------------------------------------------

class CommandInjectionValidator(BaseValidator):
    """
    Evaluates command injection findings under strict non-destructive safety policy.
    STRICT SAFETY: Zero OS command execution, zero file creation, zero file deletion, zero shells.
    Always returns NOT_APPLICABLE rather than attempting dangerous active execution.
    """
    name = "CommandInjectionValidator"
    description = "Evaluates command injection findings under strict non-destructive safety policy"

    def can_validate(self, finding: Finding) -> bool:
        if finding.category == "Vulnerability Intelligence" and not finding.parameter and not finding.endpoint:
            return False
        title_lower = finding.title.lower()
        if "command injection" in title_lower or "os command" in title_lower or "rce" in title_lower:
            return True
        if finding.parameter and finding.parameter.lower() in {"cmd", "exec", "ping", "command"}:
            return True
        return False

    def validate(
        self,
        finding: Finding,
        context: Optional[Any] = None,
        timeout: int = DEFAULT_VALIDATION_TIMEOUT,
        **kwargs: Any
    ) -> ValidationResult:
        return ValidationResult(
            finding_id=finding.id,
            target=finding.affected_asset,
            port=finding.affected_port,
            service=finding.affected_service or "HTTP",
            vulnerability_id=finding.id,
            owasp_category=finding.owasp_category or "A03:2021-Injection",
            status=ValidationStatus.NOT_APPLICABLE,
            confidence=finding.confidence,
            evidence="Automated command injection validation prohibited by non-destructive safety policy. Zero operating-system commands, files, or shells were executed.",
            validation_method="Command Injection Safety Policy Filter",
            limitations="Command injection verification requires safe out-of-band canary execution which is restricted in this non-destructive assessment mode.",
            structured_evidence={"action": "skipped_by_policy", "reason": "non_destructive_policy"}
        )


# ---------------------------------------------------------------------------
# 5. CSRF VALIDATOR
# ---------------------------------------------------------------------------

class CSRFValidator(BaseValidator):
    """
    Validates anti-CSRF protections on state-changing forms and session cookies without form submission.
    STRICT SAFETY: Never submits state-changing forms, never modifies account data.
    """
    name = "CSRFValidator"
    description = "Validates anti-CSRF protections on state-changing forms and session cookies without form submission"

    CSRF_TOKEN_NAMES = {
        "csrf", "xsrf", "_token", "csrf_token", "authenticity_token",
        "xsrf_token", "__requestverificationtoken", "csrfmiddlewaretoken"
    }

    def can_validate(self, finding: Finding) -> bool:
        if finding.category == "Vulnerability Intelligence" and not finding.parameter and not finding.endpoint:
            return False
        title_lower = finding.title.lower()
        if "csrf" in title_lower or "cross-site request forgery" in title_lower:
            return True
        return False

    def validate(
        self,
        finding: Finding,
        context: Optional[Any] = None,
        timeout: int = DEFAULT_VALIDATION_TIMEOUT,
        **kwargs: Any
    ) -> ValidationResult:
        engine = kwargs.get("engine")
        url = _resolve_url(finding)

        result = ValidationResult(
            finding_id=finding.id,
            target=finding.affected_asset,
            port=finding.affected_port,
            service=finding.affected_service or "HTTP",
            vulnerability_id=finding.id,
            owasp_category=finding.owasp_category or "A01:2021-Broken Access Control",
            validation_method="Passive Anti-CSRF Token & SameSite Cookie Analysis",
            confidence=finding.confidence,
            limitations="Passive inspection of form parameters and cookie security attributes only. State-changing forms were not submitted."
        )

        forms = []
        if context and isinstance(context, dict):
            surface = context.get("attack_surface")
            if surface and hasattr(surface, "endpoints"):
                for ep in surface.endpoints:
                    if ep.url == url or ep.path in url:
                        forms.append({"action": ep.url, "method": ep.method, "parameters": ep.parameters})

        try:
            resp = _send_request(engine, "GET", url, timeout=timeout)
            if resp:
                cookies_header = resp.headers.get("Set-Cookie", "")
                form_pattern = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
                for form_match in form_pattern.finditer(resp.text):
                    attrs_str = form_match.group(1)
                    inner_html = form_match.group(2)

                    method_m = re.search(r'method=["\']?(\w+)', attrs_str, re.IGNORECASE)
                    f_method = (method_m.group(1) if method_m else "GET").upper()

                    action_m = re.search(r'action=["\']?([^"\'\s>]+)', attrs_str, re.IGNORECASE)
                    f_action = action_m.group(1) if action_m else url

                    name_pattern = re.compile(r'<(?:input|textarea|select)\b[^>]*?name=["\']?([^"\'\s>]+)', re.IGNORECASE)
                    params = name_pattern.findall(inner_html)
                    forms.append({"action": f_action, "method": f_method, "parameters": params})

                has_samesite = "samesite=strict" in cookies_header.lower() or "samesite=lax" in cookies_header.lower()
                post_forms = [f for f in forms if f.get("method") == "POST"]

                if not post_forms:
                    if "csrf" in finding.evidence.lower():
                        result.status = ValidationStatus.VALIDATED
                        result.confidence = Confidence.PROBABLE
                        result.evidence = "Potential CSRF protection weakness: Application endpoint lacks anti-CSRF token verification on state-changing actions."
                    else:
                        result.status = ValidationStatus.NOT_VALIDATED
                        result.evidence = "No state-changing POST forms observed without anti-CSRF protection."
                    return result

                unprotected_forms = []
                for pf in post_forms:
                    param_names = [p.lower() for p in pf.get("parameters", [])]
                    has_csrf_token = any(any(tok in p for tok in self.CSRF_TOKEN_NAMES) for p in param_names)
                    if not has_csrf_token and not has_samesite:
                        unprotected_forms.append(pf.get("action"))

                if unprotected_forms:
                    result.status = ValidationStatus.VALIDATED
                    result.confidence = Confidence.PROBABLE
                    result.evidence = (
                        f"Potential CSRF protection weakness: State-changing form at '{unprotected_forms[0]}' "
                        f"lacks anti-CSRF token parameter and session cookies lack SameSite restrictions."
                    )
                    result.structured_evidence = {
                        "endpoint": url,
                        "unprotected_forms": unprotected_forms,
                        "post_forms_found": len(post_forms),
                        "has_csrf_token": False,
                        "samesite_cookie": has_samesite
                    }
                else:
                    result.status = ValidationStatus.NOT_VALIDATED
                    result.confidence = Confidence.CONFIRMED
                    result.evidence = "Anti-CSRF protection observed: State-changing forms include anti-CSRF token fields or session cookies enforce SameSite restrictions."
                    result.structured_evidence = {
                        "endpoint": url,
                        "post_forms_found": len(post_forms),
                        "has_csrf_token": True,
                        "samesite_cookie": has_samesite
                    }

        except Exception as e:
            logger.debug(f"CSRF validation check error: {e}")
            result.status = ValidationStatus.INCONCLUSIVE
            result.error_message = str(e)
            result.evidence = "Target request could not be completed; CSRF status inconclusive."

        return result


# ---------------------------------------------------------------------------
# 6. SSRF CANDIDATE VALIDATOR
# ---------------------------------------------------------------------------

class SSRFCandidateValidator(BaseValidator):
    """
    Identifies potential SSRF candidates without executing blind outbound or internal network queries.
    STRICT SAFETY: Zero requests to 127.0.0.1, localhost, 169.254.169.254, or RFC1918 addresses.
    Always returns NOT_VALIDATED without safe, authorized callback infrastructure.
    """
    name = "SSRFCandidateValidator"
    description = "Identifies potential SSRF candidates without executing blind outbound or internal network queries"

    SSRF_PARAM_NAMES = {
        "url", "uri", "redirect", "callback", "webhook",
        "fetch", "image", "resource", "dest", "feed", "link", "api"
    }

    def can_validate(self, finding: Finding) -> bool:
        if finding.category == "Vulnerability Intelligence" and not finding.parameter and not finding.endpoint:
            return False
        title_lower = finding.title.lower()
        if "ssrf" in title_lower or "server-side request forgery" in title_lower or "url redirection" in title_lower:
            return True
        if finding.parameter and finding.parameter.lower() in self.SSRF_PARAM_NAMES:
            return True
        return False

    def validate(
        self,
        finding: Finding,
        context: Optional[Any] = None,
        timeout: int = DEFAULT_VALIDATION_TIMEOUT,
        **kwargs: Any
    ) -> ValidationResult:
        param = finding.parameter or "url"
        url = _resolve_url(finding)

        return ValidationResult(
            finding_id=finding.id,
            target=finding.affected_asset,
            port=finding.affected_port,
            service=finding.affected_service or "HTTP",
            vulnerability_id=finding.id,
            owasp_category=finding.owasp_category or "A10:2021-Server-Side Request Forgery (SSRF)",
            status=ValidationStatus.NOT_VALIDATED,
            confidence=Confidence.INFORMATIONAL,
            evidence=f"Potential SSRF Candidate identified via parameter '{param}'. Live outbound request testing was not performed in accordance with non-destructive policy and lack of configured callback listener.",
            validation_method="SSRF Candidate Analysis",
            limitations="No internal IPs (127.0.0.1, 169.254.169.254, RFC1918) or external callback URLs were queried.",
            structured_evidence={"endpoint": url, "candidate_parameter": param, "live_callback_tested": False}
        )


# ---------------------------------------------------------------------------
# 7. IDOR / ACCESS CONTROL CANDIDATE VALIDATOR
# ---------------------------------------------------------------------------

class IDORCandidateValidator(BaseValidator):
    """
    Identifies potential direct object reference candidates without unauthorized multi-tenant access attempts.
    STRICT SAFETY: Zero credential manipulation, zero unauthorized account identifier substitution.
    """
    name = "IDORCandidateValidator"
    description = "Identifies potential direct object reference candidates without unauthorized access attempts"

    ID_PATTERNS = [
        r"/(user|account|order|profile|document|invoice|api|item|customer)s?/\d+",
        r"/(user|account|order|profile|document|invoice|api|item|customer)s?/[0-9a-fA-F-]{36}"
    ]

    def can_validate(self, finding: Finding) -> bool:
        if finding.category == "Vulnerability Intelligence" and not finding.parameter and not finding.endpoint:
            return False
        title_lower = finding.title.lower()
        if "idor" in title_lower or "direct object reference" in title_lower or "access control" in title_lower:
            return True
        target_str = finding.endpoint or finding.affected_asset
        for pat in self.ID_PATTERNS:
            if re.search(pat, target_str):
                return True
        if finding.parameter and finding.parameter.lower() in {"id", "user_id", "account_id", "doc_id", "order_id"}:
            return True
        return False

    def validate(
        self,
        finding: Finding,
        context: Optional[Any] = None,
        timeout: int = DEFAULT_VALIDATION_TIMEOUT,
        **kwargs: Any
    ) -> ValidationResult:
        target_str = finding.endpoint or finding.affected_asset

        return ValidationResult(
            finding_id=finding.id,
            target=finding.affected_asset,
            port=finding.affected_port,
            service=finding.affected_service or "HTTP",
            vulnerability_id=finding.id,
            owasp_category=finding.owasp_category or "A01:2021-Broken Access Control",
            status=ValidationStatus.NOT_VALIDATED,
            confidence=Confidence.INFORMATIONAL,
            evidence=f"Potential Access-Control Test Candidate: Endpoint contains direct object identifier pattern ('{target_str}'). Unauthorized identifier substitution was not attempted in accordance with non-destructive testing policy.",
            validation_method="IDOR Candidate Analysis",
            limitations="Multi-tenant account substitution was not performed; test requires pre-authenticated authorized test roles.",
            structured_evidence={"endpoint": target_str, "substitution_attempted": False}
        )


# ---------------------------------------------------------------------------
# 8. AUTHENTICATION SECURITY VALIDATOR
# ---------------------------------------------------------------------------

class AuthenticationSecurityValidator(BaseValidator):
    """
    Validates authentication transport security, session cookie security attributes (HttpOnly, Secure, SameSite),
    and cleartext login exposures.
    STRICT SAFETY: Zero brute force, zero password spraying, zero credential stuffing.
    """
    name = "AuthenticationSecurityValidator"
    description = "Validates authentication transport security and cookie attributes"

    def can_validate(self, finding: Finding) -> bool:
        if finding.category == "Vulnerability Intelligence" and not finding.parameter and not finding.endpoint:
            return False
        title_lower = finding.title.lower()
        owasp_cat = (finding.owasp_category or "").lower()

        if "authentication" in title_lower or "password" in title_lower or "login" in title_lower:
            return True
        if "httponly" in title_lower or "samesite" in title_lower or "cookie" in title_lower:
            return True
        if "a07" in owasp_cat:
            return True
        return False

    def validate(
        self,
        finding: Finding,
        context: Optional[Any] = None,
        timeout: int = DEFAULT_VALIDATION_TIMEOUT,
        **kwargs: Any
    ) -> ValidationResult:
        engine = kwargs.get("engine")
        url = _resolve_url(finding)
        title_lower = finding.title.lower()

        result = ValidationResult(
            finding_id=finding.id,
            target=finding.affected_asset,
            port=finding.affected_port,
            service=finding.affected_service or "HTTP",
            vulnerability_id=finding.id,
            owasp_category=finding.owasp_category or "A07:2021-Identification and Authentication Failures",
            validation_method="Authentication Security & Cookie Attribute Inspection",
            confidence=finding.confidence,
            limitations="Passive analysis of cookie security attributes and transport encryption only. Zero brute-force or credential spraying attempted."
        )

        try:
            resp = _send_request(engine, "GET", url, timeout=timeout)
            if resp is None:
                if engine and getattr(engine, "request_limit_reached", False):
                    result.status = ValidationStatus.INCONCLUSIVE
                    result.evidence = f"Validation request limit reached ({engine.max_requests}). Request halted."
                    result.error_message = "VALIDATION_REQUEST_LIMIT_REACHED"
                else:
                    result.status = ValidationStatus.INCONCLUSIVE
                    result.evidence = "Target request could not be completed; validation inconclusive."
                return result

            set_cookie_header = resp.headers.get("Set-Cookie", "")
            is_https = url.startswith("https://")

            # Case 1: Cleartext login form over unencrypted HTTP
            if "cleartext" in title_lower or "password" in title_lower:
                if not is_https:
                    result.status = ValidationStatus.VALIDATED
                    result.confidence = Confidence.CONFIRMED
                    result.evidence = f"Cleartext transmission verified: Authentication endpoint '{url}' is accessible over unencrypted HTTP."
                    return result
                else:
                    result.status = ValidationStatus.NOT_VALIDATED
                    result.evidence = f"Authentication endpoint '{url}' uses TLS encryption (HTTPS)."
                    return result

            # Case 2: Cookie Security Flags
            if set_cookie_header:
                cookie_lower = set_cookie_header.lower()
                missing_flags = []
                if "httponly" not in cookie_lower:
                    missing_flags.append("HttpOnly")
                if "secure" not in cookie_lower:
                    missing_flags.append("Secure")
                if "samesite" not in cookie_lower:
                    missing_flags.append("SameSite")

                if missing_flags:
                    result.status = ValidationStatus.VALIDATED
                    result.confidence = Confidence.CONFIRMED
                    result.evidence = f"Session cookie security weakness confirmed: Cookie lacks [{', '.join(missing_flags)}] attribute(s)."
                    result.structured_evidence = {
                        "endpoint": url,
                        "cookie_flags_missing": missing_flags,
                        "missing_cookie_flags": missing_flags
                    }
                else:
                    result.status = ValidationStatus.NOT_VALIDATED
                    result.confidence = Confidence.CONFIRMED
                    result.evidence = "Session cookies enforce HttpOnly, Secure, and SameSite security attributes."
                    result.structured_evidence = {
                        "endpoint": url,
                        "cookie_flags_missing": [],
                        "missing_cookie_flags": []
                    }
            else:
                result.status = ValidationStatus.NOT_VALIDATED
                result.evidence = "No new Set-Cookie headers observed in fresh HTTP response."

        except requests.exceptions.Timeout:
            result.status = ValidationStatus.INCONCLUSIVE
            result.error_message = f"Request to '{url}' timed out after {timeout}s"
            result.evidence = "Target timed out during authentication check."
        except requests.exceptions.RequestException as e:
            result.status = ValidationStatus.INCONCLUSIVE
            result.error_message = f"Connection failed to '{url}': {str(e)}"
            result.evidence = "Target unreachable during authentication check."
        except Exception as e:
            logger.exception("Unexpected error in AuthenticationSecurityValidator")
            result.status = ValidationStatus.ERROR
            result.error_message = str(e)
            result.evidence = "Internal error encountered during authentication validation."

        return result


# ---------------------------------------------------------------------------
# 9. HEADER VALIDATOR
# ---------------------------------------------------------------------------

class HeaderValidator(BaseValidator):
    """
    Validates missing or insecure HTTP security headers by executing a fresh,
    non-destructive GET request to the target endpoint.
    """
    name = "HeaderValidator"
    description = "Validates missing or misconfigured HTTP security headers"

    KNOWN_HEADERS = {
        "strict-transport-security": "Strict-Transport-Security",
        "hsts": "Strict-Transport-Security",
        "content-security-policy": "Content-Security-Policy",
        "csp": "Content-Security-Policy",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
        "feature-policy": "Permissions-Policy"
    }

    def can_validate(self, finding: Finding) -> bool:
        title_lower = finding.title.lower()
        cat_lower = finding.category.lower()
        owasp_cat = finding.owasp_category or ""

        if "header" in title_lower or "header" in cat_lower:
            return True
        if "hsts" in title_lower or "csp" in title_lower:
            return True
        if "A05" in owasp_cat and ("header" in title_lower or "hsts" in title_lower):
            return True
        return False

    def _extract_header_name(self, finding: Finding) -> str:
        text = f"{finding.title} {finding.evidence}".lower()
        for key, canonical in self.KNOWN_HEADERS.items():
            if key in text:
                return canonical
        return "Security Header"

    def validate(
        self,
        finding: Finding,
        context: Optional[Any] = None,
        timeout: int = DEFAULT_VALIDATION_TIMEOUT,
        **kwargs: Any
    ) -> ValidationResult:
        engine = kwargs.get("engine")
        header_name = self._extract_header_name(finding)
        url = _resolve_url(finding)

        result = ValidationResult(
            finding_id=finding.id,
            target=finding.affected_asset,
            port=finding.affected_port,
            service=finding.affected_service or "HTTP",
            vulnerability_id=finding.id,
            owasp_category=finding.owasp_category,
            validation_method="Fresh HTTP Header Inspection",
            confidence=finding.confidence
        )

        try:
            resp = _send_request(engine, "GET", url, timeout=timeout, allow_redirects=True)
            if resp is None:
                if engine and getattr(engine, "request_limit_reached", False):
                    result.status = ValidationStatus.INCONCLUSIVE
                    result.evidence = f"Validation request limit reached ({engine.max_requests}). Request halted."
                    result.error_message = "VALIDATION_REQUEST_LIMIT_REACHED"
                else:
                    result.status = ValidationStatus.INCONCLUSIVE
                    result.evidence = "Target request could not be completed; validation inconclusive."
                return result

            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            target_key = header_name.lower()

            if target_key not in headers_lower:
                result.status = ValidationStatus.VALIDATED
                result.evidence = (
                    f"Fresh HTTP GET to '{url}' returned status {resp.status_code}. "
                    f"Verified that required security header '{header_name}' is absent from response."
                )
                result.confidence = Confidence.CONFIRMED
            else:
                result.status = ValidationStatus.NOT_VALIDATED
                result.evidence = (
                    f"Fresh HTTP GET to '{url}' returned status {resp.status_code}. "
                    f"Security header '{header_name}' was observed present: '{headers_lower[target_key]}'."
                )
                result.confidence = Confidence.OBSERVED

        except requests.exceptions.Timeout:
            result.status = ValidationStatus.INCONCLUSIVE
            result.error_message = f"Request to '{url}' timed out after {timeout}s during header validation"
            result.evidence = "Target did not respond within timeout window; header status could not be verified."
        except requests.exceptions.RequestException as e:
            result.status = ValidationStatus.INCONCLUSIVE
            result.error_message = f"Connection failed to '{url}': {str(e)}"
            result.evidence = "Target endpoint unreachable; validation inconclusive."
        except Exception as e:
            logger.exception("Unexpected error in HeaderValidator")
            result.status = ValidationStatus.ERROR
            result.error_message = str(e)
            result.evidence = "Internal error encountered during header validation."

        return result


# ---------------------------------------------------------------------------
# 10. RESPONSE BEHAVIOR VALIDATOR
# ---------------------------------------------------------------------------

class ResponseBehaviorValidator(BaseValidator):
    """
    Validates observable HTTP response behavior such as status codes or error messages.
    """
    name = "ResponseBehaviorValidator"
    description = "Validates observable HTTP response codes and error page behaviors"

    def can_validate(self, finding: Finding) -> bool:
        title_lower = finding.title.lower()
        if "response" in title_lower or "status" in title_lower or "error" in title_lower:
            return True
        return False

    def validate(
        self,
        finding: Finding,
        context: Optional[Any] = None,
        timeout: int = DEFAULT_VALIDATION_TIMEOUT,
        **kwargs: Any
    ) -> ValidationResult:
        engine = kwargs.get("engine")
        url = _resolve_url(finding)
        result = ValidationResult(
            finding_id=finding.id,
            target=finding.affected_asset,
            port=finding.affected_port,
            service=finding.affected_service or "HTTP",
            vulnerability_id=finding.id,
            owasp_category=finding.owasp_category,
            validation_method="HTTP Response Behavior Verification",
            confidence=finding.confidence
        )

        try:
            resp = _send_request(engine, "GET", url, timeout=timeout, allow_redirects=True)
            if resp is None:
                if engine and getattr(engine, "request_limit_reached", False):
                    result.status = ValidationStatus.INCONCLUSIVE
                    result.evidence = f"Validation request limit reached ({engine.max_requests}). Request halted."
                    result.error_message = "VALIDATION_REQUEST_LIMIT_REACHED"
                else:
                    result.status = ValidationStatus.INCONCLUSIVE
                    result.evidence = "Target request could not be completed; validation inconclusive."
                return result

            expected_status = None
            status_match = re.search(r"status\s*(\d{3})", finding.evidence, re.IGNORECASE)
            if status_match:
                expected_status = int(status_match.group(1))

            if expected_status and resp.status_code == expected_status:
                result.status = ValidationStatus.VALIDATED
                result.evidence = f"Target '{url}' returned expected status code {resp.status_code}."
                result.confidence = Confidence.CONFIRMED
            elif expected_status and resp.status_code != expected_status:
                result.status = ValidationStatus.NOT_VALIDATED
                result.evidence = (
                    f"Target '{url}' returned status code {resp.status_code}, "
                    f"differing from reported status {expected_status}."
                )
            else:
                result.status = ValidationStatus.VALIDATED
                result.evidence = f"Target '{url}' responded with status code {resp.status_code}."
                result.confidence = Confidence.OBSERVED

        except requests.exceptions.Timeout:
            result.status = ValidationStatus.INCONCLUSIVE
            result.error_message = f"Request to '{url}' timed out after {timeout}s"
            result.evidence = "Target did not respond within timeout window."
        except requests.exceptions.RequestException as e:
            result.status = ValidationStatus.INCONCLUSIVE
            result.error_message = f"Connection failed to '{url}': {str(e)}"
            result.evidence = "Target endpoint unreachable; validation inconclusive."
        except Exception as e:
            logger.exception("Unexpected error in ResponseBehaviorValidator")
            result.status = ValidationStatus.ERROR
            result.error_message = str(e)
            result.evidence = "Internal error encountered during response behavior validation."

        return result


# ---------------------------------------------------------------------------
# 11. MISCONFIGURATION VALIDATOR
# ---------------------------------------------------------------------------

class MisconfigurationValidator(BaseValidator):
    """
    Validates observable security misconfigurations such as directory listing,
    banner disclosure, or HTTP TRACE method.
    """
    name = "MisconfigurationValidator"
    description = "Validates observable web security misconfigurations (A05)"

    DIRECTORY_LISTING_SIGNATURES = [
        "index of /",
        "directory listing for",
        "<title>index of",
        "parent directory"
    ]

    def can_validate(self, finding: Finding) -> bool:
        title_lower = finding.title.lower()
        owasp_cat = finding.owasp_category or ""
        cat_lower = finding.category.lower()

        if "misconfiguration" in cat_lower or "a05" in owasp_cat.lower():
            return True
        if "directory listing" in title_lower or "banner" in title_lower or "trace" in title_lower:
            return True
        return False

    def validate(
        self,
        finding: Finding,
        context: Optional[Any] = None,
        timeout: int = DEFAULT_VALIDATION_TIMEOUT,
        **kwargs: Any
    ) -> ValidationResult:
        engine = kwargs.get("engine")
        url = _resolve_url(finding)
        title_lower = finding.title.lower()

        result = ValidationResult(
            finding_id=finding.id,
            target=finding.affected_asset,
            port=finding.affected_port,
            service=finding.affected_service or "HTTP",
            vulnerability_id=finding.id,
            owasp_category=finding.owasp_category,
            validation_method="Observable Misconfiguration Verification",
            confidence=finding.confidence
        )

        try:
            if "trace" in title_lower:
                resp = _send_request(engine, "TRACE", url, timeout=timeout)
                if resp is None:
                    result.status = ValidationStatus.INCONCLUSIVE
                    result.evidence = "Target request could not be completed; validation inconclusive."
                    return result
                if resp.status_code == 200:
                    result.status = ValidationStatus.VALIDATED
                    result.evidence = f"HTTP TRACE request to '{url}' succeeded with status 200 OK."
                    result.confidence = Confidence.CONFIRMED
                else:
                    result.status = ValidationStatus.NOT_VALIDATED
                    result.evidence = f"HTTP TRACE request to '{url}' was rejected with status {resp.status_code}."
                return result

            resp = _send_request(engine, "GET", url, timeout=timeout, allow_redirects=True)
            if resp is None:
                if engine and getattr(engine, "request_limit_reached", False):
                    result.status = ValidationStatus.INCONCLUSIVE
                    result.evidence = f"Validation request limit reached ({engine.max_requests}). Request halted."
                    result.error_message = "VALIDATION_REQUEST_LIMIT_REACHED"
                else:
                    result.status = ValidationStatus.INCONCLUSIVE
                    result.evidence = "Target request could not be completed; validation inconclusive."
                return result

            if "directory listing" in title_lower or "directory browsing" in title_lower:
                body_lower = resp.text.lower()
                matched = any(sig in body_lower for sig in self.DIRECTORY_LISTING_SIGNATURES)
                if matched and resp.status_code == 200:
                    result.status = ValidationStatus.VALIDATED
                    result.evidence = f"Directory listing signature confirmed in HTTP response body at '{url}'."
                    result.confidence = Confidence.CONFIRMED
                else:
                    result.status = ValidationStatus.NOT_VALIDATED
                    result.evidence = f"Directory listing signature not found at '{url}' (Status: {resp.status_code})."
            elif "banner" in title_lower or "server" in title_lower or "information disclosure" in title_lower:
                server_hdr = resp.headers.get("Server") or resp.headers.get("X-Powered-By")
                if server_hdr:
                    result.status = ValidationStatus.VALIDATED
                    result.evidence = f"Server software banner still exposed in HTTP header: '{server_hdr}'."
                    result.confidence = Confidence.OBSERVED
                else:
                    result.status = ValidationStatus.NOT_VALIDATED
                    result.evidence = "Server software banner is not disclosed in fresh HTTP response."
            else:
                if resp.status_code in [200, 403, 500]:
                    result.status = ValidationStatus.VALIDATED
                    result.evidence = f"Endpoint '{url}' is responsive and returned status {resp.status_code}."
                else:
                    result.status = ValidationStatus.NOT_VALIDATED
                    result.evidence = f"Endpoint '{url}' returned status {resp.status_code}."

        except requests.exceptions.Timeout:
            result.status = ValidationStatus.INCONCLUSIVE
            result.error_message = f"Request to '{url}' timed out after {timeout}s during misconfiguration check"
            result.evidence = "Target timed out during misconfiguration check."
        except requests.exceptions.RequestException as e:
            result.status = ValidationStatus.INCONCLUSIVE
            result.error_message = f"Connection failed to '{url}': {str(e)}"
            result.evidence = "Target endpoint unreachable; validation inconclusive."
        except Exception as e:
            logger.exception("Unexpected error in MisconfigurationValidator")
            result.status = ValidationStatus.ERROR
            result.error_message = str(e)
            result.evidence = "Internal error encountered during misconfiguration validation."

        return result


# ---------------------------------------------------------------------------
# 12. SERVICE PRESENCE VALIDATOR (CVE Port Exposure)
# ---------------------------------------------------------------------------

class ServicePresenceValidator(BaseValidator):
    """
    Validates service presence and port reachability for CVE / Vulnerability Intelligence findings.
    STRICT SAFETY: Zero exploit execution, zero payload transmission. Only verifies TCP handshake / port reachability.
    """
    name = "ServicePresenceValidator"
    description = "Verifies TCP port exposure and service reachability without exploitation"

    def can_validate(self, finding: Finding) -> bool:
        if finding.category == "Vulnerability Intelligence":
            return True
        if finding.affected_port is not None and ("cve-" in finding.title.lower() or "cve-" in finding.id.lower()):
            return True
        return False

    def validate(
        self,
        finding: Finding,
        context: Optional[Any] = None,
        timeout: int = DEFAULT_VALIDATION_TIMEOUT,
        **kwargs: Any
    ) -> ValidationResult:
        host = finding.affected_asset
        if "://" in host:
            parsed = urlparse(host)
            host = parsed.hostname or host

        port = finding.affected_port
        if not port:
            if "://" in finding.affected_asset:
                parsed = urlparse(finding.affected_asset)
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
            else:
                port = 80

        result = ValidationResult(
            finding_id=finding.id,
            target=host,
            port=port,
            service=finding.affected_service or "Unknown",
            vulnerability_id=finding.id,
            owasp_category=finding.owasp_category,
            validation_method="Non-Destructive TCP Service Handshake",
            confidence=finding.confidence
        )

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            res = sock.connect_ex((host, port))

            if res == 0:
                result.status = ValidationStatus.VALIDATED
                result.evidence = (
                    f"Target port {port} confirmed actively open on host '{host}'. "
                    f"Service '{finding.affected_service or 'detected service'}' is live and reachable; "
                    f"vulnerability candidate '{finding.title}' remains exposed on attack surface."
                )
                result.confidence = Confidence.OBSERVED
            else:
                result.status = ValidationStatus.NOT_VALIDATED
                result.evidence = (
                    f"Target port {port} on host '{host}' was not reachable (connect_ex returned code {res}). "
                    f"Service is inactive or filtered."
                )
        except socket.timeout:
            result.status = ValidationStatus.INCONCLUSIVE
            result.error_message = f"Connection to {host}:{port} timed out after {timeout}s"
            result.evidence = "TCP handshake timed out; service status inconclusive."
        except Exception as e:
            result.status = ValidationStatus.INCONCLUSIVE
            result.error_message = f"Socket connection failed for {host}:{port}: {str(e)}"
            result.evidence = "Network connection failed during service handshake check."
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return result


# ---------------------------------------------------------------------------
# 13. FALLBACK VALIDATOR
# ---------------------------------------------------------------------------

class FallbackValidator(BaseValidator):
    """
    Default validator for findings that cannot be validated deterministically or safely.
    """
    name = "FallbackValidator"
    description = "Marks unsupported or potentially dangerous checks as NOT_APPLICABLE"

    def can_validate(self, finding: Finding) -> bool:
        return True

    def validate(
        self,
        finding: Finding,
        context: Optional[Any] = None,
        timeout: int = DEFAULT_VALIDATION_TIMEOUT,
        **kwargs: Any
    ) -> ValidationResult:
        return ValidationResult(
            finding_id=finding.id,
            target=finding.affected_asset,
            port=finding.affected_port,
            service=finding.affected_service,
            vulnerability_id=finding.id,
            owasp_category=finding.owasp_category,
            status=ValidationStatus.NOT_APPLICABLE,
            confidence=finding.confidence,
            evidence="Finding type does not support non-destructive active validation.",
            validation_method="N/A (Non-Destructive Policy)"
        )
