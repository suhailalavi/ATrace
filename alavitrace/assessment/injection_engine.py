import logging
import urllib.parse
import hashlib
from typing import List, Dict, Set, Optional, Any

from alavitrace.core.models import Severity, Confidence
from alavitrace.assessment.models import (
    OwaspCategory,
    DetectionType,
    AssessmentContext,
    OWASPFinding
)
from alavitrace.assessment.injection_payloads import (
    get_sqli_payloads,
    generate_xss_canary,
    COMMAND_PARAM_CANDIDATES
)
from alavitrace.assessment.http_probe import (
    InjectionTarget,
    HttpProber,
    ProbeResponse
)
from alavitrace.assessment.response_analysis import (
    detect_sqli_error_difference,
    analyze_xss_reflection,
    XssContext
)

logger = logging.getLogger("AlaviTrace")

def discover_injection_targets(
    context: AssessmentContext,
    max_targets: int = 5
) -> List[InjectionTarget]:
    """
    Extracts observed query and form parameters from HTTP enumeration results.
    Never invents arbitrary endpoints or unseen parameters.
    """
    targets: List[InjectionTarget] = []
    seen: Set[str] = set()

    for res in context.http_results:
        if not res.status_code:
            continue

        base_raw_url = res.final_url or res.url
        parsed = urllib.parse.urlparse(base_raw_url)

        # 1. Query Parameters from URL
        if parsed.query:
            query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            all_params = {k: v for k, v in query_pairs}
            clean_base = urllib.parse.urlunparse(parsed._replace(query=""))

            for p_name, p_val in query_pairs:
                dedup_key = f"{clean_base}|GET|{p_name}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                other_params = {k: v for k, v in all_params.items() if k != p_name}
                targets.append(InjectionTarget(
                    url=clean_base,
                    http_method="GET",
                    parameter_name=p_name,
                    original_value=p_val or "test",
                    parameter_location="query",
                    source="query_string",
                    additional_params=other_params
                ))
                if len(targets) >= max_targets:
                    return targets

        # 2. HTML Form Inputs
        for form in getattr(res, "forms", []):
            action_url = form.get("action") or base_raw_url
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])

            form_inputs_dict = {
                inp.get("name"): (inp.get("value") or "test")
                for inp in inputs if inp.get("name")
            }

            for inp in inputs:
                p_name = inp.get("name")
                if not p_name:
                    continue

                # Skip submit buttons and CSRF token fields from being targeted
                p_type = inp.get("type", "text").lower()
                if p_type in ["submit", "button", "image", "reset"]:
                    continue
                if any(tok in p_name.lower() for tok in ["csrf", "xsrf", "token", "authenticity_token", "nonce"]):
                    continue

                dedup_key = f"{action_url}|{method}|{p_name}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                other_params = {k: v for k, v in form_inputs_dict.items() if k != p_name}
                targets.append(InjectionTarget(
                    url=action_url,
                    http_method=method,
                    parameter_name=p_name,
                    original_value=inp.get("value") or "test",
                    parameter_location="form",
                    source="html_form",
                    additional_params=other_params
                ))
                if len(targets) >= max_targets:
                    return targets

    return targets

class InjectionAssessmentResult:
    """
    Summarizes the execution and findings of the controlled A03 Injection Assessment.
    """
    def __init__(
        self,
        is_executed: bool,
        targets_evaluated: int,
        requests_sent: int,
        budget_exhausted: bool,
        rate_limited: bool,
        findings: List[OWASPFinding],
        sqli_candidates: int = 0,
        xss_candidates: int = 0,
        command_candidates: int = 0,
        notes: Optional[List[str]] = None
    ):
        self.is_executed = is_executed
        self.targets_evaluated = targets_evaluated
        self.requests_sent = requests_sent
        self.budget_exhausted = budget_exhausted
        self.rate_limited = rate_limited
        self.findings = findings
        self.sqli_candidates = sqli_candidates
        self.xss_candidates = xss_candidates
        self.command_candidates = command_candidates
        self.notes = notes or []

    def to_dict(self) -> Dict[str, Any]:
        """Serializes injection assessment results to a structured dictionary."""
        return {
            "is_executed": self.is_executed,
            "targets_evaluated": self.targets_evaluated,
            "requests_sent": self.requests_sent,
            "budget_exhausted": self.budget_exhausted,
            "rate_limited": self.rate_limited,
            "total_candidates": len(self.findings),
            "sqli_candidates": self.sqli_candidates,
            "xss_candidates": self.xss_candidates,
            "command_candidates": self.command_candidates,
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes
        }

class ControlledInjectionDetector:
    """
    Executes controlled, deterministic, non-destructive A03 Injection assessment.
    Tests observed parameters against SQL syntax perturbation, harmless XSS canary reflection,
    and safe command parameter heuristics.
    """

    def __init__(
        self,
        max_requests: int = 20,
        max_targets: int = 5,
        timeout: int = 5,
        delay_seconds: float = 0.1
    ):
        self.max_requests = max_requests
        self.max_targets = max_targets
        self.timeout = timeout
        self.delay_seconds = delay_seconds

    def execute(self, context: AssessmentContext) -> InjectionAssessmentResult:
        """
        Executes controlled injection testing against the provided AssessmentContext.
        """
        notes: List[str] = []
        findings: List[OWASPFinding] = []
        sqli_count = 0
        xss_count = 0
        cmd_count = 0

        # 1. Discover observed injection targets
        targets = discover_injection_targets(context, max_targets=self.max_targets)
        prober = HttpProber(
            max_requests=self.max_requests,
            timeout=self.timeout,
            delay_seconds=self.delay_seconds
        )

        if not targets:
            # Passive fallback: check observed parameters for command injection heuristics
            for res in context.http_results:
                observed_params = getattr(res, "observed_parameters", [])
                for p in observed_params:
                    if p.lower() in COMMAND_PARAM_CANDIDATES:
                        h = hashlib.md5(f"{res.url}|{p}".encode()).hexdigest()[:6]
                        findings.append(OWASPFinding.create(
                            id=f"OWASP-A03-CMDI-{h}",
                            title="Potential Command Injection Candidate",
                            owasp_category=OwaspCategory.A03_2021.value,
                            severity=Severity.LOW,
                            confidence=Confidence.POTENTIAL,
                            description="Parameter naming conventions suggest potential command-processing or execution functionality.",
                            evidence=f"Observed parameter '{p}' on endpoint {res.url} matches known command execution parameter conventions.",
                            affected_asset=res.url,
                            endpoint=res.url,
                            http_method="GET",
                            parameter=p,
                            detection_type=DetectionType.PASSIVE.value,
                            recommendation="Ensure the application uses safe native APIs rather than shell invocations. Enforce strict allowlists.",
                            limitations="Parameter naming heuristic only. Command execution was not tested. Manual validation is required.",
                            references=["https://owasp.org/Top10/A03_2021-Injection/"]
                        ))
                        cmd_count += 1
                        break

            return InjectionAssessmentResult(
                is_executed=True,
                targets_evaluated=0,
                requests_sent=0,
                budget_exhausted=False,
                rate_limited=False,
                findings=findings,
                sqli_candidates=0,
                xss_candidates=0,
                command_candidates=cmd_count,
                notes=["No active query or form parameters discovered for dynamic injection probing."]
            )

        logger.info(f"Starting controlled injection testing against {len(targets)} targets (Budget: {self.max_requests} requests)...")

        # 2. Iterate discovered targets
        for target in targets:
            if not prober.can_send_request():
                notes.append("Injection testing stopped because configured request budget or rate limit was reached.")
                break

            target_id = f"{target.url} [{target.parameter_name}]"
            logger.debug(f"Testing injection target: {target_id}")

            # Baseline Request
            baseline_resp = prober.get_baseline(target)
            if baseline_resp.error_message:
                notes.append(f"Baseline failed for {target_id}: {baseline_resp.error_message}")
                continue

            # Command Injection Heuristic Check
            if target.parameter_name.lower() in COMMAND_PARAM_CANDIDATES:
                h = hashlib.md5(f"{target.url}|{target.parameter_name}|cmd".encode()).hexdigest()[:6]
                findings.append(OWASPFinding.create(
                    id=f"OWASP-A03-CMDI-{h}",
                    title="Potential Command Injection Candidate",
                    owasp_category=OwaspCategory.A03_2021.value,
                    severity=Severity.LOW,
                    confidence=Confidence.POTENTIAL,
                    description="Observed parameter naming suggests potential command-processing or execution functionality.",
                    evidence=f"Parameter '{target.parameter_name}' on {target.url} matches known command execution parameter conventions.",
                    affected_asset=target.url,
                    endpoint=target.url,
                    http_method=target.http_method,
                    parameter=target.parameter_name,
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation="Ensure the application uses safe native APIs rather than shell invocations. Validate user input on the server side.",
                    limitations="Parameter naming heuristic only. No command execution payloads were tested. Manual validation is required.",
                    references=["https://owasp.org/Top10/A03_2021-Injection/"]
                ))
                cmd_count += 1

            # A. SQL Injection Testing (Controlled Syntax Perturbations)
            for sqli_payload in get_sqli_payloads():
                if not prober.can_send_request():
                    break

                test_resp = prober.send_probe(target, sqli_payload.value)
                if test_resp.error_message:
                    continue

                diff = detect_sqli_error_difference(baseline_resp.body, test_resp.body)
                if diff:
                    h = hashlib.md5(f"{target.url}|{target.parameter_name}|sqli".encode()).hexdigest()[:6]
                    findings.append(OWASPFinding.create(
                        id=f"OWASP-A03-SQLI-{h}",
                        title="Potential SQL Injection",
                        owasp_category=OwaspCategory.A03_2021.value,
                        severity=Severity.HIGH,
                        confidence=Confidence.PROBABLE,
                        description=(
                            "Controlled input mutation produced a database-specific error signature not present "
                            "in the baseline response. This indicates user-supplied input may be concatenated directly "
                            "into database query strings."
                        ),
                        evidence=(
                            f"Controlled input '{sqli_payload.value}' on parameter '{target.parameter_name}' ({target.http_method}) "
                            f"triggered a {diff['database']} error: '{diff['matched_snippet']}'. Signature was absent in baseline response."
                        ),
                        affected_asset=target.url,
                        endpoint=target.url,
                        http_method=target.http_method,
                        parameter=target.parameter_name,
                        detection_type=DetectionType.ACTIVE.value,
                        recommendation="Enforce parameterized queries (prepared statements) or use an ORM across all database interactions.",
                        limitations="No data extraction or database exploitation was performed. Manual validation is required.",
                        references=["https://owasp.org/Top10/A03_2021-Injection/"]
                    ))
                    sqli_count += 1
                    break

            # B. XSS Reflection Testing (Harmless Canary)
            if prober.can_send_request():
                canary = generate_xss_canary()
                xss_resp = prober.send_probe(target, canary.value)

                if not xss_resp.error_message:
                    reflection = analyze_xss_reflection(baseline_resp.body, xss_resp.body, canary.value)
                    if reflection:
                        ctx = reflection["context"]
                        encoded = reflection["is_encoded"]

                        if ctx == XssContext.SCRIPT.value:
                            sev = Severity.HIGH
                            conf = Confidence.PROBABLE
                        elif ctx in [XssContext.ATTRIBUTE.value, XssContext.URL.value]:
                            sev = Severity.MEDIUM
                            conf = Confidence.PROBABLE if not encoded else Confidence.POTENTIAL
                        else:
                            sev = Severity.LOW
                            conf = Confidence.POTENTIAL if encoded else Confidence.OBSERVED

                        h = hashlib.md5(f"{target.url}|{target.parameter_name}|xss".encode()).hexdigest()[:6]
                        findings.append(OWASPFinding.create(
                            id=f"OWASP-A03-XSS-{h}",
                            title="Potential Reflected Cross-Site Scripting (XSS)",
                            owasp_category=OwaspCategory.A03_2021.value,
                            severity=sev,
                            confidence=conf,
                            description=(
                                f"Controlled test input was reflected in the HTTP response within a {ctx} context. "
                                "If unencoded user input is rendered in executable contexts, client-side script execution may occur."
                            ),
                            evidence=(
                                f"Unique canary '{canary.value}' sent via parameter '{target.parameter_name}' "
                                f"was reflected in {ctx} context (HTML encoded: {encoded}). Canary was absent in baseline response."
                            ),
                            affected_asset=target.url,
                            endpoint=target.url,
                            http_method=target.http_method,
                            parameter=target.parameter_name,
                            detection_type=DetectionType.ACTIVE.value,
                            recommendation="Implement context-aware output encoding (HTML, JavaScript, attribute) and enforce a strong Content-Security-Policy.",
                            limitations="Harmless canary reflection only. Browser script execution was not performed. Manual validation is required.",
                            references=["https://owasp.org/Top10/A03_2021-Injection/"]
                        ))
                        xss_count += 1

        if prober.budget_exhausted:
            notes.append(f"Configured request budget of {prober.max_requests} requests was reached.")
        if prober.rate_limited:
            notes.append("Target returned HTTP 429 Too Many Requests; probing was safely halted.")

        return InjectionAssessmentResult(
            is_executed=True,
            targets_evaluated=len(targets),
            requests_sent=prober.requests_sent,
            budget_exhausted=prober.budget_exhausted,
            rate_limited=prober.rate_limited,
            findings=findings,
            sqli_candidates=sqli_count,
            xss_candidates=xss_count,
            command_candidates=cmd_count,
            notes=notes
        )
