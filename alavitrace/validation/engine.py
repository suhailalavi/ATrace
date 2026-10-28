import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse
import requests

from alavitrace.core.models import Finding
from alavitrace.validation.models import ValidationStatus, ValidationResult
from alavitrace.validation.base import (
    BaseValidator,
    DEFAULT_VALIDATION_TIMEOUT,
    DEFAULT_MAX_VALIDATION_REQUESTS
)
from alavitrace.validation.registry import ValidatorRegistry

logger = logging.getLogger("AlaviTrace")

@dataclass
class ValidationEngineResult:
    """
    Container summarizing validation execution across candidate findings.
    """
    total_candidates: int
    results: Dict[str, ValidationResult] = field(default_factory=dict)
    requests_sent: int = 0
    request_limit_reached: bool = False

    @property
    def validated_count(self) -> int:
        return sum(1 for r in self.results.values() if r.status == ValidationStatus.VALIDATED)

    @property
    def not_validated_count(self) -> int:
        return sum(1 for r in self.results.values() if r.status == ValidationStatus.NOT_VALIDATED)

    @property
    def inconclusive_count(self) -> int:
        return sum(1 for r in self.results.values() if r.status == ValidationStatus.INCONCLUSIVE)

    @property
    def not_applicable_count(self) -> int:
        return sum(1 for r in self.results.values() if r.status == ValidationStatus.NOT_APPLICABLE)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results.values() if r.status == ValidationStatus.ERROR)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_candidates": self.total_candidates,
            "requests_sent": self.requests_sent,
            "request_limit_reached": self.request_limit_reached,
            "validated_count": self.validated_count,
            "not_validated_count": self.not_validated_count,
            "inconclusive_count": self.inconclusive_count,
            "not_applicable_count": self.not_applicable_count,
            "error_count": self.error_count,
            "results": {fid: res.to_dict() for fid, res in self.results.items()}
        }


class ValidationEngine:
    """
    Orchestrates controlled, deterministic, non-destructive validation of prioritized findings.
    Strictly adheres to target scope boundaries, request budgets, and timeouts.
    """

    def __init__(
        self,
        registry: Optional[ValidatorRegistry] = None,
        timeout: int = DEFAULT_VALIDATION_TIMEOUT,
        max_requests: int = DEFAULT_MAX_VALIDATION_REQUESTS,
        attack_surface: Optional[Any] = None
    ):
        self.registry = registry or ValidatorRegistry()
        self.timeout = timeout
        self.max_requests = max_requests
        self.attack_surface = attack_surface
        self.requests_sent: int = 0
        self.request_limit_reached: bool = False
        self._current_scope: Optional[str] = None

    def _is_target_in_scope(self, finding: Finding, target_scope: Optional[str]) -> bool:
        """
        Verifies that the finding's target matches the authorized scope.
        Prevents outbound testing against off-scope or redirected domains.
        """
        if not target_scope:
            return True

        asset = finding.affected_asset or ""
        endpoint = finding.endpoint or ""

        # Normalize target scope
        scope = target_scope.lower().strip()
        if "://" in scope:
            scope = urlparse(scope).hostname or scope

        for candidate in [asset, endpoint]:
            if not candidate:
                continue
            cand_host = candidate.lower().strip()
            if "://" in cand_host:
                cand_host = urlparse(cand_host).hostname or cand_host
            if ":" in cand_host:
                cand_host = cand_host.split(":")[0]

            if cand_host == scope or cand_host in [f"www.{scope}", scope.replace("www.", "")]:
                return True

        return False

    def is_url_in_scope(self, url: str) -> bool:
        """Checks if a candidate URL belongs strictly to authorized target scope."""
        if not self._current_scope:
            return True
        try:
            parsed = urlparse(url)
            cand_host = (parsed.hostname or "").lower().strip()
            if not cand_host:
                return False
            scope = self._current_scope.lower().strip()
            if "://" in scope:
                scope = urlparse(scope).hostname or scope
            return cand_host == scope or cand_host in [f"www.{scope}", scope.replace("www.", "")]
        except Exception:
            return False

    def execute_request(self, method: str, url: str, **kwargs: Any) -> Optional[requests.Response]:
        """
        Centralized request executor enforcing the global validation request budget,
        scope enforcement, timeouts, and safe error handling.
        """
        if self.requests_sent >= self.max_requests:
            self.request_limit_reached = True
            logger.info(f"ValidationEngine reached maximum request budget ({self.max_requests}). Request halted.")
            return None

        if not self.is_url_in_scope(url):
            logger.warning(f"ValidationEngine refused outbound request to off-scope URL: '{url}'")
            return None

        # Check for blocked internal addresses (SSRF safety guard)
        parsed = urlparse(url)
        cand_host = (parsed.hostname or "").lower()
        if cand_host in ["127.0.0.1", "localhost", "169.254.169.254", "0.0.0.0", "::1"]:
            logger.warning(f"ValidationEngine refused request to restricted internal host: '{cand_host}'")
            return None

        self.requests_sent += 1
        req_timeout = kwargs.pop("timeout", self.timeout)
        headers = kwargs.pop("headers", {})
        if "User-Agent" not in headers:
            from alavitrace.validation.base import DEFAULT_VALIDATION_USER_AGENT
            headers["User-Agent"] = DEFAULT_VALIDATION_USER_AGENT

        try:
            requests.packages.urllib3.disable_warnings()
            req_m = method.upper()
            if req_m == "GET":
                resp = requests.get(url, timeout=req_timeout, verify=False, headers=headers, **kwargs)
            elif req_m == "POST":
                resp = requests.post(url, timeout=req_timeout, verify=False, headers=headers, **kwargs)
            elif req_m == "HEAD":
                resp = requests.head(url, timeout=req_timeout, verify=False, headers=headers, **kwargs)
            elif req_m == "OPTIONS":
                resp = requests.options(url, timeout=req_timeout, verify=False, headers=headers, **kwargs)
            else:
                resp = requests.request(
                    method=req_m,
                    url=url,
                    timeout=req_timeout,
                    verify=False,
                    headers=headers,
                    **kwargs
                )
            return resp
        except requests.exceptions.Timeout:
            logger.debug(f"Validation request to '{url}' timed out ({req_timeout}s).")
            raise
        except requests.exceptions.RequestException as e:
            logger.debug(f"Validation request to '{url}' failed: {e}")
            raise

    def validate_findings(
        self,
        findings: List[Finding],
        context: Optional[Any] = None,
        target_scope: Optional[str] = None
    ) -> ValidationEngineResult:
        """
        Executes controlled validation for a list of prioritized findings.
        Attaches the validation outcome directly to each finding.
        """
        self._current_scope = target_scope
        logger.info(f"Phase 11: Starting controlled validation for {len(findings)} candidate findings (Budget: {self.max_requests} requests)...")
        engine_result = ValidationEngineResult(total_candidates=len(findings))

        for idx, finding in enumerate(findings):
            # 1. Check if global request budget is already exhausted
            if self.requests_sent >= self.max_requests:
                self.request_limit_reached = True
                res = ValidationResult(
                    finding_id=finding.id,
                    target=finding.affected_asset,
                    status=ValidationStatus.INCONCLUSIVE,
                    evidence=f"Global validation request limit reached ({self.max_requests}). Candidate validation halted.",
                    error_message="VALIDATION_REQUEST_LIMIT_REACHED",
                    validation_method="Central Request Budget Controller"
                )
                finding.validation_result = res
                engine_result.results[finding.id] = res
                continue

            # 2. Check scope boundary
            if not self._is_target_in_scope(finding, target_scope):
                logger.warning(f"Finding {finding.id} target '{finding.affected_asset}' out of scope '{target_scope}'. Skipping.")
                res = ValidationResult(
                    finding_id=finding.id,
                    target=finding.affected_asset,
                    status=ValidationStatus.NOT_APPLICABLE,
                    evidence="Finding target is outside the authorized scan scope boundary.",
                    validation_method="Scope Verification Filter"
                )
                finding.validation_result = res
                engine_result.results[finding.id] = res
                continue

            validator = self.registry.get_validator(finding)
            logger.debug(f"Validating finding '{finding.title}' using {validator.name}...")

            try:
                res = validator.validate(
                    finding=finding,
                    context=context,
                    timeout=self.timeout,
                    engine=self
                )
            except Exception as e:
                logger.exception(f"Unexpected exception in validator {validator.name} for finding {finding.id}")
                res = ValidationResult(
                    finding_id=finding.id,
                    target=finding.affected_asset,
                    status=ValidationStatus.ERROR,
                    evidence=f"Internal validator error: {str(e)}",
                    error_message=str(e),
                    validation_method=validator.name
                )

            finding.validation_result = res
            engine_result.results[finding.id] = res

        engine_result.requests_sent = self.requests_sent
        engine_result.request_limit_reached = self.request_limit_reached

        logger.info(
            f"Validation complete: {engine_result.validated_count} VALIDATED, "
            f"{engine_result.not_validated_count} NOT_VALIDATED, "
            f"{engine_result.inconclusive_count} INCONCLUSIVE, "
            f"{engine_result.not_applicable_count} NOT_APPLICABLE, "
            f"{engine_result.error_count} ERROR (Requests: {self.requests_sent}/{self.max_requests})."
        )

        return engine_result
