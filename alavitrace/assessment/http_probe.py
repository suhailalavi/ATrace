import time
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Any
import requests

logger = logging.getLogger("AlaviTrace")

@dataclass
class InjectionTarget:
    """
    Normalized representation of an observed parameter candidate for injection assessment.
    """
    url: str
    http_method: str
    parameter_name: str
    original_value: str = ""
    parameter_location: str = "query"  # "query", "form"
    content_type: Optional[str] = None
    source: str = "observed"
    additional_params: Dict[str, str] = field(default_factory=dict)

@dataclass
class ProbeResponse:
    """
    Normalized response structure captured during controlled HTTP injection testing.
    """
    status_code: Optional[int] = None
    response_time_ms: float = 0.0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_length: int = 0
    final_url: str = ""
    error_message: Optional[str] = None

class HttpProber:
    """
    Controlled HTTP probing engine for active injection assessment.
    Enforces per-target request budgets, request timeouts, rate-limiting delays,
    and HTTP 429 Too Many Requests backoff.
    Separates request execution from vulnerability detection logic.
    """

    def __init__(
        self,
        max_requests: int = 20,
        timeout: int = 5,
        delay_seconds: float = 0.1,
        user_agent: str = "AlaviTrace-InjectionProber/0.1"
    ):
        self.max_requests = max_requests
        self.timeout = timeout
        self.delay_seconds = delay_seconds
        self.user_agent = user_agent

        self.requests_sent: int = 0
        self.budget_exhausted: bool = False
        self.rate_limited: bool = False

    def can_send_request(self) -> bool:
        """Checks if budget and rate-limit state permit sending another request."""
        if self.budget_exhausted or self.requests_sent >= self.max_requests:
            self.budget_exhausted = True
            return False
        if self.rate_limited:
            return False
        return True

    def execute_request(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None
    ) -> ProbeResponse:
        """
        Executes a controlled HTTP request while respecting budget and rate-limiting limits.
        """
        if not self.can_send_request():
            reason = "Rate limit (HTTP 429) active" if self.rate_limited else f"Request budget exhausted ({self.requests_sent}/{self.max_requests})"
            logger.warning(f"HttpProber blocked request to {url}: {reason}")
            return ProbeResponse(error_message=reason)

        if self.requests_sent > 0 and self.delay_seconds > 0:
            time.sleep(self.delay_seconds)

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*"
        }

        start_time = time.time()
        try:
            requests.packages.urllib3.disable_warnings()
            resp = requests.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            self.requests_sent += 1

            # Detect rate-limiting responses
            if resp.status_code == 429:
                self.rate_limited = True
                logger.warning(f"HTTP 429 Too Many Requests received from {url}. Halting further active probes.")

            # Check if budget reached
            if self.requests_sent >= self.max_requests:
                self.budget_exhausted = True
                logger.info(f"Injection request budget reached ({self.requests_sent}/{self.max_requests}).")

            body_text = resp.text or ""
            resp_headers = {k: v for k, v in resp.headers.items()}

            return ProbeResponse(
                status_code=resp.status_code,
                response_time_ms=elapsed_ms,
                headers=resp_headers,
                body=body_text,
                content_length=len(resp.content),
                final_url=resp.url,
                error_message=None
            )

        except requests.exceptions.Timeout:
            self.requests_sent += 1
            logger.debug(f"HttpProber request timed out for {url}")
            return ProbeResponse(error_message=f"Request timed out after {self.timeout}s")
        except requests.exceptions.RequestException as e:
            self.requests_sent += 1
            logger.debug(f"HttpProber request connection failed for {url}: {e}")
            return ProbeResponse(error_message=f"Connection failed: {e}")

    def get_baseline(self, target: InjectionTarget) -> ProbeResponse:
        """Captures a baseline response using the observed original parameter value."""
        params_dict = dict(target.additional_params)
        params_dict[target.parameter_name] = target.original_value

        if target.parameter_location == "form" and target.http_method.upper() == "POST":
            return self.execute_request(
                url=target.url,
                method="POST",
                data=params_dict
            )
        else:
            return self.execute_request(
                url=target.url,
                method="GET",
                params=params_dict
            )

    def send_probe(self, target: InjectionTarget, test_value: str) -> ProbeResponse:
        """Sends a controlled mutation probe for a specific parameter."""
        params_dict = dict(target.additional_params)
        params_dict[target.parameter_name] = test_value

        if target.parameter_location == "form" and target.http_method.upper() == "POST":
            return self.execute_request(
                url=target.url,
                method="POST",
                data=params_dict
            )
        else:
            return self.execute_request(
                url=target.url,
                method="GET",
                params=params_dict
            )
