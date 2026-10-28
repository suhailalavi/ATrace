from abc import ABC, abstractmethod
from typing import Any, Optional, Dict
from alavitrace.core.models import Finding
from alavitrace.validation.models import ValidationResult

DEFAULT_VALIDATION_TIMEOUT: int = 5
DEFAULT_MAX_VALIDATION_REQUESTS: int = 20
DEFAULT_VALIDATION_USER_AGENT: str = "AlaviTrace-ValidationEngine/1.0"
MAX_RESPONSE_BODY_SIZE: int = 1024 * 1024  # 1 MB maximum response body size
DISALLOWED_SCHEMES = {"javascript", "mailto", "data", "file", "ftp", "tel", "ssh", "gopher", "dict", "ldap"}
BLOCKED_INTERNAL_HOSTS = {"127.0.0.1", "localhost", "169.254.169.254", "0.0.0.0", "::1"}
SENSITIVE_PARAM_NAMES = {
    "password", "passwd", "token", "secret", "api_key", "apikey",
    "authorization", "access_token", "auth_token", "session", "csrf", "xsrf"
}

def redact_sensitive_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Returns a copy of params with any sensitive parameter values redacted."""
    redacted = {}
    for k, v in params.items():
        if any(s in k.lower() for s in SENSITIVE_PARAM_NAMES):
            redacted[k] = "[REDACTED]"
        else:
            redacted[k] = v
    return redacted

class BaseValidator(ABC):
    """
    Abstract base class for all deterministic, non-destructive finding validators.
    """
    name: str = "BaseValidator"
    description: str = "Base validator interface"

    @abstractmethod
    def can_validate(self, finding: Finding) -> bool:
        """
        Determines whether this validator supports the provided finding.
        """
        pass

    @abstractmethod
    def validate(
        self,
        finding: Finding,
        context: Optional[Any] = None,
        timeout: int = DEFAULT_VALIDATION_TIMEOUT,
        **kwargs: Any
    ) -> ValidationResult:
        """
        Executes a controlled, non-destructive validation check on the given finding.
        Returns a ValidationResult describing the observed status and evidence.
        """
        pass
