from enum import Enum
from dataclasses import dataclass
import uuid
from typing import List, Set

class PayloadType(Enum):
    """Classification of safe test inputs."""
    SQLI_SYNTAX = "sqli_syntax"
    XSS_CANARY = "xss_canary"
    CMD_HEURISTIC = "cmd_heuristic"

@dataclass
class SafePayload:
    """
    Represents a controlled, non-destructive test input designed for evidence collection.
    ATrace test inputs strictly avoid functional exploitation, data dumping, shellcode,
    or denial-of-service payloads.
    """
    id: str
    payload_type: PayloadType
    value: str
    description: str
    safety_classification: str = "Non-destructive"

# Standard non-destructive quote perturbations for SQL syntax error detection
SQLI_SAFE_PAYLOADS: List[SafePayload] = [
    SafePayload(
        id="SQLI-QUOTE-SINGLE",
        payload_type=PayloadType.SQLI_SYNTAX,
        value="'",
        description="Single quote delimiter syntax perturbation",
        safety_classification="Non-destructive syntax test"
    ),
    SafePayload(
        id="SQLI-QUOTE-DOUBLE",
        payload_type=PayloadType.SQLI_SYNTAX,
        value='"',
        description="Double quote delimiter syntax perturbation",
        safety_classification="Non-destructive syntax test"
    ),
    SafePayload(
        id="SQLI-QUOTE-ESCAPE",
        payload_type=PayloadType.SQLI_SYNTAX,
        value=r"\'",
        description="Escaped quote delimiter perturbation",
        safety_classification="Non-destructive syntax test"
    )
]

def get_sqli_payloads() -> List[SafePayload]:
    """Returns safe SQL syntax perturbation payloads."""
    return SQLI_SAFE_PAYLOADS

def generate_xss_canary(prefix: str = "ATRACE_CANARY_") -> SafePayload:
    """
    Generates a unique harmless alphanumeric canary string for reflection analysis.
    The canary contains no script tags or JavaScript execution payloads.
    """
    token = uuid.uuid4().hex[:8]
    canary_val = f"{prefix}{token}"
    return SafePayload(
        id=f"XSS-CANARY-{token}",
        payload_type=PayloadType.XSS_CANARY,
        value=canary_val,
        description="Harmless unique alphanumeric canary string for reflection context analysis",
        safety_classification="Harmless canary string"
    )

# Parameter names whose naming conventionally suggests potential command/shell processing
COMMAND_PARAM_CANDIDATES: Set[str] = {
    "cmd", "command", "exec", "execute", "ping", "host", "ip",
    "query_ip", "daemon", "cli", "run", "do", "target_host"
}
