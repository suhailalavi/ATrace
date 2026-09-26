import ipaddress
import re
from alavitrace.core.models import Target

# Standard domain/hostname regex (RFC 1123 compliant)
DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9]'
    r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    r'[a-zA-Z]{2,63}$'
)

HOSTNAME_REGEX = re.compile(
    r'^[a-zA-Z0-9]'
    r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
)

def validate_target(raw_target: str) -> Target:
    """
    Validates and normalizes user target input (IPv4, Hostname, or Domain).
    Rejects malformed inputs, special characters, and shell injection patterns.
    """
    if not raw_target or not raw_target.strip():
        return Target(
            raw_input=raw_target or "",
            normalized="",
            target_type="Invalid",
            is_valid=False,
            error_message="Target string cannot be empty."
        )

    cleaned = raw_target.strip().lower()

    # Remove protocol prefix if accidentally included (e.g. http:// or https://)
    if cleaned.startswith("http://"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("https://"):
        cleaned = cleaned[8:]

    # Remove trailing slash or path if present
    cleaned = cleaned.split('/')[0]

    # Remove port specification if provided in target string (e.g. host:80)
    if ':' in cleaned and not cleaned.count(':') > 1:  # Not IPv6
        cleaned = cleaned.split(':')[0]

    # 1. Check IPv4
    try:
        ip_obj = ipaddress.IPv4Address(cleaned)
        # Check for loopback / multicast / private warning if needed, but allow valid IPv4
        return Target(
            raw_input=raw_target,
            normalized=str(ip_obj),
            target_type="IPv4",
            is_valid=True
        )
    except ValueError:
        pass

    # 2. Check Domain
    if DOMAIN_REGEX.match(cleaned):
        return Target(
            raw_input=raw_target,
            normalized=cleaned,
            target_type="Domain",
            is_valid=True
        )

    # 3. Check Single Hostname (e.g., 'localhost', 'metasploitable')
    if HOSTNAME_REGEX.match(cleaned):
        return Target(
            raw_input=raw_target,
            normalized=cleaned,
            target_type="Hostname",
            is_valid=True
        )

    return Target(
        raw_input=raw_target,
        normalized=cleaned,
        target_type="Invalid",
        is_valid=False,
        error_message=f"Invalid target format: '{raw_target}'. Expected valid IPv4 address, domain, or hostname."
    )
