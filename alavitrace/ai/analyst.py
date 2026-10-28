import logging
import re
from typing import List, Dict, Any, Optional
from alavitrace.core.models import ScanResult, HttpResult, Finding
from alavitrace.analysis.prioritization import PrioritizationResult
from alavitrace.ai.base import AIProvider
from alavitrace.ai.models import AIAnalysisResult

logger = logging.getLogger("AlaviTrace")

SENSITIVE_PATTERNS = [
    (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), '[REDACTED_AWS_KEY]'),
    (re.compile(r'(?i)bearer\s+[a-zA-Z0-9_\-\.\=\+]{8,}'), 'Bearer [REDACTED]'),
    (re.compile(r'(?i)(basic|digest)\s+[a-zA-Z0-9\+\/\=]{8,}'), r'\1 [REDACTED]'),
    (re.compile(r'(?i)(password|passwd|pwd|secret|token|api_?key|auth_?token|access_?token)=([^&\s"\'>]+)'), r'\1=[REDACTED]'),
    (re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----'), '[REDACTED_PRIVATE_KEY]')
]

def sanitize_value(val: Any) -> Any:
    """Recursively redacts passwords, tokens, API keys and private keys from strings, dicts, and lists."""
    if isinstance(val, str):
        res = val
        for pattern, replacement in SENSITIVE_PATTERNS:
            res = pattern.sub(replacement, res)
        return res
    elif isinstance(val, dict):
        return {k: sanitize_value(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [sanitize_value(item) for item in val]
    return val

class SecurityAnalyst:
    """
    Orchestrates AI-assisted security analysis by serializing deterministic evidence
    into compact, sanitized structured inputs for the AI provider.
    """

    def __init__(self, provider: AIProvider):
        self.provider = provider

    @staticmethod
    def prepare_structured_input(
        scan_result: ScanResult,
        http_results: List[HttpResult],
        prioritization_result: Any,
        owasp_result: Optional[Any] = None,
        attack_surface: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Prepares a clean, sanitized JSON data structure representing prioritized security evidence.
        Supplies top-N prioritized findings and total correlation counts to optimize token usage.
        """
        if isinstance(prioritization_result, list):
            from alavitrace.analysis.prioritization import VulnerabilityPrioritizer
            prioritization_result = VulnerabilityPrioritizer().prioritize(prioritization_result)

        hosts_data: List[Dict[str, Any]] = []

        for host in scan_result.hosts:
            open_ports_data = []
            for service in host.open_ports:
                open_ports_data.append({
                    "port": service.port,
                    "protocol": service.protocol,
                    "service": service.name,
                    "product": service.product,
                    "version": service.version,
                    "extra_info": service.extra_info,
                    "cpes": service.cpes
                })

            hosts_data.append({
                "ipv4": host.ipv4 or host.target.normalized,
                "hostname": host.hostname,
                "os_matches": host.os_matches,
                "open_ports": open_ports_data
            })

        http_data: List[Dict[str, Any]] = []
        for res in http_results:
            if res.error_message:
                http_data.append({"url": res.url, "error": res.error_message})
            else:
                http_data.append({
                    "url": res.url,
                    "status_code": res.status_code,
                    "final_url": res.final_url,
                    "response_time_ms": res.response_time_ms,
                    "server_header": res.server_header,
                    "powered_by": res.powered_by_header,
                    "missing_security_headers": res.missing_security_headers,
                    "present_security_headers": list(res.security_headers.keys())
                })

        findings_data: List[Dict[str, Any]] = []
        for f in prioritization_result.prioritized_findings:
            f_item = {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "owasp_category": f.owasp_category,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "affected_asset": f.affected_asset,
                "endpoint": f.endpoint,
                "evidence": f.evidence,
                "recommendation": f.recommendation
            }
            if getattr(f, "validation_result", None):
                vr = f.validation_result
                val_dict = {
                    "status": vr.status.value if hasattr(vr.status, "value") else str(vr.status),
                    "method": vr.validation_method,
                    "evidence": vr.evidence,
                    "error_message": vr.error_message
                }
                if getattr(vr, "structured_evidence", None):
                    val_dict["structured_evidence"] = vr.structured_evidence
                if getattr(vr, "limitations", None):
                    val_dict["limitations"] = vr.limitations
                f_item["validation"] = val_dict
            findings_data.append(f_item)

        additional_count = max(0, prioritization_result.total_correlated - prioritization_result.prioritized_count)

        payload: Dict[str, Any] = {
            "target": scan_result.target.normalized,
            "hosts": hosts_data,
            "http_enumeration": http_data,
            "vulnerability_summary": {
                "total_unique_cves_correlated": prioritization_result.total_correlated,
                "prioritized_candidates_count": prioritization_result.prioritized_count,
                "additional_correlated_cves_retained_in_json": additional_count
            },
            "prioritized_findings": findings_data
        }

        validated_findings = [f for f in prioritization_result.prioritized_findings if getattr(f, "validation_result", None)]
        if validated_findings:
            payload["validation_summary"] = {
                "total_candidates": len(validated_findings),
                "statuses": {
                    "VALIDATED": sum(1 for f in validated_findings if getattr(f.validation_result.status, "value", str(f.validation_result.status)) == "VALIDATED"),
                    "NOT_VALIDATED": sum(1 for f in validated_findings if getattr(f.validation_result.status, "value", str(f.validation_result.status)) == "NOT_VALIDATED"),
                    "INCONCLUSIVE": sum(1 for f in validated_findings if getattr(f.validation_result.status, "value", str(f.validation_result.status)) == "INCONCLUSIVE"),
                    "NOT_APPLICABLE": sum(1 for f in validated_findings if getattr(f.validation_result.status, "value", str(f.validation_result.status)) == "NOT_APPLICABLE"),
                    "ERROR": sum(1 for f in validated_findings if getattr(f.validation_result.status, "value", str(f.validation_result.status)) == "ERROR")
                }
            }

        if owasp_result:
            payload["owasp_assessment"] = {
                "enabled": True,
                "is_http_available": getattr(owasp_result, "is_http_available", False),
                "findings_count": len(getattr(owasp_result, "findings", [])),
                "findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "owasp_category": f.owasp_category,
                        "severity": f.severity.value,
                        "confidence": f.confidence.value,
                        "endpoint": f.endpoint,
                        "evidence": f.evidence,
                        "recommendation": f.recommendation
                    }
                    for f in getattr(owasp_result, "findings", [])
                ]
            }

        if attack_surface:
            payload["attack_surface"] = {
                "base_urls": getattr(attack_surface, "base_urls", []),
                "total_endpoints": len(getattr(attack_surface, "endpoints", [])),
                "endpoints": [
                    {
                        "method": getattr(ep, "method", "GET"),
                        "path": getattr(ep, "path", "/"),
                        "status_code": getattr(ep, "status_code", None),
                        "parameters": getattr(ep, "parameters", []),
                        "source": getattr(ep, "source", "unknown")
                    }
                    for ep in getattr(attack_surface, "endpoints", [])[:30]
                ],
                "technologies": [
                    {
                        "name": getattr(t, "name", ""),
                        "version": getattr(t, "version", None),
                        "confidence": getattr(t.confidence, "value", str(t.confidence)) if hasattr(t, "confidence") else "Unknown"
                    }
                    for t in getattr(attack_surface, "technologies", [])
                ],
                "parameters": [getattr(p, "name", str(p)) for p in getattr(attack_surface, "parameters", [])[:30]],
                "methods": getattr(attack_surface, "methods", []),
                "total_redirects": len(getattr(attack_surface, "redirects", []))
            }

        return sanitize_value(payload)

    sanitize_sensitive_data = staticmethod(sanitize_value)

    def analyze(
        self,
        scan_result: ScanResult,
        http_results: List[HttpResult],
        prioritization_result: Any,
        owasp_result: Optional[Any] = None,
        attack_surface: Optional[Any] = None
    ) -> AIAnalysisResult:
        """
        Generates AI-assisted security analysis over prioritized evidence.
        """
        logger.info("Preparing structured prioritized security data for AI analysis...")
        structured_input = self.prepare_structured_input(
            scan_result,
            http_results,
            prioritization_result,
            owasp_result=owasp_result,
            attack_surface=attack_surface
        )
        return self.provider.analyze_security_data(structured_input)
