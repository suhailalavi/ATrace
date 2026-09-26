import logging
from typing import List, Dict, Any, Optional
from alavitrace.core.models import ScanResult, HttpResult, Finding
from alavitrace.analysis.prioritization import PrioritizationResult
from alavitrace.ai.base import AIProvider
from alavitrace.ai.models import AIAnalysisResult

logger = logging.getLogger("AlaviTrace")

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
        prioritization_result: Any
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
            findings_data.append({
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "affected_asset": f.affected_asset,
                "evidence": f.evidence,
                "recommendation": f.recommendation
            })

        additional_count = max(0, prioritization_result.total_correlated - prioritization_result.prioritized_count)

        return {
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

    def analyze(
        self,
        scan_result: ScanResult,
        http_results: List[HttpResult],
        prioritization_result: PrioritizationResult
    ) -> AIAnalysisResult:
        """
        Generates AI-assisted security analysis over prioritized evidence.
        """
        logger.info("Preparing structured prioritized security data for AI analysis...")
        structured_input = self.prepare_structured_input(scan_result, http_results, prioritization_result)
        return self.provider.analyze_security_data(structured_input)
