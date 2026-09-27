import os
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from alavitrace import __version__
from alavitrace.core.models import ScanResult, HttpResult, Finding
from alavitrace.ai.models import AIAnalysisResult
from alavitrace.analysis.prioritization import PrioritizationResult

logger = logging.getLogger("ATrace")

def generate_json_report(
    scan_result: ScanResult,
    http_results: List[HttpResult],
    prioritization_result: Any,
    ai_analysis: Optional[AIAnalysisResult],
    output_dir: str = "reports",
    filename_prefix: str = "atrace"
) -> str:
    """
    Generates a structured, machine-readable JSON security assessment report.
    Retains the complete vulnerability dataset alongside prioritized investigation candidates.

    Returns:
        str: Absolute path to generated JSON report file.
    """
    if isinstance(prioritization_result, list):
        from alavitrace.analysis.prioritization import VulnerabilityPrioritizer
        prioritization_result = VulnerabilityPrioritizer().prioritize(prioritization_result)

    os.makedirs(output_dir, exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"{filename_prefix}_{timestamp_str}.json")

    hosts_data = []
    for host in scan_result.hosts:
        ports_data = []
        for s in host.open_ports:
            ports_data.append({
                "port": s.port,
                "protocol": s.protocol,
                "state": s.state,
                "name": s.name,
                "product": s.product,
                "version": s.version,
                "extra_info": s.extra_info,
                "cpes": s.cpes
            })
        hosts_data.append({
            "ipv4": host.ipv4 or host.target.normalized,
            "status": host.state,
            "hostname": host.hostname,
            "hostnames": host.hostnames,
            "os_matches": host.os_matches,
            "cpes": host.cpes,
            "open_ports": ports_data
        })

    http_data = []
    for h in http_results:
        http_data.append({
            "url": h.url,
            "status_code": h.status_code,
            "final_url": h.final_url,
            "response_time_ms": h.response_time_ms,
            "server_header": h.server_header,
            "powered_by_header": h.powered_by_header,
            "content_type": h.content_type,
            "redirect_chain": h.redirect_chain,
            "security_headers": h.security_headers,
            "missing_security_headers": h.missing_security_headers,
            "error_message": h.error_message
        })

    def format_finding(f: Finding) -> Dict[str, Any]:
        return {
            "id": f.id,
            "title": f.title,
            "category": f.category,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "description": f.description,
            "evidence": f.evidence,
            "affected_asset": f.affected_asset,
            "affected_port": f.affected_port,
            "affected_service": f.affected_service,
            "product": f.product,
            "version": f.version,
            "recommendation": f.recommendation,
            "references": f.references,
            "source": f.source
        }

    prioritized_findings_data = [format_finding(f) for f in prioritization_result.prioritized_findings]
    all_findings_data = [format_finding(f) for f in prioritization_result.all_findings]

    vuln_prioritized = [f for f in prioritized_findings_data if f["category"] == "Vulnerability Intelligence"]
    vuln_all = [f for f in all_findings_data if f["category"] == "Vulnerability Intelligence"]

    ai_data = None
    if ai_analysis and ai_analysis.is_available:
        ai_data = {
            "executive_summary": ai_analysis.executive_summary,
            "attack_surface_summary": ai_analysis.attack_surface_summary,
            "key_observations": ai_analysis.key_observations,
            "investigation_priorities": ai_analysis.investigation_priorities,
            "remediation_summary": ai_analysis.remediation_summary,
            "limitations": ai_analysis.limitations
        }

    report_payload = {
        "metadata": {
            "framework": "ATrace",
            "version": __version__,
            "timestamp": datetime.now().isoformat(),
            "target": scan_result.target.normalized,
            "target_type": scan_result.target.target_type
        },
        "reconnaissance": {
            "hosts": hosts_data
        },
        "http_enumeration": http_data,
        "vulnerability_intelligence": {
            "total_correlated": prioritization_result.total_correlated,
            "prioritized_count": prioritization_result.prioritized_count,
            "prioritization_notes": prioritization_result.prioritization_notes,
            "prioritized_vulnerabilities": vuln_prioritized,
            "all_correlated_vulnerabilities": vuln_all
        },
        "findings": prioritized_findings_data,
        "all_findings": all_findings_data,
        "ai_analysis": ai_data
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=2)

    logger.info(f"JSON report generated at: {filepath}")
    return filepath
