import os
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from alavitrace import __version__
from alavitrace.core.models import ScanResult, HttpResult, Finding
from alavitrace.ai.models import AIAnalysisResult
from alavitrace.analysis.prioritization import PrioritizationResult

logger = logging.getLogger("AlaviTrace")

def generate_json_report(
    scan_result: ScanResult,
    http_results: List[HttpResult],
    prioritization_result: Any,
    ai_analysis: Optional[AIAnalysisResult],
    output_dir: str = "reports",
    filename_prefix: str = "alavitrace",
    owasp_result: Optional[Any] = None,
    attack_surface: Optional[Any] = None,
    assessment: Optional[Any] = None
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
        from alavitrace.core.models import determine_technical_category, FindingLifecycle
        tc = getattr(f, "technical_category", None) or determine_technical_category(f)
        ls = getattr(f, "lifecycle_stage", FindingLifecycle.DISCOVERED)
        ls_val = ls.value if hasattr(ls, "value") else str(ls)

        return {
            "id": f.id,
            "title": f.title,
            "category": f.category,
            "technical_category": tc,
            "lifecycle_stage": ls_val,
            "priority_score": getattr(f, "priority_score", 0),
            "cvss": getattr(f, "cvss", None),
            "cve_ids": getattr(f, "cve_ids", []),
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
            "source": f.source,
            "owasp_category": f.owasp_category,
            "endpoint": f.endpoint,
            "url": getattr(f, "url", f.endpoint or f.affected_asset),
            "http_method": f.http_method,
            "parameter": f.parameter,
            "detection_type": f.detection_type,
            "remediation": getattr(f, "remediation", f.recommendation),
            "limitations": getattr(f, "limitations", ""),
            "validation": f.validation_result.to_dict() if getattr(f, "validation_result", None) and hasattr(f.validation_result, "to_dict") else None
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

    owasp_data = None
    a03_injection_data = None
    if owasp_result:
        owasp_data = owasp_result.to_dict() if hasattr(owasp_result, "to_dict") else {
            "is_http_available": getattr(owasp_result, "is_http_available", False),
            "findings_count": len(getattr(owasp_result, "findings", [])),
            "findings": [format_finding(f) for f in getattr(owasp_result, "findings", [])]
        }
        a03_findings = [
            f for f in getattr(owasp_result, "findings", [])
            if (getattr(f, "owasp_category", None) and "A03" in f.owasp_category)
            or "Injection" in f.title or "XSS" in f.title
        ]
        a03_injection_data = {
            "total_candidates": len(a03_findings),
            "sqli_candidates": sum(1 for f in a03_findings if "SQL" in f.title),
            "xss_candidates": sum(1 for f in a03_findings if "XSS" in f.title),
            "command_candidates": sum(1 for f in a03_findings if "Command" in f.title),
            "findings": [format_finding(f) for f in a03_findings]
        }
        a05_findings = [
            f for f in getattr(owasp_result, "findings", [])
            if getattr(f, "owasp_category", None) and "A05" in f.owasp_category
        ]
        a06_findings = [
            f for f in getattr(owasp_result, "findings", [])
            if getattr(f, "owasp_category", None) and "A06" in f.owasp_category
        ]

        owasp_data["a03_injection"] = a03_injection_data
        owasp_data["a05_misconfiguration"] = {
            "total_count": len(a05_findings),
            "findings": [format_finding(f) for f in a05_findings]
        }
        owasp_data["a06_vulnerable_components"] = {
            "total_count": len(a06_findings),
            "findings": [format_finding(f) for f in a06_findings]
        }

    a05_all = [f for f in all_findings_data if f.get("owasp_category") and "A05" in f["owasp_category"]]
    a06_all = [f for f in all_findings_data if f.get("owasp_category") and "A06" in f["owasp_category"]]

    from alavitrace.assessment.coverage import get_owasp_coverage_summary
    from alavitrace.core.models import AssessmentSummary, Severity

    if assessment and getattr(assessment, "summary", None):
        summary_dict = assessment.summary.to_dict()
    else:
        all_fs = prioritization_result.all_findings
        crit = sum(1 for f in all_fs if f.severity == Severity.CRITICAL)
        high = sum(1 for f in all_fs if f.severity == Severity.HIGH)
        med = sum(1 for f in all_fs if f.severity == Severity.MEDIUM)
        low = sum(1 for f in all_fs if f.severity == Severity.LOW)
        info = sum(1 for f in all_fs if f.severity == Severity.INFO)

        val_fs = [f for f in all_fs if getattr(f, "validation_result", None)]
        val_cnt = sum(1 for f in val_fs if getattr(f.validation_result.status, "value", str(f.validation_result.status)) == "VALIDATED")
        not_val_cnt = sum(1 for f in val_fs if getattr(f.validation_result.status, "value", str(f.validation_result.status)) == "NOT_VALIDATED")
        inconc_cnt = sum(1 for f in val_fs if getattr(f.validation_result.status, "value", str(f.validation_result.status)) == "INCONCLUSIVE")

        tot_ports = sum(len(h.open_ports) for h in scan_result.hosts)
        tot_eps = len(getattr(attack_surface, "endpoints", [])) if attack_surface else 0
        tot_forms = len(getattr(attack_surface, "forms", [])) if attack_surface else 0

        if crit > 0:
            overall_rating = "Critical"
        elif high > 0:
            overall_rating = "High"
        elif med > 0:
            overall_rating = "Medium"
        elif low > 0:
            overall_rating = "Low"
        else:
            overall_rating = "Informational"

        summary_dict = AssessmentSummary(
            total_findings=len(all_fs),
            critical_findings=crit,
            high_findings=high,
            medium_findings=med,
            low_findings=low,
            info_findings=info,
            validated_findings=val_cnt,
            unvalidated_findings=not_val_cnt,
            inconclusive_findings=inconc_cnt,
            total_services=tot_ports,
            total_endpoints=tot_eps,
            total_forms=tot_forms,
            attack_surface_score=round(tot_ports * 5.0 + tot_eps * 2.0 + tot_forms * 3.0, 1),
            overall_risk_rating=overall_rating
        ).to_dict()

    owasp_coverage_dict = get_owasp_coverage_summary(prioritization_result.all_findings).to_dict()

    report_payload = {
        "metadata": {
            "framework": "AlaviTrace",
            "version": __version__,
            "timestamp": datetime.now().isoformat(),
            "target": scan_result.target.normalized,
            "target_type": scan_result.target.target_type
        },
        "summary": summary_dict,
        "assessment_summary": summary_dict,
        "owasp_coverage": owasp_coverage_dict,
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
        "owasp_assessment": owasp_data,
        "a03_injection": a03_injection_data,
        "a05_misconfiguration": {
            "total_count": len(a05_all),
            "findings": a05_all
        },
        "a06_vulnerable_components": {
            "total_count": len(a06_all),
            "findings": a06_all
        },
        "findings": prioritized_findings_data,
        "all_findings": all_findings_data,
        "validation_summary": {
            "enabled": any(f.get("validation") is not None for f in prioritized_findings_data),
            "total_candidates": sum(1 for f in prioritized_findings_data if f.get("validation")),
            "statuses": {
                "VALIDATED": sum(1 for f in prioritized_findings_data if f.get("validation") and f["validation"]["status"] == "VALIDATED"),
                "NOT_VALIDATED": sum(1 for f in prioritized_findings_data if f.get("validation") and f["validation"]["status"] == "NOT_VALIDATED"),
                "INCONCLUSIVE": sum(1 for f in prioritized_findings_data if f.get("validation") and f["validation"]["status"] == "INCONCLUSIVE"),
                "NOT_APPLICABLE": sum(1 for f in prioritized_findings_data if f.get("validation") and f["validation"]["status"] == "NOT_APPLICABLE"),
                "ERROR": sum(1 for f in prioritized_findings_data if f.get("validation") and f["validation"]["status"] == "ERROR")
            }
        } if any(f.get("validation") is not None for f in prioritized_findings_data) else None,
        "attack_surface": attack_surface.to_dict() if attack_surface and hasattr(attack_surface, "to_dict") else None,
        "ai_analysis": ai_data
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=2)

    logger.info(f"JSON report generated at: {filepath}")
    return filepath
