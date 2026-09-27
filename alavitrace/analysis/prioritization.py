import logging
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Any, Optional, Set
from alavitrace.core.models import Finding, Severity, Confidence

logger = logging.getLogger("ATrace")

SEVERITY_WEIGHTS: Dict[Severity, int] = {
    Severity.CRITICAL: 100,
    Severity.HIGH: 75,
    Severity.MEDIUM: 50,
    Severity.LOW: 25,
    Severity.INFO: 5
}

CONFIDENCE_WEIGHTS: Dict[Confidence, int] = {
    Confidence.PROBABLE: 50,
    Confidence.POTENTIAL: 25,
    Confidence.CONFIRMED: 50,
    Confidence.INFORMATIONAL: 10
}

@dataclass
class PrioritizationResult:
    """
    Container separating prioritized top-N findings for human-facing reports
    from the complete list of all correlated vulnerability findings.
    """
    total_correlated: int
    prioritized_count: int
    prioritized_findings: List[Finding]
    all_findings: List[Finding]
    prioritization_notes: List[str] = field(default_factory=list)

class VulnerabilityPrioritizer:
    """
    Deterministic prioritization and deduplication engine for vulnerability intelligence findings.
    Calculates explainable priority scores based on severity, CVSS metrics, match confidence,
    and open service exposure without inferring unobserved exploitability.
    """

    @staticmethod
    def calculate_priority_score(finding: Finding) -> Tuple[int, str]:
        """
        Calculates an explainable internal priority score for a Finding.

        Returns:
            Tuple[int, str]: (numeric_score, explanation_rationale)
        """
        sev_score = SEVERITY_WEIGHTS.get(finding.severity, 10)
        conf_score = CONFIDENCE_WEIGHTS.get(finding.confidence, 10)

        # Extract CVSS score from evidence or description if present
        cvss_score = 0.0
        if "CVSS " in finding.evidence:
            try:
                part = finding.evidence.split("CVSS ")[1].split(")")[0].split()[0]
                if part != "N/A":
                    cvss_score = float(part)
            except (IndexError, ValueError):
                pass

        cvss_weight = int(cvss_score * 10)
        exposure_weight = 20 if finding.affected_port else 0

        total_score = sev_score + conf_score + cvss_weight + exposure_weight

        rationale = (
            f"Score: {total_score} (Severity {finding.severity.value}: {sev_score}pts, "
            f"Confidence {finding.confidence.value}: {conf_score}pts, "
            f"CVSS {cvss_score}: {cvss_weight}pts, Exposed Port: {exposure_weight}pts)"
        )

        return total_score, rationale

    def prioritize(
        self,
        findings: List[Finding],
        max_findings: int = 5
    ) -> PrioritizationResult:
        """
        Deduplicates findings, orders them deterministically by priority score,
        and splits into top-N prioritized candidates while retaining all correlated findings.

        Args:
            findings: Raw list of correlated Finding objects.
            max_findings: Maximum number of top findings to select (default: 5).

        Returns:
            PrioritizationResult containing total count, prioritized subset, and full list.
        """
        if max_findings < 1:
            raise ValueError(f"max_findings must be at least 1 (got {max_findings})")

        vuln_findings = [f for f in findings if f.category == "Vulnerability Intelligence"]
        non_vuln_findings = [f for f in findings if f.category != "Vulnerability Intelligence"]

        # 1. Deduplicate by CVE ID and asset, merging multi-port service context
        dedup_map: Dict[Tuple[str, str], Finding] = {}
        affected_ports_map: Dict[Tuple[str, str], List[int]] = {}

        for f in vuln_findings:
            # Key by Title/CVE and Asset
            key = (f.title, f.affected_asset)
            if key not in dedup_map:
                dedup_map[key] = f
                if f.affected_port:
                    affected_ports_map[key] = [f.affected_port]
            else:
                if f.affected_port and f.affected_port not in affected_ports_map[key]:
                    affected_ports_map[key].append(f.affected_port)

        dedup_findings: List[Finding] = list(dedup_map.values())

        # Update evidence for multi-port duplicates
        for key, ports in affected_ports_map.items():
            if len(ports) > 1:
                finding = dedup_map[key]
                ports_str = ", ".join(str(p) for p in sorted(ports))
                finding.evidence += f" (Observed across ports: {ports_str})"

        # 2. Score and Sort Deterministically
        scored_findings: List[Tuple[int, float, Finding]] = []
        for f in dedup_findings:
            score, rationale = self.calculate_priority_score(f)
            cvss_val = 0.0
            if "CVSS " in f.evidence:
                try:
                    part = f.evidence.split("CVSS ")[1].split(")")[0].split()[0]
                    if part != "N/A":
                        cvss_val = float(part)
                except (IndexError, ValueError):
                    pass

            scored_findings.append((score, cvss_val, f))

        # Deterministic sorting: Score DESC -> CVSS DESC -> Title ASC
        scored_findings.sort(key=lambda x: (-x[0], -x[1], x[2].title))

        sorted_vuln_findings = [item[2] for item in scored_findings]

        # Combine sorted vulnerabilities with non-vulnerability findings (security header recommendations)
        all_retained_findings = sorted_vuln_findings + non_vuln_findings

        # Select Top N prioritized vulnerability findings
        top_vuln_findings = sorted_vuln_findings[:max_findings]
        prioritized_findings = top_vuln_findings + non_vuln_findings

        notes: List[str] = []
        total_vuln_count = len(sorted_vuln_findings)
        prioritized_vuln_count = len(top_vuln_findings)
        additional_count = max(0, total_vuln_count - prioritized_vuln_count)

        if total_vuln_count > 0:
            notes.append(
                f"Prioritized top {prioritized_vuln_count} investigation candidates from {total_vuln_count} total unique correlated CVEs."
            )
            if additional_count > 0:
                notes.append(
                    f"{additional_count} additional correlated vulnerabilities are preserved in the full JSON report."
                )

        logger.info(
            f"Prioritization complete. Selected top {prioritized_vuln_count} candidates from {total_vuln_count} unique CVEs."
        )

        return PrioritizationResult(
            total_correlated=total_vuln_count,
            prioritized_count=prioritized_vuln_count,
            prioritized_findings=prioritized_findings,
            all_findings=all_retained_findings,
            prioritization_notes=notes
        )
