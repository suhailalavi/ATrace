import os
import json
import hashlib
import logging
import time
import requests
from typing import Optional, List, Dict, Any
from alavitrace.core.models import Severity
from alavitrace.intelligence.base import VulnerabilityProvider
from alavitrace.intelligence.models import VulnerabilityRecord, VulnQueryResult

logger = logging.getLogger("ATrace")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".alavitrace", "cache")

def convert_cpe22_to_cpe23(cpe22: str) -> str:
    """
    Converts a standard Nmap CPE 2.2 string to CPE 2.3 format expected by NVD API v2.
    Example: 'cpe:/a:openbsd:openssh:7.9p1' -> 'cpe:2.3:a:openbsd:openssh:7.9p1:*:*:*:*:*:*'
    """
    if not cpe22:
        return ""
    if cpe22.startswith("cpe:2.3:"):
        return cpe22

    cleaned = cpe22.strip()
    if cleaned.startswith("cpe:/"):
        parts = cleaned[5:].split(":")
        part_type = parts[0] if len(parts) > 0 else "a"
        vendor = parts[1] if len(parts) > 1 else "*"
        product = parts[2] if len(parts) > 2 else "*"
        version = parts[3] if len(parts) > 3 else "*"
        update = parts[4] if len(parts) > 4 else "*"
        return f"cpe:2.3:{part_type}:{vendor}:{product}:{version}:{update}:*:*:*:*:*"

    return cpe22

class NVDProvider(VulnerabilityProvider):
    """
    Vulnerability intelligence provider interfacing with the official NIST NVD API v2.
    Supports API key authorization, disk caching, rate limiting, and CPE/keyword queries.
    """

    def __init__(self, api_key: Optional[str] = None, timeout_seconds: int = 15, enable_cache: bool = True):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.timeout_seconds = timeout_seconds
        self.enable_cache = enable_cache
        self.in_memory_cache: Dict[str, VulnQueryResult] = {}

        if self.enable_cache:
            os.makedirs(CACHE_DIR, exist_ok=True)

    def _get_cache_path(self, query_key: str) -> str:
        digest = hashlib.md5(query_key.encode("utf-8")).hexdigest()
        return os.path.join(CACHE_DIR, f"nvd_{digest}.json")

    def _read_from_cache(self, query_key: str) -> Optional[VulnQueryResult]:
        if not self.enable_cache:
            return None

        if query_key in self.in_memory_cache:
            res = self.in_memory_cache[query_key]
            res.from_cache = True
            return res

        cache_file = self._get_cache_path(query_key)
        if os.path.exists(cache_file):
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                records = [
                    VulnerabilityRecord(
                        cve_id=r["cve_id"],
                        description=r["description"],
                        severity=Severity(r["severity"]),
                        cvss_score=r.get("cvss_score"),
                        cvss_vector=r.get("cvss_vector"),
                        published_date=r.get("published_date"),
                        last_modified_date=r.get("last_modified_date"),
                        references=r.get("references", []),
                        affected_product=r.get("affected_product"),
                        affected_version=r.get("affected_version"),
                        matched_cpe=r.get("matched_cpe"),
                        source=r.get("source", "NVD")
                    ) for r in data.get("records", [])
                ]
                res = VulnQueryResult(
                    query_type=data["query_type"],
                    query_value=data["query_value"],
                    records=records,
                    from_cache=True
                )
                self.in_memory_cache[query_key] = res
                return res
            except (json.JSONDecodeError, OSError, ValueError) as e:
                logger.warning(f"Failed to read cache file {cache_file}: {e}")

        return None

    def _write_to_cache(self, query_key: str, result: VulnQueryResult) -> None:
        self.in_memory_cache[query_key] = result
        if not self.enable_cache or result.error_message:
            return

        cache_file = self._get_cache_path(query_key)
        try:
            records_data = [
                {
                    "cve_id": r.cve_id,
                    "description": r.description,
                    "severity": r.severity.value,
                    "cvss_score": r.cvss_score,
                    "cvss_vector": r.cvss_vector,
                    "published_date": r.published_date,
                    "last_modified_date": r.last_modified_date,
                    "references": r.references,
                    "affected_product": r.affected_product,
                    "affected_version": r.affected_version,
                    "matched_cpe": r.matched_cpe,
                    "source": r.source
                } for r in result.records
            ]
            data = {
                "query_type": result.query_type,
                "query_value": result.query_value,
                "records": records_data
            }
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except OSError as e:
            logger.warning(f"Failed to write cache file {cache_file}: {e}")

    def _execute_nvd_request(self, params: Dict[str, str], query_type: str, query_value: str) -> VulnQueryResult:
        cache_key = f"{query_type}:{query_value}"
        cached = self._read_from_cache(cache_key)
        if cached:
            logger.info(f"Retrieved NVD vulnerability result for '{query_value}' from cache.")
            return cached

        headers = {"User-Agent": "ATrace-Recon/0.1"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        logger.info(f"Querying NVD API v2 ({query_type}={query_value})...")
        try:
            response = requests.get(
                NVD_API_URL,
                params=params,
                headers=headers,
                timeout=self.timeout_seconds
            )

            if response.status_code == 429:
                logger.warning("NVD API rate limit exceeded (HTTP 429).")
                return VulnQueryResult(
                    query_type=query_type,
                    query_value=query_value,
                    error_message="NVD API rate limit exceeded (HTTP 429). Please try again later or configure NVD_API_KEY."
                )

            if response.status_code != 200:
                logger.warning(f"NVD API returned non-200 status code: {response.status_code}")
                return VulnQueryResult(
                    query_type=query_type,
                    query_value=query_value,
                    error_message=f"NVD API returned status code {response.status_code}."
                )

            data = response.json()
            records = self._parse_nvd_json(data, query_value)
            result = VulnQueryResult(
                query_type=query_type,
                query_value=query_value,
                records=records,
                from_cache=False
            )
            self._write_to_cache(cache_key, result)
            return result

        except requests.exceptions.Timeout:
            logger.warning(f"NVD API request timed out for {query_value}")
            return VulnQueryResult(query_type=query_type, query_value=query_value, error_message=f"NVD API request timed out after {self.timeout_seconds}s.")
        except requests.exceptions.RequestException as e:
            logger.warning(f"NVD API connection error: {e}")
            return VulnQueryResult(query_type=query_type, query_value=query_value, error_message=f"NVD API connection error: {e}")
        except json.JSONDecodeError:
            logger.warning("NVD API returned malformed JSON response.")
            return VulnQueryResult(query_type=query_type, query_value=query_value, error_message="Malformed JSON response from NVD API.")

    def search_by_cpe(self, cpe_string: str) -> VulnQueryResult:
        """
        Searches NVD for CVEs using a formatted CPE 2.3 string.
        """
        cpe23 = convert_cpe22_to_cpe23(cpe_string)
        params = {"cpeName": cpe23}
        return self._execute_nvd_request(params, query_type="cpe", query_value=cpe_string)

    def search_by_product_version(self, product: str, version: str) -> VulnQueryResult:
        """
        Searches NVD using keyword search when CPE is missing/unknown.
        """
        if not product or product.lower() in ["unknown", "none"] or not version or version.lower() in ["unknown", "none"]:
            return VulnQueryResult(query_type="keyword", query_value=f"{product} {version}", records=[])

        keyword = f"{product} {version}"
        params = {"keywordSearch": keyword}
        return self._execute_nvd_request(params, query_type="keyword", query_value=keyword)

    def _parse_nvd_json(self, data: Dict[str, Any], query_value: str) -> List[VulnerabilityRecord]:
        records: List[VulnerabilityRecord] = []
        vuln_items = data.get("vulnerabilities", [])

        for item in vuln_items:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id")
            if not cve_id:
                continue

            # Description (prefer English)
            descriptions = cve_data.get("descriptions", [])
            desc_text = "No description available."
            for d in descriptions:
                if d.get("lang") == "en":
                    desc_text = d.get("value", desc_text)
                    break

            # Metrics (CVSS v3.1, v3.0, or v2)
            metrics = cve_data.get("metrics", {})
            cvss_score: Optional[float] = None
            cvss_vector: Optional[str] = None
            source_sev: str = "INFORMATIONAL"

            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                v31 = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_score = v31.get("baseScore")
                cvss_vector = v31.get("vectorString")
                source_sev = v31.get("baseSeverity", "INFORMATIONAL")
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                v30 = metrics["cvssMetricV30"][0].get("cvssData", {})
                cvss_score = v30.get("baseScore")
                cvss_vector = v30.get("vectorString")
                source_sev = v30.get("baseSeverity", "INFORMATIONAL")
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                v2 = metrics["cvssMetricV2"][0].get("cvssData", {})
                cvss_score = v2.get("baseScore")
                cvss_vector = v2.get("vectorString")
                source_sev = metrics["cvssMetricV2"][0].get("baseSeverity", "INFORMATIONAL")

            severity_enum = self._map_severity(source_sev, cvss_score)

            # References
            refs: List[str] = []
            for r in cve_data.get("references", []):
                if r.get("url"):
                    refs.append(r["url"])
                if len(refs) >= 3:
                    break

            records.append(VulnerabilityRecord(
                cve_id=cve_id,
                description=desc_text,
                severity=severity_enum,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                published_date=cve_data.get("published"),
                last_modified_date=cve_data.get("lastModified"),
                references=refs,
                affected_product=query_value,
                matched_cpe=query_value if query_value.startswith("cpe:") else None,
                source="NVD"
            ))

        return records

    @staticmethod
    def _map_severity(base_severity: str, cvss_score: Optional[float]) -> Severity:
        sev_upper = base_severity.upper() if base_severity else ""
        if sev_upper == "CRITICAL":
            return Severity.CRITICAL
        elif sev_upper == "HIGH":
            return Severity.HIGH
        elif sev_upper == "MEDIUM":
            return Severity.MEDIUM
        elif sev_upper == "LOW":
            return Severity.LOW

        if cvss_score is not None:
            if cvss_score >= 9.0:
                return Severity.CRITICAL
            elif cvss_score >= 7.0:
                return Severity.HIGH
            elif cvss_score >= 4.0:
                return Severity.MEDIUM
            elif cvss_score > 0.0:
                return Severity.LOW

        return Severity.INFO
