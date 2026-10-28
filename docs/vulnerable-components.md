# OWASP A06:2021 Vulnerable and Outdated Components

## 1. Overview & Objectives

**OWASP A06: Vulnerable and Outdated Components** addresses the risks associated with running client-side or server-side software with known security vulnerabilities (Common Vulnerabilities and Exposures - CVEs).

In **AlaviTrace Phase 9**, the framework unifies the Phase 4 NVD vulnerability intelligence provider with the OWASP Web Security Assessment Engine. Rather than creating a disjointed, duplicative vulnerability lookup subsystem, AlaviTrace maps all correlated CVE records from discovered network services (e.g. OpenSSH on port 22, FTP on port 21, Apache/Nginx on ports 80/443) directly into **A06:2021 - Vulnerable and Outdated Components**.

> [!IMPORTANT]
> **Evidence-Grounded Confidence Boundaries**:
> AlaviTrace strictly respects the boundary between *reconnaissance correlation* and *confirmed exploitation*:
> - **Never Claim Confirmed Exploitation**: Detected versions and correlated CVEs are classified as **PROBABLE** (for exact CPE matches) or **POTENTIAL** (for keyword/product matching).
> - **Context Matters**: A correlated CVE does not confirm that the target is exploitable in its current configuration or runtime state.
> - **Zero Hallucination**: Every reported CVE is grounded in verified NVD API v2 records.

---

## 2. Component Correlation Pipeline

```
Nmap Service Detection (-sV)
  ├─ Discovered Services: OpenSSH 7.9p1, vsftpd 3.0.3, Apache 2.4.38
  └─ Extracted CPEs: cpe:/a:openbsd:openssh:7.9p1
        ↓
Phase 4 Vulnerability Intelligence Engine
  ├─ Primary Query: Exact CPE lookup via NVD API v2
  ├─ Secondary Fallback: Product + Version keyword lookup
  └─ Local Response Cache (Reduces NVD rate-limiting & latency)
        ↓
Phase 9 OWASP A06 Unification
  ├─ Maps all service CVEs into A06:2021 - Vulnerable and Outdated Components
  ├─ Enriches findings with CVSS metrics, vector strings, and references
  └─ Preserves affected asset, port, service name, product, and version
        ↓
Vulnerability Prioritizer
  ├─ Scored by Severity Weight + CVSS Metric + Match Confidence
  ├─ Ranked deterministically (Score DESC -> CVSS DESC -> Title ASC)
  └─ Top N displayed in terminal/reports; full dataset retained in JSON
```

---

## 3. Confidence Classification & Limitations

| Correlation Source | Match Type | Assigned Confidence | Meaning & Limitations |
| :--- | :--- | :--- | :--- |
| **NVD API v2 via CPE** | Exact Common Platform Enumeration | `PROBABLE` | High confidence that the installed component version matches the affected range in the NVD database. Exploitability depends on runtime configuration, loaded modules, and network reachability. |
| **NVD API v2 via Keyword** | Product + Version String Search | `POTENTIAL` | Moderate confidence based on keyword heuristics. May include false positives where version ranges overlap or software naming differs. |
| **Active Verification** | Controlled Non-Destructive Probe | `CONFIRMED` | Confirmed observable behavior (e.g., missing header, exposed banner, active response signature). *Note: CVE exploitability is never labeled CONFIRMED.* |

---

## 4. Deduplication & Unified Identity Fingerprints

To prevent noisy, redundant reports where a single service produces both general recommendations and multiple CVE alerts, AlaviTrace implements a unified identity fingerprint algorithm:

$$\text{Fingerprint} = \text{MD5}(\text{norm\_title} \parallel \text{norm\_target} \parallel \text{norm\_port} \parallel \text{norm\_param} \parallel \text{norm\_method})$$

- When an OWASP check identifies an issue already detected in Phase 3 (e.g. Missing CSP), the existing record is enriched with OWASP category metadata without creating duplicate rows.
- Correlated CVE findings across ports are deduplicated by `(cve_id, target_asset, port)`.

---

## 5. Multi-Format Report Integration

Correlated A06 findings appear across all AlaviTrace reporting artifacts:

1. **CLI Output**:
   ```
   [A06] Vulnerable and Outdated Components
   [HIGH] Known CVE Associated with OpenSSH 7.9p1 (CVE-2019-6111)
     CVE:        CVE-2019-6111
     Service:    ssh
     Port:       22/tcp
     Confidence: Probable
     Evidence:   Service OpenSSH 7.9p1 detected on port 22/tcp matched vulnerability record CVE-2019-6111 (CVSS 5.8).
   ```

2. **JSON Report**:
   ```json
   "a06_vulnerable_components": {
     "total_count": 5,
     "findings": [
       {
         "id": "FIND-VULN-CVE-2019-6111-22",
         "title": "Known CVE Associated with OpenSSH 7.9p1 (CVE-2019-6111)",
         "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
         "severity": "medium",
         "confidence": "probable",
         "affected_port": 22,
         "affected_service": "ssh"
       }
     ]
   }
   ```

3. **Markdown & HTML Reports**:
   - Markdown includes `### A06:2021 Vulnerable and Outdated Components Summary`.
   - HTML report displays the `A06 Outdated Components` count badge and dedicated finding tables.
