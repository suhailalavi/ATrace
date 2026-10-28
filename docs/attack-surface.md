# Attack Surface Mapping & Web Endpoint Discovery (Phase 10)

## 1. Overview & Objective

The **Attack Surface Mapping & Web Endpoint Discovery Engine** is a deterministic, conservative discovery layer in AlaviTrace. Its purpose is to map an authorized target application's attack surface—discovering URLs, web forms, query/body parameters, allowed HTTP methods, redirect chains, and underlying software technologies—without aggressive crawling, fuzzing, or destructive actions.

Crucially, AlaviTrace maintains a strict separation of concerns and inventory boundaries:

```
Target Validation
       ↓
Nmap Reconnaissance & Parsing
       ↓
Passive HTTP Enumeration
       ↓
Attack Surface Mapping & Web Endpoint Discovery (Phase 10)
       ↓
OWASP Web Security Assessment (A01, A03, A05, A06)
       ↓
Vulnerability Intelligence (NVD CVE Correlation)
       ↓
Vulnerability Prioritization & Deduplication (Top-N Candidates)
       ↓
Controlled Finding Validation (Phase 9)
       ↓
AI-Assisted Security Analysis (Gemini Explanation with Attack Surface Context)
       ↓
Multi-Format Reporting (JSON / Markdown / HTML)
```

**Core Architectural Rule:** Attack surface inventory (endpoints, parameters, forms, technologies) represents the target's exposed technical landscape, **not** security vulnerabilities. Endpoints are documented as attack surface context; vulnerabilities are detected only by deterministic assessment engines and correlated CVEs. The AI reasoning layer (Gemini) explains the discovered attack surface but is strictly forbidden from hallucinating endpoints or classifying neutral endpoints as vulnerabilities.

---

## 2. Discovery Capabilities

The Attack Surface Mapping engine extracts technical inventory across five deterministic vectors:

1. **Root HTTP Response Evidence (Depth 0)**:
   - Root URL status code, content type, content length, and observed headers.
   - Advertised HTTP methods via `OPTIONS` or `Allow` headers.
   - Root query parameters.
2. **HTML Link Extraction (`<a>` and `<link>`)**:
   - Discovers relative paths (`/about.php`, `../docs/api.html`, `contact.html`) and absolute same-origin URLs.
   - Discards fragment identifiers (`#section`) and collapses redundant path slashes (`//`).
   - Normalizes all paths against the base URL.
3. **HTML Form & Parameter Extraction**:
   - Parses `<form>` action endpoints and HTTP submission methods (`GET`, `POST`).
   - Extracts all input parameter names (`<input name="...">`, `<textarea name="...">`, `<select name="...">`).
   - Maps parameters to specific HTTP locations (`query` vs `form_body`).
4. **Observed Redirect Chains**:
   - Tracks redirect history from passive HTTP enumeration and depth-1 requests.
   - Evaluates each redirect hop (`source_url` -> `target_url` + HTTP status code).
   - In-scope redirects are recorded; out-of-scope redirects are flagged as `OUT_OF_SCOPE_REDIRECT` and are **never requested**.
5. **Passive Inspection of `/robots.txt` & `/sitemap.xml`**:
   - Deterministically queries `/robots.txt` for `Disallow`, `Allow`, and `Sitemap` paths.
   - Parses XML sitemaps for `<loc>` endpoints.
   - Discovered paths are added to the endpoint inventory without executing crawl requests against disallowed routes.

---

## 3. Technology Fingerprinting

The `TechnologyFingerprinter` deterministically identifies web servers, runtimes, frameworks, and CMS platforms by correlating multiple observation sources:

| Source | Detection Target | Example Match | Confidence |
| :--- | :--- | :--- | :--- |
| **Server Header** | Web servers and reverse proxies | `Apache/2.4.41 (Ubuntu)` → Apache `2.4.41` | `CONFIRMED` |
| **X-Powered-By** | Language runtimes & frameworks | `PHP/7.4.3` → PHP `7.4.3` | `CONFIRMED` |
| **Framework Headers** | Application framework banners | `X-AspNet-Version: 4.0.30319` → ASP.NET `4.0.30319` | `CONFIRMED` |
| **Cookies** | Session identifier patterns | `PHPSESSID` → PHP; `csrftoken` → Django; `JSESSIONID` → Java | `PROBABLE` |
| **HTML Meta Generator** | CMS and application generators | `<meta name="generator" content="WordPress 6.2">` → WordPress `6.2` | `CONFIRMED` |
| **Nmap Reconnaissance** | Service and product banners | `nginx 1.18.0` on Port 80/tcp | `CONFIRMED` |

---

## 4. Scope Control & Safety Boundaries

The engine implements conservative, non-destructive safety guardrails:

1. **Strict Target Scope Boundary (`ScopeController`)**:
   - Discovered candidate URLs must belong to the explicitly authorized target host or IP.
   - Links pointing to external domains (e.g., third-party trackers, CDNs, external websites) are rejected immediately.
2. **SSRF and Out-of-Scope Redirect Protection**:
   - If a target redirects to an external origin, the hop is recorded in the report as `OUT_OF_SCOPE_REDIRECT`.
   - The engine explicitly refuses to make outbound requests to out-of-scope redirect destinations, preventing server-side request forgery or unintended reconnaissance.
3. **Bounded Depth & Request Limits**:
   - `--max-depth` (default: `1`): Limits crawling to immediate child links. Set to `0` for passive discovery from root responses only.
   - `--max-requests` (default: `20`): Hard cap on the total number of HTTP requests issued by the attack surface mapper.
   - If the request ceiling is reached, crawling terminates immediately and records `status: "REQUEST_LIMIT_REACHED"`.
4. **Privacy & Credential Protection**:
   - The engine extracts parameter *names* only.
   - Sensitive fields (`password`, `passwd`, `token`, `secret`, `api_key`, `apikey`, `authorization`, `access_token`, `auth_token`, `session`) have their values strictly excluded from all logs, reports, and AI payloads.
5. **Zero Destructive Actions**:
   - Forms are **never submitted** automatically.
   - No fuzzing, SQL injection payloads, or directory brute-forcing are performed during attack surface mapping.

---

## 5. Modular Architecture

The engine is implemented in `alavitrace/attacksurface/`:

- `models.py`: Defines dataclasses for `Technology`, `Parameter`, `Endpoint`, `RedirectEntry`, and `AttackSurface` with full dictionary serialization (`to_dict()`).
- `scope.py`: Implements `ScopeController` for URI normalization, scheme validation (rejecting `javascript:`, `mailto:`, `data:`), in-scope verification, and redirect safety checking.
- `extractor.py`: Implements `HTMLExtractor` (BeautifulSoup-based link and form extraction), `RobotsExtractor`, `SitemapExtractor`, `extract_query_parameters`, and sensitive parameter pattern definitions.
- `technologies.py`: Implements `TechnologyFingerprinter` correlating HTTP banners, headers, cookies, meta tags, and Nmap services into structured `Technology` instances.
- `mapper.py`: Implements `AttackSurfaceMapper`, coordinating multi-source discovery, budget tracking, scope enforcement, depth gating, and attack surface assembly.
- `__init__.py`: Clean public API export.

---

## 6. CLI Usage

Attack surface mapping is optional and enabled via the `--attack-surface` flag:

```bash
# Basic scan with default attack surface mapping (depth: 1, max requests: 20)
python -m alavitrace.cli -t 192.168.56.101 --pn --attack-surface --format all

# Custom depth and request limits
python -m alavitrace.cli -t 192.168.56.101 --pn --attack-surface --max-depth 2 --max-requests 50

# Passive root-only attack surface mapping (no secondary crawl requests)
python -m alavitrace.cli -t 192.168.56.101 --pn --attack-surface --max-depth 0

# Comprehensive assessment pipeline: Attack Surface + OWASP + Validation + AI
python -m alavitrace.cli -t 192.168.56.101 --pn --attack-surface --owasp --validate --max-findings 5 --format all
```

---

## 7. Report Integration

The discovered attack surface is rendered across all report formats:

- **JSON Report (`alavitrace_*.json`)**:
  - Full `"attack_surface"` object containing `target`, `base_urls`, `total_endpoints`, `endpoints` list, `total_technologies`, `technologies` list, `total_parameters`, `parameters` list, `methods`, and `redirects`.
- **Markdown Report (`alavitrace_*.md`)**:
  - Dedicated "Attack Surface & Web Endpoint Discovery" section.
  - Identified Technologies table (Name, Version, Category/Source, Confidence).
  - Discovered Web Endpoints table (Method, Path/URL, Status Code, Content Type, Parameters, Depth, Source).
  - Observed Parameters table (Name, Location, Endpoint, Evidence).
  - Observed Redirects table with `OUT_OF_SCOPE_REDIRECT` flags clearly highlighted.
- **HTML Report (`alavitrace_*.html`)**:
  - Styled visual card with technology badges.
  - Metrics summary (Total Endpoints, Total Parameters, Total Technologies).
  - Filterable endpoint table with HTTP method tags (`GET`, `POST`, `OPTIONS`).

---

## 8. Known Limitations & Next Steps

1. **Client-Side Rendering (SPA)**: Heavy single-page applications built with React/Angular/Vue that require client-side JavaScript execution to render routes are only partially mapped via static HTML parsing. Future enhancements may integrate headless browser rendering where authorized.
2. **Authenticated Surfaces**: Endpoints located behind authentication gates, session cookies, or CSRF-protected logins are not accessed without explicit credential provisioning.
3. **Hidden / Unlinked Endpoints**: Unlinked administrative interfaces, hidden debug endpoints, or API routes not referenced in HTML, robots.txt, or sitemaps remain unmapped under this non-brute-force approach.
