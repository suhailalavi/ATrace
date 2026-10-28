import logging
import requests
from typing import List, Dict, Set, Optional, Any, Tuple
from urllib.parse import urlparse

from alavitrace.core.models import Target, ScanResult, HttpResult, Confidence
from alavitrace.attacksurface.models import (
    Endpoint,
    Parameter,
    Technology,
    RedirectEntry,
    AttackSurface
)
from alavitrace.attacksurface.scope import ScopeController
from alavitrace.attacksurface.extractor import (
    HTMLExtractor,
    RobotsExtractor,
    SitemapExtractor,
    extract_query_parameters
)
from alavitrace.attacksurface.technologies import TechnologyFingerprinter

logger = logging.getLogger("AlaviTrace")

class AttackSurfaceMapper:
    """
    Deterministic, bounded attack surface mapper and web endpoint discovery engine.
    Discovers URLs, forms, parameters, HTTP methods, and technologies without aggressive crawling,
    destructive actions, or out-of-scope requests.
    """

    def __init__(
        self,
        authorized_target: str,
        max_depth: int = 1,
        max_requests: int = 20,
        timeout_seconds: int = 5,
        user_agent: str = "AlaviTrace-AttackSurfaceMapper/1.0"
    ):
        self.authorized_target = authorized_target
        self.max_depth = max_depth
        self.max_requests = max_requests
        self.timeout_seconds = timeout_seconds
        self.user_agent = user_agent

        self.scope_controller = ScopeController(authorized_target)
        self.requests_sent: int = 0
        self.request_limit_reached: bool = False

    def _fetch_url(self, url: str) -> Optional[requests.Response]:
        """
        Executes a controlled HTTP GET request while strictly enforcing request limits and timeouts.
        """
        if self.requests_sent >= self.max_requests:
            self.request_limit_reached = True
            logger.info(f"Attack surface mapper reached request limit ({self.max_requests}).")
            return None

        if not self.scope_controller.is_in_scope(url):
            logger.warning(f"Refusing to fetch out-of-scope URL: {url}")
            return None

        self.requests_sent += 1
        headers = {"User-Agent": self.user_agent}

        try:
            requests.packages.urllib3.disable_warnings()
            resp = requests.get(
                url,
                headers=headers,
                timeout=self.timeout_seconds,
                allow_redirects=True,
                verify=False
            )
            return resp
        except requests.exceptions.Timeout:
            logger.debug(f"Attack surface mapper request timed out for {url}")
            return None
        except requests.exceptions.RequestException as e:
            logger.debug(f"Attack surface mapper connection failed for {url}: {e}")
            return None
        except Exception as e:
            logger.debug(f"Unexpected error fetching {url}: {e}")
            return None

    def map_surface(
        self,
        target: Target,
        http_results: List[HttpResult],
        scan_result: Optional[ScanResult] = None
    ) -> AttackSurface:
        """
        Maps the target application's attack surface using existing enumeration data
        and bounded, scope-controlled endpoint discovery.
        """
        logger.info(f"Phase 10: Initiating attack surface mapping for '{target.normalized}' (Max Depth: {self.max_depth}, Max Requests: {self.max_requests})...")

        base_urls: List[str] = []
        endpoints_map: Dict[Tuple[str, str], Endpoint] = {}
        parameters_map: Dict[Tuple[str, str, str], Parameter] = {}
        redirects: List[RedirectEntry] = []
        observed_methods: Set[str] = {"GET"}
        meta_generators: List[str] = []

        discovered_links_to_crawl: List[Tuple[str, int, str]] = []  # (url, depth, source)

        # -------------------------------------------------------------
        # STEP 1: Process Depth 0 from existing HttpResult evidence
        # -------------------------------------------------------------
        for hr in http_results:
            if hr.error_message and not hr.status_code:
                continue

            base_urls.append(hr.url)
            parsed_root = urlparse(hr.url)
            root_path = parsed_root.path or "/"

            # Register base endpoint
            ep_key = ("GET", hr.url)
            endpoints_map[ep_key] = Endpoint(
                url=hr.url,
                path=root_path,
                method="GET",
                status_code=hr.status_code,
                content_type=hr.content_type,
                content_length=hr.content_length,
                parameters=[],
                source="root_url",
                depth=0
            )

            # Record advertised OPTIONS methods
            if hr.options_methods:
                for m in hr.options_methods:
                    observed_methods.add(m)

            # Process redirects from enumeration history
            if hr.redirect_chain:
                for idx in range(len(hr.redirect_chain) - 1):
                    src_r = hr.redirect_chain[idx]
                    dst_r = hr.redirect_chain[idx + 1]
                    red_entry = self.scope_controller.check_redirect(src_r, dst_r)
                    redirects.append(red_entry)

            # Extract Query Parameters from base URL
            for q_param in extract_query_parameters(hr.url):
                endpoints_map[ep_key].parameters.append(q_param)
                param_key = (q_param, hr.url, "query")
                parameters_map[param_key] = Parameter(
                    name=q_param,
                    location="query",
                    endpoint=hr.url,
                    evidence=f"URL query string on {hr.url}"
                )

            # Extract HTML links, forms, and generators from base body
            body_text = getattr(hr, "raw_body", None) or hr.body_sample or ""
            html_data = HTMLExtractor.extract_from_html(body_text, hr.url)
            meta_generators.extend(html_data.get("meta_generators", []))

            # A. Process HTML Links
            for raw_link in html_data.get("links", []):
                norm_link = self.scope_controller.normalize_url(hr.url, raw_link)
                if not norm_link:
                    continue

                if self.scope_controller.is_in_scope(norm_link):
                    parsed_link = urlparse(norm_link)
                    l_key = ("GET", norm_link)
                    if l_key not in endpoints_map:
                        endpoints_map[l_key] = Endpoint(
                            url=norm_link,
                            path=parsed_link.path or "/",
                            method="GET",
                            source="html_link",
                            depth=1
                        )
                        # Extract query parameters
                        for p in extract_query_parameters(norm_link):
                            endpoints_map[l_key].parameters.append(p)
                            p_key = (p, norm_link, "query")
                            parameters_map[p_key] = Parameter(
                                name=p,
                                location="query",
                                endpoint=norm_link,
                                evidence=f"Query parameter in HTML link {norm_link}"
                            )

                        if self.max_depth >= 1:
                            discovered_links_to_crawl.append((norm_link, 1, "html_link"))

            # B. Process HTML Forms
            for form in html_data.get("forms", []):
                raw_action = form.get("action")
                form_method = form.get("method", "GET").upper()
                observed_methods.add(form_method)

                action_url = self.scope_controller.normalize_url(hr.url, raw_action or hr.url)
                if not action_url or not self.scope_controller.is_in_scope(action_url):
                    continue

                parsed_action = urlparse(action_url)
                form_ep_key = (form_method, action_url)
                form_params = form.get("parameters", [])

                if form_ep_key not in endpoints_map:
                    endpoints_map[form_ep_key] = Endpoint(
                        url=action_url,
                        path=parsed_action.path or "/",
                        method=form_method,
                        parameters=form_params,
                        source="html_form",
                        depth=1
                    )
                else:
                    for fp in form_params:
                        if fp not in endpoints_map[form_ep_key].parameters:
                            endpoints_map[form_ep_key].parameters.append(fp)

                for fp in form_params:
                    p_key = (fp, action_url, "form_body" if form_method == "POST" else "query")
                    parameters_map[p_key] = Parameter(
                        name=fp,
                        location="form_body" if form_method == "POST" else "query",
                        endpoint=action_url,
                        evidence=f"HTML form ({form_method}) input on {hr.url}"
                    )

        # -------------------------------------------------------------
        # STEP 2: Safe Bounded Inspection of /robots.txt & /sitemap.xml
        # -------------------------------------------------------------
        for b_url in list(base_urls):
            base_clean = b_url.rstrip("/")
            robots_url = f"{base_clean}/robots.txt"
            sitemap_url = f"{base_clean}/sitemap.xml"

            # Check robots.txt
            if self.requests_sent < self.max_requests and self.scope_controller.is_in_scope(robots_url):
                resp = self._fetch_url(robots_url)
                if resp and resp.status_code == 200:
                    ep_key = ("GET", robots_url)
                    endpoints_map[ep_key] = Endpoint(
                        url=robots_url,
                        path="/robots.txt",
                        method="GET",
                        status_code=200,
                        source="robots_txt",
                        depth=1
                    )
                    parsed_rob = RobotsExtractor.extract_paths(resp.text)
                    all_rob_paths = parsed_rob.get("disallow", []) + parsed_rob.get("allow", [])
                    for r_path in all_rob_paths:
                        norm_p = self.scope_controller.normalize_url(base_clean, r_path)
                        if norm_p and self.scope_controller.is_in_scope(norm_p):
                            p_key = ("GET", norm_p)
                            if p_key not in endpoints_map:
                                endpoints_map[p_key] = Endpoint(
                                    url=norm_p,
                                    path=urlparse(norm_p).path or "/",
                                    method="GET",
                                    source="robots_txt",
                                    depth=1
                                )
                    for sm in parsed_rob.get("sitemaps", []):
                        norm_sm = self.scope_controller.normalize_url(base_clean, sm)
                        if norm_sm and self.scope_controller.is_in_scope(norm_sm):
                            sm_key = ("GET", norm_sm)
                            if sm_key not in endpoints_map:
                                endpoints_map[sm_key] = Endpoint(
                                    url=norm_sm,
                                    path=urlparse(norm_sm).path or "/",
                                    method="GET",
                                    source="robots_txt",
                                    depth=1
                                )

            # Check sitemap.xml
            if self.requests_sent < self.max_requests and self.scope_controller.is_in_scope(sitemap_url):
                resp = self._fetch_url(sitemap_url)
                if resp and resp.status_code == 200:
                    ep_key = ("GET", sitemap_url)
                    endpoints_map[ep_key] = Endpoint(
                        url=sitemap_url,
                        path="/sitemap.xml",
                        method="GET",
                        status_code=200,
                        source="sitemap_xml",
                        depth=1
                    )
                    for sm_loc in SitemapExtractor.extract_urls(resp.text):
                        norm_loc = self.scope_controller.normalize_url(base_clean, sm_loc)
                        if norm_loc and self.scope_controller.is_in_scope(norm_loc):
                            loc_key = ("GET", norm_loc)
                            if loc_key not in endpoints_map:
                                endpoints_map[loc_key] = Endpoint(
                                    url=norm_loc,
                                    path=urlparse(norm_loc).path or "/",
                                    method="GET",
                                    source="sitemap_xml",
                                    depth=1
                                )

        # -------------------------------------------------------------
        # STEP 3: Controlled Crawling of Depth 1 Endpoints
        # -------------------------------------------------------------
        if self.max_depth >= 1:
            for cand_url, depth, source in discovered_links_to_crawl:
                if self.requests_sent >= self.max_requests:
                    self.request_limit_reached = True
                    break

                ep_key = ("GET", cand_url)
                existing = endpoints_map.get(ep_key)
                if existing and existing.status_code is not None:
                    # Already probed
                    continue

                resp = self._fetch_url(cand_url)
                if not resp:
                    continue

                # Record/Update endpoint details
                content_len = len(resp.content)
                ct = resp.headers.get("Content-Type")

                if ep_key in endpoints_map:
                    endpoints_map[ep_key].status_code = resp.status_code
                    endpoints_map[ep_key].content_type = ct
                    endpoints_map[ep_key].content_length = content_len
                else:
                    endpoints_map[ep_key] = Endpoint(
                        url=cand_url,
                        path=urlparse(cand_url).path or "/",
                        method="GET",
                        status_code=resp.status_code,
                        content_type=ct,
                        content_length=content_len,
                        source=source,
                        depth=depth
                    )

                # Check if this request redirected
                if resp.history:
                    for h_idx in range(len(resp.history)):
                        h_src = resp.history[h_idx].url
                        h_dst = resp.history[h_idx + 1].url if h_idx + 1 < len(resp.history) else resp.url
                        redirects.append(self.scope_controller.check_redirect(h_src, h_dst, resp.history[h_idx].status_code))

        # -------------------------------------------------------------
        # STEP 4: Consolidate Technologies & Final Metadata
        # -------------------------------------------------------------
        technologies = TechnologyFingerprinter.identify(
            http_results=http_results,
            scan_result=scan_result,
            meta_generators=meta_generators
        )

        metadata: Dict[str, Any] = {
            "max_depth": self.max_depth,
            "max_requests": self.max_requests,
            "requests_sent": self.requests_sent,
            "request_limit_reached": self.request_limit_reached,
            "status": "REQUEST_LIMIT_REACHED" if self.request_limit_reached else "COMPLETED"
        }

        attack_surface = AttackSurface(
            target=target.normalized,
            base_urls=base_urls,
            endpoints=list(endpoints_map.values()),
            technologies=technologies,
            parameters=list(parameters_map.values()),
            methods=sorted(list(observed_methods)),
            redirects=redirects,
            metadata=metadata
        )

        logger.info(
            f"Attack surface mapping complete: {len(attack_surface.endpoints)} endpoints, "
            f"{len(attack_surface.parameters)} parameters, {len(attack_surface.technologies)} technologies, "
            f"{len(attack_surface.redirects)} redirects (Requests: {self.requests_sent}/{self.max_requests})."
        )

        return attack_surface
