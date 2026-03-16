from __future__ import annotations

import asyncio
import json
import logging
import re
import ssl
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

import dns.resolver
import aiohttp
from bs4 import BeautifulSoup, Comment

from aegis.core.ai_client import estimate_tokens
from aegis.core.config import settings
from aegis.core.cve_correlator import CVECorrelator
from aegis.models.target_model import TargetModel

logger = logging.getLogger(__name__)

_NMAP_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="nmap")

_TECH_INDICATORS: dict[str, list[str]] = {
    "wordpress": ["wp-content", "wp-includes"],
    "django": ["csrfmiddlewaretoken", "__admin__"],
    "rails": ["csrf-token", "data-remote"],
    "laravel": ["laravel_session", "XSRF-TOKEN"],
    "php": [".php", "<?php"],
    "react": ["__reactFiber", "_react"],
    "angular": ["ng-version", "angular"],
    "vue": ["__vue__", "v-bind"],
}

_WAF_SIGNATURES: list[tuple[str, str, str]] = [
    ("x-sucuri-id", "", "sucuri"),
    ("x-firewall", "", "generic_firewall"),
    ("server", "cloudflare", "cloudflare"),
    ("x-cdn", "", "cdn_waf"),
    ("cf-ray", "", "cloudflare"),
    ("x-cache", "sucuri", "sucuri"),
    ("x-protected-by", "", "generic_waf"),
    ("x-waf-event-info", "", "barracuda"),
    ("x-distil-cs", "", "distil"),
    ("x-akamai-transformed", "", "akamai"),
    ("server", "akamaighost", "akamai"),
    ("x-fw-hash", "", "fortiweb"),
    ("x-sucuri-cache", "", "sucuri"),
    ("x-cache-hits", "", "varnish_cdn"),
    ("server", "awselb", "aws_waf"),
    ("x-amzn-requestid", "", "aws_waf"),
]


@dataclass
class _CrawlPage:
    url: str
    body: str
    title: str
    forms: list[dict]
    links: list[str]
    script_urls: list[str]
    html_comments: list[str]
    classification: str


class ReconnaissanceAgent:
    def __init__(self, db) -> None:
        self.db = db

    async def run(self, target_urls: list[str], config: dict) -> TargetModel:
        if not target_urls:
            raise ValueError("target_urls cannot be empty")

        target_url = target_urls[0]
        parsed = urlparse(target_url)
        if not parsed.scheme:
            target_url = f"https://{target_url}"
            parsed = urlparse(target_url)

        depth = int(config.get("crawl_depth", 2))

        ssl_ctx = self._resolve_ssl_context()
        connector = aiohttp.TCPConnector(ssl=ssl_ctx)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=20, connect=10),
        ) as session:
            fp_task = self._fingerprint_technologies(target_url, session)
            crawl_task = self._crawl_and_extract(target_url, session, depth)
            common_task = self._check_common_paths(target_url, session)
            port_task = self._port_scan(parsed.netloc)
            subdomain_task = self._enumerate_subdomains(parsed.netloc)
            cors_task = self._check_cors_misconfiguration(target_url, session)

            fingerprint, crawled, common_paths, open_ports, subdomains, cors_signals = await asyncio.gather(
                fp_task,
                crawl_task,
                common_task,
                port_task,
                subdomain_task,
                cors_task,
            )

            js_analysis = await self._fetch_and_analyze_javascript(
                crawled.get("script_urls", []),
                session,
                parsed.netloc,
            )

        injection_points = self._collect_injection_points(
            crawled=crawled,
            openapi_endpoints=common_paths.get("openapi_endpoints", []),
            js_fetch_endpoints=js_analysis.get("fetch_endpoints", []),
            root_url=target_url,
        )
        injection_points.extend(common_paths.get("graphql_injection_points", []))
        injection_points = list(
            {
                (
                    p.get("url"),
                    p.get("method"),
                    p.get("param_name"),
                    p.get("param_type"),
                ): p
                for p in injection_points
            }.values()
        )

        api_endpoints = sorted(
            set(crawled.get("endpoints", []))
            | set(common_paths.get("openapi_endpoints", []))
            | set(common_paths.get("sitemap_urls", []))
            | set(js_analysis.get("api_paths", []))
            | set(js_analysis.get("fetch_endpoints", []))
        )

        technologies = sorted(
            set(fingerprint.get("body_technologies", []))
            | self._header_techs(fingerprint.get("headers", {}))
        )

        backend_language, framework = self._infer_backend_and_framework(technologies, fingerprint.get("headers", {}))
        database_hint = self._infer_database_hint(crawled.get("page_bodies", []))
        cve_correlations: list[dict[str, Any]] = []
        try:
            cve_correlations = await CVECorrelator().correlate(technologies, fingerprint.get("headers", {}))
        except Exception as exc:
            logger.debug("cve_correlation_failed domain=%s error=%s", parsed.netloc, exc)

        attack_surface_signals = self._build_attack_surface_signals(
            fingerprint=fingerprint,
            crawled=crawled,
            common_paths=common_paths,
            js_analysis=js_analysis,
            database_hint=database_hint,
            cve_correlations=cve_correlations,
        )
        attack_surface_signals.extend(fingerprint.get("security_header_signals", []))
        attack_surface_signals.extend(fingerprint.get("cookie_security_signals", []))
        attack_surface_signals.extend(cors_signals)
        attack_surface_signals = list(dict.fromkeys(attack_surface_signals))

        model = TargetModel(
            url=target_url,
            domain=parsed.netloc,
            technologies=technologies,
            waf_detected=fingerprint.get("waf_detected"),
            backend_language=backend_language,
            database_hint=database_hint,
            framework=framework,
            injection_points=injection_points,
            forms=crawled.get("forms", []),
            api_endpoints=api_endpoints,
            html_comments=crawled.get("html_comments", []),
            hardcoded_values=js_analysis.get("hardcoded_secrets", []),
            graphql_schema=common_paths.get("graphql_schema", {}),
            interesting_paths=sorted(common_paths.get("found_paths", {}).keys()),
            open_ports=open_ports,
            subdomains=subdomains,
            cve_correlations=cve_correlations,
            subdomain_takeover_risk=(
                "High Risk" if any(sd.get("takeover_risk") for sd in subdomains)
                else "Medium Risk" if len(subdomains) > 3
                else "Low Risk"
            ),
            attack_surface_signals=attack_surface_signals,
            page_classifications=crawled.get("page_classifications", {}),
        )

        if estimate_tokens(json.dumps(model.to_hypothesis_context())) >= 2000:
            logger.warning("Hypothesis context still high after truncation for domain=%s", model.domain)

        return model

    def _resolve_ssl_context(self) -> ssl.SSLContext | bool:
        try:
            from aegis.core.probing.probe_executor import _build_ssl_context

            return _build_ssl_context()
        except Exception:
            if not settings.VERIFY_SSL:
                return False
            return ssl.create_default_context()

    async def _fingerprint_technologies(self, url: str, session: aiohttp.ClientSession) -> dict:
        headers_out: dict[str, str] = {}
        body_technologies: list[str] = []
        waf_detected: str | None = None
        security_header_signals: list[str] = []
        cookie_security_signals: list[str] = []

        try:
            async with session.get(url) as resp:
                text = await resp.text(errors="replace")
                response_headers = {str(k): str(v) for k, v in resp.headers.items()}
                headers_out.update(response_headers)
                for key in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "X-Framework"]:
                    if key in resp.headers:
                        headers_out[key] = resp.headers[key]

                header_lower = {k.lower(): v for k, v in resp.headers.items()}
                for key, contains, waf_name in _WAF_SIGNATURES:
                    if key in header_lower:
                        if not contains or contains in header_lower[key].lower():
                            waf_detected = waf_name
                            break

                security_header_signals = self._analyze_security_headers(response_headers, url)
                cookie_security_signals = self._analyze_cookies(response_headers, url)

                body_l = text.lower()
                for tech, indicators in _TECH_INDICATORS.items():
                    if any(ind.lower() in body_l for ind in indicators):
                        body_technologies.append(tech)
        except Exception as exc:
            logger.warning("Technology fingerprint failed for %s: %s", url, exc)

        if waf_detected is None:
            try:
                parsed = urlparse(url)
                sep = "&" if parsed.query else "?"
                probe_url = f"{url}{sep}aegis_waf_probe=<script>alert(1)</script>"
                async with session.get(probe_url) as probe_resp:
                    if probe_resp.status == 403:
                        waf_detected = "behavioral_waf_detected"
            except Exception as exc:
                logger.debug("Behavioral WAF probe failed for %s: %s", url, exc)

        return {
            "headers": headers_out,
            "body_technologies": sorted(set(body_technologies)),
            "waf_detected": waf_detected,
            "security_header_signals": security_header_signals,
            "cookie_security_signals": cookie_security_signals,
        }

    def _analyze_security_headers(self, headers: dict[str, str], url: str) -> list[str]:
        signals = []
        header_keys_lower = {k.lower() for k in headers}

        security_headers = {
            "content-security-policy": "Missing Content-Security-Policy header — XSS and injection risk (A05:2023)",
            "x-frame-options": "Missing X-Frame-Options header — clickjacking risk (A05:2023)",
            "strict-transport-security": "Missing HSTS header — downgrade attack risk (A02:2023)",
            "x-content-type-options": "Missing X-Content-Type-Options header — MIME sniffing risk (A05:2023)",
            "referrer-policy": "Missing Referrer-Policy header — information leakage risk (A05:2023)",
            "permissions-policy": "Missing Permissions-Policy header (A05:2023)",
        }
        for header, message in security_headers.items():
            if header not in header_keys_lower:
                signals.append(message)

        csp = headers.get("Content-Security-Policy", headers.get("content-security-policy", ""))
        if csp and "unsafe-inline" in csp:
            signals.append("Content-Security-Policy contains unsafe-inline — CSP bypass possible (A05:2023)")
        if csp and "unsafe-eval" in csp:
            signals.append("Content-Security-Policy contains unsafe-eval — CSP bypass possible (A05:2023)")

        return signals

    def _analyze_cookies(self, response_headers: dict, url: str) -> list[str]:
        signals = []
        is_https = url.startswith("https://")
        set_cookie_headers = []
        for k, v in response_headers.items():
            if k.lower() == "set-cookie":
                set_cookie_headers.append(v)

        for cookie in set_cookie_headers:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split("=")[0].strip()

            if "httponly" not in cookie_lower:
                signals.append(f"Cookie '{cookie_name}' missing HttpOnly flag — XSS cookie theft risk (A07:2023)")
            if is_https and "secure" not in cookie_lower:
                signals.append(f"Cookie '{cookie_name}' missing Secure flag on HTTPS endpoint (A02:2023)")
            if "samesite" not in cookie_lower:
                signals.append(f"Cookie '{cookie_name}' missing SameSite attribute — CSRF risk (A01:2023)")

        return signals[:10]

    async def _check_cors_misconfiguration(self, url: str, session: aiohttp.ClientSession) -> list[str]:
        signals = []
        try:
            async with session.options(url, headers={
                "Origin": "https://evil-attacker.com",
                "Access-Control-Request-Method": "GET",
            }) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "*":
                    signals.append("CORS wildcard origin (*) — any site can read responses (A05:2023)")
                elif urlparse(acao).netloc.lower() == "evil-attacker.com":
                    signals.append("CORS reflects arbitrary Origin — any site can read responses (A05:2023)")
                    if acac.lower() == "true":
                        signals.append("CORS reflects Origin with Allow-Credentials:true — authenticated CORS attack possible (A05:2023) CRITICAL")
        except Exception:
            pass
        return signals

    async def _crawl_and_extract(self, url: str, session: aiohttp.ClientSession, depth: int) -> dict:
        parsed_root = urlparse(url)
        root_host = parsed_root.netloc

        queue: list[tuple[str, int]] = [(url, 0)]
        seen: set[str] = set()

        endpoints: set[str] = set()
        forms: list[dict] = []
        html_comments: list[str] = []
        script_urls: set[str] = set()
        page_classifications: dict[str, str] = {}
        page_bodies: list[str] = []

        while queue and len(seen) < 100:
            current, level = queue.pop(0)
            if current in seen or level > depth:
                continue
            seen.add(current)
            endpoints.add(current)

            try:
                async with session.get(current) as resp:
                    if resp.status >= 400:
                        continue
                    body = await resp.text(errors="replace")
            except Exception:
                continue

            page_bodies.append(body[:5000])
            soup = BeautifulSoup(body, "html.parser")
            title = (soup.title.string or "").strip() if soup.title else ""

            extracted_forms = self._extract_forms(soup, current)
            forms.extend(extracted_forms)

            for a in soup.find_all("a", href=True):
                full = urljoin(current, a["href"])
                p = urlparse(full)
                if p.netloc == root_host and p.scheme in {"http", "https"} and full not in seen:
                    queue.append((full, level + 1))

            for sc in soup.find_all("script", src=True):
                full = urljoin(current, sc["src"])
                if urlparse(full).netloc == root_host:
                    script_urls.add(full)

            for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
                comment_text = str(c).strip()
                if comment_text:
                    html_comments.append(comment_text)

            classification = self._classify_page(current, extracted_forms)
            page_classifications[current] = classification

        return {
            "endpoints": sorted(endpoints),
            "forms": forms,
            "html_comments": list(dict.fromkeys(html_comments)),
            "script_urls": sorted(script_urls),
            "page_classifications": page_classifications,
            "page_bodies": page_bodies,
        }

    def _shannon_entropy(self, s: str) -> float:
        from collections import Counter
        from math import log2

        if not s:
            return 0.0
        counts = Counter(s)
        total = len(s)
        return -sum((c / total) * log2(c / total) for c in counts.values())

    async def _fetch_and_analyze_javascript(
        self,
        script_urls: list[str],
        session: aiohttp.ClientSession,
        root_host: str,
    ) -> dict:
        api_paths: set[str] = set()
        hardcoded_secrets: list[dict[str, str]] = []
        fetch_endpoints: set[str] = set()

        api_path_re = re.compile(r'["\'](/api/[^\'\"]{3,60})["\']')
        full_url_re = re.compile(r'https?://[^\s"\']{10,150}')
        token_re = re.compile(r'["\']([A-Za-z0-9+/=_\-.]{20,})["\']')
        secret_re = re.compile(r'(?:password|secret|api[_-]?key|token)["\s]*[:=]["\s]*([^\s"\']{8,})', re.I)
        fetch_re = re.compile(r'fetch\(["\']([^\'\"]+)["\']')
        axios_re = re.compile(r'axios\.[a-z]+\(["\']([^\'\"]+)["\']')
        named_patterns = {
            "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
            "bearer_token": re.compile(r"bearer\s+[A-Za-z0-9\-_]{20,}", re.I),
            "private_key_header": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            "stripe_key": re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24,}"),
            "github_token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
            "github_pat": re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
            "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b"),
        }
        hex_re = re.compile(r"\b[0-9a-f]{32,64}\b", re.I)
        seen: set[tuple[str, str]] = set()

        def _redact(value: str) -> str:
            value = value.strip()
            return f"{value[:6]}..." if value else "......"

        def _append_secret(secret_type: str, value: str, source_url: str) -> None:
            key = (secret_type, value)
            if key in seen or not value:
                return
            seen.add(key)
            hardcoded_secrets.append({
                "type": secret_type,
                "value": _redact(value),
                "source_url": source_url,
            })

        for script_url in script_urls[:10]:
            try:
                async with session.get(script_url) as resp:
                    content = await resp.text(errors="replace")
            except Exception:
                continue

            api_paths.update(api_path_re.findall(content))
            for candidate in token_re.findall(content):
                if len(candidate) > 20 and self._shannon_entropy(candidate) > 3.5:
                    _append_secret("high_entropy", candidate, script_url)
            for candidate in secret_re.findall(content):
                if self._shannon_entropy(candidate) > 3.5 and len(candidate) >= 12:
                    _append_secret("high_entropy", candidate, script_url)
            for pattern_name, pattern in named_patterns.items():
                for match in pattern.finditer(content):
                    _append_secret(pattern_name, match.group(0), script_url)
            for candidate in hex_re.findall(content):
                if self._shannon_entropy(candidate) > 3.8:
                    _append_secret("high_entropy_hex", candidate, script_url)

            for endpoint in fetch_re.findall(content) + axios_re.findall(content):
                if endpoint.startswith("/"):
                    fetch_endpoints.add(endpoint)

            for full in full_url_re.findall(content):
                parsed = urlparse(full)
                if parsed.netloc == root_host:
                    api_paths.add(parsed.path)

        return {
            "api_paths": sorted(api_paths),
            "hardcoded_secrets": hardcoded_secrets,
            "fetch_endpoints": sorted(fetch_endpoints),
        }

    async def _check_common_paths(self, url: str, session: aiohttp.ClientSession) -> dict:
        common = [
            "/.git/HEAD", "/api/swagger.json", "/api/openapi.json", "/swagger.json", "/openapi.json",
            "/api/docs", "/robots.txt", "/sitemap.xml", "/.env", "/config.json", "/api/graphql", "/graphql",
            "/actuator/env", "/actuator/health", "/actuator/mappings",
            "/.env.local", "/.env.backup", "/.git/config",
            "/wp-admin/", "/wp-login.php", "/phpmyadmin/",
            "/server-status", "/server-info",
            "/api/v2/", "/api/v1/", "/api/",
            "/admin/", "/administrator/",
            "/.well-known/security.txt",
            "/backup.zip", "/backup.sql", "/dump.sql",
        ]
        found_paths: dict[str, int] = {}
        openapi_endpoints: set[str] = set()
        sitemap_urls: set[str] = set()
        graphql_available = False
        graphql_endpoint: str | None = None
        graphql_schema: dict[str, list[dict[str, Any]]] = {"queries": [], "mutations": []}
        graphql_injection_points: list[dict[str, str]] = []
        introspection_query = """
        { __schema {
            queryType { name fields { name args { name type { name kind ofType { name kind } } } } }
            mutationType { name fields { name args { name type { name kind ofType { name kind } } } } }
        } }
        """
        common_graphql_fields = ["id", "user", "admin", "token", "secret", "password", "email", "role", "permissions"]

        for path in common:
            full = urljoin(url, path)
            status = None
            needs_get_fallback = False
            try:
                async with session.head(full) as resp:
                    status = resp.status
                if status == 404:
                    needs_get_fallback = False
                elif status == 200:
                    needs_get_fallback = False
                else:
                    needs_get_fallback = True
            except Exception:
                needs_get_fallback = True

            if needs_get_fallback:
                try:
                    async with session.get(full) as resp:
                        status = resp.status
                except Exception:
                    status = None

            if status == 200:
                found_paths[path] = status

            if path == "/robots.txt" and status == 200:
                try:
                    async with session.get(full) as resp:
                        robots_text = await resp.text(errors="replace")
                    disallowed_paths = []
                    for line in robots_text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("disallow:"):
                            dp = line.split(":", 1)[1].strip()
                            if dp and dp != "/":
                                disallowed_paths.append(dp)
                    for dp in disallowed_paths[:20]:
                        found_paths[f"robots_disallowed:{dp}"] = 200
                except Exception:
                    pass

            if path == "/sitemap.xml" and status == 200:
                try:
                    async with session.get(full) as resp:
                        sitemap_text = await resp.text(errors="replace")
                    import re as _re

                    for loc in _re.findall(r"<loc>\s*(https?://[^\s<]+)\s*</loc>", sitemap_text):
                        sitemap_urls.add(loc)
                except Exception:
                    pass

            if path in {"/api/swagger.json", "/api/openapi.json", "/swagger.json", "/openapi.json"} and status == 200:
                try:
                    async with session.get(full) as resp:
                        spec = await resp.json(content_type=None)
                    for p, methods in (spec.get("paths", {}) or {}).items():
                        openapi_endpoints.add(p)
                        if isinstance(methods, dict):
                            for method, details in methods.items():
                                if isinstance(details, dict):
                                    for prm in details.get("parameters", []) or []:
                                        _ = prm.get("name")
                except Exception:
                    pass

            if path in {"/api/graphql", "/graphql"} and status == 200:
                graphql_available = True
                graphql_endpoint = full

        if graphql_available and graphql_endpoint:
            try:
                async with session.post(graphql_endpoint, json={"query": introspection_query}) as resp:
                    payload = await resp.json(content_type=None)
                schema = (payload.get("data", {}) or {}).get("__schema", {}) if isinstance(payload, dict) else {}

                def _fmt_type(t: dict | None) -> str:
                    if not isinstance(t, dict):
                        return "UNKNOWN"
                    name = t.get("name")
                    kind = t.get("kind")
                    of_type = t.get("ofType")
                    if name:
                        return str(name)
                    if isinstance(of_type, dict):
                        child_name = of_type.get("name") or of_type.get("kind")
                        if child_name:
                            return str(child_name)
                    return str(kind or "UNKNOWN")

                for key, output_key in (("queryType", "queries"), ("mutationType", "mutations")):
                    fields = ((schema.get(key) or {}).get("fields") or []) if isinstance(schema, dict) else []
                    for field in fields:
                        if not isinstance(field, dict):
                            continue
                        field_name = str(field.get("name", "")).strip()
                        args = []
                        for arg in field.get("args") or []:
                            if not isinstance(arg, dict):
                                continue
                            arg_name = str(arg.get("name", "")).strip()
                            arg_type = _fmt_type(arg.get("type"))
                            if not field_name or not arg_name:
                                continue
                            args.append({"name": arg_name, "type": arg_type})
                            graphql_injection_points.append({
                                "url": graphql_endpoint,
                                "method": "POST",
                                "param_name": f"{field_name}.{arg_name}",
                                "param_type": "graphql",
                                "context_hint": "GraphQL argument",
                            })
                        graphql_schema[output_key].append({"name": field_name, "args": args})
            except Exception:
                logger.debug("GraphQL introspection parse failed for %s", graphql_endpoint)
                try:
                    for field in common_graphql_fields:
                        probe_query = {"query": f"query {{ {field} }}"}
                        async with session.post(graphql_endpoint, json=probe_query) as resp:
                            body = await resp.text(errors="replace")
                        if "introspection" in body.lower():
                            found_paths["graphql_introspection_disabled"] = 200
                        if any(token in body.lower() for token in ["data", "errors", field.lower()]):
                            graphql_injection_points.append({
                                "url": graphql_endpoint,
                                "method": "POST",
                                "param_name": field,
                                "param_type": "graphql",
                                "context_hint": "GraphQL field name probe",
                            })
                except Exception:
                    pass

        return {
            "found_paths": found_paths,
            "openapi_endpoints": sorted(openapi_endpoints),
            "graphql_available": graphql_available,
            "graphql_schema": graphql_schema,
            "graphql_injection_points": graphql_injection_points,
            "sitemap_urls": sorted(sitemap_urls)[:50],
        }

    async def _port_scan(self, domain: str) -> list[dict]:
        loop = asyncio.get_running_loop()

        def _normalize_host(raw_domain: str) -> tuple[str, bool]:
            target = raw_domain.strip()
            if target.startswith("["):
                closing = target.find("]")
                host = target[1:closing] if closing != -1 else target.strip("[]")
            elif target.count(":") == 1:
                host = target.split(":", 1)[0]
            else:
                host = target

            is_ipv6 = ":" in host and not host.startswith("[")
            nmap_target = f"[{host}]" if is_ipv6 else host
            return nmap_target, is_ipv6

        def _run_scan() -> list[dict]:
            try:
                host_target, is_ipv6 = _normalize_host(domain)
                cmd = ["nmap", "-F", "-T4", "--open"]
                if is_ipv6:
                    cmd.append("-6")
                cmd.append(host_target)
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if proc.returncode != 0:
                    raise RuntimeError(proc.stderr.strip() or "nmap failed")

                results: list[dict] = []
                for line in proc.stdout.splitlines():
                    m = re.match(r"^(\d+)/tcp\s+open\s+([^\s]+)\s*(.*)$", line.strip())
                    if not m:
                        continue
                    results.append({
                        "port": int(m.group(1)),
                        "service": m.group(2),
                        "banner": m.group(3).strip(),
                    })
                return results
            except Exception as exc:
                logger.warning("Port scan failed for %s: %s", domain, exc)
                return []

        return await loop.run_in_executor(_NMAP_POOL, _run_scan)
    
    async def _enumerate_subdomains(self, domain: str) -> list[dict]:
        try:
            base_domain = domain.strip()
            if base_domain.startswith("["):
                return []
            if base_domain.count(":") == 1:
                base_domain = base_domain.split(":", 1)[0]

            wordlist_path = Path(__file__).resolve().parent.parent / "data" / "subdomain_wordlist.txt"
            if not wordlist_path.exists():
                return []

            words: list[str] = []
            for line in wordlist_path.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                words.append(stripped)
                if len(words) >= 200:
                    break

            semaphore = asyncio.Semaphore(20)
            resolver = dns.resolver.Resolver(configure=True)
            crt_discovered: set[str] = set()
            try:
                crt_url = f"https://crt.sh/?q=%.{base_domain}&output=json"
                timeout = aiohttp.ClientTimeout(total=10)
                async with aiohttp.ClientSession(timeout=timeout) as crt_session:
                    async with crt_session.get(crt_url) as resp:
                        if resp.status == 200:
                            crt_data = await resp.json(content_type=None)
                            if isinstance(crt_data, list):
                                for item in crt_data:
                                    if not isinstance(item, dict):
                                        continue
                                    name_value = str(item.get("name_value", ""))
                                    for raw_name in name_value.splitlines():
                                        name = raw_name.strip().lstrip("*.").lower()
                                        if name and name.endswith(base_domain.lower()):
                                            crt_discovered.add(name)
            except Exception as exc:
                logger.warning("crt_sh_unreachable domain=%s error=%s", base_domain, exc)

            async def _resolve_candidate(candidate: str) -> dict[str, Any] | None:
                async with semaphore:
                    try:
                        a_answers = await asyncio.to_thread(resolver.resolve, candidate, "A", lifetime=2)
                    except Exception:
                        return None

                    ip = str(a_answers[0]) if len(a_answers) else ""
                    if not ip:
                        return None

                    takeover_risk = False
                    try:
                        cname_answers = await asyncio.to_thread(resolver.resolve, candidate, "CNAME", lifetime=2)
                        if len(cname_answers):
                            cname_target = str(cname_answers[0]).rstrip(".").lower()
                            risky = ["github.io", "amazonaws.com", "azurewebsites.net", "herokuapp.com", "fastly.net", "shopify.com"]
                            if any(r in cname_target for r in risky):
                                cname_resolves = True
                                try:
                                    await asyncio.to_thread(resolver.resolve, cname_target, "A", lifetime=2)
                                except Exception:
                                    cname_resolves = False
                                takeover_risk = not cname_resolves
                    except Exception:
                        pass

                    result = {"subdomain": candidate, "ip": ip}
                    if takeover_risk:
                        result["takeover_risk"] = True
                    return result

            wordlist_candidates = [
                f"{word}.{base_domain}"
                for word in words
                if f"{word}.{base_domain}".lower() not in crt_discovered
            ]
            all_candidates = sorted(crt_discovered) + wordlist_candidates
            resolved = await asyncio.gather(*[_resolve_candidate(c) for c in all_candidates], return_exceptions=True)
            out = [r for r in resolved if isinstance(r, dict)]
            return out
        except Exception as exc:
            logger.debug("Subdomain enumeration failed for %s: %s", domain, exc)
            return []

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> list[dict]:
        out: list[dict] = []
        for form in soup.find_all("form"):
            method = str(form.get("method", "GET")).upper()
            action = form.get("action") or base_url
            action_abs = action if action.startswith(("http://", "https://")) else urljoin(base_url, action)

            inputs: list[dict] = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                inputs.append({"name": name, "type": inp.get("type", "text")})

            out.append({"action": action_abs, "method": method, "inputs": inputs})
        return out

    def _classify_page(self, url: str, forms: list[dict]) -> str:
        lower = url.lower()
        has_password = any(
            i.get("type", "").lower() == "password"
            for f in forms for i in f.get("inputs", [])
        )
        has_file = any(
            i.get("type", "").lower() == "file"
            for f in forms for i in f.get("inputs", [])
        )

        if "/login" in lower or "/signin" in lower or has_password:
            return "login_page"
        if "/admin" in lower or "/dashboard" in lower:
            return "admin_page"
        if "/upload" in lower or has_file:
            return "upload_page"
        if "/api/" in lower:
            return "api_endpoint"
        return "general"

    def _collect_injection_points(
        self,
        crawled: dict,
        openapi_endpoints: list[str],
        js_fetch_endpoints: list[str],
        root_url: str,
    ) -> list[dict]:
        points: dict[tuple[str, str, str], dict] = {}

        for endpoint in crawled.get("endpoints", []):
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for param in params:
                key = (base, param, "GET")
                points[key] = {
                    "url": base,
                    "method": "GET",
                    "param_name": param,
                    "param_type": "query",
                    "context_hint": "query parameter from crawl",
                    "other_params": {},
                }

        form_actions: set[str] = set()
        for form in crawled.get("forms", []):
            method = str(form.get("method", "GET")).upper()
            action = form.get("action", "")
            form_actions.add(action)
            for inp in form.get("inputs", []):
                name = inp.get("name")
                if not name:
                    continue
                key = (action, name, method)
                points[key] = {
                    "url": action,
                    "method": method,
                    "param_name": name,
                    "param_type": "form" if method == "POST" else "query",
                    "context_hint": f"form input ({inp.get('type', 'text')})",
                    "other_params": {},
                }

        template_re = re.compile(r"\{([^}]+)\}")
        for ep in openapi_endpoints:
            key = (ep, "id", "GET")
            points.setdefault(key, {
                "url": ep,
                "method": "GET",
                "param_name": "id",
                "param_type": "query",
                "context_hint": "OpenAPI-discovered endpoint",
                "other_params": {},
            })

            for param_name in template_re.findall(ep):
                clean_url = template_re.sub("", ep)
                clean_url = clean_url if clean_url.startswith(("http://", "https://")) else urljoin(root_url, clean_url)
                key_tpl = (clean_url, param_name, "GET")
                points.setdefault(key_tpl, {
                    "url": clean_url,
                    "method": "GET",
                    "param_name": param_name,
                    "param_type": "query",
                    "context_hint": "OpenAPI path template parameter",
                    "other_params": {},
                })

        for endpoint in js_fetch_endpoints:
            if "/api/" not in endpoint:
                continue
            endpoint_url = endpoint if endpoint.startswith(("http://", "https://")) else urljoin(root_url, endpoint)
            if endpoint_url in form_actions:
                continue
            key = (endpoint_url, "data", "POST")
            points.setdefault(key, {
                "url": endpoint_url,
                "method": "POST",
                "param_name": "data",
                "param_type": "json",
                "context_hint": "JS fetch/axios API endpoint",
                "other_params": {},
            })

        return list(points.values())

    def _infer_database_hint(self, page_bodies: list[str]) -> str | None:
        corpus = "\n".join(page_bodies).lower()
        if any(p in corpus for p in ["mysql", "sql syntax", "you have an error in your sql"]):
            return "MySQL"
        if any(p in corpus for p in ["postgresql", "pg_", "psql:"]):
            return "PostgreSQL"
        if any(p in corpus for p in ["ora-", "oracle"]):
            return "Oracle"
        return None

    def _header_techs(self, headers: dict[str, str]) -> set[str]:
        out: set[str] = set()
        header_map = {str(k).lower(): str(v).lower() for k, v in headers.items()}
        joined = " ".join(f"{k}:{v}" for k, v in header_map.items())
        if "php" in joined:
            out.add("php")
        aspnet_prefix = ".".join(["asp", "net"])
        if "x-aspnet-version" in header_map or header_map.get("x-powered-by", "").startswith(aspnet_prefix):
            out.add("aspnet")
        if "nginx" in joined:
            out.add("nginx")
        if "apache" in joined:
            out.add("apache")
        return out

    def _infer_backend_and_framework(self, technologies: list[str], headers: dict[str, str]) -> tuple[str | None, str | None]:
        tech_set = set(t.lower() for t in technologies)
        backend = None
        framework = None

        if "php" in tech_set:
            backend = "PHP"
        elif "django" in tech_set:
            backend = "Python"
            framework = "Django"
        elif "rails" in tech_set:
            backend = "Ruby"
            framework = "Rails"
        elif "laravel" in tech_set:
            backend = "PHP"
            framework = "Laravel"

        if framework is None:
            if "wordpress" in tech_set:
                framework = "WordPress"
            elif "react" in tech_set:
                framework = "React"
            elif "angular" in tech_set:
                framework = "Angular"
            elif "vue" in tech_set:
                framework = "Vue"

        if backend is None and "X-AspNet-Version" in headers:
            backend = "ASP.NET"

        return backend, framework

    def _build_attack_surface_signals(
        self,
        fingerprint: dict,
        crawled: dict,
        common_paths: dict,
        js_analysis: dict,
        database_hint: str | None,
        cve_correlations: list[dict[str, Any]],
    ) -> list[str]:
        signals: list[str] = []

        if fingerprint.get("waf_detected"):
            signals.append(f"WAF detected: {fingerprint['waf_detected']}")

        if database_hint:
            signals.append(f"Database hint indicates {database_hint}")

        for comment in crawled.get("html_comments", [])[:10]:
            if any(k in comment.lower() for k in ["todo", "password", "debug", "key"]):
                signals.append(f"HTML comment contains potentially sensitive note: {comment[:120]}")

        for endpoint in js_analysis.get("fetch_endpoints", [])[:10]:
            signals.append(f"JavaScript file reveals endpoint {endpoint}")

        if common_paths.get("graphql_available"):
            signals.append("A01:2023 signal — GraphQL endpoint exposed")

        for secret in js_analysis.get("hardcoded_secrets", [])[:10]:
            secret_type = secret.get("type", "unknown") if isinstance(secret, dict) else "unknown"
            signals.append(f"A02:2023 signal — JavaScript secret candidate ({secret_type})")

        for path, status in common_paths.get("found_paths", {}).items():
            if status == 200:
                if path == "/.git/HEAD":
                    signals.append("/.git/HEAD returns 200 — source code may be accessible")
                else:
                    signals.append(f"Interesting path {path} returned 200")

        for cve in cve_correlations[:10]:
            cve_id = cve.get("cve_id")
            score = cve.get("cvss_score")
            if cve_id:
                signals.append(f"A06:2023 signal — {cve_id} correlated (CVSS {score})")

        return list(dict.fromkeys(signals))
