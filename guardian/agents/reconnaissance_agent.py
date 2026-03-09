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

from guardian.core.ai_client import estimate_tokens
from guardian.core.config import settings
from guardian.models.target_model import TargetModel

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

            fingerprint, crawled, common_paths, open_ports, subdomains = await asyncio.gather(
                fp_task,
                crawl_task,
                common_task,
                port_task,
                subdomain_task,
            )

            js_analysis = await self._fetch_and_analyze_javascript(
                crawled.get("script_urls", []),
                session,
                parsed.netloc,
            )

        injection_points = self._collect_injection_points(
            crawled=crawled,
            openapi_endpoints=common_paths.get("openapi_endpoints", []),
        )

        api_endpoints = sorted(
            set(crawled.get("endpoints", []))
            | set(common_paths.get("openapi_endpoints", []))
            | set(js_analysis.get("api_paths", []))
            | set(js_analysis.get("fetch_endpoints", []))
        )

        technologies = sorted(
            set(fingerprint.get("body_technologies", []))
            | self._header_techs(fingerprint.get("headers", {}))
        )

        backend_language, framework = self._infer_backend_and_framework(technologies, fingerprint.get("headers", {}))
        database_hint = self._infer_database_hint(crawled.get("page_bodies", []))

        attack_surface_signals = self._build_attack_surface_signals(
            fingerprint=fingerprint,
            crawled=crawled,
            common_paths=common_paths,
            js_analysis=js_analysis,
            database_hint=database_hint,
        )

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
            interesting_paths=sorted(common_paths.get("found_paths", {}).keys()),
            open_ports=open_ports,
            subdomains=subdomains,
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
            from guardian.core.probing.probe_executor import _build_ssl_context

            return _build_ssl_context()
        except Exception:
            if not settings.VERIFY_SSL:
                return False
            return ssl.create_default_context()

    async def _fingerprint_technologies(self, url: str, session: aiohttp.ClientSession) -> dict:
        headers_out: dict[str, str] = {}
        body_technologies: list[str] = []
        waf_detected: str | None = None

        try:
            async with session.get(url) as resp:
                text = await resp.text(errors="replace")
                for key in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "X-Framework"]:
                    if key in resp.headers:
                        headers_out[key] = resp.headers[key]

                header_lower = {k.lower(): v for k, v in resp.headers.items()}
                for key, contains, waf_name in _WAF_SIGNATURES:
                    if key in header_lower:
                        if not contains or contains in header_lower[key].lower():
                            waf_detected = waf_name
                            break

                body_l = text.lower()
                for tech, indicators in _TECH_INDICATORS.items():
                    if any(ind.lower() in body_l for ind in indicators):
                        body_technologies.append(tech)
        except Exception as exc:
            logger.warning("Technology fingerprint failed for %s: %s", url, exc)

        if not waf_detected:
            try:
                probe_url = f"{url}?guardian_waf_probe=<script>alert(1)</script>"
                async with session.get(probe_url) as resp:
                    probe_body = (await resp.text(errors="replace")).lower()
                    location = (resp.headers.get("Location") or resp.headers.get("location") or "").lower()

                    if resp.status in (403, 406):
                        waf_detected = "behavioral_waf_detected"
                        logger.info("Behavioral WAF detected via status probe for %s", url)
                    elif any(
                        key in probe_body
                        for key in [
                            "blocked",
                            "forbidden",
                            "security",
                            "firewall",
                            "protection",
                            "access denied",
                            "request rejected",
                            "mod_security",
                        ]
                    ):
                        waf_detected = "behavioral_waf_detected"
                        logger.info("Behavioral WAF detected via response-body probe for %s", url)
                    elif resp.status == 302 and any(key in location for key in ["captcha", "challenge"]):
                        waf_detected = "captcha_waf_detected"
                        logger.info("Behavioral WAF challenge detected for %s", url)
            except Exception as exc:
                logger.debug("Behavioral WAF probe failed for %s: %s", url, exc)

        return {
            "headers": headers_out,
            "body_technologies": sorted(set(body_technologies)),
            "waf_detected": waf_detected,
        }

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
            if title:
                classification = classification
            page_classifications[current] = classification

        return {
            "endpoints": sorted(endpoints),
            "forms": forms,
            "html_comments": list(dict.fromkeys(html_comments)),
            "script_urls": sorted(script_urls),
            "page_classifications": page_classifications,
            "page_bodies": page_bodies,
        }

    async def _fetch_and_analyze_javascript(
        self,
        script_urls: list[str],
        session: aiohttp.ClientSession,
        root_host: str,
    ) -> dict:
        api_paths: set[str] = set()
        hardcoded_secrets: set[str] = set()
        fetch_endpoints: set[str] = set()

        api_path_re = re.compile(r'["\'](/api/[^\'\"]{3,60})["\']')
        full_url_re = re.compile(r'https?://[^\s"\']{10,150}')
        aws_re = re.compile(r'AKIA[0-9A-Z]{16}')
        secret_re = re.compile(r'(?:password|secret|api[_-]?key|token)["\s]*[:=]["\s]*([^\s"\']{8,})', re.I)
        fetch_re = re.compile(r'fetch\(["\']([^\'\"]+)["\']')
        axios_re = re.compile(r'axios\.[a-z]+\(["\']([^\'\"]+)["\']')

        for script_url in script_urls[:10]:
            try:
                async with session.get(script_url) as resp:
                    content = await resp.text(errors="replace")
            except Exception:
                continue

            api_paths.update(api_path_re.findall(content))
            hardcoded_secrets.update(aws_re.findall(content))
            hardcoded_secrets.update(secret_re.findall(content))

            for endpoint in fetch_re.findall(content) + axios_re.findall(content):
                if endpoint.startswith("/"):
                    fetch_endpoints.add(endpoint)

            for full in full_url_re.findall(content):
                parsed = urlparse(full)
                if parsed.netloc == root_host:
                    api_paths.add(parsed.path)

        return {
            "api_paths": sorted(api_paths),
            "hardcoded_secrets": sorted(hardcoded_secrets),
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
        graphql_available = False

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

            if path in {"/robots.txt", "/sitemap.xml"} and status == 200:
                try:
                    async with session.get(full) as resp:
                        _ = await resp.text(errors="replace")
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

        return {
            "found_paths": found_paths,
            "openapi_endpoints": sorted(openapi_endpoints),
            "graphql_available": graphql_available,
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

            async def _resolve_candidate(word: str) -> dict[str, Any] | None:
                candidate = f"{word}.{base_domain}"
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

            resolved = await asyncio.gather(*[_resolve_candidate(w) for w in words], return_exceptions=True)
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

    def _collect_injection_points(self, crawled: dict, openapi_endpoints: list[str]) -> list[dict]:
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

        for form in crawled.get("forms", []):
            method = str(form.get("method", "GET")).upper()
            action = form.get("action", "")
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
        joined = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        if "php" in joined:
            out.add("php")
        if "asp.net" in joined:
            out.add("asp.net")
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

        for path, status in common_paths.get("found_paths", {}).items():
            if status == 200:
                if path == "/.git/HEAD":
                    signals.append("/.git/HEAD returns 200 — source code may be accessible")
                else:
                    signals.append(f"Interesting path {path} returned 200")

        return list(dict.fromkeys(signals))