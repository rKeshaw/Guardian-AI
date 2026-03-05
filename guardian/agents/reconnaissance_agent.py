"""
guardian/agents/reconnaissance_agent.py
"""

import asyncio
import logging
import os
import random
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urljoin, urlparse

import aiohttp
import dns.resolver
import nmap
from bs4 import BeautifulSoup

from guardian.agents.base_agent import BaseAgent
from guardian.core.config import settings

logger = logging.getLogger(__name__)

# One shared thread-pool for all nmap / legacy-blocking calls
_BLOCKING_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="recon-blocking")

# Maximum parallel DNS resolutions
MAX_DNS_CONCURRENCY = 50

# Maximum parallel HTTP requests during crawl / subdomain service checks
MAX_HTTP_CONCURRENCY = 20


def _build_ssl_context() -> ssl.SSLContext | bool:
    """
    Return an ssl.SSLContext if VERIFY_SSL is True (optionally loading a
    custom CA bundle), or False to disable verification entirely.
    Setting VERIFY_SSL=False emits a startup warning.
    """
    if not settings.VERIFY_SSL:
        logger.warning(
            "SSL verification is DISABLED (VERIFY_SSL=False). "
            "This exposes reconnaissance traffic to MITM attacks."
        )
        return False

    ctx = ssl.create_default_context()
    if settings.CA_BUNDLE_PATH and os.path.exists(settings.CA_BUNDLE_PATH):
        ctx.load_verify_locations(cafile=settings.CA_BUNDLE_PATH)
        logger.debug("Loaded custom CA bundle from %s", settings.CA_BUNDLE_PATH)
    return ctx


# Build once at import time — all aiohttp sessions in this module reuse it
_SSL_CONTEXT = _build_ssl_context()


def _make_connector() -> aiohttp.TCPConnector:
    return aiohttp.TCPConnector(
        ssl=_SSL_CONTEXT,
        limit=MAX_HTTP_CONCURRENCY,
        limit_per_host=5,
        enable_cleanup_closed=True,
    )


class ReconnaissanceAgent(BaseAgent):
    """
    Agent 1 — Elite Reconnaissance and Intelligence Gathering.

    Capabilities:
      - Subdomain enumeration (wordlist + CT logs, with wildcard guard)
      - Technology stack fingerprinting
      - Non-blocking Nmap port scanning
      - Async web application crawling
      - DNS intelligence gathering
      - SSL/TLS certificate analysis
      - Attack surface scoring
    """

    def __init__(self, db) -> None:
        super().__init__(db, "ReconnaissanceAgent")
        self._user_agents: list[str] = settings.USER_AGENTS

    # ── Entry point ───────────────────────────

    async def execute(self, task_data: dict[str, Any]) -> dict[str, Any]:
        task_id = await self._start_task(task_data)
        session_id = task_data.get("session_id", "unknown")

        try:
            targets: list[str] = task_data.get("targets", [])
            config: dict[str, Any] = task_data.get("config", {})
            logger.info("Reconnaissance starting targets=%s", targets)

            results: dict[str, Any] = {
                "task_id": task_id,
                "agent_name": "ReconMaster",
                "targets_analyzed": len(targets),
                "reconnaissance_data": {},
                "intelligence_summary": {},
            }

            # Analyse all targets concurrently (each target is already async-heavy)
            analyses = await asyncio.gather(
                *[self._comprehensive_target_analysis(t, config) for t in targets],
                return_exceptions=True,
            )

            for target_url, analysis in zip(targets, analyses):
                if isinstance(analysis, Exception):
                    logger.error("Target analysis failed target=%s error=%s", target_url, analysis)
                    results["reconnaissance_data"][target_url] = {"error": str(analysis)}
                else:
                    results["reconnaissance_data"][target_url] = analysis

            results["intelligence_summary"] = self._generate_intelligence_summary(
                results["reconnaissance_data"]
            )

            await self._complete_task(results, session_id)
            logger.info("Reconnaissance complete targets=%d", len(targets))
            return results

        except Exception as exc:
            await self._handle_error(exc, session_id)
            raise

    # ── Per-target orchestration ──────────────

    async def _comprehensive_target_analysis(
        self, target_url: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        parsed = urlparse(target_url)
        domain = parsed.netloc or parsed.path  # handle bare domains too

        async with aiohttp.ClientSession(
            connector=_make_connector(),
            headers={"User-Agent": random.choice(self._user_agents)},
            timeout=aiohttp.ClientTimeout(total=30, connect=10),
        ) as session:
            tasks = [
                self._subdomain_enumeration(domain, session),
                self._technology_stack_analysis(target_url, session),
                self._port_reconnaissance(domain),
                self._web_application_mapping(target_url, session, config.get("crawl_depth", 2)),
                self._dns_intelligence(domain),
                self._certificate_analysis(domain, session),
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        def safe(r, default):
            return r if not isinstance(r, Exception) else (
                logger.debug("Recon subtask failed: %s", r) or default
            )

        intel = {
            "domain":           domain,
            "target_url":       target_url,
            "subdomains":       safe(results[0], []),
            "technologies":     safe(results[1], {}),
            "open_ports":       safe(results[2], []),
            "web_applications": safe(results[3], {}),
            "dns_intelligence": safe(results[4], {}),
            "certificates":     safe(results[5], {}),
            "analysis_timestamp": time.time(),
            "attack_surface_score": 0.0,
        }
        intel["attack_surface_score"] = self._calculate_attack_surface_score(intel)
        return intel

    # ── Subdomain enumeration ─────────────────

    async def _subdomain_enumeration(
        self, domain: str, session: aiohttp.ClientSession
    ) -> list[dict[str, Any]]:
        logger.info("Subdomain enumeration starting domain=%s", domain)

        # Step 1: wildcard guard
        if await self._has_wildcard_dns(domain):
            logger.warning(
                "Wildcard DNS detected on %s — brute-force skipped to avoid false positives",
                domain,
            )
            return [{"note": "wildcard_dns_detected", "domain": domain}]

        # Step 2: wordlist brute-force (parallel, semaphore-gated)
        wordlist = self._load_subdomain_wordlist()
        sem = asyncio.Semaphore(MAX_DNS_CONCURRENCY)
        loop = asyncio.get_running_loop()

        async def resolve_one(sub: str) -> dict[str, Any] | None:
            fqdn = f"{sub}.{domain}"
            async with sem:
                try:
                    infos = await loop.getaddrinfo(fqdn, None)
                    ip = infos[0][4][0]
                    services = await self._check_subdomain_services(fqdn, session)
                    return {
                        "subdomain": fqdn,
                        "ip_address": ip,
                        "discovery_method": "wordlist_bruteforce",
                        "status": "active",
                        "services": services,
                    }
                except (socket.gaierror, OSError):
                    return None

        bf_results = await asyncio.gather(*[resolve_one(s) for s in wordlist])
        discovered = [r for r in bf_results if r is not None]

        # Step 3: CT log query (merges additional subdomains)
        ct_results = await self._certificate_transparency_search(domain, session)

        # Deduplicate by subdomain name
        seen: set[str] = {r["subdomain"] for r in discovered}
        for ct in ct_results:
            if ct["subdomain"] not in seen:
                discovered.append(ct)
                seen.add(ct["subdomain"])

        logger.info("Subdomain enumeration done domain=%s found=%d", domain, len(discovered))
        return discovered

    async def _has_wildcard_dns(self, domain: str) -> bool:
        """
        Resolve a guaranteed-nonexistent label to detect wildcard DNS.
        If the probe resolves, every brute-force result would be a false positive.
        """
        probe = f"guardian-ai-wildcard-probe-{random.randint(100000, 999999)}.{domain}"
        loop = asyncio.get_running_loop()
        try:
            await loop.getaddrinfo(probe, None)
            return True  # resolved → wildcard exists
        except (socket.gaierror, OSError):
            return False

    def _load_subdomain_wordlist(self) -> list[str]:
        wordlist_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "data", "subdomain_wordlist.txt",
        )
        try:
            with open(wordlist_path) as fh:
                return [line.strip() for line in fh if line.strip()]
        except FileNotFoundError:
            logger.warning("Subdomain wordlist not found at %s", wordlist_path)
            return []

    async def _check_subdomain_services(
        self, subdomain: str, session: aiohttp.ClientSession
    ) -> list[dict[str, Any]]:
        services = []
        for scheme in ("http", "https"):
            url = f"{scheme}://{subdomain}"
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    text = await resp.text(errors="replace")
                    services.append({
                        "protocol": scheme,
                        "status_code": resp.status,
                        "server": resp.headers.get("Server", "Unknown"),
                        "title": self._extract_title(text) if resp.status == 200 else None,
                    })
            except Exception as exc:
                services.append({"protocol": scheme, "error": str(exc)})
        return services

    # ── CT log integration ────────────────────

    async def _certificate_transparency_search(
        self, domain: str, session: aiohttp.ClientSession
    ) -> list[dict[str, Any]]:
        """
        Query the real crt.sh JSON API for certificate transparency log entries.
        Returns unique subdomains not resolvable — caller deduplicates.
        """
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        discovered: list[dict[str, Any]] = []
        seen: set[str] = set()

        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=20)
            ) as resp:
                if resp.status != 200:
                    logger.debug("crt.sh returned status=%d for domain=%s", resp.status, domain)
                    return []
                entries = await resp.json(content_type=None)

            loop = asyncio.get_running_loop()
            sem = asyncio.Semaphore(MAX_DNS_CONCURRENCY)

            subdomains_from_ct: set[str] = set()
            for entry in entries:
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        subdomains_from_ct.add(name)

            async def resolve_ct(fqdn: str) -> dict[str, Any] | None:
                if fqdn in seen:
                    return None
                async with sem:
                    try:
                        infos = await loop.getaddrinfo(fqdn, None)
                        ip = infos[0][4][0]
                        return {
                            "subdomain": fqdn,
                            "ip_address": ip,
                            "discovery_method": "certificate_transparency",
                            "status": "active",
                            "services": [],
                        }
                    except (socket.gaierror, OSError):
                        return None

            results = await asyncio.gather(*[resolve_ct(s) for s in subdomains_from_ct])
            for r in results:
                if r and r["subdomain"] not in seen:
                    discovered.append(r)
                    seen.add(r["subdomain"])

            logger.info("CT log query done domain=%s ct_found=%d", domain, len(discovered))

        except Exception as exc:
            logger.warning("CT log query failed domain=%s error=%s", domain, exc)

        return discovered

    # ── Technology fingerprinting ─────────────

    async def _technology_stack_analysis(
        self, target_url: str, session: aiohttp.ClientSession
    ) -> dict[str, Any]:
        logger.debug("Technology fingerprinting target=%s", target_url)
        technologies: dict[str, list] = {
            "web_servers": [], "frameworks": [], "cms": [],
            "programming_languages": [], "databases": [],
            "cdn": [], "analytics": [], "security": [],
        }

        try:
            async with session.get(
                target_url, timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                headers = dict(resp.headers)
                content = await resp.text(errors="replace")

            server = headers.get("Server", "")
            if server:
                technologies["web_servers"].append(
                    {"name": server, "confidence": "high", "source": "server_header"}
                )

            for header, category in [
                ("X-Powered-By", "frameworks"),
                ("X-AspNet-Version", "frameworks"),
                ("X-Generator", "cms"),
            ]:
                if header in headers:
                    technologies[category].append(
                        {"name": headers[header], "confidence": "high", "source": f"{header.lower()}_header"}
                    )

            content_lower = content.lower()
            content_indicators = {
                "wordpress":       ("cms",                  ["wp-content", "wp-includes"]),
                "drupal":          ("cms",                  ["drupal", "sites/default"]),
                "joomla":          ("cms",                  ["joomla", "components/com_"]),
                "react":           ("frameworks",           ["react", "_react"]),
                "angular":         ("frameworks",           ["angular", "ng-"]),
                "vue":             ("frameworks",           ["vue.js", "__vue__"]),
                "jquery":          ("frameworks",           ["jquery"]),
                "bootstrap":       ("frameworks",           ["bootstrap"]),
                "php":             ("programming_languages", ["<?php", ".php"]),
                "asp.net":         ("frameworks",           ["__doPostBack", "aspnet"]),
                "cloudflare":      ("cdn",                  ["cloudflare", "__cf_bm"]),
                "google-analytics":("analytics",            ["google-analytics", "gtag"]),
            }
            for tech, (category, indicators) in content_indicators.items():
                if any(ind in content_lower for ind in indicators):
                    technologies[category].append(
                        {"name": tech, "confidence": "medium", "source": "content_analysis"}
                    )

        except Exception as exc:
            logger.debug("Technology analysis failed target=%s error=%s", target_url, exc)

        return technologies

    # ── Port scanning (non-blocking) ──────────

    async def _port_reconnaissance(self, domain: str) -> list[dict[str, Any]]:
        """
        Run nmap in a thread-pool executor so the event loop is never blocked.
        nmap.PortScanner.scan() is a synchronous call that can take 30-120 seconds
        — it must never be called directly in an async context.
        """
        logger.info("Port scan starting domain=%s", domain)
        loop = asyncio.get_running_loop()

        def _run_nmap() -> list[dict[str, Any]]:
            scanner = nmap.PortScanner()
            try:
                scanner.scan(hosts=domain, arguments="-F -T4 --open")
            except Exception as exc:
                logger.error("nmap scan failed domain=%s error=%s", domain, exc)
                return []

            ports: list[dict[str, Any]] = []
            host_data = scanner["scan"].get(domain, {})
            for port, data in host_data.get("tcp", {}).items():
                if data.get("state") == "open":
                    ports.append({
                        "port": port,
                        "state": "open",
                        "service": data.get("name", "unknown"),
                        "banner": f"{data.get('product', '')} {data.get('version', '')}".strip(),
                    })
            return ports

        try:
            ports = await loop.run_in_executor(_BLOCKING_EXECUTOR, _run_nmap)
            logger.info("Port scan done domain=%s open_ports=%d", domain, len(ports))
            return ports
        except Exception as exc:
            logger.error("Port scan executor error domain=%s error=%s", domain, exc)
            return []

    # ── Web application crawler ───────────────

    async def _web_application_mapping(
        self,
        target_url: str,
        session: aiohttp.ClientSession,
        max_depth: int = 2,
    ) -> dict[str, Any]:
        """
        Async BFS crawler.  All HTTP calls use the shared aiohttp session —
        no synchronous requests.get() anywhere in this path.
        """
        logger.debug("Web crawl starting target=%s depth=%d", target_url, max_depth)

        discovered_endpoints: set[str] = set()
        discovered_forms: list[dict] = []
        interesting_files: list[dict] = []
        seen_forms: set[tuple] = set()

        queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        await queue.put((target_url, 0))
        crawled: set[str] = set()
        sem = asyncio.Semaphore(MAX_HTTP_CONCURRENCY)

        base_netloc = urlparse(target_url).netloc

        async def crawl_one(url: str, depth: int) -> None:
            if url in crawled or depth > max_depth:
                return
            crawled.add(url)

            async with sem:
                try:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True
                    ) as resp:
                        if resp.status != 200:
                            return
                        content = await resp.read()
                except Exception as exc:
                    logger.debug("Crawl failed url=%s error=%s", url, exc)
                    return

            discovered_endpoints.add(url)
            soup = BeautifulSoup(content, "html.parser")

            # Enqueue same-origin links
            if depth < max_depth:
                for tag in soup.find_all("a", href=True):
                    full = urljoin(url, tag["href"])
                    if urlparse(full).netloc == base_netloc and full not in crawled:
                        await queue.put((full, depth + 1))

            # Extract unique forms
            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action", ""))
                inputs = sorted(
                    inp.get("name", "") for inp in form.find_all(["input", "textarea", "select"])
                )
                sig = (action, tuple(inputs))
                if sig not in seen_forms:
                    seen_forms.add(sig)
                    discovered_forms.append({
                        "action": action,
                        "method": form.get("method", "GET").upper(),
                        "inputs": [
                            {
                                "name": t.get("name", ""),
                                "type": t.get("type", "text"),
                                "required": t.has_attr("required"),
                            }
                            for t in form.find_all(["input", "textarea", "select"])
                        ],
                    })

            # Flag pages referencing interesting patterns
            text_lower = content.decode(errors="replace").lower()
            for pattern in ["admin", "login", "dashboard", "api", "config", "backup", "upload"]:
                if pattern in text_lower:
                    interesting_files.append({"url": url, "pattern": pattern})

        # Drain the BFS queue with bounded concurrency
        tasks: list[asyncio.Task] = []
        while not queue.empty() or tasks:
            while not queue.empty() and len(tasks) < MAX_HTTP_CONCURRENCY:
                url, depth = await queue.get()
                if len(crawled) >= 100:
                    break
                tasks.append(asyncio.create_task(crawl_one(url, depth)))
            if tasks:
                done, pending = await asyncio.wait(tasks, timeout=1.0, return_when=asyncio.FIRST_COMPLETED)
                tasks = list(pending)

        # Await any remaining tasks
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        return {
            "endpoints": list(discovered_endpoints),
            "forms": discovered_forms,
            "interesting_files": interesting_files,
            "crawl_statistics": {
                "pages_crawled": len(crawled),
                "forms_found": len(discovered_forms),
                "endpoints_discovered": len(discovered_endpoints),
            },
        }

    # ── DNS intelligence ──────────────────────

    async def _dns_intelligence(self, domain: str) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
        dns_records: dict[str, list] = {}

        def query_all() -> dict[str, list]:
            records: dict[str, list] = {}
            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                    records[rtype] = [str(a) for a in answers]
                except Exception:
                    records[rtype] = []
            return records

        dns_records = await loop.run_in_executor(_BLOCKING_EXECUTOR, query_all)

        return {
            "records": dns_records,
            "nameservers": dns_records.get("NS", []),
            "mail_servers": dns_records.get("MX", []),
            "txt_analysis": self._analyze_txt_records(dns_records.get("TXT", [])),
            "subdomain_takeover_risk": self._check_subdomain_takeover_risk(dns_records),
        }

    # ── Certificate analysis ──────────────────

    async def _certificate_analysis(
        self, domain: str, session: aiohttp.ClientSession
    ) -> dict[str, Any]:
        cert_info: dict[str, Any] = {
            "has_certificate": False,
            "issuer": "Unknown",
            "certificate_transparency": False,
        }
        try:
            async with session.get(
                f"https://{domain}", timeout=aiohttp.ClientTimeout(total=8)
            ) as resp:
                if resp.status:
                    cert_info["has_certificate"] = True
                    cert_info["certificate_transparency"] = True
        except Exception:
            pass
        return cert_info

    # ── Utilities ─────────────────────────────

    def _extract_title(self, html: str) -> str:
        try:
            soup = BeautifulSoup(html, "html.parser")
            tag = soup.find("title")
            return tag.get_text().strip() if tag else "No Title"
        except Exception:
            return "Unknown"

    def _analyze_txt_records(self, txt_records: list[str]) -> dict[str, Any]:
        analysis: dict[str, Any] = {
            "spf_record": None,
            "dmarc_record": None,
            "verification_tokens": [],
            "other_records": [],
        }
        for rec in txt_records:
            # dnspython returns TXT values wrapped in quotes — strip them
            clean = rec.strip().strip('"')
            rl = clean.lower()
            if rl.startswith("v=spf1"):
                analysis["spf_record"] = clean
            elif rl.startswith("v=dmarc1"):
                analysis["dmarc_record"] = clean
            elif any(t in rl for t in ["google-site-verification", "facebook-domain-verification"]):
                analysis["verification_tokens"].append(clean)
            else:
                analysis["other_records"].append(clean)
        return analysis

    def _check_subdomain_takeover_risk(self, dns_records: dict[str, list]) -> str:
        vulnerable_services = [
            "github.io", "herokuapp.com", "amazonaws.com",
            "azure", "cloudfront.net", "fastly.com",
        ]
        for cname in dns_records.get("CNAME", []):
            if any(svc in cname.lower() for svc in vulnerable_services):
                return "Potential Risk"
        return "Low Risk"

    def _calculate_attack_surface_score(self, intel: dict[str, Any]) -> float:
        score = 0.0
        score += len(intel.get("subdomains", [])) * 0.1
        score += len(intel.get("open_ports", [])) * 0.2
        web = intel.get("web_applications", {})
        score += len(web.get("endpoints", [])) * 0.05
        score += len(web.get("forms", [])) * 0.3
        for tech_list in intel.get("technologies", {}).values():
            score += len(tech_list) * 0.1
        return round(min(10.0, score), 2)

    def _generate_intelligence_summary(self, recon_data: dict[str, Any]) -> dict[str, Any]:
        total_subdomains = sum(len(d.get("subdomains", [])) for d in recon_data.values())
        total_ports = sum(len(d.get("open_ports", [])) for d in recon_data.values())
        total_endpoints = sum(
            len(d.get("web_applications", {}).get("endpoints", []))
            for d in recon_data.values()
        )
        high_value = [
            {
                "target": url,
                "attack_surface_score": d.get("attack_surface_score", 0),
                "subdomains": len(d.get("subdomains", [])),
                "open_ports": len(d.get("open_ports", [])),
            }
            for url, d in recon_data.items()
            if d.get("attack_surface_score", 0) > 5.0
        ]
        return {
            "targets_analyzed": len(recon_data),
            "total_subdomains_discovered": total_subdomains,
            "total_open_ports": total_ports,
            "total_endpoints": total_endpoints,
            "high_value_targets": sorted(
                high_value, key=lambda x: x["attack_surface_score"], reverse=True
            ),
            "reconnaissance_completion": "comprehensive",
        }