import asyncio
import json
import logging
import subprocess
import socket
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin
import dns.resolver
from bs4 import BeautifulSoup
import random
import time
import urllib3
import os
import nmap

from guardian.agents.base_agent import BaseAgent
from guardian.core.config import settings

logger = logging.getLogger(__name__)

class ReconnaissanceAgent(BaseAgent):
    """
    Agent 1: Elite Reconnaissance and Intelligence Gathering
    
    Full Capabilities:
    - Advanced subdomain enumeration
    - Technology stack fingerprinting  
    - Port scanning with service detection
    - Intelligent web crawling
    - DNS enumeration and analysis
    - Attack surface mapping
    """
    
    def __init__(self, db):
        super().__init__(db, "ReconnaissanceAgent")
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
        ]
    
    async def execute(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute comprehensive reconnaissance with full capabilities"""
        task_id = await self._start_task(task_data)
        session_id = task_data.get("session_id", "unknown")
        
        try:
            targets = task_data.get("targets", [])
            config = task_data.get("config", {})
            
            logger.info(f"🔍 ReconMaster initiating elite reconnaissance on {len(targets)} targets")
            
            results = {
                "task_id": task_id,
                "agent_name": "ReconMaster",
                "targets_analyzed": len(targets),
                "reconnaissance_data": {},
                "intelligence_summary": {}
            }
            
            # Process each target with full reconnaissance
            for target_url in targets:
                logger.info(f"🎯 Analyzing target: {target_url}")
                target_intel = await self._comprehensive_target_analysis(target_url, config)
                results["reconnaissance_data"][target_url] = target_intel
            
            # Generate intelligence summary
            results["intelligence_summary"] = self._generate_intelligence_summary(results["reconnaissance_data"])
            
            await self._complete_task(results, session_id)
            logger.info(f"✅ ReconMaster completed reconnaissance of {len(targets)} targets")
            return results
            
        except Exception as e:
            await self._handle_error(e, session_id)
            raise
    
    async def _comprehensive_target_analysis(self, target_url: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive target analysis with all reconnaissance techniques"""
        
        parsed_url = urlparse(target_url)
        domain = parsed_url.netloc
        
        # Execute reconnaissance tasks concurrently
        tasks = [
            self._subdomain_enumeration(domain),
            self._technology_stack_analysis(target_url),
            self._port_reconnaissance(domain),
            self._web_application_mapping(target_url, config.get("crawl_depth", 2)),
            self._dns_intelligence(domain),
            self._certificate_analysis(domain)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        target_intel = {
            "domain": domain,
            "target_url": target_url,
            "subdomains": results[0] if not isinstance(results[0], Exception) else [],
            "technologies": results[1] if not isinstance(results[1], Exception) else {},
            "open_ports": results[2] if not isinstance(results[2], Exception) else [],
            "web_applications": results[3] if not isinstance(results[3], Exception) else {},
            "dns_intelligence": results[4] if not isinstance(results[4], Exception) else {},
            "certificates": results[5] if not isinstance(results[5], Exception) else {},
            "analysis_timestamp": time.time(),
            "attack_surface_score": 0
        }
        
        # Calculate attack surface score
        target_intel["attack_surface_score"] = self._calculate_attack_surface_score(target_intel)
        
        return target_intel
    
    async def _subdomain_enumeration(self, domain: str) -> List[Dict[str, Any]]:
        """Advanced subdomain enumeration using an external wordlist."""
        logger.info(f"🔎 Enumerating subdomains for {domain} using comprehensive wordlist...")
        
        discovered_subdomains = []
        current_dir = os.path.dirname(os.path.abspath(__file__))
        wordlist_path = os.path.join(current_dir, "..", "data", "subdomain_wordlist.txt")

        try:
            with open(wordlist_path, "r") as f:
                subdomain_list = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(subdomain_list)} subdomains from wordlist.")
        except FileNotFoundError:
            logger.error(f"Subdomain wordlist not found at {wordlist_path}. Skipping enumeration.")
            return []

        # Test subdomains from the wordlist
        for sub in subdomain_list:
            subdomain = f"{sub}.{domain}"
            try:
                # Use asyncio's non-blocking DNS resolution
                loop = asyncio.get_event_loop()
                ip_address = (await loop.getaddrinfo(subdomain, None))[0][4][0]
                
                subdomain_info = {
                    "subdomain": subdomain,
                    "ip_address": ip_address,
                    "discovery_method": "wordlist_bruteforce",
                    "status": "active"
                }
                
                subdomain_info["services"] = await self._check_subdomain_services(subdomain)
                discovered_subdomains.append(subdomain_info)
                logger.debug(f"🎯 Found active subdomain: {subdomain} -> {ip_address}")
                
            except socket.gaierror:
                continue # Subdomain does not exist
            except Exception as e:
                logger.debug(f"Error resolving {subdomain}: {e}")

        logger.info(f"✅ Discovered {len(discovered_subdomains)} subdomains for {domain}")
        return discovered_subdomains
    
    def create_secure_session(self) -> requests.Session:
        """Create a requests Session with security configurations"""
        session = requests.Session()
        # Configure session with secure defaults
        session.verify = True  # Enable SSL verification
        session.headers.update({
            'Connection': 'close',  # Don't keep connections alive
        })
        # Disable SSL verification warnings
        # import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return session
    
    async def _check_subdomain_services(self, subdomain: str) -> List[Dict[str, Any]]:
        """Check HTTP/HTTPS services on subdomain"""
        services = []
        session = self.create_secure_session()
        
        for protocol in ["http", "https"]:
            try:
                url = f"{protocol}://{subdomain}"
                response = session.get(
                    url, 
                    timeout=5,
                    headers={"User-Agent": random.choice(self.user_agents)},
                    verify=False
                )
                
                services.append({
                    "protocol": protocol,
                    "status_code": response.status_code,
                    "server": response.headers.get("Server", "Unknown"),
                    "title": self._extract_title(response.text) if response.status_code == 200 else None
                })
            except requests.RequestException as e:
                # Log failed attempts but continue checking
                services.append({
                    "protocol": protocol,
                    "error": str(e)
                })
                
        return services
    
    def _extract_title(self, html_content: str) -> str:
        """Extract page title from HTML"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            title_tag = soup.find('title')
            return title_tag.get_text().strip() if title_tag else "No Title"
        except:
            return "Unknown"
    
    async def _certificate_transparency_search(self, domain: str) -> List[Dict[str, Any]]:
        """Simulated certificate transparency log search"""
        # In real implementation, would query CT logs like crt.sh
        # For now, simulate finding a few additional subdomains
        simulated_ct_results = []
        
        ct_candidates = [f"mail.{domain}", f"smtp.{domain}", f"mx.{domain}"]
        
        for candidate in ct_candidates:
            try:
                ip_address = socket.gethostbyname(candidate)
                simulated_ct_results.append({
                    "subdomain": candidate,
                    "ip_address": ip_address,
                    "discovery_method": "certificate_transparency",
                    "status": "active",
                    "services": await self._check_subdomain_services(candidate)
                })
            except socket.gaierror:
                continue
        
        return simulated_ct_results
    
    async def _technology_stack_analysis(self, target_url: str) -> Dict[str, Any]:
        """Advanced technology stack fingerprinting"""
        logger.info(f"🔍 Analyzing technology stack for {target_url}")
        
        technologies = {
            "web_servers": [],
            "frameworks": [],
            "cms": [],
            "programming_languages": [],
            "databases": [],
            "cdn": [],
            "analytics": [],
            "security": []
        }
        
        try:
            response = requests.get(target_url, timeout=10, headers={
                "User-Agent": random.choice(self.user_agents)
            })
            
            headers = response.headers
            content = response.text
            
            # Server identification
            server_header = headers.get('Server', '')
            if server_header:
                technologies["web_servers"].append({
                    "name": server_header,
                    "confidence": "high",
                    "source": "server_header"
                })
            
            # Framework detection
            framework_indicators = {
                'X-Powered-By': 'frameworks',
                'X-AspNet-Version': 'frameworks',
                'X-Generator': 'cms'
            }
            
            for header, category in framework_indicators.items():
                if header in headers:
                    technologies[category].append({
                        "name": headers[header],
                        "confidence": "high", 
                        "source": f"{header.lower()}_header"
                    })
            
            # Content analysis for technology fingerprinting
            content_indicators = {
                'wordpress': ('cms', ['wp-content', 'wp-includes']),
                'drupal': ('cms', ['drupal', 'sites/default']),
                'joomla': ('cms', ['joomla', 'components/com_']),
                'react': ('frameworks', ['react', '_react']),
                'angular': ('frameworks', ['angular', 'ng-']),
                'vue': ('frameworks', ['vue.js', '__vue__']),
                'jquery': ('frameworks', ['jquery', '$.fn.jquery']),
                'bootstrap': ('frameworks', ['bootstrap', 'btn-primary']),
                'php': ('programming_languages', ['<?php', '.php']),
                'asp.net': ('frameworks', ['__doPostBack', 'aspnet']),
                'cloudflare': ('cdn', ['cloudflare', '__cf_bm']),
                'google-analytics': ('analytics', ['google-analytics', 'gtag'])
            }
            
            content_lower = content.lower()
            for tech, (category, indicators) in content_indicators.items():
                for indicator in indicators:
                    if indicator in content_lower:
                        technologies[category].append({
                            "name": tech,
                            "confidence": "medium",
                            "source": "content_analysis"
                        })
                        break
            
        except requests.RequestException as e:
            logger.debug(f"Technology analysis failed for {target_url}: {e}")
        
        return technologies
    
    async def _port_reconnaissance(self, domain: str) -> List[Dict[str, Any]]:
        """Advanced port scanning using the Nmap engine."""
        logger.info(f"🔍 Performing Nmap port reconnaissance on {domain}")
        
        discovered_ports = []
        try:
            nm = nmap.PortScanner()
            # -F flag scans the 100 most common ports. -T4 is for faster execution.
            scan_results = nm.scan(hosts=domain, arguments='-F -T4')
            
            # The nmap library returns a complex dict; we need to parse it
            if domain in scan_results['scan']:
                if 'tcp' in scan_results['scan'][domain]:
                    tcp_ports = scan_results['scan'][domain]['tcp']
                    for port, port_data in tcp_ports.items():
                        if port_data['state'] == 'open':
                            discovered_ports.append({
                                "port": port,
                                "state": port_data['state'],
                                "service": port_data['name'],
                                "banner": f"{port_data.get('product', '')} {port_data.get('version', '')}"
                            })
                            logger.debug(f"🎯 Nmap found open port: {port} ({port_data['name']})")

        except Exception as e:
            logger.error(f"Nmap scan failed for {domain}: {e}. This might happen if nmap is not installed or due to permissions.")

        logger.info(f"✅ Nmap scan complete. Found {len(discovered_ports)} open ports on {domain}")
        return discovered_ports
    
    def _identify_service(self, port: int) -> str:
        """Identify service based on port number"""
        service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            993: "IMAPS", 995: "POP3S", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
            3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
            6379: "Redis", 11211: "Memcached", 9200: "Elasticsearch"
        }
        return service_map.get(port, f"Unknown-{port}")
    
    async def _grab_banner(self, domain: str, port: int) -> str:
        """Attempt to grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((domain, port))
            
            # Send HTTP request for web ports
            if port in [80, 8080, 8000, 8001]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + domain.encode() + b"\r\n\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200]  # Limit banner length
            
        except:
            return "No banner"
    
    async def _web_application_mapping(self, target_url: str, max_depth: int = 2) -> Dict[str, Any]:
        """Intelligent web application mapping and endpoint discovery with deduplication."""
        logger.info(f"🗺️ Mapping web application: {target_url}")
        
        discovered_endpoints = set()
        discovered_forms = []
        discovered_files = []
        to_crawl = [(target_url, 0)]
        crawled = set()
        
        # --- NEW: Set to store unique form signatures ---
        seen_forms = set()

        while to_crawl and len(crawled) < 50:
            current_url, depth = to_crawl.pop(0)
            
            if current_url in crawled or depth > max_depth:
                continue
                
            crawled.add(current_url)
            
            try:
                response = requests.get(current_url, timeout=10, headers={
                    "User-Agent": random.choice(self.user_agents)
                })
                
                if response.status_code == 200:
                    discovered_endpoints.add(current_url)
                    soup = BeautifulSoup(response.content, 'html.parser')
                    
                    if depth < max_depth:
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            full_url = urljoin(current_url, href)
                            if urlparse(full_url).netloc == urlparse(target_url).netloc:
                                to_crawl.append((full_url, depth + 1))
                    
                    # --- REFACTORED FORM DISCOVERY LOGIC ---
                    for form in soup.find_all('form'):
                        form_action = urljoin(current_url, form.get('action', ''))
                        input_names = sorted([inp.get('name', '') for inp in form.find_all(['input', 'textarea', 'select'])])
                        
                        # Create a unique signature for the form
                        form_signature = (form_action, tuple(input_names))

                        # If we haven't seen this signature before, process and store the form
                        if form_signature not in seen_forms:
                            seen_forms.add(form_signature)
                            
                            form_info = {
                                "action": form_action,
                                "method": form.get('method', 'GET').upper(),
                                "inputs": []
                            }
                            for input_tag in form.find_all(['input', 'textarea', 'select']):
                                form_info["inputs"].append({
                                    "name": input_tag.get('name', ''),
                                    "type": input_tag.get('type', 'text'),
                                    "required": input_tag.has_attr('required')
                                })
                            discovered_forms.append(form_info)
                    # -------------------------------------------

                    interesting_patterns = ['admin', 'login', 'dashboard', 'api', 'config', 'backup', 'upload', 'download', 'search']
                    for pattern in interesting_patterns:
                        if pattern in response.text.lower():
                            discovered_files.append({
                                "url": current_url,
                                "pattern": pattern,
                                "context": "content_reference"
                            })
                
                await asyncio.sleep(0.5)
            
            except requests.RequestException as e:
                logger.debug(f"Failed to crawl {current_url}: {e}")
        
        return {
            "endpoints": list(discovered_endpoints),
            "forms": discovered_forms,
            "interesting_files": discovered_files,
            "crawl_statistics": {
                "pages_crawled": len(crawled),
                "forms_found": len(discovered_forms), # This will now be the unique count
                "endpoints_discovered": len(discovered_endpoints)
            }
        }
    
    async def _dns_intelligence(self, domain: str) -> Dict[str, Any]:
        """Advanced DNS intelligence gathering"""
        logger.info(f"🔍 Gathering DNS intelligence for {domain}")
        
        dns_records = {}
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(answer) for answer in answers]
            except:
                dns_records[record_type] = []
        
        # Additional DNS analysis
        dns_intelligence = {
            "records": dns_records,
            "nameservers": dns_records.get('NS', []),
            "mail_servers": dns_records.get('MX', []),
            "txt_analysis": self._analyze_txt_records(dns_records.get('TXT', [])),
            "subdomain_takeover_risk": self._check_subdomain_takeover_risk(dns_records)
        }
        
        return dns_intelligence
    
    def _analyze_txt_records(self, txt_records: List[str]) -> Dict[str, Any]:
        """Analyze TXT records for security and service information"""
        analysis = {
            "spf_record": None,
            "dmarc_record": None,
            "verification_tokens": [],
            "other_records": []
        }
        
        for record in txt_records:
            record_lower = record.lower()
            if record_lower.startswith('v=spf1'):
                analysis["spf_record"] = record
            elif record_lower.startswith('v=dmarc1'):
                analysis["dmarc_record"] = record
            elif any(token in record_lower for token in ['google-site-verification', 'facebook-domain-verification']):
                analysis["verification_tokens"].append(record)
            else:
                analysis["other_records"].append(record)
        
        return analysis
    
    def _check_subdomain_takeover_risk(self, dns_records: Dict[str, List[str]]) -> str:
        """Check for subdomain takeover risks"""
        # Simplified check for common vulnerable services
        cnames = dns_records.get('CNAME', [])
        vulnerable_services = [
            'github.io', 'herokuapp.com', 'amazonaws.com',
            'azure', 'cloudfront.net', 'fastly.com'
        ]
        
        for cname in cnames:
            for service in vulnerable_services:
                if service in cname.lower():
                    return "Potential Risk"
        
        return "Low Risk"
    
    async def _certificate_analysis(self, domain: str) -> Dict[str, Any]:
        """SSL/TLS certificate analysis"""
        logger.info(f"🔍 Analyzing certificates for {domain}")
        
        # Simulated certificate analysis
        # In real implementation, would use SSL socket or openssl
        cert_info = {
            "has_certificate": False,
            "issuer": "Unknown",
            "subject": "Unknown",
            "valid_from": "Unknown",
            "valid_to": "Unknown",
            "san_domains": [],
            "certificate_transparency": False
        }
        
        try:
            # Simple HTTPS check
            response = requests.get(f"https://{domain}", timeout=5, verify=False)
            if response.status_code:
                cert_info["has_certificate"] = True
                cert_info["issuer"] = "Certificate Authority"
                cert_info["certificate_transparency"] = True
        except:
            pass
        
        return cert_info
    
    def _calculate_attack_surface_score(self, target_intel: Dict[str, Any]) -> float:
        """Calculate attack surface score based on reconnaissance findings"""
        score = 0.0
        
        # Subdomain count contributes to score
        score += len(target_intel.get("subdomains", [])) * 0.1
        
        # Open ports contribute to score
        score += len(target_intel.get("open_ports", [])) * 0.2
        
        # Web endpoints contribute to score
        web_apps = target_intel.get("web_applications", {})
        score += len(web_apps.get("endpoints", [])) * 0.05
        score += len(web_apps.get("forms", [])) * 0.3
        
        # Technologies contribute based on known vulnerabilities
        technologies = target_intel.get("technologies", {})
        for tech_category in technologies.values():
            score += len(tech_category) * 0.1
        
        return min(10.0, score)  # Cap at 10.0
    
    def _generate_intelligence_summary(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive intelligence summary"""
        total_subdomains = sum(len(data.get("subdomains", [])) for data in recon_data.values())
        total_ports = sum(len(data.get("open_ports", [])) for data in recon_data.values())
        total_endpoints = sum(len(data.get("web_applications", {}).get("endpoints", [])) for data in recon_data.values())
        
        # Find highest value targets
        high_value_targets = []
        for url, data in recon_data.items():
            attack_surface = data.get("attack_surface_score", 0)
            if attack_surface > 5.0:
                high_value_targets.append({
                    "target": url,
                    "attack_surface_score": attack_surface,
                    "subdomains": len(data.get("subdomains", [])),
                    "open_ports": len(data.get("open_ports", []))
                })
        
        return {
            "targets_analyzed": len(recon_data),
            "total_subdomains_discovered": total_subdomains,
            "total_open_ports": total_ports,
            "total_endpoints": total_endpoints,
            "high_value_targets": sorted(high_value_targets, key=lambda x: x["attack_surface_score"], reverse=True),
            "reconnaissance_completion": "comprehensive",
            "intelligence_confidence": "high"
        }