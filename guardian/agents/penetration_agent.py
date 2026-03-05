import asyncio
import json
import logging
import random
import time
import aiohttp
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse, urljoin
import hashlib
import urllib

from guardian.agents.base_agent import BaseAgent
from guardian.core.ai_client import ai_client, AIPersona
from guardian.core.config import settings

logger = logging.getLogger(__name__)

class PenetrationAgent(BaseAgent):
    """
    Agent 4: Stealthy Penetration Testing Execution.
    This definitive version is refactored to work with the AI-driven,
    list-based payload arsenal.
    """

    def __init__(self, db):
        super().__init__(db, "PenetrationAgent")
        self.user_agents = settings.USER_AGENTS
        self.success_indicators = self._load_success_indicators()
        self.stealth_config = self._initialize_stealth_config()

    async def execute(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute stealthy penetration testing using AI-generated payloads."""
        task_id = await self._start_task(task_data)
        session_id = task_data.get("session_id", "unknown")
        
        try:
            payloads_data = task_data.get("payloads", {})
            recon_data = task_data.get("targets", {})
            config = task_data.get("config", {})
            
            if not recon_data.get("reconnaissance_data"):
                raise ValueError("Reconnaissance data is empty for penetration test.")
            
            target_url = list(recon_data["reconnaissance_data"].keys())[0]
            target_recon_data = recon_data["reconnaissance_data"][target_url]

            results = {
                "task_id": task_id,
                "execution_timestamp": datetime.utcnow().isoformat(),
                "penetration_results": {}
            }
            
            payload_arsenal = payloads_data.get("payload_arsenal", [])
            
            target_results = await self._execute_target_penetration(
                target_url,
                payload_arsenal, # Pass the entire list of payloads
                target_recon_data,
                config
            )
            results["penetration_results"][target_url] = target_results

            ai_analysis = await self._ai_analyze_penetration_results(results)
            results["ai_analysis"] = ai_analysis
            
            evidence_package = await self._generate_evidence_package(results)
            results["evidence_package"] = evidence_package
            
            await self._complete_task(results, session_id)
            return results
            
        except Exception as e:
            await self._handle_error(e, session_id)
            raise

    async def _execute_target_penetration(
        self,
        target_url: str,
        payload_arsenal: List[Dict[str, Any]], # Now expects a LIST
        recon_data: Dict[str, Any],
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute penetration testing for a specific target by iterating through vulnerabilities."""
        logger.info(f"🥷 Executing stealth penetration test against {target_url}")

        injection_points = await self._discover_injection_points(target_url, recon_data)
        if not injection_points:
            logger.warning(f"⚠️ No injection points discovered for {target_url}. Skipping active tests.")
            return {"target_url": target_url, "status": "skipped", "reason": "No injection points found"}

        target_results = {
            "target_url": target_url,
            "vulnerabilities_tested": len(payload_arsenal),
            "vulnerability_results": {},
            "successful_exploits": [],
            "failed_attempts": [],
            "stealth_metrics": {"requests_made": 0, "detection_probability": 0.0}
        }
        
        stealth_session = await self._create_stealth_session()
        
        try:
            # Iterate through each vulnerability's payload set from the arsenal
            for vuln_payload_set in payload_arsenal:
                vuln_name = vuln_payload_set.get("target_vulnerability", "Unknown")
                logger.info(f"🎯 Testing for '{vuln_name}' on {target_url}")
                
                vuln_results = await self._test_vulnerability_payloads(
                    vuln_payload_set, injection_points, stealth_session
                )
                
                target_results["vulnerability_results"][vuln_name] = vuln_results
                
                if vuln_results.get("exploitation_successful"):
                    target_results["successful_exploits"].append({
                        "vulnerability": vuln_name,
                        "successful_payload": vuln_results.get("successful_payload"),
                        "evidence": vuln_results.get("evidence"),
                        "impact_level": vuln_results.get("impact_level")
                    })
                else:
                    target_results["failed_attempts"].append({
                        "vulnerability": vuln_name,
                        "attempted_payloads": len(vuln_results.get("tested_payloads", [])),
                        "failure_reason": vuln_results.get("failure_reason")
                    })
                
                target_results["stealth_metrics"]["requests_made"] += vuln_results.get("requests_made", 0)
                await self._stealth_delay()
        
        finally:
            await stealth_session.close()
        
        target_results["stealth_metrics"]["detection_probability"] = self._calculate_detection_probability(
            target_results["stealth_metrics"]["requests_made"]
        )
        return target_results

    async def _test_vulnerability_payloads(
        self,
        vuln_payload_set: Dict[str, Any], # Now takes one vuln's data at a time
        injection_points: List[Dict[str, Any]],
        session: aiohttp.ClientSession
    ) -> Dict[str, Any]:
        """Test a single vulnerability's payloads against all relevant injection points."""
        results = {
            "vulnerability_name": vuln_payload_set.get("target_vulnerability"),
            "owasp_category": vuln_payload_set.get("owasp_category"),
            "tested_payloads": [],
            "exploitation_successful": False,
            "successful_payload": None,
            "evidence": {},
            "impact_level": "None",
            "requests_made": 0,
            "failure_reason": "Payloads ineffective against target"
        }

        payloads_to_test = vuln_payload_set.get("payloads", [])
        
        # Determine which injection points are relevant for this vulnerability
        # (A simple implementation for now, can be made more intelligent later)
        relevant_points = injection_points 

        for point in relevant_points:
            for payload_obj in payloads_to_test:
                payload = payload_obj.get("payload")
                if not payload: continue

                logger.debug(f"🔥 Testing payload for '{results['vulnerability_name']}' on {point['method']} {point['url']} param: {point['param_name']}")
                
                test_result = await self._execute_payload(point, payload_obj, vuln_payload_set , session)  # results['owasp_category']
                
                results["tested_payloads"].append({
                    "injection_point": point,
                    "payload": payload,
                    "response_code": test_result.get("status_code")
                })
                results["requests_made"] += 1
                
                if test_result.get("exploitation_detected"):
                    results["exploitation_successful"] = True
                    results["successful_payload"] = payload
                    results["evidence"] = test_result.get("evidence")
                    results["impact_level"] = self._assess_impact_level(test_result, results['owasp_category'])
                    logger.info(f"🎉 SUCCESSFUL EXPLOIT for {results['vulnerability_name']} at {point['url']}")
                    return results
                
                await self._stealth_delay()
        
        return results

    async def _execute_payload(
        self,
        injection_point: Dict[str, Any],
        payload_obj: Dict[str, Any], # Now takes the full payload object
        vuln_info: Dict[str, Any], # Takes the vulnerability info
        session: aiohttp.ClientSession
    ) -> Dict[str, Any]:
        """
        Executes an individual payload against a specific injection point with
        context-aware logic for different vulnerability types.
        """
        start_time = time.time()
        result = {"exploitation_detected": False, "evidence": {}}
        payload = payload_obj.get("payload")
        vuln_name = vuln_info.get("target_vulnerability")

        try:
            target_url = injection_point['url']
            param_name = injection_point['param_name']
            response = None
            
            # --- NEW: Context-Aware Execution Logic ---
            if "IDOR" in vuln_name:
                # For IDOR, the payload IS the new value for the parameter.
                params = {param_name: payload}
                absolute_url = urljoin(session._base_url, target_url) if not target_url.startswith('http') else target_url
                logger.debug(f"Executing IDOR test on {absolute_url} with params {params}")
                response = await session.get(absolute_url, params=params)
            else:
                # Default behavior for XSS, SQLi, etc.
                if injection_point['method'] == 'POST':
                    data = {param_name: payload}
                    absolute_url = urljoin(session._base_url, target_url) if not target_url.startswith('http') else target_url
                    logger.debug(f"Executing POST test on {absolute_url} with data {data}")
                    response = await session.post(absolute_url, data=data)
                else: # Default to GET
                    params = {param_name: payload}
                    absolute_url = urljoin(session._base_url, target_url) if not target_url.startswith('http') else target_url
                    logger.debug(f"Executing GET test on {absolute_url} with params {params}")
                    response = await session.get(absolute_url, params=params)
            # --- END OF NEW LOGIC ---

            result["status_code"] = response.status
            response_text = await response.text()
            response_headers = dict(response.headers)
            
            # This is our initial "evidence collection"
            success_indicators = self._analyze_response_for_success(response_text, response_headers, vuln_info.get("owasp_category"))
            
            if success_indicators:
                result["exploitation_detected"] = True
                result["evidence"] = {
                    "response_snippet": response_text[:1000],
                    "success_indicators": success_indicators,
                    "injection_point": injection_point,
                    "payload_used": payload
                }
        except Exception as e:
            logger.debug(f"Payload execution failed: {str(e)}")
            result["status_code"] = -1
        
        return result

    async def _discover_injection_points(self, target_url: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyzes recon data to find all potential injection points."""
        logger.info(f"🗺️ Discovering injection points for {target_url}")
        injection_points = []
        web_app_data = recon_data.get("web_applications", {})
        
        # Discover from URL query parameters
        for endpoint in web_app_data.get("endpoints", []):
            parsed_url = urlparse(endpoint)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            for param_name in query_params:
                injection_points.append({"url": endpoint.split('?')[0], "method": "GET", "param_name": param_name})

        # Discover from HTML forms
        for form in web_app_data.get("forms", []):
            for input_field in form.get("inputs", []):
                param_name = input_field.get("name")
                if param_name:
                    injection_points.append({"url": form.get("action"), "method": form.get("method", "GET").upper(), "param_name": param_name})
        
        unique_points = [dict(t) for t in {tuple(d.items()) for d in injection_points}]
        logger.info(f"✅ Discovered {len(unique_points)} unique injection points.")
        return unique_points

    # --- Other helper functions (_create_stealth_session, _load_success_indicators, etc.) remain below ---
    # (They are not shown here for brevity but are part of the full file)

    def _load_success_indicators(self) -> Dict[str, List[str]]:
        """Load success indicators for different vulnerability types"""
        return {
            "A01:2023": ["admin", "dashboard", "unauthorized", "root:", "uid=0"],
            "A02:2023": ["-----BEGIN", "private key", "encryption key"],
            "A03:2023": ["syntax error", "mysql", "ORA-", "you have an error in your sql syntax"],
            "A05:2023": ["directory listing", "server status", "phpinfo"],
            "A07:2023": ["login successful", "authentication bypassed", "welcome"],
            "A08:2023": ["deserialized", "serialization error"],
            "A10:2023": ["localhost", "127.0.0.1", "metadata"]
        }
    
    def _initialize_stealth_config(self) -> Dict[str, Any]:
        """Initialize stealth operation configuration"""
        return {"request_delay_min": 0.5, "request_delay_max": 1.5}
    
    async def _create_stealth_session(self) -> aiohttp.ClientSession:
        """Create HTTP session with stealth configurations"""
        headers = {"User-Agent": random.choice(self.user_agents)}
        return aiohttp.ClientSession(headers=headers, timeout=aiohttp.ClientTimeout(total=20))
    
    def _analyze_response_for_success(self, response_text: str, headers: Dict[str, str], owasp_category: str) -> List[str]:
        """Analyze response for exploitation success indicators"""
        found_indicators = []
        category_indicators = self.success_indicators.get(owasp_category, [])
        response_lower = response_text.lower()
        for indicator in category_indicators:
            if indicator.lower() in response_lower:
                found_indicators.append(indicator)
        return found_indicators
    
    def _assess_impact_level(self, test_result: Dict[str, Any], owasp_category: str) -> str:
        return "High" # Simplified for now
    
    async def _stealth_delay(self):
        await asyncio.sleep(random.uniform(self.stealth_config["request_delay_min"], self.stealth_config["request_delay_max"]))
        
    def _calculate_detection_probability(self, requests_made: int) -> float:
        return min(0.95, requests_made * 0.01)

    async def _ai_analyze_penetration_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        # This can be enhanced later
        return {"summary": "Penetration test phase completed."}

    async def _generate_evidence_package(self, results: Dict[str, Any]) -> Dict[str, Any]:
        # This can be enhanced later
        return {"status": "Evidence package generated."}
