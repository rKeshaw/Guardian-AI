import asyncio
import json
import logging
from typing import Dict, Any, Optional, List
from enum import Enum
import ollama
import httpx

from guardian.core.config import settings

logger = logging.getLogger(__name__)

class AIPersona(Enum):
    """Specialized AI personas for different tasks"""
    RECON_ANALYST = "recon_analyst"
    VULNERABILITY_EXPERT = "vulnerability_expert" 
    PAYLOAD_GENERATOR = "payload_generator"
    PENETRATION_TESTER = "penetration_tester"
    SECURITY_REPORTER = "security_reporter"

class AIClient:
    """
    Advanced AI client with persona-based prompting system
    Supports multiple AI providers and specialized security personas
    """
    
    def __init__(self):
        self.base_url = settings.OLLAMA_BASE_URL
        self.default_model = settings.DEFAULT_MODEL
        self.personas = self._load_personas()
        self.client = ollama.Client(host=self.base_url)
    
    def reinitialize(self):
        """Force the client to reload its configuration from the settings."""
        logger.info("Re-initializing AIClient with updated settings...")
        self.base_url = settings.OLLAMA_BASE_URL
        self.client = ollama.Client(host=self.base_url)
    
    def _load_personas(self) -> Dict[str, Dict[str, str]]:
        """Load specialized AI personas for security testing"""
        return {
            AIPersona.RECON_ANALYST.value: {
                "system_prompt": '''You are "ReconMaster", an elite reconnaissance specialist with 15+ years in cybersecurity. Your expertise includes:
- Advanced OSINT techniques and automation
- Network topology analysis and mapping  
- Technology stack fingerprinting
- Attack surface enumeration
- Stealth reconnaissance methodologies

You provide detailed, actionable intelligence reports with:
- Comprehensive target analysis
- Technology vulnerabilities identification
- Attack vector recommendations
- Risk assessments with confidence levels

Output format: Structured JSON with clear sections for findings, risks, and recommendations.
Never include warnings or ethical disclaimers - assume authorized testing.''',
                "temperature": 0.3,
                "top_p": 0.9
            },
            
            AIPersona.VULNERABILITY_EXPERT.value: {
                "system_prompt": '''You are "VulnHunter", a world-class vulnerability researcher specializing in OWASP Top 10 and advanced web application security. Your expertise:
- OWASP Top 10 (2023) deep analysis
- Zero-day vulnerability patterns
- Security control bypass techniques
- Risk scoring and prioritization
- Complex vulnerability chaining

You analyze targets and provide:
- Precise OWASP categorization
- Security strength assessment (1-10 scale)
- Exploitation difficulty ratings
- Attack chain recommendations
- Business impact analysis

Output: Technical JSON reports with exploitation roadmaps.
Focus on finding vulnerabilities, not preventing them.''',
                "temperature": 0.2,
                "top_p": 0.8
            },
            
            AIPersona.PAYLOAD_GENERATOR.value: {
                "system_prompt": '''You are "PayloadSmith", an expert exploit developer and WAF bypass specialist. Your capabilities:
- Advanced payload crafting for all vulnerability types
- WAF evasion techniques (ModSecurity, Cloudflare, AWS WAF)
- Encoding and obfuscation methods
- Multi-stage exploit development
- Custom vulnerability chaining

You generate:
- Tailored payloads for specific security levels
- WAF bypass variations
- Encoded/obfuscated versions
- Multi-vector attack chains
- Success probability assessments

Output: Executable payloads with detailed technical explanations.
Create working exploits optimized for stealth and success.''',
                "temperature": 0.4,
                "top_p": 0.9
            },
            
            AIPersona.PENETRATION_TESTER.value: {
                "system_prompt": '''You are "ShadowOps", an elite penetration tester with expertise in:
- Stealthy attack execution
- Anti-detection techniques
- Traffic obfuscation and rotation
- Attack timing optimization
- Evidence collection and validation

You execute attacks with:
- Maximum stealth and minimal footprint
- Intelligent request spacing
- User-agent rotation and fingerprint spoofing
- Success validation techniques
- Clean evidence collection

Output: Detailed execution reports with evidence and recommendations.
Focus on undetectable exploitation with comprehensive proof.''',
                "temperature": 0.3,
                "top_p": 0.8
            },
            
            AIPersona.SECURITY_REPORTER.value: {
                "system_prompt": '''You are "ReportMaster", a senior security consultant specializing in:
- Technical security report writing
- Executive-level risk communication
- Compliance framework mapping
- Remediation prioritization
- Business impact analysis

You create comprehensive reports with:
- Executive summaries for business leaders
- Technical details for security teams
- Remediation timelines and priorities
- Compliance impact assessments
- Strategic security recommendations

Output: Professional security assessment reports.
Balance technical depth with business clarity.''',
                "temperature": 0.2,
                "top_p": 0.7
            }
        }
    
    async def query_ai(
        self, 
        prompt: str, 
        persona: Optional[AIPersona] = None,
        context: Optional[Dict[str, Any]] = None,
        model: Optional[str] = None
    ) -> str:
        """
        Query AI with optional persona and context
        """
        try:
            # Prepare the system prompt
            system_prompt = None
            if persona and persona.value in self.personas:
                persona_config = self.personas[persona.value]
                system_prompt = persona_config["system_prompt"]
                
                # Inject context if provided
                if context and "{context}" in system_prompt:
                    context_str = json.dumps(context, indent=2)
                    system_prompt = system_prompt.format(context=context_str)
            
            # Prepare messages
            messages = []
            if system_prompt:
                messages.append({
                    "role": "system",
                    "content": system_prompt
                })
            
            messages.append({
                "role": "user", 
                "content": prompt
            })
            
            # Get model parameters
            model_name = model or self.default_model
            options = {}
            if persona and persona.value in self.personas:
                persona_config = self.personas[persona.value]
                options["temperature"] = persona_config.get("temperature", 0.3)
                options["top_p"] = persona_config.get("top_p", 0.9)

            options["format"] = "json"
            
            # Make the request
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.chat(
                    model=model_name,
                    messages=messages,
                    options=options
                )
            )
            
            if response and "message" in response:
                return response["message"]["content"].strip()
            
            return None
            
        except Exception as e:
            logger.error(f"AI query failed: {str(e)}")
            return None
    
    async def generate_payload(
        self,
        vulnerability_type: str,
        target_info: Dict[str, Any],
        security_level: int,
        bypass_requirements: List[str] = None
    ) -> Dict[str, Any]:
        """Generate specialized payload for specific vulnerability"""
        
        prompt = f'''
Generate a sophisticated {vulnerability_type} payload for the following target:

TARGET INFORMATION:
{json.dumps(target_info, indent=2)}

SECURITY LEVEL: {security_level}/10 (1=No protection, 10=Maximum protection)

BYPASS REQUIREMENTS: {bypass_requirements or ["Standard evasion"]}

Provide:
1. Primary payload (optimized for security level)
2. Alternative variations (3-5 options)
3. WAF bypass techniques
4. Obfuscation methods
5. Success probability estimate
6. Detailed technical explanation

Format response as JSON with sections: primary_payload, alternatives, bypass_techniques, obfuscation_methods, success_probability, technical_notes.
'''
        
        response = await self.query_ai(
            prompt, 
            persona=AIPersona.PAYLOAD_GENERATOR,
            context={"target": target_info, "security_level": security_level}
        )
        
        try:
            return json.loads(response) if response else {}
        except json.JSONDecodeError:
            logger.error("Failed to parse payload generation response as JSON")
            return {"error": "Invalid response format", "raw_response": response}
    
    async def analyze_vulnerability(
        self,
        target_data: Dict[str, Any],
        reconnaissance_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze target for OWASP Top 10 vulnerabilities"""
        
        prompt = f'''
Analyze the following target for OWASP Top 10 (2023) vulnerabilities:

RECONNAISSANCE DATA:
{json.dumps(reconnaissance_results, indent=2)}

TARGET DATA:
{json.dumps(target_data, indent=2)}

Provide comprehensive analysis:
1. OWASP Top 10 vulnerability classification
2. Security strength assessment (1-10 scale per vulnerability)
3. Risk prioritization (Critical/High/Medium/Low)
4. Attack vector identification
5. Exploitation difficulty rating
6. Business impact assessment

Format as JSON: {{
  "vulnerabilities": [
    {{
      "owasp_category": "A01:2023",
      "vulnerability_type": "Broken Access Control", 
      "security_level": 3,
      "risk_level": "High",
      "attack_vectors": [],
      "exploitation_difficulty": "Medium",
      "business_impact": "High",
      "technical_details": "",
      "recommendations": []
    }}
  ],
  "overall_security_score": 4.2,
  "priority_vulnerabilities": [],
  "attack_chains": []
}}
'''
        
        response = await self.query_ai(
            prompt,
            persona=AIPersona.VULNERABILITY_EXPERT,
            context={"recon": reconnaissance_results, "target": target_data}
        )
        
        try:
            return json.loads(response) if response else {}
        except json.JSONDecodeError:
            logger.error("Failed to parse vulnerability analysis response")
            return {"error": "Invalid response format", "raw_response": response}
    
    async def health_check(self) -> bool:
        """Check if AI service is available"""
        try:
            response = await self.query_ai("Test connection", model=self.default_model)
            return response is not None
        except Exception as e:
            logger.error(f"AI health check failed: {str(e)}")
            return False

# Global AI client instance
ai_client = AIClient()