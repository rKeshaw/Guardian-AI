# import asyncio
# import json
# import logging
# from typing import Dict, List, Any, Optional
# from datetime import datetime, timedelta
# import hashlib
# from jinja2 import Template

# from guardian.agents.base_agent import BaseAgent
# from guardian.core.ai_client import ai_client, AIPersona
# from guardian.core.config import settings

# logger = logging.getLogger(__name__)

# class ReportingAgent(BaseAgent):
#     """
#     Agent 5: Comprehensive Security Reporting
    
#     Capabilities:
#     - Executive summary generation
#     - Technical detailed reporting
#     - Risk assessment and prioritization
#     - Remediation recommendations
#     - Compliance mapping (OWASP, NIST, etc.)
#     - Evidence compilation and presentation
#     """
    
#     def __init__(self, db):
#         super().__init__(db, "ReportingAgent")
#         self.report_templates = self._load_report_templates()
#         self.compliance_mappings = self._load_compliance_mappings()
        
#     def _load_report_templates(self) -> Dict[str, str]:
#         """Load report templates for different audiences"""
#         return {
#             "executive_summary": """
# # Executive Summary - Guardian AI Security Assessment

# **Assessment Date:** {{ assessment_date }}
# **Target(s):** {{ target_count }} web applications
# **Overall Risk Level:** {{ overall_risk_level }}

# ## Key Findings

# {{ key_findings }}

# ## Business Impact

# {{ business_impact }}

# ## Immediate Actions Required

# {{ immediate_actions }}

# ## Budget Implications

# {{ budget_implications }}
#             """,
            
#             "technical_report": """
# # Technical Security Assessment Report

# ## Assessment Overview
# - **Assessment Period:** {{ start_date }} to {{ end_date }}
# - **Methodology:** Guardian AI Multi-Agent OWASP Top 10 2023 Assessment
# - **Targets Analyzed:** {{ target_count }}
# - **Vulnerabilities Identified:** {{ vuln_count }}

# ## Vulnerability Summary

# {{ vulnerability_summary }}

# ## Detailed Findings

# {{ detailed_findings }}

# ## Technical Recommendations

# {{ technical_recommendations }}

# ## Evidence Package

# {{ evidence_summary }}
#             """,
            
#             "remediation_plan": """
# # Vulnerability Remediation Plan

# ## Priority Matrix

# {{ priority_matrix }}

# ## Remediation Timeline

# {{ remediation_timeline }}

# ## Resource Requirements

# {{ resource_requirements }}

# ## Implementation Steps

# {{ implementation_steps }}
#             """
#         }
    
#     def _load_compliance_mappings(self) -> Dict[str, Dict[str, Any]]:
#         """Load compliance framework mappings"""
#         return {
#             "OWASP_2023": {
#                 "A01:2023": {
#                     "name": "Broken Access Control",
#                     "nist_controls": ["AC-3", "AC-6", "IA-2"],
#                     "iso27001": ["A.9.1.1", "A.9.4.1"],
#                     "remediation_priority": "High"
#                 },
#                 "A02:2023": {
#                     "name": "Cryptographic Failures",
#                     "nist_controls": ["SC-8", "SC-13", "SC-28"],
#                     "iso27001": ["A.10.1.1", "A.14.1.2"],
#                     "remediation_priority": "High"
#                 },
#                 "A03:2023": {
#                     "name": "Injection",
#                     "nist_controls": ["SI-3", "SI-10"],
#                     "iso27001": ["A.14.2.1", "A.14.2.5"],
#                     "remediation_priority": "Critical"
#                 }
#                 # ... (other mappings)
#             }
#         }
    
#     async def execute(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
#         """Generate comprehensive security assessment report"""
#         task_id = await self._start_task(task_data)
#         session_id = task_data.get("session_id", "unknown")
        
#         try:
#             all_results = task_data.get("all_results", {})
#             config = task_data.get("config", {})
            
#             results = {
#                 "task_id": task_id,
#                 "report_generation_timestamp": datetime.utcnow().isoformat(),
#                 "reports": {}
#             }
            
#             logger.info("📊 Generating comprehensive Guardian AI security reports...")
            
#             # Generate different types of reports
#             executive_summary = await self._generate_executive_summary(all_results)
#             results["reports"]["executive_summary"] = executive_summary
            
#             technical_report = await self._generate_technical_report(all_results)
#             results["reports"]["technical_report"] = technical_report
            
#             remediation_plan = await self._generate_remediation_plan(all_results)
#             results["reports"]["remediation_plan"] = remediation_plan
            
#             compliance_report = await self._generate_compliance_report(all_results)
#             results["reports"]["compliance_report"] = compliance_report
            
#             # AI-powered report enhancement
#             ai_enhancement = await self._ai_enhance_reports(results)
#             results["ai_enhancement"] = ai_enhancement
            
#             # Generate final consolidated report
#             consolidated_report = await self._generate_consolidated_report(results)
#             results["consolidated_report"] = consolidated_report
            
#             await self._complete_task(results, session_id)
#             return results
            
#         except Exception as e:
#             await self._handle_error(e, session_id)
#             raise
    
#     async def _generate_executive_summary(self, all_results: Dict[str, Any]) -> Dict[str, Any]:
#         """Generate executive summary for business stakeholders"""
        
#         logger.info("📋 Generating executive summary for C-level stakeholders")
        
#         # Extract key metrics
#         penetration_results = all_results.get("penetration", {}).get("penetration_results", {})
#         vulnerability_data = all_results.get("vulnerability_analysis", {})
        
#         # Calculate high-level metrics
#         total_targets = len(penetration_results)
#         total_vulnerabilities = 0
#         critical_vulnerabilities = 0
#         successful_exploits = 0
        
#         for target_results in penetration_results.values():
#             successful_exploits += len(target_results.get("successful_exploits", []))
#             for vuln_result in target_results.get("vulnerability_results", {}).values():
#                 total_vulnerabilities += 1
#                 if vuln_result.get("impact_level") in ["Critical", "High"]:
#                     critical_vulnerabilities += 1
        
#         # Determine overall risk level
#         if critical_vulnerabilities >= 3 or successful_exploits >= 2:
#             overall_risk = "Critical"
#             risk_color = "Red"
#         elif critical_vulnerabilities >= 1 or successful_exploits >= 1:
#             overall_risk = "High"
#             risk_color = "Orange"
#         elif total_vulnerabilities >= 5:
#             overall_risk = "Medium"
#             risk_color = "Yellow"
#         else:
#             overall_risk = "Low"
#             risk_color = "Green"
        
#         # Generate business impact assessment
#         business_impact = self._assess_business_impact(
#             overall_risk, successful_exploits, critical_vulnerabilities
#         )
        
#         # Create key findings
#         key_findings = [
#             f"Guardian AI identified {total_vulnerabilities} security vulnerabilities across {total_targets} applications",
#             f"Successfully exploited {successful_exploits} vulnerabilities demonstrating real attack potential",
#             f"Found {critical_vulnerabilities} critical/high-risk vulnerabilities requiring immediate attention"
#         ]
        
#         if successful_exploits > 0:
#             key_findings.append("Confirmed exploitability indicates active threat to business operations")
        
#         # Generate immediate actions
#         immediate_actions = self._generate_immediate_actions(overall_risk, successful_exploits)
        
#         return {
#             "assessment_date": datetime.utcnow().strftime("%B %d, %Y"),
#             "overall_risk_level": overall_risk,
#             "risk_color": risk_color,
#             "total_targets": total_targets,
#             "total_vulnerabilities": total_vulnerabilities,
#             "critical_vulnerabilities": critical_vulnerabilities,
#             "successful_exploits": successful_exploits,
#             "key_findings": key_findings,
#             "business_impact": business_impact,
#             "immediate_actions": immediate_actions,
#             "budget_implications": self._assess_budget_implications(overall_risk)
#         }
    
#     def _assess_business_impact(self, risk_level: str, exploits: int, critical_vulns: int) -> Dict[str, Any]:
#         """Assess business impact of security vulnerabilities"""
        
#         impact_assessment = {
#             "financial_risk": "Low",
#             "operational_risk": "Low", 
#             "reputational_risk": "Low",
#             "regulatory_risk": "Low",
#             "description": ""
#         }
        
#         if risk_level == "Critical":
#             impact_assessment.update({
#                 "financial_risk": "High",
#                 "operational_risk": "High",
#                 "reputational_risk": "High",
#                 "regulatory_risk": "Medium",
#                 "description": "Critical vulnerabilities pose immediate threat to business continuity, customer data, and regulatory compliance. Potential for significant financial losses through data breaches, system downtime, and regulatory penalties."
#             })
#         elif risk_level == "High":
#             impact_assessment.update({
#                 "financial_risk": "Medium",
#                 "operational_risk": "Medium",
#                 "reputational_risk": "Medium", 
#                 "regulatory_risk": "Medium",
#                 "description": "High-risk vulnerabilities create substantial security gaps that could lead to data compromise, service disruption, and compliance violations if exploited by attackers."
#             })
#         elif risk_level == "Medium":
#             impact_assessment.update({
#                 "financial_risk": "Low",
#                 "operational_risk": "Low",
#                 "reputational_risk": "Low",
#                 "regulatory_risk": "Low",
#                 "description": "Medium-risk vulnerabilities should be addressed in planned security improvements to maintain robust security posture and prevent future exploitation."
#             })
        
#         return impact_assessment
    
#     def _generate_immediate_actions(self, risk_level: str, exploits: int) -> List[str]:
#         """Generate immediate action items"""
        
#         actions = []
        
#         if risk_level == "Critical":
#             actions.extend([
#                 "🚨 Immediately patch or mitigate all critical vulnerabilities",
#                 "🔒 Implement emergency incident response procedures",
#                 "⚠️ Consider taking affected systems offline until patches are applied",
#                 "🔍 Conduct emergency security review of all critical systems",
#                 "📢 Notify relevant stakeholders and compliance teams"
#             ])
#         elif risk_level == "High":
#             actions.extend([
#                 "⚡ Prioritize patching of high-risk vulnerabilities within 7 days",
#                 "👀 Implement additional monitoring on affected systems",
#                 "🛡️ Review and strengthen security controls",
#                 "📋 Plan comprehensive security assessment of related systems"
#             ])
#         else:
#             actions.extend([
#                 "📅 Schedule vulnerability remediation within 30 days",
#                 "📖 Review security policies and procedures",
#                 "🔄 Plan regular security assessments",
#                 "🎓 Enhance security awareness training"
#             ])
        
#         if exploits > 0:
#             actions.insert(0, "🚨 URGENT: Investigate systems for signs of actual compromise")
        
#         return actions
    
#     def _assess_budget_implications(self, risk_level: str) -> Dict[str, Any]:
#         """Assess budget implications for remediation"""
        
#         budget_ranges = {
#             "Critical": {
#                 "immediate_costs": "$50,000 - $200,000",
#                 "ongoing_costs": "$100,000 - $500,000 annually",
#                 "description": "Significant investment required for immediate remediation, security controls upgrade, and enhanced monitoring."
#             },
#             "High": {
#                 "immediate_costs": "$25,000 - $100,000",
#                 "ongoing_costs": "$50,000 - $200,000 annually", 
#                 "description": "Moderate investment needed for vulnerability remediation and security improvements."
#             },
#             "Medium": {
#                 "immediate_costs": "$10,000 - $50,000",
#                 "ongoing_costs": "$25,000 - $100,000 annually",
#                 "description": "Standard security maintenance costs with some additional remediation work."
#             },
#             "Low": {
#                 "immediate_costs": "$5,000 - $25,000",
#                 "ongoing_costs": "$10,000 - $50,000 annually",
#                 "description": "Minimal additional costs beyond standard security maintenance."
#             }
#         }
        
#         return budget_ranges.get(risk_level, budget_ranges["Medium"])
    
#     async def _generate_technical_report(self, all_results: Dict[str, Any]) -> Dict[str, Any]:
#         """Generate detailed technical report"""
        
#         logger.info("🔧 Generating comprehensive technical report")
        
#         penetration_results = all_results.get("penetration", {}).get("penetration_results", {})
#         vulnerability_analysis = all_results.get("vulnerability_analysis", {})
#         reconnaissance_data = all_results.get("reconnaissance", {})
        
#         technical_report = {
#             "methodology": {
#                 "framework": "Guardian AI Multi-Agent OWASP Top 10 2023",
#                 "tools_used": ["Guardian AI Multi-Agent System", "AI Payload Generator", "Stealth Testing Engine"],
#                 "assessment_scope": list(penetration_results.keys()),
#                 "testing_approach": "Black-box automated penetration testing with AI-powered analysis"
#             },
#             "reconnaissance_summary": self._summarize_reconnaissance(reconnaissance_data),
#             "vulnerability_details": [],
#             "exploitation_results": [],
#             "evidence_summary": {},
#             "technical_recommendations": []
#         }
        
#         # Compile detailed vulnerability information
#         for target_url, target_results in penetration_results.items():
            
#             # Vulnerability details
#             for owasp_category, vuln_result in target_results.get("vulnerability_results", {}).items():
#                 if vuln_result.get("exploitation_successful"):
#                     vuln_detail = {
#                         "target": target_url,
#                         "owasp_category": owasp_category,
#                         "vulnerability_name": vuln_result.get("vulnerability_name"),
#                         "severity": vuln_result.get("impact_level"),
#                         "successful_payload": vuln_result.get("successful_payload"),
#                         "evidence": vuln_result.get("evidence"),
#                         "technical_description": self._get_technical_description(owasp_category),
#                         "remediation": self._get_remediation_guidance(owasp_category)
#                     }
#                     technical_report["vulnerability_details"].append(vuln_detail)
            
#             # Exploitation results
#             for exploit in target_results.get("successful_exploits", []):
#                 technical_report["exploitation_results"].append({
#                     "target": target_url,
#                     "vulnerability": exploit["vulnerability"],
#                     "payload": exploit["successful_payload"],
#                     "impact": exploit["impact_level"],
#                     "evidence": exploit.get("evidence", {})
#                 })
        
#         # Generate technical recommendations
#         technical_report["technical_recommendations"] = await self._generate_technical_recommendations(
#             all_results
#         )
        
#         return technical_report
    
#     def _summarize_reconnaissance(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
#         """Summarize reconnaissance findings"""
        
#         reconnaissance_data = recon_data.get("reconnaissance_data", {})
        
#         summary = {
#             "targets_analyzed": len(reconnaissance_data),
#             "total_subdomains": 0,
#             "total_endpoints": 0,
#             "technologies_identified": [],
#             "open_ports_summary": {},
#             "attack_surface_assessment": "Medium"
#         }
        
#         for target_url, target_recon in reconnaissance_data.items():
#             summary["total_subdomains"] += len(target_recon.get("subdomains", []))
#             summary["total_endpoints"] += len(target_recon.get("endpoints", []))
            
#             # Collect technologies
#             technologies = target_recon.get("technologies", {})
#             for tech_type, tech_list in technologies.items():
#                 for tech in tech_list:
#                     if tech not in summary["technologies_identified"]:
#                         summary["technologies_identified"].append(tech)
            
#             # Summarize open ports
#             for port_info in target_recon.get("open_ports", []):
#                 port = port_info.get("port")
#                 service = port_info.get("service")
#                 if service not in summary["open_ports_summary"]:
#                     summary["open_ports_summary"][service] = []
#                 summary["open_ports_summary"][service].append(port)
        
#         # Assess attack surface
#         if summary["total_endpoints"] > 50 or summary["total_subdomains"] > 20:
#             summary["attack_surface_assessment"] = "Large"
#         elif summary["total_endpoints"] > 20 or summary["total_subdomains"] > 10:
#             summary["attack_surface_assessment"] = "Medium"
#         else:
#             summary["attack_surface_assessment"] = "Small"
        
#         return summary
    
#     def _get_technical_description(self, owasp_category: str) -> str:
#         """Get technical description for OWASP category"""
        
#         descriptions = {
#             "A01:2023": "Broken Access Control vulnerabilities occur when access restrictions are not properly enforced, allowing unauthorized users to access restricted functionality or data.",
#             "A02:2023": "Cryptographic Failures involve weaknesses in encryption, hashing, or other cryptographic implementations that can lead to sensitive data exposure.",
#             "A03:2023": "Injection vulnerabilities allow attackers to send malicious data to interpreters as part of commands or queries, potentially leading to data theft or system compromise.",
#             "A04:2023": "Insecure Design represents security flaws in the application's architecture and design that cannot be fixed through implementation changes alone.",
#             "A05:2023": "Security Misconfiguration occurs when security settings are improperly configured, leaving applications vulnerable to various attacks.",
#             "A06:2023": "Vulnerable and Outdated Components involve the use of components with known security vulnerabilities that can be exploited by attackers.",
#             "A07:2023": "Identification and Authentication Failures occur when the application fails to properly authenticate users or manage sessions securely.",
#             "A08:2023": "Software and Data Integrity Failures involve assumptions about software updates, plugins, or critical data without verifying integrity.",
#             "A09:2023": "Security Logging and Monitoring Failures occur when applications fail to properly log security events or monitor for suspicious activity.",
#             "A10:2023": "Server-Side Request Forgery (SSRF) allows attackers to induce server-side applications to make requests to unintended locations."
#         }
        
#         return descriptions.get(owasp_category, "Security vulnerability requiring immediate attention.")
    
#     def _get_remediation_guidance(self, owasp_category: str) -> List[str]:
#         """Get specific remediation guidance for OWASP category"""
        
#         guidance = {
#             "A01:2023": [
#                 "Implement proper access control mechanisms with deny-by-default principle",
#                 "Use centralized access control enforcement",
#                 "Validate all user permissions server-side",
#                 "Implement proper session management"
#             ],
#             "A02:2023": [
#                 "Use strong, up-to-date encryption algorithms",
#                 "Implement proper key management practices",
#                 "Ensure data is encrypted in transit and at rest",
#                 "Remove hardcoded cryptographic keys"
#             ],
#             "A03:2023": [
#                 "Implement input validation and output encoding",
#                 "Use parameterized queries or prepared statements",
#                 "Apply principle of least privilege to database accounts",
#                 "Use positive input validation with whitelisting"
#             ]
#             # Add more remediation guidance...
#         }
        
#         return guidance.get(owasp_category, ["Review and implement appropriate security controls"])
    
#     async def _generate_technical_recommendations(self, all_results: Dict[str, Any]) -> List[Dict[str, Any]]:
#         """Generate specific technical recommendations"""
        
#         recommendations = []
        
#         # Analyze results to generate targeted recommendations
#         penetration_results = all_results.get("penetration", {}).get("penetration_results", {})
        
#         # Count vulnerability types
#         vuln_counts = {}
#         for target_results in penetration_results.values():
#             for owasp_category, vuln_result in target_results.get("vulnerability_results", {}).items():
#                 if vuln_result.get("exploitation_successful"):
#                     vuln_counts[owasp_category] = vuln_counts.get(owasp_category, 0) + 1
        
#         # Generate recommendations based on most common vulnerabilities
#         for owasp_category, count in sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True):
#             compliance_info = self.compliance_mappings["OWASP_2023"].get(owasp_category, {})
            
#             recommendation = {
#                 "vulnerability_type": compliance_info.get("name", owasp_category),
#                 "priority": compliance_info.get("remediation_priority", "Medium"),
#                 "affected_targets": count,
#                 "remediation_steps": self._get_remediation_guidance(owasp_category),
#                 "compliance_controls": {
#                     "nist": compliance_info.get("nist_controls", []),
#                     "iso27001": compliance_info.get("iso27001", [])
#                 },
#                 "estimated_effort": self._estimate_remediation_effort(owasp_category, count)
#             }
            
#             recommendations.append(recommendation)
        
#         return recommendations
    
#     def _estimate_remediation_effort(self, owasp_category: str, affected_count: int) -> Dict[str, Any]:
#         """Estimate effort required for remediation"""
        
#         base_efforts = {
#             "A01:2023": {"hours": 40, "complexity": "Medium"},
#             "A02:2023": {"hours": 60, "complexity": "High"}, 
#             "A03:2023": {"hours": 30, "complexity": "Medium"},
#             "A04:2023": {"hours": 80, "complexity": "High"},
#             "A05:2023": {"hours": 20, "complexity": "Low"},
#         }
        
#         base_effort = base_efforts.get(owasp_category, {"hours": 40, "complexity": "Medium"})
        
#         # Scale by number of affected targets
#         total_hours = base_effort["hours"] * max(1, affected_count * 0.8)
        
#         return {
#             "estimated_hours": int(total_hours),
#             "complexity": base_effort["complexity"],
#             "recommended_resources": "Senior Security Engineer + Developer",
#             "estimated_duration": f"{int(total_hours / 40)} - {int(total_hours / 20)} weeks"
#         }
    
#     async def _generate_remediation_plan(self, all_results: Dict[str, Any]) -> Dict[str, Any]:
#         """Generate comprehensive remediation plan"""
        
#         logger.info("🛠️ Generating comprehensive remediation plan")
        
#         # Extract successful exploits for prioritization
#         all_exploits = []
#         penetration_results = all_results.get("penetration", {}).get("penetration_results", {})
        
#         for target_url, target_results in penetration_results.items():
#             for exploit in target_results.get("successful_exploits", []):
#                 exploit["target_url"] = target_url
#                 all_exploits.append(exploit)
        
#         # Prioritize by impact level
#         priority_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Very Low": 5}
#         all_exploits.sort(key=lambda x: priority_order.get(x.get("impact_level", "Low"), 4))
        
#         # Generate remediation timeline
#         timeline = self._generate_remediation_timeline(all_exploits)
        
#         # Resource requirements
#         resource_requirements = self._calculate_resource_requirements(all_exploits)
        
#         return {
#             "total_vulnerabilities": len(all_exploits),
#             "critical_count": len([e for e in all_exploits if e.get("impact_level") == "Critical"]),
#             "high_count": len([e for e in all_exploits if e.get("impact_level") == "High"]),
#             "priority_matrix": self._create_priority_matrix(all_exploits),
#             "remediation_timeline": timeline,
#             "resource_requirements": resource_requirements,
#             "implementation_phases": self._create_implementation_phases(all_exploits),
#             "success_metrics": self._define_success_metrics()
#         }
    
#     def _generate_remediation_timeline(self, exploits: List[Dict[str, Any]]) -> Dict[str, Any]:
#         """Generate remediation timeline"""
        
#         now = datetime.utcnow()
        
#         timeline = {
#             "immediate": [],  # 0-7 days
#             "short_term": [],  # 1-4 weeks
#             "medium_term": [],  # 1-3 months
#             "long_term": []   # 3+ months
#         }
        
#         for exploit in exploits:
#             impact = exploit.get("impact_level", "Low")
            
#             if impact == "Critical":
#                 timeline["immediate"].append({
#                     "vulnerability": exploit["vulnerability"],
#                     "target": exploit["target_url"],
#                     "deadline": (now + timedelta(days=3)).strftime("%Y-%m-%d")
#                 })
#             elif impact == "High":
#                 timeline["short_term"].append({
#                     "vulnerability": exploit["vulnerability"],
#                     "target": exploit["target_url"],
#                     "deadline": (now + timedelta(weeks=2)).strftime("%Y-%m-%d")
#                 })
#             elif impact == "Medium":
#                 timeline["medium_term"].append({
#                     "vulnerability": exploit["vulnerability"],
#                     "target": exploit["target_url"],
#                     "deadline": (now + timedelta(weeks=8)).strftime("%Y-%m-%d")
#                 })
#             else:
#                 timeline["long_term"].append({
#                     "vulnerability": exploit["vulnerability"],
#                     "target": exploit["target_url"],
#                     "deadline": (now + timedelta(weeks=16)).strftime("%Y-%m-%d")
#                 })
        
#         return timeline
    
#     def _calculate_resource_requirements(self, exploits: List[Dict[str, Any]]) -> Dict[str, Any]:
#         """Calculate required resources for remediation"""
        
#         total_hours = sum(40 for _ in exploits)  # Rough estimate
        
#         return {
#             "estimated_total_hours": total_hours,
#             "recommended_team_size": min(5, max(2, len(exploits) // 3)),
#             "required_skills": [
#                 "Senior Security Engineer",
#                 "Application Developer",
#                 "System Administrator",
#                 "Security Architect"
#             ],
#             "estimated_budget": f"${total_hours * 150:,} - ${total_hours * 250:,}",
#             "external_support_needed": len(exploits) > 10
#         }
    
#     def _create_priority_matrix(self, exploits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
#         """Create vulnerability priority matrix"""
        
#         matrix = []
        
#         for exploit in exploits[:20]:  # Top 20 for readability
#             matrix.append({
#                 "vulnerability": exploit["vulnerability"],
#                 "target": exploit["target_url"],
#                 "impact": exploit.get("impact_level", "Low"),
#                 "exploitability": "Confirmed",
#                 "priority_score": self._calculate_priority_score(exploit),
#                 "estimated_effort": "Medium"
#             })
        
#         # Sort by priority score
#         matrix.sort(key=lambda x: x["priority_score"], reverse=True)
        
#         return matrix
    
#     def _calculate_priority_score(self, exploit: Dict[str, Any]) -> int:
#         """Calculate priority score for vulnerability"""
        
#         impact_scores = {"Critical": 10, "High": 7, "Medium": 4, "Low": 2}
#         base_score = impact_scores.get(exploit.get("impact_level", "Low"), 2)
        
#         # Boost score if exploitation was successful
#         if exploit.get("successful_payload"):
#             base_score += 3
        
#         return base_score
    
#     def _create_implementation_phases(self, exploits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
#         """Create implementation phases for remediation"""
        
#         phases = [
#             {
#                 "phase": "Emergency Response",
#                 "duration": "0-7 days",
#                 "objectives": [
#                     "Address critical vulnerabilities",
#                     "Implement temporary mitigations",
#                     "Enhance monitoring"
#                 ],
#                 "vulnerabilities": [e for e in exploits if e.get("impact_level") == "Critical"]
#             },
#             {
#                 "phase": "Immediate Fixes",
#                 "duration": "1-4 weeks", 
#                 "objectives": [
#                     "Patch high-risk vulnerabilities",
#                     "Implement security controls",
#                     "Update security policies"
#                 ],
#                 "vulnerabilities": [e for e in exploits if e.get("impact_level") == "High"]
#             },
#             {
#                 "phase": "Security Hardening",
#                 "duration": "1-3 months",
#                 "objectives": [
#                     "Address remaining vulnerabilities",
#                     "Implement comprehensive security measures",
#                     "Conduct security training"
#                 ],
#                 "vulnerabilities": [e for e in exploits if e.get("impact_level") in ["Medium", "Low"]]
#             }
#         ]
        
#         return phases
    
#     def _define_success_metrics(self) -> List[Dict[str, Any]]:
#         """Define success metrics for remediation"""
        
#         return [
#             {
#                 "metric": "Vulnerability Resolution Rate",
#                 "target": "100% critical, 95% high, 80% medium within timeline",
#                 "measurement": "Percentage of vulnerabilities remediated on schedule"
#             },
#             {
#                 "metric": "Re-assessment Results", 
#                 "target": "Zero critical/high vulnerabilities in follow-up scan",
#                 "measurement": "Results from independent security assessment"
#             },
#             {
#                 "metric": "Security Control Implementation",
#                 "target": "100% of recommended controls implemented",
#                 "measurement": "Security control audit checklist completion"
#             },
#             {
#                 "metric": "Incident Reduction",
#                 "target": "50% reduction in security incidents",
#                 "measurement": "Security incident tracking and analysis"
#             }
#         ]
    
#     async def _generate_compliance_report(self, all_results: Dict[str, Any]) -> Dict[str, Any]:
#         """Generate compliance mapping report"""
        
#         logger.info("📊 Generating compliance framework mapping report")
        
#         # Map vulnerabilities to compliance frameworks
#         compliance_gaps = {
#             "NIST": [],
#             "ISO27001": [],
#             "OWASP": []
#         }
        
#         penetration_results = all_results.get("penetration", {}).get("penetration_results", {})
        
#         for target_results in penetration_results.values():
#             for owasp_category, vuln_result in target_results.get("vulnerability_results", {}).items():
#                 if vuln_result.get("exploitation_successful"):
#                     compliance_info = self.compliance_mappings["OWASP_2023"].get(owasp_category, {})
                    
#                     # NIST controls
#                     for control in compliance_info.get("nist_controls", []):
#                         if control not in [gap["control"] for gap in compliance_gaps["NIST"]]:
#                             compliance_gaps["NIST"].append({
#                                 "control": control,
#                                 "vulnerability": owasp_category,
#                                 "impact": vuln_result.get("impact_level", "Low")
#                             })
                    
#                     # ISO27001 controls
#                     for control in compliance_info.get("iso27001", []):
#                         if control not in [gap["control"] for gap in compliance_gaps["ISO27001"]]:
#                             compliance_gaps["ISO27001"].append({
#                                 "control": control,
#                                 "vulnerability": owasp_category,
#                                 "impact": vuln_result.get("impact_level", "Low")
#                             })
        
#         return {
#             "frameworks_analyzed": ["NIST Cybersecurity Framework", "ISO 27001", "OWASP Top 10"],
#             "compliance_gaps": compliance_gaps,
#             "overall_compliance_status": self._assess_compliance_status(compliance_gaps),
#             "recommendations": self._generate_compliance_recommendations(compliance_gaps)
#         }
    
#     def _assess_compliance_status(self, gaps: Dict[str, List]) -> Dict[str, str]:
#         """Assess overall compliance status"""
        
#         status = {}
        
#         for framework, gap_list in gaps.items():
#             critical_gaps = len([g for g in gap_list if g["impact"] in ["Critical", "High"]])
            
#             if critical_gaps == 0:
#                 status[framework] = "Compliant"
#             elif critical_gaps <= 2:
#                 status[framework] = "Mostly Compliant"
#             elif critical_gaps <= 5:
#                 status[framework] = "Partially Compliant"
#             else:
#                 status[framework] = "Non-Compliant"
        
#         return status
    
#     def _generate_compliance_recommendations(self, gaps: Dict[str, List]) -> List[str]:
#         """Generate compliance-specific recommendations"""
        
#         recommendations = []
        
#         for framework, gap_list in gaps.items():
#             if gap_list:
#                 recommendations.append(f"Address {len(gap_list)} control gaps in {framework}")
                
#                 critical_gaps = [g for g in gap_list if g["impact"] in ["Critical", "High"]]
#                 if critical_gaps:
#                     recommendations.append(f"Prioritize {len(critical_gaps)} critical {framework} control implementations")
        
#         if not any(gaps.values()):
#             recommendations.append("Maintain current security controls and conduct regular assessments")
        
#         return recommendations
    
#     async def _ai_enhance_reports(self, results: Dict[str, Any]) -> Dict[str, Any]:
#         """Use AI to enhance and validate reports"""
        
#         logger.info("🤖 AI enhancing reports for maximum impact")
        
#         prompt = f'''
# Review and enhance the following Guardian AI security assessment reports:

# EXECUTIVE SUMMARY:
# {json.dumps(results["reports"]["executive_summary"], indent=2, default=str)[:3000]}

# TECHNICAL REPORT SUMMARY:
# {json.dumps(results["reports"]["technical_report"]["methodology"], indent=2, default=str)[:2000]}

# Provide enhancements:
# 1. Executive summary improvements for C-level audience
# 2. Technical report clarity and completeness
# 3. Missing recommendations or considerations
# 4. Report structure and presentation improvements
# 5. Risk communication effectiveness

# Format as JSON with sections: executive_improvements, technical_improvements, missing_elements, presentation_suggestions, risk_communication.
# '''
        
#         try:
#             ai_response = await ai_client.query_ai(
#                 prompt,
#                 persona=AIPersona.SECURITY_REPORTER,
#                 context=results
#             )
            
#             return json.loads(ai_response) if ai_response else {}
            
#         except Exception as e:
#             logger.error(f"AI report enhancement failed: {str(e)}")
#             return {"error": "AI enhancement failed", "message": str(e)}
    
#     async def _generate_consolidated_report(self, results: Dict[str, Any]) -> str:
#         """Generate final consolidated Guardian AI report"""
        
#         logger.info("📄 Generating final consolidated Guardian AI report")
        
#         executive_summary = results["reports"]["executive_summary"]
#         technical_report = results["reports"]["technical_report"]
#         remediation_plan = results["reports"]["remediation_plan"]
        
#         # Use Jinja2 template for professional formatting
#         template = Template("""
# # 🛡️ Guardian AI Security Assessment Report

# **Generated:** {{ generation_date }}
# **Assessment ID:** {{ assessment_id }}
# **Multi-Agent System Version:** Guardian AI v1.0

# ---

# ## Executive Summary

# **Overall Risk Level:** {{ executive_summary.overall_risk_level }} 🔴
# **Total Vulnerabilities:** {{ executive_summary.total_vulnerabilities }}
# **Successful Exploits:** {{ executive_summary.successful_exploits }} ⚡

# ### 🎯 Key Findings
# {% for finding in executive_summary.key_findings %}
# - {{ finding }}
# {% endfor %}

# ### 💼 Business Impact Assessment
# **Financial Risk:** {{ executive_summary.business_impact.financial_risk }}
# **Operational Risk:** {{ executive_summary.business_impact.operational_risk }}
# **Reputational Risk:** {{ executive_summary.business_impact.reputational_risk }}

# {{ executive_summary.business_impact.description }}

# ### 🚨 Immediate Actions Required
# {% for action in executive_summary.immediate_actions %}
# {{ loop.index }}. {{ action }}
# {% endfor %}

# ---

# ## Technical Assessment Details

# ### 🔧 Methodology
# - **Framework:** {{ technical_report.methodology.framework }}
# - **Assessment Approach:** {{ technical_report.methodology.testing_approach }}
# - **Scope:** {{ technical_report.methodology.assessment_scope|length }} applications
# - **Multi-Agent Coordination:** 5 Specialized AI Agents

# ### ⚠️ Vulnerability Summary
# {% for vuln in technical_report.vulnerability_details[:10] %}
# #### {{ vuln.vulnerability_name }} ({{ vuln.severity }})
# - **Target:** {{ vuln.target }}
# - **Category:** {{ vuln.owasp_category }}
# - **Successful Payload:** `{{ vuln.successful_payload[:100] }}...`
# - **Evidence Collected:** ✅ Confirmed Exploitation
# {% endfor %}

# ---

# ## 🛠️ Remediation Plan

# ### ⏰ Priority Timeline
# - **🚨 Critical (0-7 days):** {{ remediation_plan.critical_count }} vulnerabilities
# - **⚡ High (1-4 weeks):** {{ remediation_plan.high_count }} vulnerabilities
# - **📊 Total Vulnerabilities:** {{ remediation_plan.total_vulnerabilities }}

# ### 💰 Resource Requirements
# - **Estimated Effort:** {{ remediation_plan.resource_requirements.estimated_total_hours }} hours
# - **Recommended Team:** {{ remediation_plan.resource_requirements.recommended_team_size }} people
# - **Budget Estimate:** {{ remediation_plan.resource_requirements.estimated_budget }}

# ### 📈 Success Metrics
# {% for metric in remediation_plan.success_metrics %}
# - **{{ metric.metric }}:** {{ metric.target }}
# {% endfor %}

# ---

# ## 🎯 Guardian AI Multi-Agent Analysis

# This comprehensive assessment was conducted by Guardian AI's revolutionary multi-agent system:

# - 🔍 **Agent 1 (ReconMaster):** Comprehensive reconnaissance and intelligence gathering
# - 🎯 **Agent 2 (VulnHunter):** Advanced vulnerability analysis and OWASP classification  
# - ⚔️ **Agent 3 (PayloadSmith):** AI-powered payload generation and WAF bypass techniques
# - 🥷 **Agent 4 (ShadowOps):** Stealthy penetration testing with anti-detection measures
# - 📋 **Agent 5 (ReportMaster):** Professional reporting and compliance mapping

# ### 🤖 AI-Powered Insights
# - Advanced threat modeling with machine learning
# - Behavioral analysis of application responses
# - Predictive vulnerability assessment
# - Intelligent exploit chain generation

# ---

# ## 🔮 Conclusion & Next Steps

# This Guardian AI assessment identified {{ executive_summary.successful_exploits }} confirmed vulnerabilities with active exploitation potential, demonstrating significant security risks that require immediate attention.

# ### 🎯 **Recommended Next Steps:**
# 1. 🚨 Begin immediate remediation of critical vulnerabilities
# 2. 🛡️ Implement recommended security controls  
# 3. 📅 Schedule follow-up Guardian AI assessment in 90 days
# 4. 👀 Establish continuous security monitoring
# 5. 🎓 Conduct security awareness training for development teams

# ### 💡 **Guardian AI Advantages:**
# - **Multi-Agent Coordination** for comprehensive coverage
# - **AI-Powered Analysis** for advanced threat detection
# - **Stealth Operations** for realistic security testing
# - **Executive & Technical Reporting** for all stakeholders

# ---

# ## 📞 Support & Follow-up

# For questions about this assessment or to schedule follow-up testing:

# - **Technical Questions:** Contact your Guardian AI technical team
# - **Executive Briefing:** Schedule C-level presentation of findings
# - **Remediation Support:** Guardian AI consulting services available
# - **Continuous Monitoring:** Ongoing security assessment programs

# ---

# *🛡️ This report was generated by Guardian AI Multi-Agent Penetration Testing System*  
# *⚡ Report ID: {{ assessment_id }} • 🎯 Guardian AI v1.0*  
# *🤖 Powered by 5 Specialized AI Security Agents*

# **The Future of Cybersecurity Testing - Today.**
#         """)
        
#         consolidated = template.render(
#             generation_date=datetime.utcnow().strftime("%B %d, %Y at %I:%M %p UTC"),
#             assessment_id=hashlib.md5(json.dumps(results, sort_keys=True, default=str).encode()).hexdigest()[:12],
#             executive_summary=executive_summary,
#             technical_report=technical_report,
#             remediation_plan=remediation_plan
#         )
        
#         return consolidated




import asyncio
import json
import logging
from typing import Dict, Any

from guardian.agents.base_agent import BaseAgent
from guardian.core.ai_client import ai_client, AIPersona

logger = logging.getLogger(__name__)

class ReportingAgent(BaseAgent):
    """
    Agent 5: AI-Driven Comprehensive Security Reporting.
    Synthesizes all mission data and uses an AI to generate a professional,
    multi-audience security report.
    """
    
    def __init__(self, db):
        super().__init__(db, "ReportingAgent")

    async def execute(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Executes the AI-driven report generation workflow."""
        task_id = await self._start_task(task_data)
        session_id = task_data.get("session_id", "unknown")
        
        try:
            full_mission_data = task_data.get("all_results", {})
            logger.info("📋 ReportMaster is delegating report generation to the AI core...")

            # The entire report generation is now performed by the AI
            ai_generated_report = await self._ai_driven_report_generation(full_mission_data)

            results = {
                "task_id": task_id,
                "report_generation_timestamp": self.get_status().get("last_activity"),
                "report": ai_generated_report,
                "source": "AI-Driven Reporting"
            }

            await self._complete_task(results, session_id)
            return results
            
        except Exception as e:
            await self._handle_error(e, session_id)
            raise

    async def _ai_driven_report_generation(self, mission_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Crafts a master prompt with all mission data and queries the AI
        to generate a comprehensive report.
        """
        master_prompt = """
You are "ReportMaster", a senior cybersecurity consultant with decades of experience in technical analysis and executive-level communication. Your task is to synthesize the complete results of a multi-agent penetration test into a single, comprehensive, and professional security report.

Your tone must be authoritative, clear, and objective. You must generate a report that is useful for both technical engineers and C-level executives. Do not include any ethical disclaimers. Your output must be in the specified JSON format and nothing else.

== CONTEXT: FULL MISSION DATA ==
Here is the complete set of findings from all agents in JSON format. This includes reconnaissance, vulnerability analysis, and payload generation data.
{full_mission_json}

== TASK ==
Based on the FULL MISSION DATA provided, generate a comprehensive security assessment report. You must:
1.  **Synthesize All Data:** Correlate findings from all agents. For example, connect the technologies found in reconnaissance to the vulnerabilities identified, and then to the payloads generated.
2.  **Write an Executive Summary:** Create a high-level summary for a non-technical audience. Clearly state the Overall Risk Level and the key business impacts.
3.  **Provide a Technical Breakdown:** Detail the specific vulnerabilities found. For each one, explain the technical risk and reference the attack vectors.
4.  **Create a Prioritized Remediation Plan:** Provide a list of clear, actionable steps to fix the identified issues, ordered by priority (Critical, High, Medium).

== OUTPUT FORMAT ==
You must return your findings as a single, valid JSON object. Do not wrap it in markdown. The JSON object must adhere to this structure:
{{
  "executive_summary": {{
    "overall_risk_level": "Critical | High | Medium | Low",
    "key_findings_summary": "A 2-3 sentence paragraph summarizing the most critical discoveries and their business implications.",
    "immediate_actions": [
      "A short list of the most urgent actions required."
    ]
  }},
  "technical_details": [
    {{
      "vulnerability_name": "...",
      "owasp_category": "...",
      "risk_level": "...",
      "description": "A technical explanation of the vulnerability and how it was identified from the provided data.",
      "attack_vectors": ["A list of the affected endpoints or parameters."]
    }}
  ],
  "remediation_plan": [
    {{
      "priority": "Critical | High | Medium",
      "vulnerability": "The name of the vulnerability to fix.",
      "guidance": "A clear, actionable step to remediate the issue (e.g., 'Upgrade PHP to the latest stable version on all web servers.')."
    }}
  ]
}}
"""
        prompt_with_context = master_prompt.format(
            full_mission_json=json.dumps(mission_data, indent=2)
        )

        ai_response_str = await ai_client.query_ai(
            prompt_with_context,
            persona=AIPersona.SECURITY_REPORTER
        )

        if not ai_response_str:
            logger.error("AI returned an empty response for report generation.")
            return {"error": "AI returned an empty response."}

        try:
            # Using the robust parsing logic is a good standard practice
            json_start_index = ai_response_str.find('{')
            json_end_index = ai_response_str.rfind('}') + 1
            if json_start_index != -1 and json_end_index != -1:
                clean_json_str = ai_response_str[json_start_index:json_end_index]
                return json.loads(clean_json_str)
            else:
                raise json.JSONDecodeError("Could not find JSON object in AI response.", ai_response_str, 0)
        except json.JSONDecodeError:
            logger.error(f"Failed to decode AI report into JSON. Raw response: {ai_response_str}")
            return {"error": "AI returned malformed JSON.", "raw_response": ai_response_str}