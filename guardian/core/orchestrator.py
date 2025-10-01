import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
import uuid
import logging
from enum import Enum

from guardian.core.config import settings
from guardian.core.database import Database
from guardian.models.scan_session import ScanSession, ScanStatus

logger = logging.getLogger(__name__)

class OrchestratorStatus(Enum):
    IDLE = "idle"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"

class CentralOrchestrator:
    """
    Central coordinator for the Guardian AI multi-agent system.
    Manages the lifecycle and coordination of all 5 specialized agents.
    FULL POWER VERSION - Complete OWASP Top 10 workflow
    """
    
    def __init__(self, db: Database):
        self.db = db
        self.session_id = None
        self.status = OrchestratorStatus.IDLE
        self.agents = {}
        self.current_session: Optional[ScanSession] = None
        self.results = {}
        self.agent_performance_metrics = {}
        
        # Initialize agents with full power
        self._initialize_agents()
    
    def _initialize_agents(self):
        """Initialize all specialized agents with FULL CAPABILITIES"""
        try:
            from guardian.agents.reconnaissance_agent import ReconnaissanceAgent
            from guardian.agents.vulnerability_agent import VulnerabilityAnalysisAgent
            from guardian.agents.payload_agent import PayloadGenerationAgent
            from guardian.agents.penetration_agent import PenetrationAgent
            from guardian.agents.reporting_agent import ReportingAgent
            
            self.agents = {
                "reconnaissance": ReconnaissanceAgent(self.db),
                "vulnerability_analysis": VulnerabilityAnalysisAgent(self.db),
                "payload_generation": PayloadGenerationAgent(self.db),
                "penetration": PenetrationAgent(self.db),
                "reporting": ReportingAgent(self.db)
            }
            logger.info("🛡️ All 5 Guardian AI agents initialized with FULL POWER")
            
        except ImportError as e:
            logger.error(f"❌ Failed to import agent: {e}")
            raise RuntimeError(f"Guardian AI agent initialization failed: {e}")
    
    async def start_scan(self, target_urls: List[str], scan_config: Dict[str, Any]) -> str:
        """Start a new FULL POWER penetration testing scan session"""
        try:
            # Create new session
            self.session_id = str(uuid.uuid4())
            self.status = OrchestratorStatus.INITIALIZING
            
            # Create session record
            self.current_session = ScanSession(
                session_id=self.session_id,
                target_urls=target_urls,
                config=scan_config,
                status=ScanStatus.INITIALIZING,
                started_at=datetime.utcnow()
            )
            
            await self.db.save_session(self.current_session)
            logger.info(f"🚀 Guardian AI FULL POWER scan session initiated: {self.session_id}")
            
            # Start the complete workflow
            asyncio.create_task(self._execute_complete_workflow(target_urls, scan_config))
            
            return self.session_id
            
        except Exception as e:
            logger.error(f"❌ Error starting Guardian AI FULL POWER scan: {str(e)}")
            self.status = OrchestratorStatus.ERROR
            raise
    
    async def _execute_complete_workflow(self, target_urls: List[str], config: Dict[str, Any]):
        """Execute the COMPLETE 5-agent OWASP Top 10 workflow"""
        try:
            self.status = OrchestratorStatus.RUNNING
            self.current_session.status = ScanStatus.RUNNING
            await self.db.save_session(self.current_session)
            
            logger.info("🔥 Guardian AI COMPLETE multi-agent workflow executing...")
            
            # Phase 1: Elite Reconnaissance
            logger.info("🔍 Phase 1: ReconMaster executing elite reconnaissance...")
            start_time = datetime.utcnow()
            recon_results = await self.agents["reconnaissance"].execute({
                "targets": target_urls,
                "config": config.get("reconnaissance", {
                    "crawl_depth": 3,
                    "subdomain_enumeration": True,
                    "port_scanning": True,
                    "technology_fingerprinting": True,
                    "comprehensive_analysis": True
                }),
                "session_id": self.session_id
            })
            self.results["reconnaissance"] = recon_results
            self.agent_performance_metrics["reconnaissance"] = {
                "execution_time": (datetime.utcnow() - start_time).total_seconds(),
                "targets_analyzed": recon_results.get("targets_analyzed", 0),
                "success": True
            }
            logger.info("✅ Phase 1 complete - Reconnaissance intelligence gathered")
            
            # Phase 2: Advanced Vulnerability Analysis
            logger.info("🎯 Phase 2: VulnHunter analyzing OWASP Top 10 vulnerabilities...")
            start_time = datetime.utcnow()
            vuln_results = await self.agents["vulnerability_analysis"].execute({
                "reconnaissance_data": recon_results,
                "config": config.get("vulnerability_analysis", {
                    "owasp_top_10_analysis": True,
                    "security_level_assessment": True,
                    "risk_prioritization": True,
                    "exploit_difficulty_rating": True
                }),
                "session_id": self.session_id
            })
            self.results["vulnerability_analysis"] = vuln_results
            self.agent_performance_metrics["vulnerability_analysis"] = {
                "execution_time": (datetime.utcnow() - start_time).total_seconds(),
                "vulnerabilities_identified": len(vuln_results.get("vulnerability_assessment", {})),
                "success": True
            }
            vuln_count = len(vuln_results.get("vulnerability_assessment", {}).get("vulnerabilities", []))
            logger.info(f"✅ Phase 2 complete. VulnHunter identified {vuln_count} potential vulnerabilities.")
            
            # Phase 3: AI-Powered Payload Generation
            logger.info("⚔️ Phase 3: PayloadSmith crafting custom exploits...")
            start_time = datetime.utcnow()
            payload_results = await self.agents["payload_generation"].execute({
                "vulnerability_data": vuln_results,
                "reconnaissance_data": recon_results,
                "config": config.get("payload_generation", {
                    "ai_powered_generation": True,
                    "waf_bypass_techniques": True,
                    "exploit_chain_development": True,
                    "stealth_optimization": True
                }),
                "session_id": self.session_id
            })
            self.results["payload_generation"] = payload_results
            self.agent_performance_metrics["payload_generation"] = {
                "execution_time": (datetime.utcnow() - start_time).total_seconds(),
                "payloads_generated": len(payload_results.get("payload_arsenal", {})),
                "success": True
            }
            payload_count = len(payload_results.get("payload_arsenal", []))
            logger.info(f"✅ Phase 3 complete. PayloadSmith generated an arsenal with {payload_count} entries.")

            # Phase 4: Stealthy Penetration Testing
            logger.info("🥷 Phase 4: ShadowOps executing stealth penetration tests...")
            start_time = datetime.utcnow()
            penetration_results = await self.agents["penetration"].execute({
                "payloads": payload_results,
                "targets": recon_results,
                "vulnerabilities": vuln_results,
                "config": config.get("penetration", {
                    "stealth_mode": True,
                    "anti_detection": True,
                    "evidence_collection": True,
                    "success_validation": True
                }),
                "session_id": self.session_id
            })
            self.results["penetration"] = penetration_results
            self.agent_performance_metrics["penetration"] = {
                "execution_time": (datetime.utcnow() - start_time).total_seconds(),
                "successful_exploits": len(penetration_results.get("penetration_results", {})),
                "success": True
            }
            exploit_count = sum(len(res.get("successful_exploits", [])) for res in penetration_results.get("penetration_results", {}).values())
            logger.info(f"✅ Phase 4 complete. ShadowOps confirmed {exploit_count} successful exploits.")
            
            # Phase 5: Comprehensive Reporting
            logger.info("📋 Phase 5: ReportMaster generating comprehensive reports...")
            start_time = datetime.utcnow()
            report_results = await self.agents["reporting"].execute({
                "all_results": self.results,
                "session_id": self.session_id,
                "config": config.get("reporting", {
                    "executive_summary": True,
                    "technical_report": True,
                    "remediation_plan": True,
                    "compliance_mapping": True
                })
            })
            self.results["reporting"] = report_results
            self.agent_performance_metrics["reporting"] = {
                "execution_time": (datetime.utcnow() - start_time).total_seconds(),
                "reports_generated": len(report_results.get("reports", {})),
                "success": True
            }
            logger.info("✅ Phase 5 complete - Comprehensive reports generated")
            
            # Mark session as completed
            self.status = OrchestratorStatus.COMPLETED
            self.current_session.status = ScanStatus.COMPLETED
            self.current_session.completed_at = datetime.utcnow()
            await self.db.save_session(self.current_session)
            
            # Save final workflow summary
            workflow_summary = self._generate_workflow_summary()
            self.results["workflow_summary"] = workflow_summary
            
            logger.info(f"🎉 Guardian AI COMPLETE workflow finished successfully: {self.session_id}")
            
        except Exception as e:
            logger.error(f"❌ Guardian AI workflow execution error: {str(e)}")
            self.status = OrchestratorStatus.ERROR
            if self.current_session:
                self.current_session.status = ScanStatus.ERROR
                self.current_session.error_message = str(e)
                await self.db.save_session(self.current_session)
            raise
    
    def _generate_workflow_summary(self) -> Dict[str, Any]:
        """Generate comprehensive workflow execution summary"""
        total_time = sum(metrics.get("execution_time", 0) for metrics in self.agent_performance_metrics.values())
        
        # Extract key metrics from results
        recon_data = self.results.get("reconnaissance", {})
        vuln_data = self.results.get("vulnerability_analysis", {})
        payload_data = self.results.get("payload_generation", {})
        penetration_data = self.results.get("penetration", {})
        
        return {
            "workflow_execution_time": total_time,
            "agent_performance": self.agent_performance_metrics,
            "key_findings": {
                "targets_analyzed": recon_data.get("targets_analyzed", 0),
                "subdomains_discovered": sum(
                    len(target.get("subdomains", [])) 
                    for target in recon_data.get("reconnaissance_data", {}).values()
                ),
                "vulnerabilities_found": len(vuln_data.get("vulnerability_assessment", {})),
                "payloads_generated": len(payload_data.get("payload_arsenal", {})),
                "successful_exploits": sum(
                    len(target.get("successful_exploits", [])) 
                    for target in penetration_data.get("penetration_results", {}).values()
                ),
                "overall_risk_level": self._calculate_overall_risk_level()
            },
            "workflow_status": "completed_successfully",
            "guardian_ai_version": "1.0.0"
        }
    
    def _calculate_overall_risk_level(self) -> str:
        """Calculate overall risk level based on findings"""
        penetration_results = self.results.get("penetration", {}).get("penetration_results", {})
        
        total_successful_exploits = sum(
            len(target.get("successful_exploits", [])) 
            for target in penetration_results.values()
        )
        
        if total_successful_exploits >= 3:
            return "Critical"
        elif total_successful_exploits >= 2:
            return "High" 
        elif total_successful_exploits >= 1:
            return "Medium"
        else:
            return "Low"
    
    async def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """Get comprehensive session status with agent details - DEBUG VERSION"""
        session = await self.db.get_session(session_id)
        if not session:
            raise ValueError(f"Guardian AI session {session_id} not found")
        
        # DEBUG: Log the session object types
        logger.info(f"🔍 DEBUG - Session started_at type: {type(session.started_at)}")
        logger.info(f"🔍 DEBUG - Session completed_at type: {type(session.completed_at)}")
        
        # Force string conversion
        started_at_str = None
        completed_at_str = None
        
        if session.started_at:
            if hasattr(session.started_at, 'isoformat'):
                started_at_str = session.started_at.isoformat()
            else:
                started_at_str = str(session.started_at)
        
        if session.completed_at:
            if hasattr(session.completed_at, 'isoformat'):
                completed_at_str = session.completed_at.isoformat()
            else:
                completed_at_str = str(session.completed_at)
        
        result = {
            "session_id": session_id,
            "status": session.status,
            "progress": self._calculate_detailed_progress(),
            "started_at": started_at_str,
            "completed_at": completed_at_str,
            "agent_status": self._get_agent_status(),
            "results_preview": self._get_results_preview() if session_id == self.session_id else {},
            "performance_metrics": self.agent_performance_metrics if session_id == self.session_id else {}
        }
        
        # DEBUG: Log the final result types
        logger.info(f"🔍 DEBUG - Final started_at type: {type(result['started_at'])}")
        logger.info(f"🔍 DEBUG - Final completed_at type: {type(result['completed_at'])}")
        
        return result


    
    def _calculate_detailed_progress(self) -> Dict[str, Any]:
        """Calculate detailed progress with agent breakdown"""
        if self.status == OrchestratorStatus.COMPLETED:
            return {"overall": 100.0, "agents": {agent: 100.0 for agent in self.agents.keys()}}
        
        completed_agents = len([r for r in self.results.values() if r])
        total_agents = len(self.agents)
        overall_progress = (completed_agents / total_agents) * 100.0
        
        agent_progress = {}
        for agent_name in self.agents.keys():
            if agent_name in self.results:
                agent_progress[agent_name] = 100.0
            elif self.status == OrchestratorStatus.RUNNING:
                agent_progress[agent_name] = 50.0  # Assume in progress
            else:
                agent_progress[agent_name] = 0.0
        
        return {"overall": overall_progress, "agents": agent_progress}
    
    def _get_agent_status(self) -> Dict[str, Dict[str, Any]]:
        """Get detailed status of all agents"""
        return {name: agent.get_status() for name, agent in self.agents.items()}
    
    def _get_results_preview(self) -> Dict[str, Any]:
        """Get preview of current results"""
        return {
            "reconnaissance": {
                "targets_analyzed": self.results.get("reconnaissance", {}).get("targets_analyzed", 0),
                "completed": "reconnaissance" in self.results
            },
            "vulnerability_analysis": {
                "vulnerabilities_found": len(self.results.get("vulnerability_analysis", {}).get("vulnerability_assessment", {})),
                "completed": "vulnerability_analysis" in self.results
            },
            "payload_generation": {
                "payloads_generated": len(self.results.get("payload_generation", {}).get("payload_arsenal", {})),
                "completed": "payload_generation" in self.results
            },
            "penetration": {
                "exploits_attempted": len(self.results.get("penetration", {}).get("penetration_results", {})),
                "completed": "penetration" in self.results
            },
            "reporting": {
                "reports_ready": len(self.results.get("reporting", {}).get("reports", {})),
                "completed": "reporting" in self.results
            }
        }
    
    async def pause_scan(self, session_id: str):
        """Pause the current scan"""
        if session_id == self.session_id:
            self.status = OrchestratorStatus.PAUSED
            logger.info(f"🛑 Guardian AI scan {session_id} paused")
    
    async def resume_scan(self, session_id: str):
        """Resume a paused scan"""
        if session_id == self.session_id and self.status == OrchestratorStatus.PAUSED:
            self.status = OrchestratorStatus.RUNNING
            logger.info(f"▶️ Guardian AI scan {session_id} resumed")
    
    async def stop_scan(self, session_id: str):
        """Stop and cleanup a scan session"""
        if session_id == self.session_id:
            self.status = OrchestratorStatus.IDLE
            # Cleanup all agents
            for agent in self.agents.values():
                await agent.cleanup()
            logger.info(f"🛑 Guardian AI scan {session_id} stopped and cleaned up")
    
    async def get_agent_individual_results(self, session_id: str, agent_name: str) -> Dict[str, Any]:
        """Get individual agent results for detailed analysis"""
        if agent_name not in self.agents:
            raise ValueError(f"Agent {agent_name} not found")
        
        return await self.db.get_results(session_id, agent_name)
    
    def get_workflow_health(self) -> Dict[str, Any]:
        """Get overall Guardian AI workflow health status"""
        return {
            "orchestrator_status": self.status.value,
            "active_session": self.session_id,
            "agents_initialized": len(self.agents),
            "agents_healthy": sum(1 for agent in self.agents.values() if agent.status != "error"),
            "database_connection": "healthy",  # Simplified check
            "last_activity": datetime.utcnow().isoformat()
        }