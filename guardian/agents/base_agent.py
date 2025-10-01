import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime
import uuid
import json

from guardian.core.database import Database

logger = logging.getLogger(__name__)

class AgentStatus:
    IDLE = "idle"
    INITIALIZING = "initializing"
    RUNNING = "running" 
    COMPLETED = "completed"
    ERROR = "error"
    PAUSED = "paused"

class BaseAgent(ABC):
    """
    Abstract base class for all Guardian AI agents
    FULL POWER VERSION - Complete agent framework with advanced capabilities
    """
    
    def __init__(self, db: Database, name: str):
        self.db = db
        self.name = name
        self.status = AgentStatus.IDLE
        self.current_task_id = None
        self.results = {}
        self.performance_metrics = {}
        self.agent_capabilities = []
        self.execution_history = []
        
    @abstractmethod
    async def execute(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the agent's specialized functionality - MUST BE IMPLEMENTED"""
        pass
    
    async def _start_task(self, task_data: Dict[str, Any]) -> str:
        """Initialize a new task with comprehensive logging and metrics"""
        self.current_task_id = str(uuid.uuid4())
        self.status = AgentStatus.RUNNING
        
        task_start_time = datetime.utcnow()
        
        # Log task initiation
        logger.info(f"🚀 {self.name} Agent starting task {self.current_task_id}")
        
        # Initialize performance metrics
        self.performance_metrics[self.current_task_id] = {
            "start_time": task_start_time,
            "task_data_size": len(json.dumps(task_data, default=str)),
            "agent_name": self.name,
            "status": "running"
        }
        
        # Save task start to database with detailed information
        try:
            await self.db.save_result(
                task_data.get("session_id", "unknown"),
                self.name,
                "task_started",
                {
                    "task_id": self.current_task_id,
                    "started_at": task_start_time.isoformat(),
                    "input_data_summary": self._summarize_input_data(task_data),
                    "agent_capabilities": self.agent_capabilities,
                    "agent_status": self.status
                }
            )
        except Exception as e:
            logger.warning(f"Could not save task start to database: {e}")
        
        return self.current_task_id
    
    def _summarize_input_data(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a summary of input data for logging"""
        summary = {
            "data_keys": list(task_data.keys()),
            "session_id": task_data.get("session_id", "unknown"),
            "config_provided": bool(task_data.get("config")),
            "data_types": {key: type(value).__name__ for key, value in task_data.items()}
        }
        
        # Add specific summaries based on data content
        if "targets" in task_data:
            summary["target_count"] = len(task_data["targets"])
        if "reconnaissance_data" in task_data:
            recon_data = task_data["reconnaissance_data"]
            summary["reconnaissance_targets"] = len(recon_data.get("reconnaissance_data", {}))
        if "vulnerability_data" in task_data:
            vuln_data = task_data["vulnerability_data"]
            summary["vulnerabilities_to_analyze"] = len(vuln_data.get("vulnerability_assessment", {}))
        
        return summary
    
    async def _complete_task(self, results: Dict[str, Any], session_id: str):
        """Mark task as completed with comprehensive metrics and logging"""
        self.status = AgentStatus.COMPLETED
        self.results = results
        
        completion_time = datetime.utcnow()
        
        # Update performance metrics
        if self.current_task_id in self.performance_metrics:
            metrics = self.performance_metrics[self.current_task_id]
            metrics.update({
                "end_time": completion_time,
                "execution_duration": (completion_time - metrics["start_time"]).total_seconds(),
                "results_size": len(json.dumps(results, default=str)),
                "status": "completed",
                "success": True
            })
        
        # Add to execution history
        self.execution_history.append({
            "task_id": self.current_task_id,
            "completed_at": completion_time.isoformat(),
            "execution_time": self.performance_metrics.get(self.current_task_id, {}).get("execution_duration", 0),
            "results_summary": self._summarize_results(results)
        })
        
        # Save results to database with comprehensive information
        try:
            await self.db.save_result(
                session_id,
                self.name,
                "task_completed", 
                {
                    "task_id": self.current_task_id,
                    "completed_at": completion_time.isoformat(),
                    "results": results,
                    "performance_metrics": self.performance_metrics.get(self.current_task_id, {}),
                    "agent_status": self.status
                }
            )
        except Exception as e:
            logger.warning(f"Could not save task completion to database: {e}")
        
        logger.info(f"✅ {self.name} Agent completed task {self.current_task_id} successfully")
    
    def _summarize_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Create a summary of results for logging"""
        summary = {
            "result_keys": list(results.keys()),
            "task_id": results.get("task_id"),
            "agent_name": self.name
        }
        
        # Add agent-specific result summaries
        if "reconnaissance_data" in results:
            recon_data = results["reconnaissance_data"]
            summary["targets_analyzed"] = len(recon_data)
            summary["total_subdomains"] = sum(len(target.get("subdomains", [])) for target in recon_data.values())
        
        if "vulnerability_assessment" in results:
            vuln_data = results["vulnerability_assessment"]
            vuln_list = vuln_data.get("vulnerabilities", [])
            summary["vulnerabilities_found"] = len(vuln_data)
            summary["high_risk_vulns"] = sum(1 for vuln in vuln_list
                                           if vuln.get("risk_level") in ["Critical", "High"])
        
        if "payload_arsenal" in results:
            payload_data = results["payload_arsenal"]
            summary["targets_with_payloads"] = len(payload_data)
            summary["total_payloads"] = sum(len(vuln.get("payloads", [])) for vuln in payload_data)
        
        if "penetration_results" in results:
            pen_data = results["penetration_results"]
            summary["targets_tested"] = len(pen_data)
            summary["successful_exploits"] = sum(len(target.get("successful_exploits", [])) 
                                               for target in pen_data.values())
        
        if "reports" in results:
            report_data = results["reports"]
            summary["reports_generated"] = len(report_data)
        
        return summary
    
    async def _handle_error(self, error: Exception, session_id: str):
        """Handle task errors with comprehensive error reporting"""
        self.status = AgentStatus.ERROR
        
        error_time = datetime.utcnow()
        
        # Update performance metrics with error information
        if self.current_task_id in self.performance_metrics:
            metrics = self.performance_metrics[self.current_task_id]
            metrics.update({
                "end_time": error_time,
                "execution_duration": (error_time - metrics["start_time"]).total_seconds(),
                "status": "error",
                "success": False,
                "error_details": {
                    "error_type": type(error).__name__,
                    "error_message": str(error)
                }
            })
        
        error_data = {
            "task_id": self.current_task_id,
            "error_at": error_time.isoformat(),
            "error_type": type(error).__name__,
            "error_message": str(error),
            "agent_name": self.name,
            "performance_metrics": self.performance_metrics.get(self.current_task_id, {})
        }
        
        # Add to execution history
        self.execution_history.append({
            "task_id": self.current_task_id,
            "failed_at": error_time.isoformat(),
            "error_type": type(error).__name__,
            "error_message": str(error)
        })
        
        # Save error to database
        try:
            await self.db.save_result(
                session_id,
                self.name,
                "task_error",
                error_data
            )
        except Exception as db_error:
            logger.error(f"Failed to save error to database: {db_error}")
        
        logger.error(f"❌ {self.name} Agent task {self.current_task_id} failed: {str(error)}")
    
    async def pause_task(self):
        """Pause current task execution"""
        if self.status == AgentStatus.RUNNING:
            self.status = AgentStatus.PAUSED
            logger.info(f"⏸️ {self.name} Agent task {self.current_task_id} paused")
    
    async def resume_task(self):
        """Resume paused task execution"""
        if self.status == AgentStatus.PAUSED:
            self.status = AgentStatus.RUNNING
            logger.info(f"▶️ {self.name} Agent task {self.current_task_id} resumed")
    
    async def cleanup(self):
        """Cleanup agent resources with comprehensive cleanup"""
        previous_status = self.status
        self.status = AgentStatus.IDLE
        self.current_task_id = None
        
        # Preserve results and metrics for analysis
        cleanup_summary = {
            "previous_status": previous_status,
            "tasks_executed": len(self.execution_history),
            "cleanup_time": datetime.utcnow().isoformat(),
            "performance_summary": self._get_performance_summary()
        }
        
        logger.info(f"🧹 {self.name} Agent cleaned up - {cleanup_summary}")
    
    def _get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary across all executed tasks"""
        if not self.performance_metrics:
            return {"total_tasks": 0, "average_execution_time": 0, "success_rate": 0}
        
        successful_tasks = [m for m in self.performance_metrics.values() if m.get("success", False)]
        total_tasks = len(self.performance_metrics)
        
        avg_execution_time = sum(m.get("execution_duration", 0) for m in successful_tasks) / len(successful_tasks) if successful_tasks else 0
        success_rate = len(successful_tasks) / total_tasks if total_tasks > 0 else 0
        
        return {
            "total_tasks": total_tasks,
            "successful_tasks": len(successful_tasks),
            "average_execution_time": avg_execution_time,
            "success_rate": success_rate * 100,
            "total_execution_time": sum(m.get("execution_duration", 0) for m in self.performance_metrics.values())
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive agent status with performance metrics"""
        return {
            "name": self.name,
            "status": self.status,
            "current_task_id": self.current_task_id,
            "has_results": bool(self.results),
            "capabilities": self.agent_capabilities,
            "execution_history_count": len(self.execution_history),
            "performance_summary": self._get_performance_summary(),
            "last_activity": self.execution_history[-1]["completed_at"] if self.execution_history else None
        }
    
    def get_detailed_performance_metrics(self) -> Dict[str, Any]:
        """Get detailed performance metrics for analysis"""
        return {
            "agent_name": self.name,
            "current_metrics": self.performance_metrics,
            "execution_history": self.execution_history,
            "performance_summary": self._get_performance_summary()
        }
