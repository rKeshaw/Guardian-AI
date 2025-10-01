from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Dict, List, Any, Optional
import logging
import os
from datetime import datetime
import asyncio
import traceback

# Configure logging first
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s | %(levelname)s | %(name)s | %(message)s'
)
logger = logging.getLogger(__name__)

logger.info("🚀 Guardian AI starting up...")
logger.info(f"🌍 Current working directory: {os.getcwd()}")
logger.info(f"🐍 Python path: {os.environ.get('PYTHONPATH', 'Not set')}")

# Initialize FastAPI app first
app = FastAPI(
    title="Guardian AI - Multi-Agent Penetration Testing System",
    description="Advanced AI-powered penetration testing with 5 specialized agents covering OWASP Top 10 (2023)",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables for components
database = None
orchestrator = None
startup_error = None

async def initialize_guardian_components():
    """Initialize Guardian AI components with error handling"""
    global database, orchestrator, startup_error
    
    try:
        logger.info("🔧 Initializing Guardian AI components...")
        
        # Import and initialize components
        from guardian.core.config import settings
        logger.info("✅ Config loaded successfully")
        
        from guardian.core.database import Database
        database = Database()
        logger.info("✅ Database initialized successfully")
        
        from guardian.core.orchestrator import CentralOrchestrator
        orchestrator = CentralOrchestrator(database)
        logger.info("✅ Orchestrator initialized successfully")
        
        logger.info("🎉 All Guardian AI components loaded successfully!")
        return True
        
    except Exception as e:
        startup_error = str(e)
        logger.error(f"❌ Failed to initialize Guardian AI: {e}")
        logger.error(f"🔍 Traceback: {traceback.format_exc()}")
        return False

# Pydantic models
class ScanRequest(BaseModel):
    target_urls: List[str]
    config: Optional[Dict[str, Any]] = {}
    
class ScanResponse(BaseModel):
    session_id: str
    status: str
    message: str

class ScanStatus(BaseModel):
    session_id: str
    status: str
    progress: float
    started_at: Optional[str]
    completed_at: Optional[str]
    results: Optional[Dict[str, Any]] = None

# Routes
@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Guardian AI Dashboard with dynamic port"""
    port = os.environ.get('GUARDIAN_PORT', '8888')
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Guardian AI - Multi-Agent Penetration Testing System</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ 
                font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
                background: linear-gradient(135deg, #0f0f0f, #1a1a2e);
                color: #e0e0e0;
                min-height: 100vh;
                padding: 20px;
            }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            .header {{
                text-align: center;
                padding: 40px 0;
                border-bottom: 2px solid #00d4ff;
                margin-bottom: 40px;
            }}
            .header h1 {{
                font-size: 3.5em;
                font-weight: 700;
                background: linear-gradient(45deg, #00d4ff, #0099cc);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 10px;
            }}
            .card {{
                background: rgba(255, 255, 255, 0.05);
                backdrop-filter: blur(10px);
                border-radius: 15px;
                padding: 30px;
                margin: 20px 0;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }}
            .status {{
                text-align: center;
                padding: 20px;
                background: linear-gradient(45deg, #1e1e30, #2a2a40);
                border-radius: 10px;
                margin: 20px 0;
            }}
            .success {{ border-left: 4px solid #00ff88; }}
            .warning {{ border-left: 4px solid #ffaa00; }}
            .error {{ border-left: 4px solid #ff4444; }}
            .btn {{
                background: linear-gradient(45deg, #00d4ff, #0099cc);
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                font-weight: 600;
                margin: 10px;
            }}
            .btn:hover {{ transform: scale(1.05); }}
            .input-group {{
                margin: 20px 0;
            }}
            .input-group textarea {{
                width: 100%;
                padding: 15px;
                border-radius: 8px;
                border: 2px solid #444;
                background: #222;
                color: #fff;
                font-family: monospace;
                min-height: 100px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ Guardian AI</h1>
                <div style="font-size: 1.3em; color: #888;">Multi-Agent Penetration Testing System</div>
                <div style="font-size: 1.1em; color: #00d4ff; margin-top: 10px;">⚡ Running on Port {port}</div>
            </div>
            
            <div class="card status success">
                <h2 id="systemStatus">✅ Guardian AI System Status</h2>
                <p id="statusMessage">System is operational and ready for security assessments</p>
                <br>
                <p><strong>Version:</strong> v1.0.0</p>
                <p><strong>Port:</strong> {port}</p>
                <p><strong>API:</strong> <a href="/api/v1/health" style="color: #00d4ff;">/api/v1/health</a></p>
                <button class="btn" onclick="checkHealth()">🏥 Check System Health</button>
                <button class="btn" onclick="window.open('/docs', '_blank')">📚 API Docs</button>
            </div>
            
            <div class="card">
                <h2>🚀 Quick Security Assessment</h2>
                <div class="input-group">
                    <label for="targets">🎯 Target URLs (one per line):</label>
                    <textarea id="targets" placeholder="https://httpbin.org&#10;https://jsonplaceholder.typicode.com"></textarea>
                </div>
                <button class="btn" onclick="startAssessment()">🚀 Deploy Guardian AI Agents</button>
                
                <div id="assessmentResults" style="margin-top: 20px; display: none;">
                    <h3>📊 Assessment Results</h3>
                    <div id="resultsContent"></div>
                </div>
            </div>
            
            <div class="card">
                <h2>🤖 Guardian AI Multi-Agent System</h2>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 20px;">
                    <div style="background: #1e1e30; padding: 15px; border-radius: 8px; text-align: center;">
                        <div style="font-size: 2em;">🔍</div>
                        <strong>ReconMaster</strong><br>
                        <small>Elite Reconnaissance</small>
                    </div>
                    <div style="background: #1e1e30; padding: 15px; border-radius: 8px; text-align: center;">
                        <div style="font-size: 2em;">🎯</div>
                        <strong>VulnHunter</strong><br>
                        <small>OWASP Analysis</small>
                    </div>
                    <div style="background: #1e1e30; padding: 15px; border-radius: 8px; text-align: center;">
                        <div style="font-size: 2em;">⚔️</div>
                        <strong>PayloadSmith</strong><br>
                        <small>Exploit Crafting</small>
                    </div>
                    <div style="background: #1e1e30; padding: 15px; border-radius: 8px; text-align: center;">
                        <div style="font-size: 2em;">🥷</div>
                        <strong>ShadowOps</strong><br>
                        <small>Stealth Testing</small>
                    </div>
                    <div style="background: #1e1e30; padding: 15px; border-radius: 8px; text-align: center;">
                        <div style="font-size: 2em;">📋</div>
                        <strong>ReportMaster</strong><br>
                        <small>Comprehensive Reports</small>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            async function checkHealth() {{
                try {{
                    const response = await fetch('/api/v1/health');
                    const health = await response.json();
                    
                    document.getElementById('systemStatus').textContent = 
                        health.components.agents === 5 ? '✅ Guardian AI Fully Operational' : '⚠️ Guardian AI Partially Ready';
                    document.getElementById('statusMessage').textContent = 
                        `Agents: ${{health.components.agents}}/5 | Database: ${{health.components.database}} | Orchestrator: ${{health.components.orchestrator}}`;
                        
                }} catch (error) {{
                    document.getElementById('systemStatus').textContent = '❌ Guardian AI System Error';
                    document.getElementById('statusMessage').textContent = 'Unable to connect to Guardian AI API';
                }}
            }}
            
            async function startAssessment() {{
                const targets = document.getElementById('targets').value.trim().split('\\n').filter(t => t);
                if (!targets.length) {{
                    alert('Please enter at least one target URL');
                    return;
                }}
                
                try {{
                    const response = await fetch('/api/v1/scan/start', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{
                            target_urls: targets,
                            config: {{
                                reconnaissance: {{crawl_depth: 2}},
                                vulnerability_analysis: {{owasp_top_10_analysis: true}},
                                payload_generation: {{ai_powered_generation: true}},
                                penetration: {{stealth_mode: true}},
                                reporting: {{executive_summary: true}}
                            }}
                        }})
                    }});
                    
                    const result = await response.json();
                    
                    if (response.ok) {{
                        document.getElementById('assessmentResults').style.display = 'block';
                        document.getElementById('resultsContent').innerHTML = `
                            <div class="status success">
                                <strong>🚀 Assessment Started!</strong><br>
                                Session ID: ${{result.session_id}}<br>
                                <a href="/api/v1/scan/${{result.session_id}}/status" target="_blank">Monitor Progress</a>
                            </div>
                        `;
                    }} else {{
                        alert('Assessment failed: ' + result.detail);
                    }}
                }} catch (error) {{
                    alert('Error starting assessment: ' + error.message);
                }}
            }}
            
            // Auto-check health on load
            window.onload = checkHealth;
        </script>
    </body>
    </html>
    """

@app.post("/api/v1/scan/start", response_model=ScanResponse)
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new Guardian AI penetration testing scan"""
    try:
        if not orchestrator:
            raise HTTPException(
                status_code=503, 
                detail=f"Guardian AI orchestrator not available. Startup error: {startup_error}"
            )
            
        logger.info(f"🚀 Guardian AI launching assessment for targets: {scan_request.target_urls}")
        
        session_id = await orchestrator.start_scan(
            scan_request.target_urls,
            scan_request.config
        )
        
        return ScanResponse(
            session_id=session_id,
            status="started",
            message=f"Guardian AI multi-agent assessment initiated with session ID: {session_id}"
        )
        
    except Exception as e:
        logger.error(f"Failed to start Guardian AI scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/scan/{session_id}/status", response_model=ScanStatus)
async def get_scan_status(session_id: str):
    """Get the status of a Guardian AI scan session."""
    try:
        if not orchestrator:
            raise HTTPException(status_code=503, detail="Guardian AI orchestrator not available")
            
        status_data = await orchestrator.get_session_status(session_id)
        if not status_data:
            raise HTTPException(status_code=404, detail="Session not found")

        # Create a ScanStatus response model instance. FastAPI will handle serialization.
        return ScanStatus(
            session_id=session_id,
            status=status_data.get("status", "unknown"),
            progress=status_data.get("progress", {}).get("overall", 0),
            started_at=status_data.get("started_at"),
            completed_at=status_data.get("completed_at"),
            results=status_data.get("results_preview", {})
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Status check for session {session_id} failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {str(e)}")


@app.get("/api/v1/scan/{session_id}/results")
async def get_scan_results(session_id: str):
    """Get detailed results for a completed Guardian AI scan"""
    try:
        if not database:
            raise HTTPException(status_code=503, detail="Guardian AI database not available")
            
        results = await database.get_results(session_id)
        
        if not results:
            raise HTTPException(status_code=404, detail="Guardian AI results not found")
        
        return JSONResponse(content={"session_id": session_id, "results": results})
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get Guardian AI scan results: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/health")
async def health_check():
    """Guardian AI system health check - FIXED VERSION"""
    try:
        port = os.environ.get('GUARDIAN_PORT', '8888')
        
        # Check component health
        components = {
            "database": "available" if database else "unavailable",
            "orchestrator": "available" if orchestrator else "unavailable", 
            "agents": len(orchestrator.agents) if orchestrator else 0
        }
        
        status = {
            "status": "Guardian AI operational" if components["agents"] == 5 else "Guardian AI starting",
            "timestamp": str(datetime.utcnow()),
            "version": "1.0.0",
            "port": port,
            "components": components,
            "startup_error": startup_error if startup_error else None
        }
        
        return status
        
    except Exception as e:
        logger.error(f"Guardian AI health check failed: {str(e)}")
        return JSONResponse(
            status_code=200,
            content={
                "status": "Guardian AI starting", 
                "error": str(e),
                "timestamp": str(datetime.utcnow()),
                "port": os.environ.get('GUARDIAN_PORT', '8888'),
                "startup_error": startup_error
            }
        )

@app.on_event("startup")
async def startup_event():
    logger.info("🛡️ Guardian AI Multi-Agent System starting up...")
    logger.info("🤖 Initializing components...")
    
    # Initialize components asynchronously
    success = await initialize_guardian_components()
    
    if success:
        logger.info("🎯 Guardian AI ready for deployment!")
    else:
        logger.error("❌ Guardian AI startup encountered errors")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get('GUARDIAN_PORT', '8888'))
    uvicorn.run(app, host="0.0.0.0", port=port)