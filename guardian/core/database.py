import asyncio
import sqlite3
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from contextlib import asynccontextmanager
import aiosqlite
from enum import Enum

from guardian.core.config import settings
from guardian.models.scan_session import ScanSession, ScanStatus

logger = logging.getLogger(__name__)

class Database:
    """
    Asynchronous database interface for Guardian AI
    Manages scan sessions, results, and knowledge base
    FIXED VERSION - Proper async implementation
    """
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or settings.DATABASE_URL.replace("sqlite:///", "")
        # Ensure directory exists
        import os
        os.makedirs(os.path.dirname(self.db_path) if os.path.dirname(self.db_path) else ".", exist_ok=True)
        self.init_db()
    
    def init_db(self):
        """Initialize database schema"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Scan sessions table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scan_sessions (
                        id TEXT PRIMARY KEY,
                        target_urls TEXT NOT NULL,
                        config TEXT,
                        status TEXT NOT NULL,
                        started_at TIMESTAMP,
                        completed_at TIMESTAMP,
                        error_message TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Results table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scan_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT NOT NULL,
                        agent_name TEXT NOT NULL,
                        result_type TEXT NOT NULL,
                        result_data TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (session_id) REFERENCES scan_sessions (id)
                    )
                ''')
                
                # Knowledge base table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS knowledge_base (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        vulnerability_type TEXT NOT NULL,
                        target_signature TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        success_rate REAL DEFAULT 0.0,
                        security_level INTEGER,
                        bypass_methods TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_status ON scan_sessions(status)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_results_session ON scan_results(session_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_kb_vuln_type ON knowledge_base(vulnerability_type)')
                
                conn.commit()
                logger.info("✅ Database schema initialized")
                
        except Exception as e:
            logger.error(f"❌ Database initialization failed: {e}")
            raise
    
    async def save_session(self, session: ScanSession):
        """Save or update scan session asynchronously with robust type handling."""
        try:
            async with aiosqlite.connect(self.db_path) as conn:
                started_at_str = session.started_at.isoformat() if session.started_at else None
                completed_at_str = session.completed_at.isoformat() if session.completed_at else None
                
                # --- ROBUST TYPE CHECK ---
                # Explicitly check if status is an Enum and get its value.
                # from enum import Enum
                status_to_save = session.status.value if isinstance(session.status, Enum) else str(session.status)
                
                await conn.execute('''
                    INSERT OR REPLACE INTO scan_sessions 
                    (id, target_urls, config, status, started_at, completed_at, error_message)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    session.session_id,
                    json.dumps(session.target_urls),
                    json.dumps(session.config),
                    status_to_save,  # <-- Use the sanitized value
                    started_at_str,
                    completed_at_str,
                    session.error_message
                ))
                await conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to save session {session.session_id} to database: {e}")
            raise
    
    async def get_session(self, session_id: str) -> Optional[ScanSession]:
        """Get scan session by ID - FIXED VERSION"""
        try:
            async with aiosqlite.connect(self.db_path) as conn:
                conn.row_factory = aiosqlite.Row
                cursor = await conn.execute('''
                    SELECT * FROM scan_sessions WHERE id = ?
                ''', (session_id,))
                row = await cursor.fetchone()
                
                if row:
                    # Parse datetime strings back to datetime objects
                    started_at = None
                    completed_at = None
                    
                    if row['started_at']:
                        try:
                            from datetime import datetime
                            started_at = datetime.fromisoformat(row['started_at'].replace('Z', '+00:00'))
                        except:
                            started_at = None
                    
                    if row['completed_at']:
                        try:
                            from datetime import datetime
                            completed_at = datetime.fromisoformat(row['completed_at'].replace('Z', '+00:00'))
                        except:
                            completed_at = None
                    
                    return ScanSession(
                        session_id=row['id'],
                        target_urls=json.loads(row['target_urls']),
                        config=json.loads(row['config']) if row['config'] else {},
                        status=ScanStatus(row['status']),
                        started_at=started_at,
                        completed_at=completed_at,
                        error_message=row['error_message']
                    )
                return None
                
        except Exception as e:
            logger.error(f"Failed to get session: {e}")
            return None
    
    async def save_result(self, session_id: str, agent_name: str, result_type: str, result_data: Dict[str, Any]):
        """Save agent result"""
        try:
            async with aiosqlite.connect(self.db_path) as conn:
                await conn.execute('''
                    INSERT INTO scan_results (session_id, agent_name, result_type, result_data)
                    VALUES (?, ?, ?, ?)
                ''', (session_id, agent_name, result_type, json.dumps(result_data, default=str)))
                await conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to save result for agent {agent_name} in session {session_id}: {e}")
            raise # Re-raise the exception
    
    async def get_results(self, session_id: str, agent_name: str = None) -> List[Dict[str, Any]]:
        """Get results for session"""
        try:
            async with aiosqlite.connect(self.db_path) as conn:
                conn.row_factory = aiosqlite.Row
                
                if agent_name:
                    cursor = await conn.execute('''
                        SELECT * FROM scan_results 
                        WHERE session_id = ? AND agent_name = ?
                        ORDER BY created_at DESC
                    ''', (session_id, agent_name))
                else:
                    cursor = await conn.execute('''
                        SELECT * FROM scan_results 
                        WHERE session_id = ?
                        ORDER BY created_at DESC
                    ''', (session_id,))
                
                rows = await cursor.fetchall()
                results = []
                
                for row in rows:
                    try:
                        result_data = json.loads(row['result_data'])
                    except:
                        result_data = {"raw_data": row['result_data']}
                        
                    results.append({
                        'id': row['id'],
                        'session_id': row['session_id'], 
                        'agent_name': row['agent_name'],
                        'result_type': row['result_type'],
                        'result_data': result_data,
                        'created_at': row['created_at']
                    })
                
                return results
                
        except Exception as e:
            logger.error(f"Failed to get results: {e}")
            return []