from pydantic_settings import BaseSettings
from typing import List, Optional
import os

class Settings(BaseSettings):
    # Database - FIXED: Ensure proper path handling
    DATABASE_URL: str = "sqlite:///./data/guardian.db"
    
    # Redis
    REDIS_URL: str = "redis://redis:6379"
    
    # AI Models
    OLLAMA_BASE_URL: str = "http://ollama:11434"
    DEFAULT_MODEL: str = "mistral:latest"
    
    # API Configuration
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = "guardian-ai-secret-key-change-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Agent Configuration
    MAX_CONCURRENT_AGENTS: int = 5
    AGENT_TIMEOUT: int = 300
    
    # Reconnaissance Settings
    MAX_SUBDOMAINS: int = 1000
    MAX_PORTS: int = 1000
    CRAWL_DEPTH: int = 3
    
    # Security Settings
    STEALTH_MODE: bool = True
    USER_AGENTS: List[str] = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36", 
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    ]
    
    PAYLOADS_REPO_PATH: str = "../PayloadsAllTheThings"

    # Rate Limiting
    REQUESTS_PER_SECOND: float = 1.0
    BURST_SIZE: int = 5
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    
    class Config:
        env_file = ".env"

# Global settings instance
settings = Settings()
