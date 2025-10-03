# Guardian-AI

[![Development Status: In Development](https://img.shields.io/badge/status-in--development-orange)](https://github.com/rKeshaw/Guardian-AI)

Guardian-AI is an advanced, multi-agent AI-powered penetration testing and security assessment system. It is designed to automate and augment the entire security testing lifecycle, targeting the OWASP Top 10 (2023) vulnerabilities and beyond. **This project is currently under active development.**

## 🚧 Status
**Guardian-AI is a work in progress.** Features, APIs, and architecture are subject to change.

## Key Features
- **Multi-Agent Architecture**: Five specialized agents for reconnaissance, vulnerability analysis, payload generation, penetration testing, and reporting.
- **AI-Driven Workflows**: Each agent is powered by advanced language models, using Retrieval-Augmented Generation (RAG) and persona-based prompting.
- **OWASP Top 10 Coverage**: Automated identification, exploitation, and reporting for critical web vulnerabilities.
- **Stealth & Automation**: Built-in stealth modes, anti-detection, and asynchronous execution.
- **FastAPI REST API**: Run scans, retrieve results, and monitor progress via RESTful endpoints.
- **Dockerized Deployment**: Full system runs via Docker Compose, including dependencies (Ollama, Redis, etc).

## Architecture Overview

```
                   +---------------------------------------------+
                   |           Guardian-AI Orchestrator          |
                   +---------------------------------------------+
                     |        |         |         |         |
         +-----------+ +---+-----+  +----+----+ +----+----+ +---+---+
         |ReconMaster| |VulnHunter| |Payload  | |Shadow   | |Report  |
         |(Recon)    | |(Vuln)    | |Smith    | |Ops      | |Master  |
                                    |(Payload)| |(Pentest)| |(Report)|

```

- **ReconMaster**: Elite intelligence gathering & attack surface mapping
- **VulnHunter**: AI-driven vulnerability classification and risk assessment
- **PayloadSmith**: RAG-based payload generation for discovered vulnerabilities
- **ShadowOps**: Stealthy penetration testing and exploitation
- **ReportMaster**: Automated technical and executive reporting

## Quickstart

### Prerequisites
- Docker & Docker Compose
- Python 3.11+ (for development/extension)

### Deploy with Docker Compose
```bash
git clone https://github.com/rKeshaw/Guardian-AI.git
cd Guardian-AI
docker compose up --build
```
- Guardian-AI API will be available at: http://localhost:8888
- Visit `/docs` for interactive API documentation.

### Usage
- Use the web dashboard or API endpoints to launch security assessments.
- Monitor progress via `/api/v1/scan/{session_id}/status`.
- Retrieve full results via `/api/v1/scan/{session_id}/results`.

## Directory Structure

- `guardian/agents/`         - Specialized agent logic
- `guardian/api/`            - FastAPI REST API
- `guardian/core/`           - Core utilities, orchestrator, config, AI client
- `guardian/data/`           - Wordlists, auxiliary data
- `guardian/models/`         - Pydantic models and schemas
- `docker-compose.yml`       - Multi-container orchestration
- `Dockerfile`               - API server image

## Technology Stack
- Python 3.11+
- FastAPI
- Docker & Docker Compose
- Ollama (local LLM hosting)
- Redis (caching/sessions)
- SQLite (results storage)
- Nmap, requests, BeautifulSoup, aiosqlite, pydantic, etc.


## Disclaimer
Guardian-AI is intended for authorized security testing and educational purposes only. **Do not use against systems without explicit permission.**

---

> **Note:** This project is in rapid development. Expect frequent changes, incomplete features, and evolving documentation.
