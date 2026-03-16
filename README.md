# Aegis

[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/rKeshaw/Aegis/releases)

> **Aegis** — Multi-agent, LLM-assisted penetration testing framework. Automates an 8-phase pipeline covering reconnaissance, vulnerability analysis, hypothesis seeding, payload generation, active exploitation, graph-based exploration, confirmation, and reporting.

> ⚠️ **Authorized use only.** Only run this software against systems you own or have explicit written permission to test. Misuse may be illegal.

---

## Quick Start

**External mode** (bring your own Ollama):

```bash
git clone https://github.com/rKeshaw/Aegis.git
cd Aegis

# Clone the payload knowledge base (required)
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git

# Create a .env file and configure (see Configuration section)
cat > .env << 'EOF'
OLLAMA_BASE_URL=http://host.docker.internal:11434
OLLAMA_MODEL=mixtral:latest
EOF

docker compose up
```

**Managed mode** (Aegis + Ollama started together):

```bash
docker compose --profile managed up
```

Dashboard: `http://localhost:8888` — API docs: `http://localhost:8888/docs` — Health: `http://localhost:8888/api/v1/health`

---

## Architecture

Aegis runs a linear, eight-phase pipeline per scan. Each phase is independently configurable via [execution profiles](#execution-profiles).

```
Reconnaissance
    ↓
Vulnerability Analysis
    ↓
Hypothesis Seeding         ← tech-specific testable hypotheses
    ↓
Payload Generation         ← RAG-based payloads from PayloadsAllTheThings
    ↓
Active Penetration         ← baseline-aware injection testing
    ↓
Graph Exploration          ← multi-turn reasoning on the attack graph
    ↓
Active Confirmation        ← re-test findings to reduce false positives
    ↓
Reporting                  ← HTML / Markdown / JSON export
```

### Agents

| Agent | Codename | Responsibilities |
|-------|----------|-----------------|
| `ReconnaissanceAgent` | ReconMaster | Port scanning (nmap), subdomain enumeration, web crawling, tech fingerprinting, WAF detection, CORS checks |
| `VulnerabilityAnalysisAgent` | VulnHunter | OWASP Top 10 (2023) classification and triage via LLM |
| `HypothesisAgent` | — | Generates testable hypotheses from detected tech stack (WordPress, Django, Laravel, Rails, …) |
| `PayloadGenerationAgent` | PayloadSmith | RAG-based payload generation from `PayloadsAllTheThings` with deterministic OWASP→file mapping |
| `PenetrationAgent` | ShadowOps | Active injection testing with baseline-aware success detection |
| `ReportingAgent` | ReportMaster | Executive summary + per-finding technical details + remediation plans |

### Core Modules

| Module | Purpose |
|--------|---------|
| `CentralOrchestrator` | Pipeline execution, session registry, progress tracking |
| `AIClient` | Ollama LLM integration with retry, persona management, JSON repair |
| `KnowledgeIndex` | Indexes `PayloadsAllTheThings` .md files; deterministic OWASP→files mapping |
| `TokenLedger` | Per-component token budget tracking; hard limit at 7,500 tokens |
| `Database` | Async SQLite (aiosqlite + SQLAlchemy 2.0) with graph persistence |
| `AttackGraph` | Node/edge graph of hypotheses, probes, observations, and findings |
| `ReportRenderer` | Generates HTML and Markdown reports from scan results |
| `Intelligence` | `ReasoningAgent`, `Comprehender`, `ResponseAnalyzer`, `QualityMonitor`, `RagHelper` |
| `Memory` | Conversation memory + semantic unit compression for multi-turn exploration |
| `Probing` | Async HTTP probe execution with session management and baseline capture |

A `CentralOrchestrator` manages isolated `ScanContext` objects (one per scan). A `BoundedSemaphore` limits concurrent scans (default: 3).

---

## Deployment Modes

### External mode (default)

Uses your existing Ollama instance. Only the `aegis` container starts.

```env
OLLAMA_BASE_URL=http://host.docker.internal:11434
OLLAMA_MODEL=mixtral:latest
```

### Managed mode (`--profile managed`)

Starts `ollama` + `ollama-init` (model puller) + `aegis` together. Requires Docker with GPU support for best performance.

```bash
docker compose --profile managed up
```

### Port overrides

```env
OLLAMA_HOST_PORT=11435
AEGIS_PORT=8889
```

---

## Configuration

All settings are environment variables. Create a `.env` file in the project root to override defaults.

| Variable | Default | Notes |
|----------|---------|-------|
| `OLLAMA_BASE_URL` | `http://ollama:11434` | Ollama API endpoint |
| `OLLAMA_MODEL` | `mixtral:latest` | Primary LLM (analysis, generation, reasoning) |
| `OLLAMA_MODEL_FAST` | `llama3:latest` | Fast model for lightweight tasks |
| `AI_PROVIDER` | `ollama` | LLM provider (`ollama` / `openai`) |
| `DATABASE_URL` | `sqlite:////app/data/aegis.db` | SQLite database path |
| `PAYLOADS_REPO_PATH` | `/PayloadsAllTheThings` | Required knowledge base path |
| `VERIFY_SSL` | `true` | Toggle SSL certificate verification |
| `LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `AEGIS_PORT` | `8888` | HTTP port |
| `MAX_GRAPH_TOKENS` | `50000` | Global token budget for graph exploration |
| `MAX_CONCURRENT_SCANS` | `3` | Maximum parallel scans |
| `SCAN_EXECUTION_PROFILE` | `aggressive` | Pipeline profile (see below) |
| `REQUIRE_API_KEY` | `false` | Enable API key authentication |
| `API_KEY` | _(unset)_ | Bearer token when `REQUIRE_API_KEY=true` |
| `SCAN_TARGET_DENY_CIDRS` | `10.0.0.0/8,…` | Comma-separated blocked networks |
| `SCAN_TARGET_ALLOW_EXTERNAL_ONLY` | `true` | Reject private/loopback/link-local targets |
| `STEALTH_MODE` | `true` | Rotate user agents on HTTP requests |
| `ENABLE_VULN_ANALYSIS_SEEDING` | `true` | Seed hypotheses from vulnerability analysis |
| `ENABLE_RAG_PROBING` | `true` | Use RAG context when probing |
| `ENABLE_PAYLOAD_GENERATION` | `true` | Run payload generation phase |
| `ENABLE_ACTIVE_PENETRATION` | `true` | Run active exploitation phase |
| `ENABLE_ACTIVE_CONFIRMATION` | `true` | Re-test findings for false-positive reduction |

Environment warnings (missing payloads repo, Ollama unreachable, SSL disabled, etc.) are exposed at `/api/v1/health`.

---

## Execution Profiles

Set `SCAN_EXECUTION_PROFILE` to control which pipeline phases are active.

| Profile | Description | Active phases |
|---------|-------------|---------------|
| `legacy` | Original 5-phase behavior, no tier-2 features | Recon → Vuln → Payload → Penetration → Reporting |
| `safe` | Reconnaissance and analysis only, no exploitation | Recon → Vuln → Hypothesis Seeding → Reporting |
| `balanced` | Analysis + payloads, no active exploitation | Recon → Vuln → Hypothesis → Payloads → Reporting |
| `aggressive` | **All phases enabled** _(default)_ | Full 8-phase pipeline |

---

## API Reference

All endpoints (except `/api/v1/health` and `/`) require `X-API-Key` when `REQUIRE_API_KEY=true`.

### Start a scan

```http
POST /api/v1/scan/start
Content-Type: application/json

{
  "target_urls": ["https://example.com"],
  "config": {}
}
```

Response: `202 Accepted`

```json
{ "session_id": "abc123", "status": "started", "message": "Assessment initiated. session_id=abc123" }
```

### Check status

```http
GET /api/v1/scan/{session_id}/status
```

Returns overall progress (0–100), per-phase status, active feature flags, timestamps, and any error message.

### Get results

```http
GET /api/v1/scan/{session_id}/results
```

Returns the full structured results (reconnaissance data, vulnerability findings, payloads, exploitation evidence).

### Export report

```http
GET /api/v1/scan/{session_id}/report/json      # structured JSON
GET /api/v1/scan/{session_id}/report/html      # rendered HTML report
GET /api/v1/scan/{session_id}/report/markdown  # Markdown report
```

### Attack graph

```http
GET /api/v1/scan/{session_id}/graph
```

Returns the attack graph (nodes, edges, frontier size, exploration statistics).

### Stop a scan

```http
DELETE /api/v1/scan/{session_id}
```

### Health check

```http
GET /api/v1/health
```

Returns system status, component availability, active feature flags, execution profile, AI provider, and any environment warnings.

### Real-time streaming

**WebSocket** — subscribe to live scan events:

```
WS /ws/scan/{session_id}?api_key=<key>
```

**Server-Sent Events** — lightweight alternative:

```
GET /api/v1/scan/{session_id}/stream
```

Both emit heartbeats every 30 s and a final `scan_complete` / `scan_error` event.

---

## How It Works

### Session isolation

Every scan gets its own `ScanContext` (agents, event queue, attack graph, token ledger). The orchestrator evicts completed sessions after a 1-hour TTL; historical sessions are retrievable from the SQLite database.

### RAG-based payload pipeline

* At startup `KnowledgeIndex` indexes `.md` files from `PayloadsAllTheThings`.
* File selection uses a deterministic `OWASP_TO_FILES` mapping — the LLM never guesses filenames.
* Sections are scored by exploit-relevance keywords (`payload`, `bypass`, `waf`, `technique`) and selected to fit a 3,500-token budget per vulnerability.

### Hypothesis seeding

`HypothesisAgent` maps detected technologies to pre-defined hypothesis templates (e.g. WordPress XML-RPC abuse, Django debug-mode exposure, Laravel `.env` leakage) and generates typed `HypothesisSchema` objects with confidence scores and entry probes.

During seeding, hypothesis nodes are always added to the in-memory attack graph first. Database persistence is best-effort in this path, so scans continue even in lightweight/test environments where graph tables are not initialized yet.

### Graph-based exploration

The attack graph models the scan as interconnected nodes (`HYPOTHESIS`, `PROBE`, `OBSERVATION`, `FINDING`, `DEAD_END`). `GraphOrchestrator` maintains a priority frontier and dispatches `ReasoningAgent` for multi-turn LLM-assisted hypothesis testing. Explored branches are semantically compressed to stay within the `MAX_GRAPH_TOKENS` budget.

### Baseline-aware exploit detection

Before testing an injection point, `PenetrationAgent` captures a baseline (HTTP status, body length, response time, keyword presence). A positive exploitation signal requires at least one of:

* A new error keyword appears (e.g. SQL syntax error)
* HTTP status changes
* Body length increases > 200%
* Response time delta > 2 seconds

This significantly reduces false positives from benign side effects.

### LLM token discipline

`TokenLedger` tracks spend per component. Agents warn at 6,000 tokens and refuse to query the LLM above 7,500 tokens. The `Comprehender` compresses verbose exploration history into `SemanticUnit` objects to keep the working memory compact.

### Non-blocking I/O

* `nmap` port scans → `ThreadPoolExecutor`
* HTTP crawling and probing → `aiohttp.ClientSession`
* DNS / subdomain resolution → concurrent `asyncio` tasks under semaphores
* LLM calls → sync Ollama client in thread executor
* Database → `aiosqlite` async wrapper

---

## Web Dashboard

Aegis ships a built-in web dashboard served at `http://localhost:8888/`. It provides:

* **New Scan** — submit target URLs and choose an execution profile
* **Dashboard** — overview of active and completed scans
* **Findings** — browse discovered vulnerabilities with OWASP classification
* **Report** — view and download HTML / Markdown reports
* **Monitor** — live progress with WebSocket streaming
* **Graph** — interactive attack graph visualization

---

## Project Layout

```
Aegis/
├── Dockerfile                 # Multi-stage build (Python 3.11-slim)
├── docker-compose.yml         # Managed + external deployment modes
├── entrypoint.sh              # Permission fix + privilege drop (gosu)
├── requirements.txt           # Python dependencies
├── pyproject.toml             # pytest configuration
│
├── aegis/
│   ├── __init__.py            # Package version (1.0.0)
│   ├── api/
│   │   ├── main.py            # FastAPI app, all routes, lifespan
│   │   └── graph_viz.py       # Attack graph response builder
│   ├── agents/
│   │   ├── base_agent.py
│   │   ├── reconnaissance_agent.py
│   │   ├── vulnerability_agent.py
│   │   ├── hypothesis_agent.py
│   │   ├── payload_agent.py
│   │   ├── penetration_agent.py
│   │   └── reporting_agent.py
│   ├── core/
│   │   ├── config.py          # Pydantic settings + profile logic
│   │   ├── orchestrator.py    # CentralOrchestrator + ScanContext
│   │   ├── ai_client.py       # Ollama client + JSON repair utilities
│   │   ├── database.py        # Async SQLite + schema migrations
│   │   ├── knowledge_index.py # PayloadsAllTheThings RAG indexer
│   │   ├── token_ledger.py    # Token budget tracker
│   │   ├── pipeline_contracts.py  # Typed phase output schemas
│   │   ├── report_renderer.py # HTML + Markdown report generation
│   │   ├── graph/             # AttackGraph, GraphOrchestrator, PriorityQueue
│   │   ├── intelligence/      # ReasoningAgent, Comprehender, ResponseAnalyzer, QualityMonitor, RagHelper
│   │   ├── memory/            # ConversationMemory, SemanticUnit
│   │   └── probing/           # ProbeExecutor, SessionManager
│   ├── models/
│   │   ├── target_model.py    # TargetModel (recon output)
│   │   ├── scan_session.py    # ScanSession + ScanStatus enum
│   │   └── hypothesis.py      # HypothesisSchema + InjectionPointSchema
│   ├── data/
│   │   └── subdomain_wordlist.txt
│   └── static/                # Web dashboard (HTML/CSS/JS)
│       ├── index.html
│       ├── css/main.css
│       └── js/
│           ├── app.js
│           └── views/         # dashboard, new-scan, findings, report, monitor, graph
│
├── tests/                     # ~5,200 lines across 23+ test files
│   ├── conftest.py
│   ├── test_api.py
│   ├── test_orchestrator_integration.py
│   ├── test_graph_orchestrator.py
│   ├── test_hypothesis_agent.py
│   ├── test_penetration_agent.py
│   ├── test_reconnaissance_agent.py
│   ├── test_reporting_agent.py
│   ├── …
│   └── real/                  # Real-HTTP and real-LLM integration tests
│
└── data/
    └── aegis.db            # Pre-initialized SQLite database
```

---

## Requirements

* **Docker** and **Docker Compose** v2.20+
* **Ollama** with `mixtral:latest` pulled (or configure a different model via `OLLAMA_MODEL`)
* `PayloadsAllTheThings` repository cloned and accessible at `PAYLOADS_REPO_PATH`
* **8 GB RAM** recommended (4 GB minimum); 16 GB+ for smooth local LLM inference
* Optional: NVIDIA GPU + nvidia-container-toolkit for hardware-accelerated inference

---

## Running Tests

```bash
# Install dependencies
pip install -r requirements.txt

# Run all unit tests (no real HTTP or LLM calls)
python -m pytest -q

# Run only tests that make real HTTP requests
python -m pytest -q -m real_http

# Run full pipeline integration tests (requires Ollama + DVWA)
python -m pytest -q -m real_llm
```

Test markers defined in `pyproject.toml`:

| Marker | Scope |
|--------|-------|
| `anyio` | Async test support |
| `real_http` | Makes real HTTP calls (~5 s) |
| `real_llm` | Requires Ollama + DVWA (30 s – 2 min) |
| `integration` | Full pipeline (up to 15 min) |

---

## Contributing

Contributions are welcome. Please follow the standard GitHub flow:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Add tests and update documentation
4. Open a PR with a clear description of the change

Please run the test suite before submitting.

---

## Security & Legal

**Authorized use only.** Running penetration tests against systems without explicit written permission may violate computer-crime laws in many jurisdictions (e.g. CFAA in the US, Computer Misuse Act in the UK). The project authors accept no liability for misuse.

Aegis restricts scan targets to public IPs by default (`SCAN_TARGET_ALLOW_EXTERNAL_ONLY=true`) and blocks private network ranges. Do not disable these safeguards unless you are testing in an isolated lab environment.

If you discover a security vulnerability in this repository, please report it by opening a private GitHub issue or contacting the maintainers directly — do not publish exploit details publicly.

---

*Made with ❤ for security professionals.*
