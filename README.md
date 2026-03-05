# Guardian AI

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

> **Guardian AI** — Multi-agent, LLM-assisted penetration testing framework. Designed for automated reconnaissance → analysis → payload generation → exploitation → reporting.

> ⚠️ **Authorized use only.** Only run this software against systems you own or have explicit written permission to test. Misuse may be illegal.

---

## Quick Start

**Clone & run (external services available)**

```bash
git clone https://github.com/your-org/guardian-ai.git
cd guardian-ai

git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
cp .env.example .env
# edit .env to point OLLAMA_BASE_URL and REDIS_URL

docker compose up
```

**Managed mode (Guardian + Ollama + Redis started for you)**

```bash
docker compose --profile managed up
```

App: `http://localhost:8888` — API docs: `http://localhost:8888/docs`

---

## Architecture

Guardian AI runs a linear, five-stage pipeline per scan:

```
Reconnaissance → Vulnerability Analysis → Payload Generation → Penetration → Reporting
```

**Agents**

* `ReconnaissanceAgent` (ReconMaster): subdomain enumeration, port scanning, crawling, DNS/SSL, tech fingerprinting
* `VulnerabilityAnalysisAgent` (VulnHunter): OWASP Top 10 (2023) classification and triage
* `PayloadGenerationAgent` (PayloadSmith): RAG-based payloads from `PayloadsAllTheThings`
* `PenetrationAgent` (ShadowOps): active injection testing with baseline-aware success detection
* `ReportingAgent` (ReportMaster): executive + technical + remediation sections

A `CentralOrchestrator` manages `ScanContext`s. Each scan is isolated (no shared state). A `BoundedSemaphore` limits concurrent scans (default: 5).

---

## Deployment Modes

**External mode** (default): use your own Ollama + Redis. Edit `.env`:

```env
OLLAMA_BASE_URL=http://host.docker.internal:11434
REDIS_URL=redis://host.docker.internal:6379
```

Only the `guardian_ai` container is started.

**Managed mode** (`--profile managed`): guardian_ai + ollama + redis containers are started together.

If ports collide, override in `.env`:

```env
OLLAMA_HOST_PORT=11435
REDIS_HOST_PORT=6380
GUARDIAN_PORT=8889
```

---

## Configuration

All settings are environment variables (see `.env.example`). The app resolves relative paths to absolute at startup.

| Variable             |                           Default | Notes                                    |
| -------------------- | --------------------------------: | ---------------------------------------- |
| `OLLAMA_BASE_URL`    |             `http://ollama:11434` | Ollama API endpoint                      |
| `OLLAMA_MODEL`       |                  `mistral:latest` | LLM model used for analysis/generation   |
| `REDIS_URL`          |              `redis://redis:6379` | Session backend                          |
| `DATABASE_URL`       | `sqlite:////app/data/guardian.db` | Local SQLite DB                          |
| `PAYLOADS_REPO_PATH` |           `/PayloadsAllTheThings` | Required knowledge base                  |
| `VERIFY_SSL`         |                            `true` | Toggle SSL verification for HTTP clients |
| `LOG_LEVEL`          |                            `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR`         |
| `GUARDIAN_PORT`      |                            `8888` | HTTP port                                |

Environment warnings (missing payloads repo, DB not writable, SSL disabled, etc.) are exposed at `/api/v1/health` for easy debugging.

---

## API (summary)

**Start a scan**

```http
POST /api/v1/scan/start
Content-Type: application/json

{
  "target_urls": ["https://example.com"],
  "config": { /* per-agent config */ }
}
```

Response: `202 Accepted` with `session_id`.

**Status**

```http
GET /api/v1/scan/{session_id}/status
```

**Results**

```http
GET /api/v1/scan/{session_id}/results
```

**Stop**

```http
DELETE /api/v1/scan/{session_id}
```

**Health**

```http
GET /api/v1/health
```

---

## How it works (high level)

### Session isolation

Every scan gets its own `ScanContext` (agents, state, event queue). The orchestrator keeps a registry and evicts completed sessions after a TTL (default: 1 hour).

### RAG-based payload pipeline

* At startup the `KnowledgeIndex` indexes `.md` files from `PayloadsAllTheThings`.
* File selection uses a deterministic `OWASP_TO_FILES` mapping (the LLM does not guess filenames).
* Sections are scored by exploit-relevance (e.g. `payload`, `bypass`, `waf`) and selected to fit a token budget (default: 3,500 tokens).

### Non-blocking I/O

* `nmap` calls run in a `ThreadPoolExecutor`.
* HTTP uses `aiohttp`.
* DNS/subdomain resolution runs concurrently under semaphores.

### Baseline-aware exploit detection

Before testing an injection point, the system captures a baseline (status, length, time, keyword presence). A successful signal requires a change from baseline (new indicator, status bypass, size explosion, or significant timing delta) to reduce false positives.

### LLM token discipline

Agents enforce token budgets. Vulnerability analysis compresses recon data; reporting splits output into bounded calls (exec summary, per-finding technical details, remediation plans).

---

## Project layout (short)

```
guardian/
├── api/                # FastAPI app + routes
├── agents/             # recon, vuln, payload, penetration, reporting
├── core/               # orchestrator, ai client, config, db, knowledge index
├── models/             # Pydantic models
├── data/               # wordlists, seeds
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

---

## Requirements

* Docker & Docker Compose v2.20+
* Ollama running `mistral:latest` (or configure another model)
* `PayloadsAllTheThings` repo cloned next to the project
* 4 GB RAM minimum (8 GB recommended for local LLM inference)
* Optional: NVIDIA + nvidia-container-toolkit for GPU acceleration

---

## Roadmap

Planned enhancements (non-exhaustive):

* API authentication (Bearer tokens + per-key rate limits)
* WebSocket streaming for live progress
* LLM provider abstraction (Ollama/OpenAI/Anthropic)
* FTS5 payload index for fast search
* Structured logging + OpenTelemetry tracing
* Tests: unit, integration, E2E
* Pipeline checkpointing & resume

---

## Contributing

Contributions are welcome. Please follow the standard GitHub flow:

1. Fork
2. Create a feature branch
3. Add tests and docs
4. Open a PR with a clear description

Please run linters and tests before submitting. See `CONTRIBUTING.md` for details.

---

## Security & Legal

**Authorized use only.** Running tests against systems without explicit permission may violate laws in many jurisdictions (e.g. CFAA in the US, Computer Misuse Act in the UK). The project authors accept no liability for misuse.

If you find a security issue in this repository, please report it by opening a private issue or contacting the maintainers directly — do not publish exploit details.

---

## License

This project is provided under the `MIT` license. See `LICENSE`.

---

*Made with ❤ for security professionals. If you'd like a shorter README (one-page) or a dedicated `docs/` site scaffold, I can add that next.*
