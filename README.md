# False Positive Minimizer (FPM)

A two-application AI system that determines whether API security alerts are genuine threats or false positives by analysing them against a knowledge base of infrastructure configurations.

## Architecture

### Application 1 — Traceable Mock Server (port 8000)
Simulates an API security platform: generates security alerts on a schedule, stores them in SQLite, exposes a REST API, and serves a live monitoring dashboard.

### Application 2 — False Positive Minimizer
The AI engine: polls for new alerts, searches a locally-built knowledge base of infrastructure configs (Terraform, NGINX/ModSecurity, Kong Gateway), uses a multi-agent system (OpenAI Agents SDK) to analyse whether existing controls already mitigate each threat, and posts structured verdicts back.

## Prerequisites

Run all commands from this directory (`FPM/`). Python modules expect the project root on `sys.path`.

## Documentation

| Document | Purpose |
|----------|---------|
| [AGENTS.md](AGENTS.md) | AI/developer onboarding: entry points, invariants, pitfalls, change guide |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Data flow, REST API, module map, synced artifacts |

## Entry points

| Command | Purpose |
|---------|---------|
| `./start.sh` | Start mock server + FPM (background) |
| `./stop.sh` | Stop background processes |
| `python -m mock_server.run` | App 1 only (port 8000) |
| `python -m fpm.run` | App 2 only (KB build + polling) |
| `python -m evaluation.evaluate` | Offline eval (optional) |
| `python -m fpm.mcp_server.server` | MCP stdio server (optional) |

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
# Edit .env and set your OPENAI_API_KEY

# 3. Start both applications
./start.sh

# 4. Open the dashboard
open http://localhost:8000

# 5. Stop everything
./stop.sh
```

### Run individually

```bash
# Terminal 1: Mock Server
python -m mock_server.run

# Terminal 2: FPM
python -m fpm.run
```

## Key Components

| Component | Path | Purpose |
|---|---|---|
| Mock Server | `mock_server/` | FastAPI server, SQLite DB, alert templates, dashboard |
| Config Parsers | `fpm/parsers/` | Terraform, NGINX, ModSecurity, Kong YAML parsers |
| Knowledge Base | `fpm/knowledge/` | Chunking, LLM enrichment, ChromaDB embeddings |
| Retrieval | `fpm/retrieval/` | BM25 + dense search + cross-encoder reranking |
| Agents | `fpm/agents/` | Orchestrator + 3 specialist agents (WAF, Gateway, Network) |
| Evaluation | `evaluation/` | RAGAS pipeline with ground truth dataset |
| MCP Server | `fpm/mcp_server/` | Anthropic MCP SDK server for external tool access |
| Infrastructure | `infrastructure/` | Terraform, NGINX, ModSecurity, Kong config files |

## Alert Templates

21 pre-defined templates in `mock_server/alert_templates.py`:
- **20 false positives** (`fp-*`) — each has at least one compensating control that fully mitigates the threat
- **1 true positive** (`tp-missing-auth-v2-reports`) — `/api/v2/reports/{id}` has no auth plugin, no WAF rule, returns confidential financial data

Expected verdicts and control IDs for evaluation are in `evaluation/ground_truth.py` (keyed by `template_id`).

## Mock server API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/alerts` | Pending alerts (FPM poller) |
| `POST` | `/alerts/{alert_id}/verdict` | Post analysis result |
| `GET` | `/alerts/all` | All alerts |
| `GET` | `/alerts/stats` | Statistics |
| `GET` | `/health` | Health check |
| `GET` | `/` | Dashboard |

Full contract: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#rest-api-contract-mock-server).

## Troubleshooting

- **Stale retrieval after infra changes** — `build_knowledge_base()` skips rebuild if Chroma already has data. Delete `chroma_data/` (or your `CHROMADB_PERSIST_DIR`) and restart FPM.
- **Poller finds no alerts** — Start the mock server first (`python -m mock_server.run` or `./start.sh`).
- **FPM exits immediately** — Set `OPENAI_API_KEY` in `.env` (see `.env.example`).
- **Eval mismatches** — Keep `alert_templates.py`, `ground_truth.py`, and `infrastructure/` control IDs in sync.

## Changing the system

| Change | Start here |
|--------|------------|
| Verdict / agent behavior | `fpm/agents/orchestrator.py`, `fpm/agents/specialists.py` |
| Retrieval | `fpm/retrieval/hybrid_search.py`, `fpm/retrieval/query_rewriter.py` |
| New alert scenario | `mock_server/alert_templates.py`, `evaluation/ground_truth.py`, `infrastructure/` |
| New config format | `fpm/parsers/`, `fpm/knowledge/builder.py` |
| Mock API | `mock_server/server.py` |

See also the change guide in [AGENTS.md](AGENTS.md).

## Multi-Agent System

```
Orchestrator (gpt-4o-mini)
├── WAF Specialist      → NGINX + ModSecurity controls
├── Kong Specialist     → Gateway plugins, routes, services
└── Network Specialist  → Terraform SGs, NACLs, WAF ACLs
```

All agents built with the **OpenAI Agents SDK**. Every LLM call is traced via `trace()` and `generation_span` — visible in the OpenAI platform tracing UI.

## Hybrid Retrieval

1. **Query rewriting** — LLM rewrites the raw alert into an optimised search query (cached per alert)
2. **Dense search** — ChromaDB semantic similarity across 3 collections (per-control, per-layer, per-attack-type)
3. **Sparse search** — BM25 keyword matching
4. **Reranking** — `cross-encoder/ms-marco-MiniLM-L-6-v2` reranks merged candidates

## Evaluation

```bash
python -m evaluation.evaluate
```

Runs all 21 ground-truth alerts through the pipeline and reports:
- Verdict accuracy (FP/TP classification)
- Context recall (retrieval quality)
- RAGAS metrics (if ragas is installed)

## MCP Server

```bash
python -m fpm.mcp_server.server
```

Exposes two MCP tools:
- `analyse_alert` — full FPM analysis pipeline
- `search_controls` — knowledge base retrieval

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | (required) | OpenAI API key |
| `TRACEABLE_BASE_URL` | `http://localhost:8000` | Mock server URL |
| `FPM_POLL_INTERVAL_SECONDS` | `30` | Polling interval |
| `CHROMADB_PERSIST_DIR` | `./chroma_data` | ChromaDB storage path |
| `LOG_LEVEL` | `INFO` | Logging level |

## Tech Stack

- **LLM**: gpt-4o-mini (all calls)
- **Embeddings**: text-embedding-3-small
- **Agent framework**: OpenAI Agents SDK
- **Vector DB**: ChromaDB (persistent local)
- **Retrieval**: BM25 + dense + cross-encoder/ms-marco-MiniLM-L-6-v2
- **API framework**: FastAPI
- **Database**: SQLite
- **MCP**: Anthropic MCP SDK
