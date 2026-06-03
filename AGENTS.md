# Agent onboarding — FPM

This file orients AI agents and developers. For install, env vars, and tech stack, see [README.md](README.md). For data flow, REST API, and module map, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Working directory

Run every `python -m …` command from **this repository root**. Entry modules insert the project root on `sys.path` so imports like `fpm.*` and `mock_server.*` resolve.

## Entry points

| Command / script | Module | Role |
|------------------|--------|------|
| `./start.sh` | — | Starts mock server (port 8000) and FPM poller in background |
| `./stop.sh` | — | Stops background processes |
| `python -m mock_server.run` | `mock_server/run.py` | App 1: FastAPI mock Traceable platform + dashboard |
| `python -m fpm.run` | `fpm/run.py` | App 2: build KB, start alert polling loop |
| `python -m evaluation.evaluate` | `evaluation/evaluate.py` | Offline eval on 21 ground-truth alerts → `evaluation/report.json` |
| `python -m fpm.mcp_server.server` | `fpm/mcp_server/server.py` | MCP stdio server (`analyse_alert`, `search_controls`) |

## End-to-end flow

1. Mock server generates alerts from templates → SQLite (`pending`).
2. `FPMPoller` fetches `GET /alerts`, calls **`analyse_alert()`** in `fpm/agents/orchestrator.py`.
3. Pipeline: query rewrite → hybrid retrieval → orchestrator delegates to WAF / Kong / Network specialists (each searches KB) → JSON verdict.
4. Poller posts `POST /alerts/{id}/verdict`.

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Critical invariants

- **Verdict enum** (mock server and FPM must agree): `TRUE_POSITIVE`, `FALSE_POSITIVE`, `PARTIAL_RISK`, `NEEDS_HUMAN_REVIEW`. See `VerdictRequest` in `mock_server/server.py`.
- **`template_id`** links `mock_server/alert_templates.py` ↔ `evaluation/ground_truth.py` (eval builds alerts by template id).
- **Control IDs** from parsers / `infrastructure/` must match `expected_controls` in `evaluation/ground_truth.py` for context-recall metrics to be meaningful.
- **Demo data**: 20 false-positive templates (`fp-*`) + 1 true positive (`tp-missing-auth-v2-reports` on `/api/v2/reports/{id}`).

## Pitfalls

1. **ChromaDB skip-if-populated** — `build_knowledge_base()` in `fpm/knowledge/builder.py` returns early if the per-control collection already has documents. After changing `infrastructure/`, parsers, or chunking, delete `chroma_data/` (or `CHROMADB_PERSIST_DIR`) or you will debug stale embeddings.
2. **Mock server must be running** before the FPM poller can fetch/post alerts (`TRACEABLE_BASE_URL`, default `http://localhost:8000`).
3. **Cost / latency** — Each alert runs the orchestrator plus three specialist agent runs (`gpt-4o-mini`). Evaluation runs all 21 templates sequentially.
4. **`OPENAI_API_KEY`** required for FPM, evaluation, and MCP (see `.env.example`).

## If you change X, read Y

| Goal | Primary files |
|------|----------------|
| Verdict logic / agent prompts | `fpm/agents/orchestrator.py`, `fpm/agents/specialists.py` |
| Retrieval quality | `fpm/retrieval/hybrid_search.py`, `fpm/retrieval/query_rewriter.py`, `fpm/knowledge/builder.py` |
| New alert scenario | `mock_server/alert_templates.py`, `evaluation/ground_truth.py`, `infrastructure/` |
| New config source (parser) | `fpm/parsers/`, wire in `fpm/knowledge/builder.py` |
| Mock API / dashboard | `mock_server/server.py`, `mock_server/database.py` |
| Offline metrics | `evaluation/evaluate.py`, `evaluation/ground_truth.py` |

## Evaluation

```bash
python -m evaluation.evaluate
```

Writes `evaluation/report.json` with verdict accuracy, context recall, and optional RAGAS metrics.
