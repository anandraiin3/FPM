# FPMWithDevin

Demo repository for a **False Positive Minimizer (FPM)**: a mock API-security platform generates alerts, and an AI pipeline decides whether each alert is a genuine threat or already mitigated by infrastructure controls (Terraform, NGINX/ModSecurity, Kong Gateway).

All runnable application code lives in **[FPM/](FPM/)**.

## Quick start

```bash
cd FPM
pip install -r requirements.txt
cp .env.example .env   # set OPENAI_API_KEY
./start.sh
```

Open the dashboard at http://localhost:8000. Stop with `./stop.sh` from the `FPM` directory.

## Documentation

| Document | Audience | Purpose |
|----------|----------|---------|
| [FPM/README.md](FPM/README.md) | Humans | Install, run, env vars, tech stack |
| [AGENTS.md](AGENTS.md) | AI agents / developers | Entry points, invariants, pitfalls, change guide |
| [FPM/docs/ARCHITECTURE.md](FPM/docs/ARCHITECTURE.md) | Deep dive | Data flow, REST API, module map, synced artifacts |
