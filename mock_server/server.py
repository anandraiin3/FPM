"""
Traceable Mock Server — Application 1.

FastAPI app that:
  1. Auto-generates security alerts on a schedule (every hour).
  2. Exposes REST endpoints for FPM to poll and post verdicts.
  3. Serves a monitoring dashboard at GET /.
"""
import json
import logging
import os
from contextlib import asynccontextmanager

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from mock_server.database import (
    init_db,
    get_all_alerts,
    get_alert_by_id,
    get_pending_alerts,
    get_stats,
    update_verdict,
)
from mock_server.alert_generator import generate_batch

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Verdict request schema
# ---------------------------------------------------------------------------

class VerdictRequest(BaseModel):
    verdict: str = Field(..., pattern="^(TRUE_POSITIVE|FALSE_POSITIVE|PARTIAL_RISK|NEEDS_HUMAN_REVIEW)$")
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str
    controls_found: list[str] = Field(default_factory=list)
    coverage_gaps: list[str] = Field(default_factory=list)
    recommended_action: str = ""
    tokens_used: int | None = None
    analysis_latency_ms: int | None = None


# ---------------------------------------------------------------------------
# Lifespan: init DB, seed first batch, start scheduler
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("Database initialised")

    # Generate the first batch immediately so the dashboard is not empty
    generate_batch()

    scheduler = BackgroundScheduler()
    scheduler.add_job(generate_batch, "interval", hours=1, id="alert_gen")
    scheduler.start()
    logger.info("Alert scheduler started (interval=1h)")

    yield

    scheduler.shutdown(wait=False)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="Traceable Mock Server", version="1.0.0", lifespan=lifespan)

# Serve static assets (dashboard JS/CSS)
_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(_STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "Traceable Mock Server"}


@app.get("/alerts")
def alerts_pending():
    """Return all alerts with status `pending`."""
    rows = get_pending_alerts()
    # Parse JSON string fields back to objects for the response
    for r in rows:
        for field in ("http_request", "http_response", "controls_found", "coverage_gaps"):
            if isinstance(r.get(field), str):
                try:
                    r[field] = json.loads(r[field])
                except (json.JSONDecodeError, TypeError):
                    pass
    return rows


@app.get("/alerts/all")
def alerts_all():
    """Return all alerts regardless of status."""
    rows = get_all_alerts()
    for r in rows:
        for field in ("http_request", "http_response", "controls_found", "coverage_gaps"):
            if isinstance(r.get(field), str):
                try:
                    r[field] = json.loads(r[field])
                except (json.JSONDecodeError, TypeError):
                    pass
    return rows


@app.get("/alerts/stats")
def alerts_stats():
    """Return summary statistics."""
    return get_stats()


@app.post("/alerts/{alert_id}/verdict")
def post_verdict(alert_id: str, body: VerdictRequest):
    """Accept and persist a verdict from FPM."""
    existing = get_alert_by_id(alert_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    if existing["status"] == "analysed":
        raise HTTPException(status_code=409, detail=f"Alert {alert_id} already analysed")

    ok = update_verdict(alert_id, body.model_dump())
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to update verdict")

    return {"status": "ok", "alert_id": alert_id}


# ---------------------------------------------------------------------------
# Dashboard (serves index.html)
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard():
    """Serve the monitoring dashboard."""
    tmpl_path = os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")
    with open(tmpl_path) as f:
        return HTMLResponse(content=f.read())
