"""
SQLite database layer for the Traceable Mock Server.
Creates the alerts table on first run; applies migrations automatically at startup.
"""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.getenv("MOCK_SERVER_DB", os.path.join(os.path.dirname(__file__), "alerts.db"))


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


@contextmanager
def get_db():
    conn = _get_connection()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """Create the alerts table if it does not exist."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id          TEXT PRIMARY KEY,
                timestamp         TEXT NOT NULL,
                source_ip         TEXT NOT NULL,
                target_endpoint   TEXT NOT NULL,
                http_method       TEXT NOT NULL,
                attack_type       TEXT NOT NULL,
                traceable_reason  TEXT NOT NULL,
                payload_snippet   TEXT NOT NULL,
                severity          TEXT NOT NULL CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
                http_request      TEXT NOT NULL,
                http_response     TEXT NOT NULL,
                status            TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','analysed')),
                verdict           TEXT CHECK(verdict IN ('TRUE_POSITIVE','FALSE_POSITIVE','PARTIAL_RISK','NEEDS_HUMAN_REVIEW')),
                confidence        REAL,
                reasoning         TEXT,
                controls_found    TEXT,
                coverage_gaps     TEXT,
                recommended_action TEXT,
                analysed_at       TEXT,
                tokens_used       INTEGER,
                analysis_latency_ms INTEGER,
                template_id       TEXT
            )
        """)


# ---------------------------------------------------------------------------
# CRUD helpers
# ---------------------------------------------------------------------------

def insert_alert(alert: dict) -> None:
    with get_db() as conn:
        conn.execute(
            """INSERT OR IGNORE INTO alerts
               (alert_id, timestamp, source_ip, target_endpoint, http_method,
                attack_type, traceable_reason, payload_snippet, severity,
                http_request, http_response, status, template_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                alert["alert_id"],
                alert["timestamp"],
                alert["source_ip"],
                alert["target_endpoint"],
                alert["http_method"],
                alert["attack_type"],
                alert["traceable_reason"],
                alert["payload_snippet"],
                alert["severity"],
                json.dumps(alert["http_request"]),
                json.dumps(alert["http_response"]),
                "pending",
                alert.get("template_id"),
            ),
        )


def get_pending_alerts() -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE status = 'pending' ORDER BY timestamp"
        ).fetchall()
    return [dict(r) for r in rows]


def get_all_alerts() -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_alert_by_id(alert_id: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
    return dict(row) if row else None


def update_verdict(alert_id: str, verdict_data: dict) -> bool:
    with get_db() as conn:
        cur = conn.execute(
            """UPDATE alerts SET
                status = 'analysed',
                verdict = ?,
                confidence = ?,
                reasoning = ?,
                controls_found = ?,
                coverage_gaps = ?,
                recommended_action = ?,
                analysed_at = ?,
                tokens_used = ?,
                analysis_latency_ms = ?
               WHERE alert_id = ?""",
            (
                verdict_data["verdict"],
                verdict_data["confidence"],
                verdict_data["reasoning"],
                json.dumps(verdict_data.get("controls_found", [])),
                json.dumps(verdict_data.get("coverage_gaps", [])),
                verdict_data.get("recommended_action", ""),
                datetime.now(timezone.utc).isoformat(),
                verdict_data.get("tokens_used"),
                verdict_data.get("analysis_latency_ms"),
                alert_id,
            ),
        )
    return cur.rowcount > 0


def get_stats() -> dict:
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        pending = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='pending'").fetchone()[0]
        fp = conn.execute("SELECT COUNT(*) FROM alerts WHERE verdict='FALSE_POSITIVE'").fetchone()[0]
        tp = conn.execute("SELECT COUNT(*) FROM alerts WHERE verdict='TRUE_POSITIVE'").fetchone()[0]
        partial = conn.execute("SELECT COUNT(*) FROM alerts WHERE verdict='PARTIAL_RISK'").fetchone()[0]
        human = conn.execute("SELECT COUNT(*) FROM alerts WHERE verdict='NEEDS_HUMAN_REVIEW'").fetchone()[0]
    return {
        "total": total,
        "pending": pending,
        "false_positive": fp,
        "true_positive": tp,
        "partial_risk": partial,
        "needs_human_review": human,
        "analysed": total - pending,
    }
