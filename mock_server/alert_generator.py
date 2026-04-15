"""
Alert generator — creates alerts from templates on a schedule.

- Generates a batch of alerts every invocation (called hourly by APScheduler).
- Maintains 95% false-positive / 5% true-positive distribution.
- Idempotent: uses template_id + batch timestamp to derive alert_id, so
  restarting the server never duplicates alerts.
"""
import hashlib
import logging
import random
from datetime import datetime, timezone

from mock_server.alert_templates import FALSE_POSITIVE_TEMPLATES, TRUE_POSITIVE_TEMPLATES
from mock_server.database import insert_alert

logger = logging.getLogger(__name__)

# How many alerts per batch (each hourly tick)
BATCH_SIZE = 21


def _make_alert_id(template_id: str, batch_key: str) -> str:
    """Deterministic alert ID from template + batch key for idempotency."""
    raw = f"{template_id}::{batch_key}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def _random_source_ip(base_ip: str) -> str:
    """Slightly randomise the last octet of the source IP for realism."""
    parts = base_ip.rsplit(".", 1)
    return f"{parts[0]}.{random.randint(1, 254)}"


def generate_batch() -> int:
    """
    Generate one batch of alerts.  Returns count of newly inserted alerts.

    Distribution logic:
    - Pick 20 false-positive templates (all of them) and 1 true-positive template.
    - This gives exactly 20/21 ≈ 95% FP and 1/21 ≈ 5% TP per batch.
    """
    now = datetime.now(timezone.utc)
    batch_key = now.strftime("%Y-%m-%dT%H")  # one batch per hour

    selected = list(FALSE_POSITIVE_TEMPLATES) + list(TRUE_POSITIVE_TEMPLATES)
    random.shuffle(selected)

    count = 0
    for tmpl in selected:
        alert_id = _make_alert_id(tmpl["template_id"], batch_key)
        alert = {
            "alert_id": alert_id,
            "timestamp": now.isoformat(),
            "source_ip": _random_source_ip(tmpl["source_ip"]),
            "target_endpoint": tmpl["target_endpoint"],
            "http_method": tmpl["http_method"],
            "attack_type": tmpl["attack_type"],
            "traceable_reason": tmpl["traceable_reason"],
            "payload_snippet": tmpl["payload_snippet"],
            "severity": tmpl["severity"],
            "http_request": tmpl["http_request"],
            "http_response": tmpl["http_response"],
            "template_id": tmpl["template_id"],
        }
        try:
            insert_alert(alert)
            count += 1
        except Exception:
            # INSERT OR IGNORE handles duplicates; log anything else
            logger.debug("Alert %s already exists or insert failed", alert_id)

    logger.info("Generated %d alerts (batch_key=%s)", count, batch_key)
    return count
