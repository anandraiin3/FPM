"""
Polling loop — continuously polls the Traceable Mock Server for pending alerts,
analyses each one through the multi-agent system, and posts verdicts back.

Handles network failures gracefully and retries without crashing.
"""
import json
import logging
import os
import time

import httpx

from fpm.agents.orchestrator import analyse_alert

logger = logging.getLogger(__name__)

DEFAULT_POLL_INTERVAL = 30  # seconds
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds


class FPMPoller:
    """Polls the mock server for pending alerts and processes them."""

    def __init__(
        self,
        openai_client,
        retriever,
        base_url: str | None = None,
        poll_interval: int | None = None,
        max_alerts: int | None = None,
    ):
        self._openai = openai_client
        self._retriever = retriever
        self._base_url = (
            base_url
            or os.getenv("TRACEABLE_BASE_URL", "http://localhost:8000")
        ).rstrip("/")
        self._poll_interval = (
            poll_interval
            or int(os.getenv("FPM_POLL_INTERVAL_SECONDS", str(DEFAULT_POLL_INTERVAL)))
        )
        self._http = httpx.Client(timeout=30.0)
        self._running = True
        self._max_alerts = max_alerts
        self._processed_count = 0

    def run(self) -> None:
        """Main polling loop. Runs until stopped."""
        logger.info(
            "FPM poller started (server=%s, interval=%ds)",
            self._base_url, self._poll_interval,
        )

        while self._running:
            try:
                self._poll_and_process()
            except KeyboardInterrupt:
                logger.info("Poller stopped by user")
                break
            except Exception as e:
                logger.error("Unexpected error in polling loop: %s", e, exc_info=True)

            if self._running:
                time.sleep(self._poll_interval)

    def stop(self) -> None:
        """Signal the poller to stop after the current iteration."""
        self._running = False
        logger.info("Poller stop requested")

    def _poll_and_process(self) -> None:
        """Fetch pending alerts and process each one."""
        alerts = self._fetch_pending_alerts()

        if not alerts:
            logger.debug("No pending alerts found")
            return

        logger.info("Found %d pending alert(s)", len(alerts))

        for alert in alerts:
            # Check if we've hit the max alerts limit
            if self._max_alerts is not None and self._processed_count >= self._max_alerts:
                logger.info("Reached max_alerts limit (%d), stopping", self._max_alerts)
                self._running = False
                return

            alert_id = alert.get("alert_id", "unknown")
            try:
                logger.info("Processing alert %s (%s → %s)",
                            alert_id, alert.get("attack_type"), alert.get("target_endpoint"))

                verdict = analyse_alert(alert, self._openai, self._retriever)
                self._post_verdict(alert_id, verdict)
                self._processed_count += 1

                logger.info(
                    "Verdict posted for %s: %s (confidence=%.2f) [%d/%s processed]",
                    alert_id, verdict["verdict"], verdict["confidence"],
                    self._processed_count,
                    str(self._max_alerts) if self._max_alerts else "∞",
                )

            except Exception as e:
                logger.error(
                    "Failed to process alert %s: %s", alert_id, e, exc_info=True,
                )
                # Continue with the next alert — don't crash the loop

    def _fetch_pending_alerts(self) -> list[dict]:
        """Fetch pending alerts from the mock server with retry."""
        for attempt in range(MAX_RETRIES):
            try:
                resp = self._http.get(f"{self._base_url}/alerts")
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPStatusError as e:
                logger.warning("HTTP error fetching alerts (attempt %d/%d): %s",
                               attempt + 1, MAX_RETRIES, e)
            except httpx.RequestError as e:
                logger.warning("Network error fetching alerts (attempt %d/%d): %s",
                               attempt + 1, MAX_RETRIES, e)
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
        logger.error("Failed to fetch alerts after %d retries", MAX_RETRIES)
        return []

    def _post_verdict(self, alert_id: str, verdict: dict) -> None:
        """Post a verdict to the mock server with retry."""
        payload = {
            "verdict": verdict["verdict"],
            "confidence": verdict["confidence"],
            "reasoning": verdict["reasoning"],
            "controls_found": verdict.get("controls_found", []),
            "coverage_gaps": verdict.get("coverage_gaps", []),
            "recommended_action": verdict.get("recommended_action", ""),
            "tokens_used": verdict.get("tokens_used"),
            "analysis_latency_ms": verdict.get("analysis_latency_ms"),
        }

        for attempt in range(MAX_RETRIES):
            try:
                resp = self._http.post(
                    f"{self._base_url}/alerts/{alert_id}/verdict",
                    json=payload,
                )
                resp.raise_for_status()
                return
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 409:
                    logger.info("Alert %s already analysed (409), skipping", alert_id)
                    return
                logger.warning("HTTP error posting verdict (attempt %d/%d): %s",
                               attempt + 1, MAX_RETRIES, e)
            except httpx.RequestError as e:
                logger.warning("Network error posting verdict (attempt %d/%d): %s",
                               attempt + 1, MAX_RETRIES, e)
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
        logger.error("Failed to post verdict for %s after %d retries", alert_id, MAX_RETRIES)
