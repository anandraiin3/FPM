"""
Query rewriter — transforms a raw alert into an optimised retrieval query.

Results are cached per alert_id so all three specialist agents reuse the
same rewritten query (no redundant LLM calls).
"""
import json
import logging

from openai import OpenAI

logger = logging.getLogger(__name__)

_REWRITE_PROMPT = """You are an expert at converting security alerts into search queries for an infrastructure control knowledge base.

Given the following security alert, write an optimised search query that will find relevant infrastructure controls (WAF rules, NGINX rate limits, ModSecurity rules, Kong Gateway plugins, Terraform security groups) that might mitigate this threat.

The query should include:
- The attack type and its variants
- The target endpoint/path
- Relevant HTTP method
- Keywords about the compensating controls that would block this attack
- Infrastructure layers to search (WAF, Gateway, Network)

Alert:
{alert_json}

Respond with ONLY the search query text (no JSON, no explanation). Keep it under 200 words."""

# Cache: alert_id → rewritten query
_query_cache: dict[str, str] = {}


def rewrite_query(
    alert: dict,
    openai_client: OpenAI,
    model: str = "gpt-4o-mini",
) -> str:
    """
    Rewrite an alert into an optimised retrieval query.
    Cached per alert_id.
    """
    alert_id = alert.get("alert_id", "")
    if alert_id in _query_cache:
        logger.debug("Query cache hit for alert %s", alert_id)
        return _query_cache[alert_id]

    # Build a concise alert summary for the prompt
    alert_summary = {
        "attack_type": alert.get("attack_type", ""),
        "target_endpoint": alert.get("target_endpoint", ""),
        "http_method": alert.get("http_method", ""),
        "severity": alert.get("severity", ""),
        "traceable_reason": alert.get("traceable_reason", ""),
        "payload_snippet": alert.get("payload_snippet", ""),
    }

    prompt = _REWRITE_PROMPT.format(alert_json=json.dumps(alert_summary, indent=2))

    response = openai_client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.0,
        max_tokens=300,
    )
    rewritten = response.choices[0].message.content.strip()
    tokens = response.usage.total_tokens if response.usage else 0

    _query_cache[alert_id] = rewritten
    logger.info("Rewrote query for alert %s (%d tokens): %s...", alert_id, tokens, rewritten[:80])
    return rewritten


def get_cached_query(alert_id: str) -> str | None:
    """Return the cached rewritten query for an alert, if available."""
    return _query_cache.get(alert_id)


def clear_cache() -> None:
    """Clear the query cache."""
    _query_cache.clear()
