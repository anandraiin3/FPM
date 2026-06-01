"""
Orchestrator agent — receives an alert, delegates to specialists,
synthesises findings, and produces a verdict.

Uses OpenAI Agents SDK with async tool functions to avoid nested event loop issues.
"""
import asyncio
import json
import logging
import time

from agents import Agent, Runner, function_tool, RunContextWrapper, trace
from agents.tracing import generation_span, custom_span

from fpm.agents.specialists import (
    WAF_AGENT,
    KONG_AGENT,
    NETWORK_AGENT,
    SpecialistContext,
)
from fpm.retrieval.query_rewriter import rewrite_query

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Orchestrator context
# ---------------------------------------------------------------------------

class OrchestratorContext:
    """Runtime context for the orchestrator run."""

    def __init__(self, openai_client, retriever, alert: dict, reachability_analyzer=None):
        self.openai_client = openai_client
        self.retriever = retriever
        self.alert = alert
        self.reachability_analyzer = reachability_analyzer
        self.rewritten_query: str = ""
        self.specialist_results: dict[str, str] = {}
        self.total_tokens: int = 0


# ---------------------------------------------------------------------------
# Tools for the orchestrator (async to avoid nested event loop)
# ---------------------------------------------------------------------------

@function_tool
async def analyse_waf_layer(
    ctx: RunContextWrapper[OrchestratorContext],
    alert_summary: str,
) -> str:
    """Delegate analysis to the WAF Specialist (NGINX + ModSecurity).
    The specialist will search the knowledge base and return findings.

    Args:
        alert_summary: Brief summary of the alert for the specialist
    """
    oc = ctx.context
    specialist_ctx = SpecialistContext(oc.retriever, oc.rewritten_query, oc.alert)

    prompt = (
        f"Analyse this alert for WAF-layer mitigations.\n\n"
        f"Alert: {alert_summary}\n"
        f"Rewritten search query: {oc.rewritten_query}\n\n"
        f"Attack type: {oc.alert.get('attack_type', '')}\n"
        f"Target endpoint: {oc.alert.get('target_endpoint', '')}\n"
        f"HTTP method: {oc.alert.get('http_method', '')}\n"
        f"Payload: {oc.alert.get('payload_snippet', '')}"
    )

    with custom_span("waf_specialist"):
        result = await Runner.run(WAF_AGENT, input=prompt, context=specialist_ctx)
    oc.specialist_results["waf"] = result.final_output
    return result.final_output


@function_tool
async def analyse_gateway_layer(
    ctx: RunContextWrapper[OrchestratorContext],
    alert_summary: str,
) -> str:
    """Delegate analysis to the Kong Gateway Specialist.
    The specialist will search the knowledge base and return findings.

    Args:
        alert_summary: Brief summary of the alert for the specialist
    """
    oc = ctx.context
    specialist_ctx = SpecialistContext(oc.retriever, oc.rewritten_query, oc.alert)

    prompt = (
        f"Analyse this alert for Gateway-layer mitigations.\n\n"
        f"Alert: {alert_summary}\n"
        f"Rewritten search query: {oc.rewritten_query}\n\n"
        f"Attack type: {oc.alert.get('attack_type', '')}\n"
        f"Target endpoint: {oc.alert.get('target_endpoint', '')}\n"
        f"HTTP method: {oc.alert.get('http_method', '')}\n"
        f"Payload: {oc.alert.get('payload_snippet', '')}"
    )

    with custom_span("kong_specialist"):
        result = await Runner.run(KONG_AGENT, input=prompt, context=specialist_ctx)
    oc.specialist_results["gateway"] = result.final_output
    return result.final_output


@function_tool
async def analyse_network_layer(
    ctx: RunContextWrapper[OrchestratorContext],
    alert_summary: str,
) -> str:
    """Delegate analysis to the Network Specialist (Terraform SGs, NACLs, WAF ACLs).
    The specialist will search the knowledge base, perform REACHABILITY ANALYSIS
    to trace the network path from source to target, and return findings including
    whether the endpoint is internet-reachable and which security layers are bypassed.

    Args:
        alert_summary: Brief summary of the alert for the specialist
    """
    oc = ctx.context
    specialist_ctx = SpecialistContext(
        oc.retriever, oc.rewritten_query, oc.alert,
        reachability_analyzer=oc.reachability_analyzer,
    )

    prompt = (
        f"Analyse this alert for Network-layer mitigations and REACHABILITY.\n\n"
        f"Alert: {alert_summary}\n"
        f"Rewritten search query: {oc.rewritten_query}\n\n"
        f"Attack type: {oc.alert.get('attack_type', '')}\n"
        f"Target endpoint: {oc.alert.get('target_endpoint', '')}\n"
        f"HTTP method: {oc.alert.get('http_method', '')}\n"
        f"Source IP: {oc.alert.get('source_ip', '')}\n\n"
        f"IMPORTANT: You MUST call analyse_reachability with the target endpoint "
        f"and source IP to trace the full network path and determine which security "
        f"layers the traffic passes through vs. bypasses."
    )

    with custom_span("network_specialist"):
        result = await Runner.run(NETWORK_AGENT, input=prompt, context=specialist_ctx)
    oc.specialist_results["network"] = result.final_output
    return result.final_output


# ---------------------------------------------------------------------------
# Orchestrator agent definition
# ---------------------------------------------------------------------------

ORCHESTRATOR_AGENT = Agent(
    name="FPM Orchestrator",
    model="gpt-4o-mini",
    instructions="""You are the False Positive Minimizer orchestrator. Your job is to determine whether a security alert is a genuine threat or a false positive.

You have three specialist tools at your disposal — one for each infrastructure layer:
1. analyse_waf_layer — checks NGINX rate limits and ModSecurity rules
2. analyse_gateway_layer — checks Kong Gateway plugins and route configurations
3. analyse_network_layer — checks Terraform security groups, NACLs, WAF associations AND performs REACHABILITY ANALYSIS

The Network Specialist now performs reachability analysis that traces the full network path from the source IP to the target endpoint. This tells you:
- Whether the endpoint is reachable from the internet
- Which security layers (WAF, ALB, Kong Gateway) traffic passes through
- Which layers are BYPASSED (critical for true positive detection)
- The risk level based on network exposure

PROCESS:
1. Call ALL THREE specialist tools with a summary of the alert.
2. Pay special attention to the Network Specialist's REACHABILITY findings:
   - If layers are bypassed, controls in those layers DON'T APPLY even if they exist
   - If the endpoint bypasses Kong Gateway, gateway-layer plugins are IRRELEVANT
   - If the endpoint bypasses the ALB, WAF rules are IRRELEVANT
3. Synthesise findings from all three layers, weighted by actual reachability.
4. Return your final verdict as a JSON object.

VERDICT RULES:
- FALSE_POSITIVE: At least one compensating control in the ACTUAL traffic path fully mitigates the threat. Confidence 0.8-1.0.
- TRUE_POSITIVE: No compensating control exists in the actual traffic path. The threat is genuine. Confidence 0.8-1.0. This includes cases where controls exist but are BYPASSED due to network misconfiguration.
- PARTIAL_RISK: Controls exist in the traffic path but don't fully cover the threat. Include coverage_gaps. Confidence 0.5-0.8.
- NEEDS_HUMAN_REVIEW: Insufficient evidence. Confidence below 0.5.

Your final response MUST be a valid JSON object with exactly these fields:
{
  "verdict": "FALSE_POSITIVE|TRUE_POSITIVE|PARTIAL_RISK|NEEDS_HUMAN_REVIEW",
  "confidence": 0.0-1.0,
  "reasoning": "explanation",
  "controls_found": ["list", "of", "control", "IDs"],
  "coverage_gaps": ["list", "of", "gaps"],
  "recommended_action": "what to do next",
  "reachability": {
    "internet_reachable": true/false,
    "risk_level": "LOW/MEDIUM/HIGH/CRITICAL",
    "traffic_path": "Internet -> ALB SG -> Kong SG -> Service SG",
    "layers_bypassed": ["list of bypassed layers"]
  }
}

IMPORTANT: Always call all three specialist tools before making your verdict. Do not skip any layer.""",
    tools=[analyse_waf_layer, analyse_gateway_layer, analyse_network_layer],
)


# ---------------------------------------------------------------------------
# Public function: analyse a single alert
# ---------------------------------------------------------------------------

def analyse_alert(
    alert: dict,
    openai_client,
    retriever,
    reachability_analyzer=None,
) -> dict:
    """
    Analyse a single alert through the multi-agent system.

    Args:
        alert: The alert dict from the mock server.
        openai_client: OpenAI client instance.
        retriever: HybridRetriever for knowledge base search.
        reachability_analyzer: Optional ReachabilityAnalyzer for network path tracing.

    Returns a verdict dict ready to POST to the mock server.
    """
    alert_id = alert.get("alert_id", "unknown")
    start_time = time.time()

    # Run the async orchestrator in a new event loop to avoid conflicts
    result_data = _run_orchestrator(alert, openai_client, retriever, reachability_analyzer)

    elapsed_ms = int((time.time() - start_time) * 1000)

    result_data["analysis_latency_ms"] = elapsed_ms

    logger.info(
        "Alert %s → %s (confidence=%.2f, latency=%dms)",
        alert_id, result_data["verdict"], result_data["confidence"], elapsed_ms,
    )
    return result_data


def _run_orchestrator(alert: dict, openai_client, retriever, reachability_analyzer=None) -> dict:
    """Run the orchestrator in a fresh event loop."""
    alert_id = alert.get("alert_id", "unknown")

    async def _async_run():
        with trace(f"fpm-alert-{alert_id}"):
            # Step 1: Rewrite query
            with custom_span("query_rewrite"):
                rewritten_query = rewrite_query(alert, openai_client)

            # Step 2: Run orchestrator
            oc = OrchestratorContext(
                openai_client, retriever, alert,
                reachability_analyzer=reachability_analyzer,
            )
            oc.rewritten_query = rewritten_query

            alert_prompt = (
                f"Analyse this security alert and determine if it is a false positive.\n\n"
                f"Alert ID: {alert.get('alert_id', '')}\n"
                f"Attack Type: {alert.get('attack_type', '')}\n"
                f"Target Endpoint: {alert.get('target_endpoint', '')}\n"
                f"HTTP Method: {alert.get('http_method', '')}\n"
                f"Severity: {alert.get('severity', '')}\n"
                f"Source IP: {alert.get('source_ip', '')}\n"
                f"Traceable Reason: {alert.get('traceable_reason', '')}\n"
                f"Payload: {alert.get('payload_snippet', '')}\n"
                f"HTTP Response Status: {_get_response_status(alert)}\n\n"
                f"Optimised retrieval query: {rewritten_query}"
            )

            with custom_span("orchestrator_run"):
                result = await Runner.run(
                    ORCHESTRATOR_AGENT,
                    input=alert_prompt,
                    context=oc,
                )

            # Parse the orchestrator's final output as JSON
            verdict_data = _parse_verdict(result.final_output, alert_id)
            verdict_data["tokens_used"] = _estimate_tokens(result)
            return verdict_data

    # Create a new event loop for each alert to avoid conflicts
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_async_run())
    finally:
        loop.close()


def _get_response_status(alert: dict) -> str:
    """Extract HTTP response status code from alert."""
    http_response = alert.get("http_response", {})
    if isinstance(http_response, str):
        try:
            http_response = json.loads(http_response)
        except (json.JSONDecodeError, TypeError):
            return "unknown"
    return str(http_response.get("status_code", "unknown"))


def _parse_verdict(raw_output: str, alert_id: str) -> dict:
    """Parse the orchestrator's JSON output into a verdict dict."""
    # Try to extract JSON from the output
    text = raw_output.strip()

    # Strip markdown code fences if present
    if "```json" in text:
        text = text.split("```json", 1)[1]
        if "```" in text:
            text = text.split("```", 1)[0]
    elif "```" in text:
        text = text.split("```", 1)[1]
        if "```" in text:
            text = text.split("```", 1)[0]

    text = text.strip()

    try:
        data = json.loads(text)
        return {
            "verdict": data.get("verdict", "NEEDS_HUMAN_REVIEW"),
            "confidence": float(data.get("confidence", 0.5)),
            "reasoning": data.get("reasoning", ""),
            "controls_found": data.get("controls_found", []),
            "coverage_gaps": data.get("coverage_gaps", []),
            "recommended_action": data.get("recommended_action", ""),
        }
    except (json.JSONDecodeError, TypeError) as e:
        logger.error("Failed to parse verdict JSON for alert %s: %s", alert_id, e)
        logger.debug("Raw output: %s", raw_output[:500])
        return {
            "verdict": "NEEDS_HUMAN_REVIEW",
            "confidence": 0.3,
            "reasoning": f"Orchestrator output could not be parsed as JSON. Raw: {raw_output[:300]}",
            "controls_found": [],
            "coverage_gaps": ["Verdict parsing failed"],
            "recommended_action": "Manual review required — automated analysis produced unparseable output",
        }


def _estimate_tokens(result) -> int:
    """Estimate total tokens used across the run. Best-effort."""
    try:
        total = 0
        if hasattr(result, "raw_responses"):
            for resp in result.raw_responses:
                if hasattr(resp, "usage") and resp.usage:
                    total += resp.usage.total_tokens
        return total if total > 0 else 0
    except Exception:
        return 0
