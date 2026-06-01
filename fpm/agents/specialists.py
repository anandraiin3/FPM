"""
Specialist agents — WAF, Kong Gateway, and Network.

Each specialist is an OpenAI Agents SDK Agent with a tool that queries
the knowledge base for controls in its layer.
"""
import json
import logging

from agents import Agent, function_tool, RunContextWrapper

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared context dataclass for specialist runs
# ---------------------------------------------------------------------------

class SpecialistContext:
    """Runtime context passed to specialist tool functions."""

    def __init__(self, retriever, rewritten_query: str, alert: dict, reachability_analyzer=None):
        self.retriever = retriever
        self.rewritten_query = rewritten_query
        self.alert = alert
        self.reachability_analyzer = reachability_analyzer


# ---------------------------------------------------------------------------
# Tool: search the knowledge base
# ---------------------------------------------------------------------------

@function_tool
def search_waf_controls(
    ctx: RunContextWrapper[SpecialistContext],
    query: str,
) -> str:
    """Search the knowledge base for WAF-layer controls (NGINX rate limits, ModSecurity rules).
    Use the provided query to find controls relevant to the alert.

    Args:
        query: Search query describing what WAF controls to look for
    """
    results = ctx.context.retriever.retrieve(query, top_k=8)
    waf_results = [r for r in results if r.get("metadata", {}).get("layer", "") == "WAF"]
    if not waf_results:
        waf_results = results[:5]  # fallback to all results if no WAF-specific

    return json.dumps([{
        "control_id": r["chunk_id"],
        "text": r["text"][:800],
        "rerank_score": r.get("rerank_score", 0),
    } for r in waf_results], indent=2)


@function_tool
def search_gateway_controls(
    ctx: RunContextWrapper[SpecialistContext],
    query: str,
) -> str:
    """Search the knowledge base for Gateway-layer controls (Kong plugins, routes, services).
    Use the provided query to find controls relevant to the alert.

    Args:
        query: Search query describing what Gateway controls to look for
    """
    results = ctx.context.retriever.retrieve(query, top_k=8)
    gw_results = [r for r in results if r.get("metadata", {}).get("layer", "") == "Gateway"]
    if not gw_results:
        gw_results = results[:5]

    return json.dumps([{
        "control_id": r["chunk_id"],
        "text": r["text"][:800],
        "rerank_score": r.get("rerank_score", 0),
    } for r in gw_results], indent=2)


@function_tool
def search_network_controls(
    ctx: RunContextWrapper[SpecialistContext],
    query: str,
) -> str:
    """Search the knowledge base for Network-layer controls (Terraform security groups, NACLs, WAF ACLs).
    Use the provided query to find controls relevant to the alert.

    Args:
        query: Search query describing what Network controls to look for
    """
    results = ctx.context.retriever.retrieve(query, top_k=8)
    net_results = [r for r in results if r.get("metadata", {}).get("layer", "") == "Network"]
    if not net_results:
        net_results = results[:5]

    return json.dumps([{
        "control_id": r["chunk_id"],
        "text": r["text"][:800],
        "rerank_score": r.get("rerank_score", 0),
    } for r in net_results], indent=2)


@function_tool
def analyse_reachability(
    ctx: RunContextWrapper[SpecialistContext],
    target_endpoint: str,
    source_ip: str = "",
) -> str:
    """Perform reachability analysis on a target endpoint to determine if it is
    accessible from the internet or specific sources. Traces the full network path
    through security groups, identifying which security layers (WAF, ALB, Kong Gateway)
    traffic passes through and which are bypassed.

    Args:
        target_endpoint: The API path to analyse (e.g. /api/v1/graphql, /api/internal/analytics)
        source_ip: Optional source IP address to check specific reachability from
    """
    analyzer = ctx.context.reachability_analyzer
    if analyzer is None:
        return json.dumps({
            "error": "Reachability analyzer not available",
            "summary": "Cannot perform reachability analysis — Terraform controls not loaded",
        })

    result = analyzer.analyse_endpoint(
        target_endpoint=target_endpoint,
        source_ip=source_ip if source_ip else None,
    )
    return analyzer.to_json(result)


# ---------------------------------------------------------------------------
# Specialist agent definitions
# ---------------------------------------------------------------------------

_SPECIALIST_INSTRUCTIONS_BASE = """You are a security infrastructure specialist. Your job is to analyse whether infrastructure controls in your layer mitigate the threat described in an alert.

You will be given an alert and must search the knowledge base for relevant controls using the provided tool. Then analyse whether the controls you find would block, limit, or mitigate the attack.

Return your findings as a structured JSON object with:
- "controls_found": list of control IDs that are relevant
- "mitigates": true/false — whether these controls fully mitigate the threat
- "reasoning": brief explanation of how the controls address (or fail to address) the threat
- "gaps": list of any coverage gaps you identified

Always search the knowledge base using the tool — do not guess about controls."""


WAF_AGENT = Agent(
    name="WAF Specialist",
    model="gpt-4o-mini",
    instructions=_SPECIALIST_INSTRUCTIONS_BASE + """

Your scope: NGINX configuration and ModSecurity rules ONLY.
You must determine whether any WAF rule or NGINX directive blocks, limits, or transforms the request described in the alert.
Focus on: rate limiting zones, location blocks, ModSecurity CRS rules, custom SecRules, body size limits, timeout settings.""",
    tools=[search_waf_controls],
)


KONG_AGENT = Agent(
    name="Kong Gateway Specialist",
    model="gpt-4o-mini",
    instructions=_SPECIALIST_INSTRUCTIONS_BASE + """

Your scope: Kong Gateway services, routes, and plugins ONLY.
You must determine whether any Kong plugin (jwt, rate-limiting, ip-restriction, request-validator, bot-detection, request-transformer, oauth2, request-size-limiting, acl, key-auth) on the relevant route mitigates the alert.
Focus on: which service/route handles the endpoint in the alert, and what plugins are applied to that route.""",
    tools=[search_gateway_controls],
)


NETWORK_AGENT = Agent(
    name="Network Specialist",
    model="gpt-4o-mini",
    instructions=_SPECIALIST_INSTRUCTIONS_BASE + """

Your scope: Terraform security groups, NACLs, WAF rule group associations, and NETWORK REACHABILITY analysis.

You have TWO tools:
1. search_network_controls — searches the knowledge base for security groups, NACLs, WAF ACLs
2. analyse_reachability — performs reachability analysis on a target endpoint

You MUST call analyse_reachability with the alert's target_endpoint and source_ip to determine:
- Whether the endpoint is reachable from the internet
- Which security layers (WAF, ALB, Kong) traffic passes through to reach it
- Which layers are BYPASSED (this is critical for identifying true positives)
- What the full network path looks like (e.g. Internet -> ALB SG -> Kong SG -> Service SG)
- The risk level based on exposure

After reachability analysis, also search for specific network controls relevant to the alert.

Your findings JSON must include an additional field:
- "reachability": object with is_internet_reachable, risk_level, path_description, layers_bypassed

This reachability analysis is essential — a service that bypasses Kong Gateway has NO auth/rate-limit protection at the gateway layer, and a service that bypasses the ALB has NO WAF protection.""",
    tools=[search_network_controls, analyse_reachability],
)
