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

    def __init__(self, retriever, rewritten_query: str, alert: dict):
        self.retriever = retriever
        self.rewritten_query = rewritten_query
        self.alert = alert


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

Your scope: Terraform security groups, NACLs, and WAF rule group associations ONLY.
You must determine whether network-level controls (IP restrictions, ingress/egress rules, CIDR blocks, WAF associations) prevent the threat described in the alert.
Focus on: which security group governs the target service, whether the source IP is allowed/denied, and whether WAF rules are associated.""",
    tools=[search_network_controls],
)
