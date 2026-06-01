"""
MCP Server — exposes FPM capabilities as MCP-compliant tools.

Uses the Anthropic MCP SDK. Usable by any MCP-compatible client (e.g. Claude Desktop).

Tools exposed:
  1. analyse_alert — accept alert data, return a verdict
  2. search_controls — retrieve relevant controls from the knowledge base for a query
"""
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from dotenv import load_dotenv

load_dotenv()

from mcp.server import Server
from mcp.server.stdio import run_server
from mcp.types import Tool, TextContent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy-initialised globals (loaded on first tool call)
# ---------------------------------------------------------------------------

_openai_client = None
_knowledge_store = None
_retriever = None
_reachability_analyzer = None


def _ensure_initialised():
    """Lazy-load the OpenAI client, knowledge base, retriever, and reachability analyzer."""
    global _openai_client, _knowledge_store, _retriever, _reachability_analyzer

    if _openai_client is not None:
        return

    from openai import OpenAI

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")

    _openai_client = OpenAI(api_key=api_key)

    from fpm.knowledge.builder import build_knowledge_base

    _knowledge_store = build_knowledge_base(_openai_client)

    from fpm.retrieval.hybrid_search import HybridRetriever

    _retriever = HybridRetriever(_knowledge_store)

    # Build reachability analyzer from Terraform configs
    from fpm.parsers.terraform_parser import parse_terraform
    from fpm.analysis.reachability import ReachabilityAnalyzer

    infra_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "infrastructure",
    )
    tf_dir = os.path.join(infra_dir, "terraform")
    tf_controls = []
    if os.path.isdir(tf_dir):
        for fname in sorted(os.listdir(tf_dir)):
            if fname.endswith(".tf"):
                tf_controls.extend(parse_terraform(os.path.join(tf_dir, fname)))
    _reachability_analyzer = ReachabilityAnalyzer(tf_controls)

    logger.info("MCP server: FPM components initialised (including reachability analyzer)")


# ---------------------------------------------------------------------------
# MCP Server definition
# ---------------------------------------------------------------------------

app = Server("fpm-mcp-server")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="analyse_alert",
            description=(
                "Analyse a security alert to determine if it is a false positive. "
                "Accepts alert data and returns a structured verdict with reasoning, "
                "confidence score, controls found, and recommended action."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "alert_id": {"type": "string", "description": "Unique alert identifier"},
                    "attack_type": {"type": "string", "description": "Attack classification (e.g. SQL_INJECTION, XSS)"},
                    "target_endpoint": {"type": "string", "description": "The API path that received the request"},
                    "http_method": {"type": "string", "description": "HTTP verb (GET, POST, etc.)"},
                    "severity": {"type": "string", "description": "LOW, MEDIUM, HIGH, or CRITICAL"},
                    "traceable_reason": {"type": "string", "description": "Why the alert was raised"},
                    "payload_snippet": {"type": "string", "description": "Brief excerpt of the observed payload"},
                    "source_ip": {"type": "string", "description": "Attacking client IP"},
                },
                "required": ["attack_type", "target_endpoint"],
            },
        ),
        Tool(
            name="search_controls",
            description=(
                "Search the infrastructure knowledge base for controls relevant to a query. "
                "Returns matching controls from WAF, Gateway, and Network layers."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Natural language query describing what controls to search for",
                    },
                    "top_k": {
                        "type": "integer",
                        "description": "Number of results to return (default 10)",
                        "default": 10,
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="analyse_reachability",
            description=(
                "Perform network reachability analysis on a target endpoint. "
                "Traces the full network path through security groups from source to target, "
                "determines whether the endpoint is internet-reachable, which security layers "
                "(WAF, ALB, Kong Gateway) traffic passes through vs bypasses, and assesses risk level."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target_endpoint": {
                        "type": "string",
                        "description": "The API path to analyse (e.g. /api/v1/graphql, /api/internal/analytics)",
                    },
                    "source_ip": {
                        "type": "string",
                        "description": "Optional source IP address to check specific reachability from",
                    },
                },
                "required": ["target_endpoint"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    _ensure_initialised()

    if name == "analyse_alert":
        return await _handle_analyse_alert(arguments)
    elif name == "search_controls":
        return await _handle_search_controls(arguments)
    elif name == "analyse_reachability":
        return await _handle_analyse_reachability(arguments)
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def _handle_analyse_alert(args: dict) -> list[TextContent]:
    """Run the full FPM analysis pipeline on an alert."""
    from fpm.agents.orchestrator import analyse_alert

    alert = {
        "alert_id": args.get("alert_id", "mcp-manual"),
        "attack_type": args.get("attack_type", ""),
        "target_endpoint": args.get("target_endpoint", ""),
        "http_method": args.get("http_method", "GET"),
        "severity": args.get("severity", "MEDIUM"),
        "traceable_reason": args.get("traceable_reason", ""),
        "payload_snippet": args.get("payload_snippet", ""),
        "source_ip": args.get("source_ip", "0.0.0.0"),
        "http_request": args.get("http_request", {}),
        "http_response": args.get("http_response", {}),
    }

    try:
        verdict = analyse_alert(
            alert, _openai_client, _retriever,
            reachability_analyzer=_reachability_analyzer,
        )
        return [TextContent(type="text", text=json.dumps(verdict, indent=2))]
    except Exception as e:
        logger.error("MCP analyse_alert failed: %s", e, exc_info=True)
        return [TextContent(type="text", text=json.dumps({"error": str(e)}))]


async def _handle_search_controls(args: dict) -> list[TextContent]:
    """Search the knowledge base for relevant controls."""
    query = args.get("query", "")
    top_k = args.get("top_k", 10)

    try:
        results = _retriever.retrieve(query, top_k=top_k)
        output = []
        for r in results:
            output.append({
                "control_id": r["chunk_id"],
                "text": r["text"][:500],
                "rerank_score": r.get("rerank_score", 0),
                "metadata": r.get("metadata", {}),
            })
        return [TextContent(type="text", text=json.dumps(output, indent=2))]
    except Exception as e:
        logger.error("MCP search_controls failed: %s", e, exc_info=True)
        return [TextContent(type="text", text=json.dumps({"error": str(e)}))]


async def _handle_analyse_reachability(args: dict) -> list[TextContent]:
    """Run reachability analysis on a target endpoint."""
    target_endpoint = args.get("target_endpoint", "")
    source_ip = args.get("source_ip")

    try:
        result = _reachability_analyzer.analyse_endpoint(
            target_endpoint=target_endpoint,
            source_ip=source_ip,
        )
        return [TextContent(
            type="text",
            text=_reachability_analyzer.to_json(result),
        )]
    except Exception as e:
        logger.error("MCP analyse_reachability failed: %s", e, exc_info=True)
        return [TextContent(type="text", text=json.dumps({"error": str(e)}))]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )
    logger.info("Starting FPM MCP server...")
    await run_server(app)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
