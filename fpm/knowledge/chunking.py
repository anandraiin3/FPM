"""
Chunking strategies for infrastructure control records.

Three distinct strategies are applied (stored in separate ChromaDB collections):
  1. per_control  — one chunk per parsed control record (finest granularity)
  2. per_layer    — controls grouped by infrastructure layer (WAF / Gateway / Network)
  3. per_attack   — controls grouped by the attack types they mitigate (after enrichment)
"""
import json
import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Strategy 1: Per-control chunks
# ---------------------------------------------------------------------------

def chunk_per_control(controls: list[dict]) -> list[dict]:
    """One chunk per control. Preserves full context of each control."""
    chunks = []
    for ctrl in controls:
        text = _control_to_text(ctrl)
        chunks.append({
            "chunk_id": ctrl["control_id"],
            "strategy": "per_control",
            "text": text,
            "metadata": {
                "control_id": ctrl["control_id"],
                "control_type": ctrl["control_type"],
                "layer": ctrl["layer"],
                "source_file": ctrl["source_file"],
            },
        })
    return chunks


# ---------------------------------------------------------------------------
# Strategy 2: Per-layer chunks
# ---------------------------------------------------------------------------

def chunk_per_layer(controls: list[dict]) -> list[dict]:
    """Group controls by layer and produce one chunk per layer."""
    layer_map: dict[str, list[dict]] = {}
    for ctrl in controls:
        layer_map.setdefault(ctrl["layer"], []).append(ctrl)

    chunks = []
    for layer, ctrls in layer_map.items():
        parts = [f"=== {layer} Layer Controls ===\n"]
        for ctrl in ctrls:
            parts.append(f"--- {ctrl['control_id']} ({ctrl['control_type']}) ---")
            parts.append(_control_to_text(ctrl))
            parts.append("")
        text = "\n".join(parts)
        chunks.append({
            "chunk_id": f"layer:{layer}",
            "strategy": "per_layer",
            "text": text,
            "metadata": {
                "layer": layer,
                "control_count": len(ctrls),
                "control_ids": [c["control_id"] for c in ctrls],
            },
        })
    return chunks


# ---------------------------------------------------------------------------
# Strategy 3: Per-attack-type chunks (built after enrichment)
# ---------------------------------------------------------------------------

def chunk_per_attack_type(enriched_chunks: list[dict]) -> list[dict]:
    """
    Re-group enriched chunks by the attack types they mitigate.
    Requires enrichment annotations to be present.
    """
    attack_map: dict[str, list[dict]] = {}
    for chunk in enriched_chunks:
        mitigates = chunk.get("enrichment", {}).get("mitigates", "")
        # An enriched chunk may mitigate multiple attack types (comma-separated)
        attack_types = [t.strip().upper() for t in mitigates.split(",") if t.strip()]
        if not attack_types:
            attack_types = ["UNKNOWN"]
        for at in attack_types:
            attack_map.setdefault(at, []).append(chunk)

    chunks = []
    for attack_type, related in attack_map.items():
        parts = [f"=== Controls mitigating {attack_type} ===\n"]
        for ch in related:
            parts.append(f"--- {ch['chunk_id']} ---")
            parts.append(ch["text"])
            enrichment = ch.get("enrichment", {})
            if enrichment:
                parts.append(f"  MITIGATES: {enrichment.get('mitigates', '')}")
                parts.append(f"  LAYER: {enrichment.get('layer', '')}")
                parts.append(f"  DOES NOT COVER: {enrichment.get('does_not_cover', '')}")
            parts.append("")
        text = "\n".join(parts)
        chunks.append({
            "chunk_id": f"attack:{attack_type}",
            "strategy": "per_attack_type",
            "text": text,
            "metadata": {
                "attack_type": attack_type,
                "control_count": len(related),
                "control_ids": [c["chunk_id"] for c in related],
            },
        })
    return chunks


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _control_to_text(ctrl: dict) -> str:
    """Convert a parsed control record into a human-readable text chunk."""
    meta = ctrl.get("metadata", {})
    lines = [
        f"Control: {ctrl['control_id']}",
        f"Type: {ctrl['control_type']}",
        f"Layer: {ctrl['layer']}",
        f"Source: {ctrl['source_file']}",
    ]
    # Add key metadata fields
    for key, val in meta.items():
        if key in ("resource_name", "name", "description"):
            lines.append(f"{key}: {val}")
        elif isinstance(val, (list, dict)):
            lines.append(f"{key}: {json.dumps(val, indent=2)}")
        else:
            lines.append(f"{key}: {val}")

    lines.append(f"\nRaw configuration:\n{ctrl.get('raw_block', '')}")
    return "\n".join(lines)
