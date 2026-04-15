"""
LLM enrichment — annotates each chunk with structured security metadata
before embedding.

Annotations added:
  - MITIGATES: what attack types this control mitigates
  - LAYER: which infrastructure layer (WAF / Gateway / Network)
  - DOES NOT COVER: known gaps
"""
import json
import logging

from openai import OpenAI

logger = logging.getLogger(__name__)

_ENRICHMENT_PROMPT = """You are a security infrastructure analyst. Given the following infrastructure control configuration chunk, provide structured annotations.

CHUNK:
{chunk_text}

Respond with ONLY a JSON object (no markdown, no explanation) with these fields:
- "mitigates": comma-separated list of attack types this control mitigates (use standard names like SQL_INJECTION, XSS, RATE_ABUSE, CREDENTIAL_STUFFING, PATH_TRAVERSAL, COMMAND_INJECTION, SSRF, BRUTE_FORCE, BOT_TRAFFIC, BOLA, MISSING_AUTHENTICATION, INADEQUATE_AUTHENTICATION, UNAUTHORIZED_ACCESS, API_KEY_EXPOSURE, OVERSIZED_PAYLOAD, SENSITIVE_DATA_EXPOSURE, XML_INJECTION, HTTP_VERB_TAMPERING, DOS_REGEX)
- "layer": one of "WAF", "Gateway", "Network"
- "does_not_cover": known gaps or attack variants this control does NOT protect against
"""


def enrich_chunks(
    chunks: list[dict],
    openai_client: OpenAI,
    model: str = "gpt-4o-mini",
) -> list[dict]:
    """
    Enrich each chunk with LLM-generated security annotations.
    Mutates chunks in place and returns them.
    """
    total_tokens = 0
    for i, chunk in enumerate(chunks):
        try:
            prompt = _ENRICHMENT_PROMPT.format(chunk_text=chunk["text"][:3000])
            response = openai_client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=500,
            )
            raw = response.choices[0].message.content.strip()
            total_tokens += response.usage.total_tokens if response.usage else 0

            # Parse JSON response
            # Strip markdown code fences if present
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
                if raw.endswith("```"):
                    raw = raw[:-3]
                raw = raw.strip()

            enrichment = json.loads(raw)
            chunk["enrichment"] = {
                "mitigates": enrichment.get("mitigates", ""),
                "layer": enrichment.get("layer", chunk.get("metadata", {}).get("layer", "")),
                "does_not_cover": enrichment.get("does_not_cover", ""),
            }

            # Append enrichment to the chunk text so it gets embedded
            chunk["text"] += (
                f"\n\n--- Security Annotations ---"
                f"\nMITIGATES: {chunk['enrichment']['mitigates']}"
                f"\nLAYER: {chunk['enrichment']['layer']}"
                f"\nDOES NOT COVER: {chunk['enrichment']['does_not_cover']}"
            )

            logger.debug("Enriched chunk %d/%d: %s", i + 1, len(chunks), chunk["chunk_id"])

        except json.JSONDecodeError:
            logger.warning("Failed to parse enrichment JSON for chunk %s, using defaults", chunk["chunk_id"])
            chunk["enrichment"] = {
                "mitigates": "",
                "layer": chunk.get("metadata", {}).get("layer", ""),
                "does_not_cover": "Enrichment failed — manual review needed",
            }
        except Exception as e:
            logger.error("Enrichment failed for chunk %s: %s", chunk["chunk_id"], e)
            chunk["enrichment"] = {
                "mitigates": "",
                "layer": chunk.get("metadata", {}).get("layer", ""),
                "does_not_cover": f"Enrichment error: {e}",
            }

    logger.info("Enrichment complete: %d chunks, %d total tokens", len(chunks), total_tokens)
    return chunks
