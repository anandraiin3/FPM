"""
NGINX config parser — extracts rate-limiting zones, location blocks,
proxy directives, and timeout values.
"""
import re
from pathlib import Path


def parse_nginx(file_path: str) -> list[dict]:
    """
    Parse an NGINX .conf file and return structured control records.

    Each record has:
      - control_id, control_type, layer ("WAF"), source_file, raw_block, metadata
    """
    text = Path(file_path).read_text()
    controls: list[dict] = []

    # ── Rate-limiting zones ──
    for m in re.finditer(
        r'limit_req_zone\s+\S+\s+zone=(\w+):(\S+)\s+rate=(\S+);', text
    ):
        zone_name, size, rate = m.group(1), m.group(2), m.group(3)
        controls.append({
            "control_id": f"nginx-rate:{zone_name}",
            "control_type": "rate_limit_zone",
            "layer": "WAF",
            "source_file": file_path,
            "raw_block": m.group(0),
            "metadata": {
                "zone_name": zone_name,
                "size": size,
                "rate": rate,
            },
        })

    # ── client_max_body_size ──
    m = re.search(r'client_max_body_size\s+(\S+);', text)
    if m:
        controls.append({
            "control_id": "nginx:client_max_body_size",
            "control_type": "body_size_limit",
            "layer": "WAF",
            "source_file": file_path,
            "raw_block": m.group(0),
            "metadata": {"limit": m.group(1)},
        })

    # ── proxy_read_timeout ──
    m = re.search(r'proxy_read_timeout\s+(\S+);', text)
    if m:
        controls.append({
            "control_id": "nginx:proxy_read_timeout",
            "control_type": "timeout",
            "layer": "WAF",
            "source_file": file_path,
            "raw_block": m.group(0),
            "metadata": {"timeout": m.group(1)},
        })

    # ── Location blocks ──
    loc_pattern = re.compile(r'location\s+(\S+)\s*\{', re.MULTILINE)
    for m in loc_pattern.finditer(text):
        path = m.group(1)
        end = _find_block_end(text, m.start())
        block = text[m.start():end]

        # Extract limit_req directives within the location
        limit_reqs = re.findall(r'limit_req\s+zone=(\w+)([^;]*);', block)
        proxy_pass = re.search(r'proxy_pass\s+(\S+);', block)

        controls.append({
            "control_id": f"nginx-loc:{path}",
            "control_type": "location_block",
            "layer": "WAF",
            "source_file": file_path,
            "raw_block": block,
            "metadata": {
                "path": path,
                "rate_limits": [
                    {"zone": z, "params": p.strip()} for z, p in limit_reqs
                ],
                "proxy_pass": proxy_pass.group(1) if proxy_pass else None,
            },
        })

    return controls


def _find_block_end(text: str, start: int) -> int:
    depth = 0
    i = text.index("{", start)
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(text)
