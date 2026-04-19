"""
ModSecurity config parser — extracts CRS rule includes, custom SecRules,
and body size/engine settings.
"""
import re
from pathlib import Path


def parse_modsecurity(file_path: str) -> list[dict]:
    """
    Parse a ModSecurity .conf file and return structured control records.
    """
    text = Path(file_path).read_text()
    controls: list[dict] = []

    # ── SecRuleEngine setting ──
    m = re.search(r'SecRuleEngine\s+(\w+)', text)
    if m:
        controls.append({
            "control_id": "modsec:engine",
            "control_type": "engine_setting",
            "layer": "WAF",
            "source_file": file_path,
            "raw_block": m.group(0),
            "metadata": {"mode": m.group(1)},
        })

    # ── SecRequestBodyAccess ──
    m = re.search(r'SecRequestBodyAccess\s+(\w+)', text)
    if m:
        controls.append({
            "control_id": "modsec:request_body_access",
            "control_type": "body_access",
            "layer": "WAF",
            "source_file": file_path,
            "raw_block": m.group(0),
            "metadata": {"enabled": m.group(1)},
        })

    # ── SecRequestBodyLimit ──
    m = re.search(r'SecRequestBodyLimit\s+(\d+)', text)
    if m:
        controls.append({
            "control_id": "modsec:body_limit",
            "control_type": "body_size_limit",
            "layer": "WAF",
            "source_file": file_path,
            "raw_block": m.group(0),
            "metadata": {"limit_bytes": int(m.group(1))},
        })

    # ── SecResponseBodyAccess (data leak prevention) ──
    m = re.search(r'SecResponseBodyAccess\s+(\w+)', text)
    if m:
        controls.append({
            "control_id": "modsec:response_body_access",
            "control_type": "response_body_access",
            "layer": "WAF",
            "source_file": file_path,
            "raw_block": m.group(0),
            "metadata": {"enabled": m.group(1)},
        })

    # ── Paranoia Level ──
    m = re.search(r'setvar:tx\.blocking_paranoia_level=(\d+)', text)
    if m:
        controls.append({
            "control_id": "modsec:paranoia_level",
            "control_type": "paranoia_level",
            "layer": "WAF",
            "source_file": file_path,
            "raw_block": f"Paranoia Level: {m.group(1)}",
            "metadata": {"blocking_paranoia_level": int(m.group(1))},
        })

    # ── Anomaly Score Thresholds ──
    m = re.search(r'setvar:tx\.inbound_anomaly_score_threshold=(\d+)', text)
    if m:
        controls.append({
            "control_id": "modsec:anomaly_threshold",
            "control_type": "anomaly_scoring",
            "layer": "WAF",
            "source_file": file_path,
            "raw_block": f"Inbound anomaly score threshold: {m.group(1)}",
            "metadata": {"inbound_threshold": int(m.group(1))},
        })

    # ── CRS Rule Includes ──
    for m in re.finditer(r'Include\s+(\S+)', text):
        include_path = m.group(1)
        # Extract CRS rule category from filename
        rule_file = include_path.split("/")[-1] if "/" in include_path else include_path
        # Try to identify CRS rule ID range from comments
        crs_id = ""
        line_start = text.rfind("\n", 0, m.start()) + 1
        comment_region = text[max(0, line_start - 200):m.start()]
        id_match = re.search(r'rule\s+(?:ID\s+)?(\d+)', comment_region, re.IGNORECASE)
        if id_match:
            crs_id = id_match.group(1)

        controls.append({
            "control_id": f"modsec-crs:{rule_file}",
            "control_type": "crs_rule_include",
            "layer": "WAF",
            "source_file": file_path,
            "raw_block": m.group(0),
            "metadata": {
                "include_path": include_path,
                "rule_file": rule_file,
                "crs_id_range": crs_id,
            },
        })

    # ── Custom SecRules ──
    # Pattern: SecRule VARIABLES "OPERATOR" "ACTIONS"
    secrule_pattern = re.compile(
        r'SecRule\s+(\S+)\s+"([^"]+)"\s*\\\s*\n\s*"([^"]*(?:"[^"]*"[^"]*)*)"',
        re.DOTALL,
    )
    # Simpler fallback: match multi-line SecRule blocks
    alt_pattern = re.compile(
        r'(SecRule\s+\S+\s+"[^"]+"\s*\\[\s\S]*?severity:\s*\'[^\']+\'["\s]*)',
        re.MULTILINE,
    )

    for m in alt_pattern.finditer(text):
        block = m.group(0)
        rule_id = ""
        id_m = re.search(r'id:(\d+)', block)
        if id_m:
            rule_id = id_m.group(1)

        msg = ""
        msg_m = re.search(r"msg:'([^']*)'", block)
        if msg_m:
            msg = msg_m.group(1)

        severity = ""
        sev_m = re.search(r"severity:'([^']*)'", block)
        if sev_m:
            severity = sev_m.group(1)

        tags = re.findall(r"tag:'([^']*)'", block)

        status = ""
        status_m = re.search(r'status:(\d+)', block)
        if status_m:
            status = status_m.group(1)

        controls.append({
            "control_id": f"modsec-rule:{rule_id}",
            "control_type": "custom_secrule",
            "layer": "WAF",
            "source_file": file_path,
            "raw_block": block.strip(),
            "metadata": {
                "rule_id": rule_id,
                "message": msg,
                "severity": severity,
                "tags": tags,
                "action_status": status,
            },
        })

    return controls
