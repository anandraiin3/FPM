"""
Terraform HCL parser — extracts security groups, NACLs, WAF rule groups.

Since we cannot depend on a full HCL parser (pyhcl2 is fragile), we use
regex-based extraction which is sufficient for the well-structured .tf files
in our infrastructure directory.
"""
import re
from pathlib import Path


def parse_terraform(file_path: str) -> list[dict]:
    """
    Parse a Terraform .tf file and return structured control records.

    Each record is a dict with:
      - control_id: unique identifier (e.g. "sg:alb-public-sg")
      - control_type: "security_group" | "nacl" | "waf_acl" | "waf_rule" | "waf_association"
      - layer: "Network"
      - source_file: file path
      - raw_block: the original HCL block text
      - metadata: extracted fields (name, rules, cidrs, etc.)
    """
    text = Path(file_path).read_text()
    controls: list[dict] = []

    # Extract all resource blocks
    # Pattern: resource "type" "name" { ... }
    block_pattern = re.compile(
        r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE
    )

    positions = [(m.group(1), m.group(2), m.start()) for m in block_pattern.finditer(text)]

    for i, (rtype, rname, start) in enumerate(positions):
        # Find the matching closing brace (simple brace counting)
        end = _find_block_end(text, start)
        block = text[start:end]

        if rtype == "aws_security_group":
            controls.append(_parse_security_group(rname, block, file_path))
        elif rtype == "aws_network_acl":
            controls.append(_parse_nacl(rname, block, file_path))
        elif rtype == "aws_wafv2_web_acl":
            controls.append(_parse_waf_acl(rname, block, file_path))
        elif rtype == "aws_wafv2_web_acl_association":
            controls.append(_parse_waf_association(rname, block, file_path))
        elif rtype == "aws_wafv2_ip_set":
            controls.append(_parse_waf_ip_set(rname, block, file_path))
        elif rtype == "aws_wafv2_regex_pattern_set":
            controls.append(_parse_waf_regex_set(rname, block, file_path))
        elif rtype == "aws_shield_protection":
            controls.append(_parse_shield(rname, block, file_path))
        elif rtype == "aws_ec2_transit_gateway":
            controls.append(_parse_transit_gateway(rname, block, file_path))
        elif rtype == "aws_vpc_endpoint":
            controls.append(_parse_vpc_endpoint(rname, block, file_path))

    return controls


def _find_block_end(text: str, start: int) -> int:
    """Find the position after the closing brace of the block starting at `start`."""
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


def _extract_field(block: str, field: str) -> str:
    """Extract a simple field value from an HCL block."""
    m = re.search(rf'{field}\s*=\s*"([^"]*)"', block)
    return m.group(1) if m else ""


def _extract_list(block: str, field: str) -> list[str]:
    """Extract a list field (e.g. cidr_blocks = ["..."])."""
    m = re.search(rf'{field}\s*=\s*\[([^\]]*)\]', block, re.DOTALL)
    if not m:
        return []
    return re.findall(r'"([^"]*)"', m.group(1))


def _extract_ingress_egress(block: str) -> dict:
    """Extract all ingress and egress sub-blocks."""
    rules = {"ingress": [], "egress": []}
    for direction in ("ingress", "egress"):
        pattern = re.compile(rf'{direction}\s*\{{([^}}]*)\}}', re.DOTALL)
        for m in pattern.finditer(block):
            rule_block = m.group(1)
            rule = {
                "description": _extract_field(rule_block, "description"),
                "from_port": _extract_field(rule_block, "from_port"),
                "to_port": _extract_field(rule_block, "to_port"),
                "protocol": _extract_field(rule_block, "protocol"),
                "cidr_blocks": _extract_list(rule_block, "cidr_blocks"),
            }
            # Check for security_groups reference
            sg_ref = re.search(r'security_groups\s*=\s*\[([^\]]*)\]', rule_block)
            if sg_ref:
                rule["security_groups"] = sg_ref.group(1).strip()
            rules[direction].append(rule)
    return rules


def _parse_security_group(rname: str, block: str, file_path: str) -> dict:
    name = _extract_field(block, "name")
    desc = _extract_field(block, "description")
    rules = _extract_ingress_egress(block)
    return {
        "control_id": f"sg:{name}",
        "control_type": "security_group",
        "layer": "Network",
        "source_file": file_path,
        "raw_block": block,
        "metadata": {
            "name": name,
            "description": desc,
            "resource_name": rname,
            "ingress_rules": rules["ingress"],
            "egress_rules": rules["egress"],
        },
    }


def _parse_nacl(rname: str, block: str, file_path: str) -> dict:
    rules = {"ingress": [], "egress": []}
    for direction in ("ingress", "egress"):
        pattern = re.compile(rf'{direction}\s*\{{([^}}]*)\}}', re.DOTALL)
        for m in pattern.finditer(block):
            rb = m.group(1)
            rules[direction].append({
                "rule_no": _extract_field(rb, "rule_no") or re.search(r'rule_no\s*=\s*(\d+)', rb).group(1) if re.search(r'rule_no\s*=\s*(\d+)', rb) else "",
                "action": _extract_field(rb, "action"),
                "cidr_block": _extract_field(rb, "cidr_block"),
                "protocol": _extract_field(rb, "protocol"),
                "from_port": re.search(r'from_port\s*=\s*(\d+)', rb).group(1) if re.search(r'from_port\s*=\s*(\d+)', rb) else "",
                "to_port": re.search(r'to_port\s*=\s*(\d+)', rb).group(1) if re.search(r'to_port\s*=\s*(\d+)', rb) else "",
            })
    return {
        "control_id": f"nacl:{rname}",
        "control_type": "nacl",
        "layer": "Network",
        "source_file": file_path,
        "raw_block": block,
        "metadata": {
            "resource_name": rname,
            "ingress_rules": rules["ingress"],
            "egress_rules": rules["egress"],
        },
    }


def _parse_waf_acl(rname: str, block: str, file_path: str) -> dict:
    name = _extract_field(block, "name")
    # Extract managed rule group names
    groups = re.findall(r'name\s*=\s*"(AWSManagedRules\w+)"', block)
    # Extract custom rule names
    custom_rules = re.findall(r'rule\s*\{\s*name\s*=\s*"([^"]+)"', block)
    # Extract rate-based rules
    rate_limits = re.findall(r'limit\s*=\s*(\d+)', block)
    # Extract geo-match country codes
    geo_countries = re.findall(r'country_codes\s*=\s*\[([^\]]*)\]', block)
    geo_list = []
    for gc in geo_countries:
        geo_list.extend(re.findall(r'"([^"]+)"', gc))
    return {
        "control_id": f"waf:{name}",
        "control_type": "waf_acl",
        "layer": "Network",
        "source_file": file_path,
        "raw_block": block,
        "metadata": {
            "name": name,
            "resource_name": rname,
            "managed_rule_groups": groups,
            "custom_rule_names": custom_rules,
            "rate_limits": rate_limits,
            "geo_blocked_countries": geo_list,
        },
    }


def _parse_waf_association(rname: str, block: str, file_path: str) -> dict:
    return {
        "control_id": f"waf-assoc:{rname}",
        "control_type": "waf_association",
        "layer": "Network",
        "source_file": file_path,
        "raw_block": block,
        "metadata": {"resource_name": rname},
    }


def _parse_waf_ip_set(rname: str, block: str, file_path: str) -> dict:
    name = _extract_field(block, "name")
    addresses = _extract_list(block, "addresses")
    return {
        "control_id": f"waf-ipset:{name}",
        "control_type": "waf_ip_set",
        "layer": "Network",
        "source_file": file_path,
        "raw_block": block,
        "metadata": {
            "name": name,
            "resource_name": rname,
            "blocked_cidrs": addresses,
        },
    }


def _parse_waf_regex_set(rname: str, block: str, file_path: str) -> dict:
    name = _extract_field(block, "name")
    patterns = re.findall(r'regex_string\s*=\s*"([^"]+)"', block)
    return {
        "control_id": f"waf-regex:{name}",
        "control_type": "waf_regex_pattern_set",
        "layer": "Network",
        "source_file": file_path,
        "raw_block": block,
        "metadata": {
            "name": name,
            "resource_name": rname,
            "patterns": patterns,
        },
    }


def _parse_shield(rname: str, block: str, file_path: str) -> dict:
    name = _extract_field(block, "name")
    return {
        "control_id": f"shield:{name}",
        "control_type": "shield_protection",
        "layer": "Network",
        "source_file": file_path,
        "raw_block": block,
        "metadata": {
            "name": name,
            "resource_name": rname,
        },
    }


def _parse_transit_gateway(rname: str, block: str, file_path: str) -> dict:
    desc = _extract_field(block, "description")
    return {
        "control_id": f"tgw:{rname}",
        "control_type": "transit_gateway",
        "layer": "Network",
        "source_file": file_path,
        "raw_block": block,
        "metadata": {
            "resource_name": rname,
            "description": desc,
        },
    }


def _parse_vpc_endpoint(rname: str, block: str, file_path: str) -> dict:
    service_name = _extract_field(block, "service_name")
    endpoint_type = _extract_field(block, "vpc_endpoint_type")
    return {
        "control_id": f"vpce:{rname}",
        "control_type": "vpc_endpoint",
        "layer": "Network",
        "source_file": file_path,
        "raw_block": block,
        "metadata": {
            "resource_name": rname,
            "service_name": service_name,
            "endpoint_type": endpoint_type,
        },
    }
