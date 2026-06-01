"""
Reachability analysis engine — builds a network topology graph from parsed
Terraform controls and determines whether a target endpoint is reachable
from a given source, tracing the full path through security layers.

The graph models:
  Internet → WAF → ALB SG → Kong SG → Service SG → Data SG
  (with possible bypass paths for misconfigured SGs)
"""
import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Well-known network zones
INTERNET = "internet"
VPC_INTERNAL = "vpc-internal"
MANAGEMENT_VPC = "management-vpc"

# Standard traffic path through the architecture
STANDARD_PATH_ORDER = [
    "waf",          # AWS WAF v2
    "shield",       # Shield Advanced
    "alb",          # Application Load Balancer
    "kong",         # Kong API Gateway
    "service",      # Microservice
    "data",         # Database / cache tier
]


@dataclass
class SecurityGroupNode:
    """Represents a security group as a node in the reachability graph."""
    name: str
    resource_name: str
    description: str
    tier: str  # alb, kong, service, data, etc.
    vpc: str
    ingress_rules: list[dict] = field(default_factory=list)
    egress_rules: list[dict] = field(default_factory=list)
    # Which SGs are allowed as ingress sources
    allows_from_sgs: list[str] = field(default_factory=list)
    # Which CIDRs are allowed as ingress sources
    allows_from_cidrs: list[str] = field(default_factory=list)
    # Ports open for ingress
    ingress_ports: list[tuple[int, int]] = field(default_factory=list)


@dataclass
class ReachabilityPath:
    """A single path from source to target through the network."""
    source: str
    target_sg: str
    hops: list[str]  # ordered list of SG names traversed
    layers_traversed: list[str]  # security layers in the path
    layers_bypassed: list[str]  # security layers NOT in the path
    is_internet_reachable: bool
    reachable_from_cidrs: list[str]
    reachable_ports: list[str]
    risk_notes: list[str] = field(default_factory=list)


@dataclass
class ReachabilityResult:
    """Complete reachability analysis for a target endpoint."""
    target_endpoint: str
    target_sg: str
    is_internet_reachable: bool
    reachable_from: list[str]  # list of source descriptions
    paths: list[ReachabilityPath]
    waf_in_path: bool
    gateway_in_path: bool
    nacl_restrictions: list[str]
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    summary: str


class ReachabilityAnalyzer:
    """
    Builds a network topology graph from parsed Terraform controls and
    analyses reachability for target endpoints.
    """

    def __init__(self, terraform_controls: list[dict]):
        self._controls = terraform_controls
        self._sg_nodes: dict[str, SecurityGroupNode] = {}
        self._nacls: list[dict] = []
        self._waf_acls: list[dict] = []
        self._waf_associations: list[dict] = []
        self._waf_ip_sets: list[dict] = []
        self._shield_protections: list[dict] = []
        self._transit_gateways: list[dict] = []
        self._vpc_endpoints: list[dict] = []
        self._sg_ref_map: dict[str, str] = {}  # resource_name → sg_name

        self._build_graph()

    def _build_graph(self) -> None:
        """Parse all Terraform controls into the reachability graph."""
        for ctrl in self._controls:
            ctype = ctrl.get("control_type", "")
            meta = ctrl.get("metadata", {})

            if ctype == "security_group":
                self._add_sg(ctrl)
            elif ctype == "nacl":
                self._nacls.append(ctrl)
            elif ctype == "waf_acl":
                self._waf_acls.append(ctrl)
            elif ctype == "waf_association":
                self._waf_associations.append(ctrl)
            elif ctype == "waf_ip_set":
                self._waf_ip_sets.append(ctrl)
            elif ctype == "shield_protection":
                self._shield_protections.append(ctrl)
            elif ctype == "transit_gateway":
                self._transit_gateways.append(ctrl)
            elif ctype == "vpc_endpoint":
                self._vpc_endpoints.append(ctrl)

        logger.info(
            "Reachability graph: %d SGs, %d NACLs, %d WAF ACLs, %d Shield protections",
            len(self._sg_nodes), len(self._nacls),
            len(self._waf_acls), len(self._shield_protections),
        )

    def _add_sg(self, ctrl: dict) -> None:
        """Add a security group to the graph."""
        meta = ctrl["metadata"]
        name = meta.get("name", "")
        resource_name = meta.get("resource_name", "")
        desc = meta.get("description", "")

        # Classify the tier based on name and description
        tier = self._classify_sg_tier(name, desc)

        # Determine VPC
        raw = ctrl.get("raw_block", "")
        vpc = "prod"
        if "management" in raw.lower() or "mgmt" in name.lower() or "bastion" in name.lower():
            vpc = "management"

        node = SecurityGroupNode(
            name=name,
            resource_name=resource_name,
            description=desc,
            tier=tier,
            vpc=vpc,
            ingress_rules=meta.get("ingress_rules", []),
            egress_rules=meta.get("egress_rules", []),
        )

        # Parse ingress rules for reachability
        for rule in node.ingress_rules:
            cidrs = rule.get("cidr_blocks", [])
            for cidr in cidrs:
                node.allows_from_cidrs.append(cidr)

            sg_ref = rule.get("security_groups", "")
            if sg_ref:
                node.allows_from_sgs.append(sg_ref)

            from_port = rule.get("from_port", "")
            to_port = rule.get("to_port", "")
            if from_port and to_port:
                try:
                    node.ingress_ports.append((int(from_port), int(to_port)))
                except ValueError:
                    pass

        self._sg_nodes[name] = node
        self._sg_ref_map[resource_name] = name

    def _classify_sg_tier(self, name: str, desc: str) -> str:
        """Classify a security group into an architecture tier."""
        name_lower = name.lower()
        desc_lower = desc.lower()
        combined = name_lower + " " + desc_lower

        if "alb" in combined or "load balancer" in combined:
            return "alb"
        if "kong" in combined or "gateway" in combined and "api" not in combined:
            return "kong"
        if "database" in combined or "rds" in combined or "aurora" in combined:
            return "data"
        if "redis" in combined or "cache" in combined or "elasticache" in combined:
            return "data"
        if "bastion" in combined:
            return "bastion"
        if "vpc-endpoint" in combined or "vpc endpoint" in combined:
            return "infrastructure"
        if "fetch" in combined:
            return "service"
        if "graphql" in combined:
            return "service"
        if "webhook" in combined:
            return "service"
        if "payment" in combined:
            return "service"
        if "analytics" in combined:
            return "service"
        if "microservice" in combined or "internal" in combined:
            return "service"
        return "unknown"

    def _resolve_sg_ref(self, ref_text: str) -> str | None:
        """Resolve a Terraform SG reference to a SG name."""
        # Refs look like: aws_security_group.alb_sg.id
        match = re.search(r'aws_security_group\.(\w+)\.id', ref_text)
        if match:
            resource_name = match.group(1)
            return self._sg_ref_map.get(resource_name)
        return None

    def _cidr_is_internet(self, cidr: str) -> bool:
        """Check if a CIDR represents internet (public) access."""
        return cidr in ("0.0.0.0/0", "::/0")

    def _cidr_is_vpc_internal(self, cidr: str) -> bool:
        """Check if a CIDR is a private VPC range."""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            return net.is_private
        except ValueError:
            return False

    def _source_ip_matches_cidr(self, source_ip: str, cidr: str) -> bool:
        """Check if a source IP falls within a CIDR range."""
        try:
            ip = ipaddress.ip_address(source_ip)
            net = ipaddress.ip_network(cidr, strict=False)
            return ip in net
        except ValueError:
            return False

    def analyse_endpoint(
        self,
        target_endpoint: str,
        source_ip: str | None = None,
        target_service_port: int | None = None,
    ) -> ReachabilityResult:
        """
        Analyse reachability for a target endpoint.

        Args:
            target_endpoint: The API path (e.g. /api/v1/graphql)
            source_ip: Optional source IP to check specific reachability
            target_service_port: Optional port the service listens on

        Returns:
            ReachabilityResult with full path analysis
        """
        # Step 1: Identify the target SG based on endpoint
        target_sg = self._endpoint_to_sg(target_endpoint, target_service_port)

        if not target_sg:
            return ReachabilityResult(
                target_endpoint=target_endpoint,
                target_sg="UNKNOWN",
                is_internet_reachable=False,
                reachable_from=["Unable to determine target security group"],
                paths=[],
                waf_in_path=False,
                gateway_in_path=False,
                nacl_restrictions=[],
                risk_level="UNKNOWN",
                summary=f"Could not identify which security group governs {target_endpoint}",
            )

        target_node = self._sg_nodes.get(target_sg)
        if not target_node:
            return ReachabilityResult(
                target_endpoint=target_endpoint,
                target_sg=target_sg,
                is_internet_reachable=False,
                reachable_from=[],
                paths=[],
                waf_in_path=False,
                gateway_in_path=False,
                nacl_restrictions=[],
                risk_level="UNKNOWN",
                summary=f"Security group '{target_sg}' not found in Terraform configs",
            )

        # Step 2: Trace all paths to the target SG
        paths = self._trace_all_paths(target_sg, source_ip)

        # Step 3: Check WAF association
        waf_in_path = len(self._waf_associations) > 0 and any(
            p.layers_traversed for p in paths
            if "alb" in [h.lower() for h in p.layers_traversed]
        )
        # More precise: WAF is associated with ALB, so any path through ALB has WAF
        has_alb_path = any("alb" in p.layers_traversed for p in paths)
        waf_in_path = has_alb_path and len(self._waf_acls) > 0

        # Step 4: Check if Kong Gateway is in any path
        gateway_in_path = any("kong" in p.layers_traversed for p in paths)

        # Step 5: Check NACL restrictions
        nacl_restrictions = self._check_nacl_restrictions(target_node)

        # Step 6: Determine internet reachability
        is_internet_reachable = any(p.is_internet_reachable for p in paths)

        # Step 7: Collect all reachable sources
        reachable_from = set()
        for p in paths:
            reachable_from.update(p.reachable_from_cidrs)

        # Step 8: Assess risk
        risk_level = self._assess_risk(
            is_internet_reachable, waf_in_path, gateway_in_path,
            paths, target_node,
        )

        # Step 9: Generate summary
        summary = self._generate_summary(
            target_endpoint, target_sg, is_internet_reachable,
            waf_in_path, gateway_in_path, paths, risk_level,
            source_ip,
        )

        return ReachabilityResult(
            target_endpoint=target_endpoint,
            target_sg=target_sg,
            is_internet_reachable=is_internet_reachable,
            reachable_from=sorted(reachable_from),
            paths=paths,
            waf_in_path=waf_in_path,
            gateway_in_path=gateway_in_path,
            nacl_restrictions=nacl_restrictions,
            risk_level=risk_level,
            summary=summary,
        )

    def _endpoint_to_sg(
        self, endpoint: str, port: int | None = None,
    ) -> str | None:
        """
        Map an API endpoint to the security group that governs the service.

        This uses naming conventions and known service-to-port mappings.
        """
        ep = endpoint.lower().rstrip("/")

        # Known endpoint → SG mappings based on our infrastructure
        endpoint_sg_map = {
            "/api/v1/graphql": "graphql-service-sg",
            "/api/v1/webhooks": "webhook-receiver-sg",
            "/api/v1/payments": "payment-service-sg",
            "/api/v1/fetch": "fetch-service-sg",
            "/api/internal/analytics": "analytics-service-sg-MISCONFIGURED",
        }

        for path_prefix, sg_name in endpoint_sg_map.items():
            if ep.startswith(path_prefix):
                return sg_name

        # Most /api/v1/* and /api/v2/* endpoints go through the general
        # microservices SG via Kong Gateway
        if ep.startswith("/api/"):
            return "internal-microservices-sg"

        # Default: assume general microservices
        return "internal-microservices-sg"

    def _trace_all_paths(
        self, target_sg_name: str, source_ip: str | None = None,
    ) -> list[ReachabilityPath]:
        """Trace all possible network paths to the target SG."""
        paths: list[ReachabilityPath] = []
        target_node = self._sg_nodes.get(target_sg_name)
        if not target_node:
            return paths

        # Check direct internet access (any ingress from 0.0.0.0/0)
        for cidr in target_node.allows_from_cidrs:
            if self._cidr_is_internet(cidr):
                bypassed = self._determine_bypassed_layers(
                    ["internet", target_sg_name], target_node.tier,
                )
                port_strs = [
                    f"{p[0]}-{p[1]}" if p[0] != p[1] else str(p[0])
                    for p in target_node.ingress_ports
                ]
                risk_notes = [
                    f"CRITICAL: {target_sg_name} allows direct internet access on port(s) {', '.join(port_strs)}",
                    "Traffic bypasses WAF, ALB, and Kong Gateway entirely",
                ]
                paths.append(ReachabilityPath(
                    source="Internet (0.0.0.0/0)",
                    target_sg=target_sg_name,
                    hops=[target_sg_name],
                    layers_traversed=[target_node.tier],
                    layers_bypassed=bypassed,
                    is_internet_reachable=True,
                    reachable_from_cidrs=["0.0.0.0/0"],
                    reachable_ports=port_strs,
                    risk_notes=risk_notes,
                ))

        # Check access through SG chain (standard path: ALB → Kong → Service)
        for sg_ref in target_node.allows_from_sgs:
            upstream_sg_name = self._resolve_sg_ref(sg_ref)
            if not upstream_sg_name:
                continue

            # Recursively trace upstream
            upstream_paths = self._trace_upstream(
                upstream_sg_name, [target_sg_name], source_ip,
            )
            for up in upstream_paths:
                up.target_sg = target_sg_name
                layers = self._extract_layers_from_hops(up.hops)
                up.layers_traversed = layers
                up.layers_bypassed = self._determine_bypassed_layers(
                    up.hops, target_node.tier,
                )
                paths.append(up)

        # Check access from specific CIDRs (VPC internal, partner, etc.)
        for cidr in target_node.allows_from_cidrs:
            if self._cidr_is_internet(cidr):
                continue  # Already handled above
            source_desc = self._describe_cidr(cidr)
            port_strs = [
                f"{p[0]}-{p[1]}" if p[0] != p[1] else str(p[0])
                for p in target_node.ingress_ports
            ]
            is_reachable_from_source = (
                source_ip is not None and
                self._source_ip_matches_cidr(source_ip, cidr)
            )
            paths.append(ReachabilityPath(
                source=source_desc,
                target_sg=target_sg_name,
                hops=[f"CIDR:{cidr}", target_sg_name],
                layers_traversed=[target_node.tier],
                layers_bypassed=[],
                is_internet_reachable=False,
                reachable_from_cidrs=[cidr],
                reachable_ports=port_strs,
                risk_notes=[],
            ))

        return paths

    def _trace_upstream(
        self,
        sg_name: str,
        path_so_far: list[str],
        source_ip: str | None,
        depth: int = 0,
    ) -> list[ReachabilityPath]:
        """Recursively trace upstream from a SG to find all sources."""
        if depth > 10:
            return []  # Prevent infinite loops

        node = self._sg_nodes.get(sg_name)
        if not node:
            return []

        results: list[ReachabilityPath] = []
        current_hops = [sg_name] + path_so_far

        # Check if this SG has internet ingress
        for cidr in node.allows_from_cidrs:
            if self._cidr_is_internet(cidr):
                port_strs = [
                    f"{p[0]}-{p[1]}" if p[0] != p[1] else str(p[0])
                    for p in node.ingress_ports
                ]
                results.append(ReachabilityPath(
                    source="Internet (0.0.0.0/0)",
                    target_sg=path_so_far[-1] if path_so_far else sg_name,
                    hops=current_hops,
                    layers_traversed=[],  # filled in later
                    layers_bypassed=[],
                    is_internet_reachable=True,
                    reachable_from_cidrs=["0.0.0.0/0"],
                    reachable_ports=port_strs,
                ))

        # Check upstream SGs
        for sg_ref in node.allows_from_sgs:
            upstream_name = self._resolve_sg_ref(sg_ref)
            if upstream_name and upstream_name not in path_so_far:
                upstream_results = self._trace_upstream(
                    upstream_name, current_hops[1:],
                    source_ip, depth + 1,
                )
                for ur in upstream_results:
                    ur.hops = [upstream_name] + current_hops
                results.extend(upstream_results)

        # Check specific CIDR sources
        for cidr in node.allows_from_cidrs:
            if not self._cidr_is_internet(cidr):
                if source_ip and self._source_ip_matches_cidr(source_ip, cidr):
                    results.append(ReachabilityPath(
                        source=self._describe_cidr(cidr),
                        target_sg=path_so_far[-1] if path_so_far else sg_name,
                        hops=current_hops,
                        layers_traversed=[],
                        layers_bypassed=[],
                        is_internet_reachable=False,
                        reachable_from_cidrs=[cidr],
                        reachable_ports=[],
                    ))

        return results

    def _extract_layers_from_hops(self, hops: list[str]) -> list[str]:
        """Extract security layer names from the SG hops."""
        layers = []
        for hop in hops:
            node = self._sg_nodes.get(hop)
            if node:
                if node.tier not in layers:
                    layers.append(node.tier)
        return layers

    def _determine_bypassed_layers(
        self, hops: list[str], target_tier: str,
    ) -> list[str]:
        """Determine which standard security layers are bypassed."""
        traversed_tiers = set()
        for hop in hops:
            node = self._sg_nodes.get(hop)
            if node:
                traversed_tiers.add(node.tier)

        # Standard expected path for a service-tier target
        expected_layers = []
        if target_tier == "service":
            expected_layers = ["alb", "kong"]
        elif target_tier == "data":
            expected_layers = ["alb", "kong", "service"]
        elif target_tier == "kong":
            expected_layers = ["alb"]

        bypassed = [
            layer for layer in expected_layers
            if layer not in traversed_tiers
        ]

        # WAF is special — it's associated with ALB, not a SG
        if "alb" not in traversed_tiers and self._waf_acls:
            if "waf" not in bypassed:
                bypassed.insert(0, "waf")

        return bypassed

    def _check_nacl_restrictions(self, target_node: SecurityGroupNode) -> list[str]:
        """Check NACL restrictions that apply to the target's subnet."""
        restrictions = []
        for nacl in self._nacls:
            meta = nacl.get("metadata", {})
            nacl_name = meta.get("resource_name", "")
            ingress_rules = meta.get("ingress_rules", [])

            for rule in ingress_rules:
                action = rule.get("action", "")
                cidr = rule.get("cidr_block", "")
                from_port = rule.get("from_port", "")
                to_port = rule.get("to_port", "")
                rule_no = rule.get("rule_no", "")

                if action == "deny":
                    restrictions.append(
                        f"NACL {nacl_name} rule {rule_no}: DENY {cidr} ports {from_port}-{to_port}"
                    )
                elif action == "allow" and cidr:
                    restrictions.append(
                        f"NACL {nacl_name} rule {rule_no}: ALLOW {cidr} ports {from_port}-{to_port}"
                    )

        return restrictions

    def _assess_risk(
        self,
        is_internet_reachable: bool,
        waf_in_path: bool,
        gateway_in_path: bool,
        paths: list[ReachabilityPath],
        target_node: SecurityGroupNode,
    ) -> str:
        """Assess the risk level based on reachability analysis."""
        # CRITICAL: Internet reachable AND bypasses both WAF and Gateway
        has_bypass = any(
            len(p.layers_bypassed) >= 2
            for p in paths if p.is_internet_reachable
        )
        if is_internet_reachable and has_bypass:
            return "CRITICAL"

        # HIGH: Internet reachable but bypasses Gateway (goes through ALB/WAF only)
        if is_internet_reachable and not gateway_in_path:
            return "HIGH"

        # MEDIUM: Internet reachable through standard path but with concerns
        if is_internet_reachable and gateway_in_path and waf_in_path:
            return "LOW"

        # LOW: Only reachable from internal VPC
        if not is_internet_reachable:
            return "LOW"

        return "MEDIUM"

    def _describe_cidr(self, cidr: str) -> str:
        """Provide a human-readable description of a CIDR range."""
        if cidr == "0.0.0.0/0":
            return "Internet (0.0.0.0/0)"
        if cidr.startswith("10.0."):
            return f"Production VPC ({cidr})"
        if cidr.startswith("10.1."):
            return f"Management VPC ({cidr})"
        if cidr.startswith("198.51.100."):
            return f"Corporate VPN ({cidr})"
        if cidr.startswith("203.0.113."):
            return f"Known botnet range ({cidr})"
        if cidr.startswith("203.0.114."):
            return f"Partner CIDR ({cidr})"
        if cidr.startswith("3.") or cidr.startswith("13."):
            return f"AWS IP (webhook/payment provider) ({cidr})"
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.is_private:
                return f"Private network ({cidr})"
            return f"Public IP range ({cidr})"
        except ValueError:
            return cidr

    def _generate_summary(
        self,
        target_endpoint: str,
        target_sg: str,
        is_internet_reachable: bool,
        waf_in_path: bool,
        gateway_in_path: bool,
        paths: list[ReachabilityPath],
        risk_level: str,
        source_ip: str | None,
    ) -> str:
        """Generate a human-readable reachability summary."""
        lines = [f"Reachability Analysis for {target_endpoint} (SG: {target_sg})"]
        lines.append(f"Risk Level: {risk_level}")
        lines.append("")

        if is_internet_reachable:
            lines.append("INTERNET REACHABLE: Yes")
            internet_paths = [p for p in paths if p.is_internet_reachable]
            for p in internet_paths:
                path_str = " → ".join(p.hops)
                lines.append(f"  Path: Internet → {path_str}")
                if p.layers_bypassed:
                    lines.append(f"  BYPASSED LAYERS: {', '.join(p.layers_bypassed)}")
                if p.risk_notes:
                    for note in p.risk_notes:
                        lines.append(f"  WARNING: {note}")
        else:
            lines.append("INTERNET REACHABLE: No")

        lines.append("")
        lines.append(f"WAF in path: {'Yes' if waf_in_path else 'No'}")
        lines.append(f"Kong Gateway in path: {'Yes' if gateway_in_path else 'No'}")

        if source_ip:
            lines.append("")
            source_reachable = any(
                self._source_ip_matches_cidr(source_ip, cidr)
                for p in paths
                for cidr in p.reachable_from_cidrs
            )
            lines.append(f"Source IP {source_ip} can reach target: {'Yes' if source_reachable else 'No'}")

        # Unique reachable sources
        all_sources = set()
        for p in paths:
            all_sources.update(p.reachable_from_cidrs)
        if all_sources:
            lines.append("")
            lines.append("Reachable from:")
            for src in sorted(all_sources):
                lines.append(f"  - {self._describe_cidr(src)}")

        return "\n".join(lines)

    def to_json(self, result: ReachabilityResult) -> str:
        """Serialize a ReachabilityResult to JSON for agent consumption."""
        return json.dumps({
            "target_endpoint": result.target_endpoint,
            "target_sg": result.target_sg,
            "is_internet_reachable": result.is_internet_reachable,
            "reachable_from": result.reachable_from,
            "waf_in_path": result.waf_in_path,
            "gateway_in_path": result.gateway_in_path,
            "nacl_restrictions": result.nacl_restrictions[:10],  # limit for context
            "risk_level": result.risk_level,
            "summary": result.summary,
            "paths": [
                {
                    "source": p.source,
                    "hops": p.hops,
                    "layers_traversed": p.layers_traversed,
                    "layers_bypassed": p.layers_bypassed,
                    "is_internet_reachable": p.is_internet_reachable,
                    "reachable_ports": p.reachable_ports,
                    "risk_notes": p.risk_notes,
                }
                for p in result.paths
            ],
        }, indent=2)
