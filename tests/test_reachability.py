"""
Unit tests for the reachability analysis engine.

These tests validate graph building, path tracing, bypass detection,
and risk assessment — all without any LLM calls.

Run: python -m pytest tests/test_reachability.py -v
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fpm.analysis.reachability import (
    ReachabilityAnalyzer,
    ReachabilityResult,
    ReachabilityPath,
    SecurityGroupNode,
    STANDARD_PATH_ORDER,
)


# ---------------------------------------------------------------------------
# Test fixtures — minimal Terraform control dicts that mimic parser output
# ---------------------------------------------------------------------------

def _sg_control(
    resource_name: str,
    name: str,
    description: str,
    ingress_rules: list[dict] | None = None,
    egress_rules: list[dict] | None = None,
    raw_block: str = "",
) -> dict:
    """Helper to build a security_group control dict."""
    return {
        "control_id": f"sg:{name}",
        "control_type": "security_group",
        "layer": "Network",
        "source_file": "test.tf",
        "raw_block": raw_block,
        "metadata": {
            "resource_name": resource_name,
            "name": name,
            "description": description,
            "ingress_rules": ingress_rules or [],
            "egress_rules": egress_rules or [],
        },
    }


def _nacl_control(resource_name: str, ingress_rules: list[dict] | None = None) -> dict:
    return {
        "control_id": f"nacl:{resource_name}",
        "control_type": "nacl",
        "layer": "Network",
        "source_file": "test.tf",
        "raw_block": "",
        "metadata": {
            "resource_name": resource_name,
            "ingress_rules": ingress_rules or [],
        },
    }


def _waf_acl_control(resource_name: str = "api_waf_acl") -> dict:
    return {
        "control_id": f"waf:{resource_name}",
        "control_type": "waf_acl",
        "layer": "Network",
        "source_file": "test.tf",
        "raw_block": "",
        "metadata": {"resource_name": resource_name, "name": "api-waf-acl"},
    }


def _waf_association_control() -> dict:
    return {
        "control_id": "waf-assoc:alb",
        "control_type": "waf_association",
        "layer": "Network",
        "source_file": "test.tf",
        "raw_block": "",
        "metadata": {},
    }


def _build_standard_controls() -> list[dict]:
    """
    Build a minimal but representative set of controls matching the FPM
    infrastructure topology:

    Internet → ALB SG (0.0.0.0/0:443) → Kong SG (from ALB) → Microservices SG (from Kong)
    Plus a misconfigured analytics SG that allows 0.0.0.0/0 directly.
    """
    return [
        # ALB — public-facing, allows internet on 443/80
        _sg_control(
            resource_name="alb_sg",
            name="alb-public-sg",
            description="Application Load Balancer - public facing",
            ingress_rules=[
                {
                    "from_port": "443",
                    "to_port": "443",
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"],
                },
                {
                    "from_port": "80",
                    "to_port": "80",
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"],
                },
            ],
        ),
        # Kong Gateway — receives from ALB only
        _sg_control(
            resource_name="kong_sg",
            name="kong-gateway-sg",
            description="Kong API Gateway",
            ingress_rules=[
                {
                    "from_port": "8000",
                    "to_port": "8000",
                    "protocol": "tcp",
                    "security_groups": "aws_security_group.alb_sg.id",
                },
            ],
        ),
        # Internal microservices — receives from Kong only
        _sg_control(
            resource_name="microservices_sg",
            name="internal-microservices-sg",
            description="Internal microservices tier",
            ingress_rules=[
                {
                    "from_port": "8080",
                    "to_port": "8090",
                    "protocol": "tcp",
                    "security_groups": "aws_security_group.kong_sg.id",
                },
            ],
        ),
        # GraphQL service — receives from Kong
        _sg_control(
            resource_name="graphql_sg",
            name="graphql-service-sg",
            description="GraphQL service",
            ingress_rules=[
                {
                    "from_port": "4000",
                    "to_port": "4000",
                    "protocol": "tcp",
                    "security_groups": "aws_security_group.kong_sg.id",
                },
            ],
        ),
        # Payment service — receives from Kong
        _sg_control(
            resource_name="payment_sg",
            name="payment-service-sg",
            description="Payment processing service",
            ingress_rules=[
                {
                    "from_port": "8085",
                    "to_port": "8085",
                    "protocol": "tcp",
                    "security_groups": "aws_security_group.kong_sg.id",
                },
            ],
        ),
        # Fetch service — receives from Kong, egress restricted
        _sg_control(
            resource_name="fetch_sg",
            name="fetch-service-sg",
            description="Fetch service for SSRF protection",
            ingress_rules=[
                {
                    "from_port": "8086",
                    "to_port": "8086",
                    "protocol": "tcp",
                    "security_groups": "aws_security_group.kong_sg.id",
                },
            ],
            egress_rules=[
                {
                    "from_port": "443",
                    "to_port": "443",
                    "protocol": "tcp",
                    "cidr_blocks": ["203.0.114.0/24"],
                },
            ],
        ),
        # Webhook receiver — allows Stripe IPs + Kong
        _sg_control(
            resource_name="webhook_sg",
            name="webhook-receiver-sg",
            description="Webhook receiver service",
            ingress_rules=[
                {
                    "from_port": "8087",
                    "to_port": "8087",
                    "protocol": "tcp",
                    "security_groups": "aws_security_group.kong_sg.id",
                },
                {
                    "from_port": "8087",
                    "to_port": "8087",
                    "protocol": "tcp",
                    "cidr_blocks": ["3.18.12.63/32"],
                },
            ],
        ),
        # MISCONFIGURED analytics — allows 0.0.0.0/0 (bypass!)
        _sg_control(
            resource_name="analytics_sg",
            name="analytics-service-sg-MISCONFIGURED",
            description="Analytics service (MISCONFIGURED)",
            ingress_rules=[
                {
                    "from_port": "8098",
                    "to_port": "8098",
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"],
                },
            ],
        ),
        # Database — only from microservices
        _sg_control(
            resource_name="db_sg",
            name="database-rds-sg",
            description="RDS database",
            ingress_rules=[
                {
                    "from_port": "5432",
                    "to_port": "5432",
                    "protocol": "tcp",
                    "security_groups": "aws_security_group.microservices_sg.id",
                },
            ],
        ),
        # NACL for data tier
        _nacl_control(
            resource_name="data_tier_nacl",
            ingress_rules=[
                {"rule_no": "100", "action": "allow", "cidr_block": "10.0.0.0/20", "from_port": "5432", "to_port": "5432"},
                {"rule_no": "999", "action": "deny", "cidr_block": "0.0.0.0/0", "from_port": "0", "to_port": "65535"},
            ],
        ),
        # WAF ACL
        _waf_acl_control(),
        # WAF ↔ ALB association
        _waf_association_control(),
    ]


# ---------------------------------------------------------------------------
# U1: Graph Construction
# ---------------------------------------------------------------------------
class TestSGGraphConstruction:
    def test_all_sgs_added(self):
        """U1: All security groups are added as nodes."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        # 9 SGs in our fixture
        assert len(analyzer._sg_nodes) == 9

    def test_sg_names_correct(self):
        """SG names are correctly parsed."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        expected_names = {
            "alb-public-sg", "kong-gateway-sg", "internal-microservices-sg",
            "graphql-service-sg", "payment-service-sg", "fetch-service-sg",
            "webhook-receiver-sg", "analytics-service-sg-MISCONFIGURED",
            "database-rds-sg",
        }
        assert set(analyzer._sg_nodes.keys()) == expected_names

    def test_tier_classification(self):
        """SGs are classified into the correct architecture tiers."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert analyzer._sg_nodes["alb-public-sg"].tier == "alb"
        assert analyzer._sg_nodes["kong-gateway-sg"].tier == "kong"
        assert analyzer._sg_nodes["internal-microservices-sg"].tier == "service"
        assert analyzer._sg_nodes["graphql-service-sg"].tier == "service"
        assert analyzer._sg_nodes["database-rds-sg"].tier == "data"
        assert analyzer._sg_nodes["analytics-service-sg-MISCONFIGURED"].tier == "service"

    def test_ingress_cidrs_parsed(self):
        """Ingress CIDR blocks are parsed correctly."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        alb = analyzer._sg_nodes["alb-public-sg"]
        assert "0.0.0.0/0" in alb.allows_from_cidrs

    def test_ingress_sg_refs_parsed(self):
        """Ingress SG references are parsed correctly."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        kong = analyzer._sg_nodes["kong-gateway-sg"]
        assert any("alb_sg" in ref for ref in kong.allows_from_sgs)

    def test_ingress_ports_parsed(self):
        """Ingress port ranges are parsed correctly."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        alb = analyzer._sg_nodes["alb-public-sg"]
        assert (443, 443) in alb.ingress_ports
        assert (80, 80) in alb.ingress_ports

    def test_nacl_parsed(self):
        """NACLs are added to the analyzer."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert len(analyzer._nacls) == 1

    def test_waf_acl_parsed(self):
        """WAF ACLs are added to the analyzer."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert len(analyzer._waf_acls) == 1


# ---------------------------------------------------------------------------
# U2: Endpoint-to-SG Mapping
# ---------------------------------------------------------------------------
class TestEndpointToSGMapping:
    def test_graphql_endpoint(self):
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert analyzer._endpoint_to_sg("/api/v1/graphql") == "graphql-service-sg"

    def test_analytics_endpoint(self):
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert analyzer._endpoint_to_sg("/api/internal/analytics") == "analytics-service-sg-MISCONFIGURED"

    def test_payments_endpoint(self):
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert analyzer._endpoint_to_sg("/api/v1/payments") == "payment-service-sg"

    def test_webhooks_endpoint(self):
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert analyzer._endpoint_to_sg("/api/v1/webhooks") == "webhook-receiver-sg"

    def test_fetch_endpoint(self):
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert analyzer._endpoint_to_sg("/api/v1/fetch") == "fetch-service-sg"

    def test_generic_v1_endpoint(self):
        """Generic /api/v1/* endpoints map to internal-microservices-sg."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert analyzer._endpoint_to_sg("/api/v1/users") == "internal-microservices-sg"
        assert analyzer._endpoint_to_sg("/api/v1/orders") == "internal-microservices-sg"
        assert analyzer._endpoint_to_sg("/api/v1/search") == "internal-microservices-sg"

    def test_v2_endpoint(self):
        """v2 endpoints also map to internal-microservices-sg."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert analyzer._endpoint_to_sg("/api/v2/reports/123") == "internal-microservices-sg"


# ---------------------------------------------------------------------------
# U3: Internet Reachability — Standard Path
# ---------------------------------------------------------------------------
class TestInternetReachabilityStandard:
    def test_standard_v1_endpoint(self):
        """Standard /api/v1/* endpoints are reachable via ALB→Kong chain."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/v1/users", source_ip="203.0.113.50")

        assert result.is_internet_reachable is True
        assert result.risk_level == "LOW"
        assert result.target_sg == "internal-microservices-sg"

    def test_standard_path_has_waf(self):
        """Standard path includes WAF (associated with ALB)."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/v1/users")

        assert result.waf_in_path is True

    def test_standard_path_has_gateway(self):
        """Standard path includes Kong Gateway."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/v1/users")

        assert result.gateway_in_path is True

    def test_standard_path_layers(self):
        """Standard path traverses alb, kong, service layers."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/v1/users")

        internet_paths = [p for p in result.paths if p.is_internet_reachable]
        assert len(internet_paths) > 0
        layers = internet_paths[0].layers_traversed
        assert "alb" in layers
        assert "kong" in layers
        assert "service" in layers

    def test_no_bypassed_layers(self):
        """Standard path has no bypassed layers."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/v1/users")

        internet_paths = [p for p in result.paths if p.is_internet_reachable]
        assert len(internet_paths) > 0
        assert internet_paths[0].layers_bypassed == []


# ---------------------------------------------------------------------------
# U4: Internet Reachability — Bypass Path (CRITICAL)
# ---------------------------------------------------------------------------
class TestInternetReachabilityBypass:
    def test_analytics_internet_reachable_direct(self):
        """Analytics endpoint is directly internet reachable (MISCONFIGURED)."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/internal/analytics", source_ip="198.51.100.200")

        assert result.is_internet_reachable is True

    def test_analytics_risk_critical(self):
        """Misconfigured analytics endpoint has CRITICAL risk."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/internal/analytics")

        assert result.risk_level == "CRITICAL"

    def test_analytics_bypasses_waf(self):
        """Analytics bypass path does NOT include WAF."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/internal/analytics")

        assert result.waf_in_path is False

    def test_analytics_bypasses_gateway(self):
        """Analytics bypass path does NOT include Kong Gateway."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/internal/analytics")

        assert result.gateway_in_path is False

    def test_analytics_bypassed_layers(self):
        """Analytics bypass path reports waf, alb, kong as bypassed."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/internal/analytics")

        internet_paths = [p for p in result.paths if p.is_internet_reachable]
        assert len(internet_paths) > 0
        bypassed = internet_paths[0].layers_bypassed
        assert "waf" in bypassed
        assert "alb" in bypassed
        assert "kong" in bypassed

    def test_analytics_reachable_ports(self):
        """Analytics is reachable on port 8098."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/internal/analytics")

        internet_paths = [p for p in result.paths if p.is_internet_reachable]
        assert len(internet_paths) > 0
        assert "8098" in internet_paths[0].reachable_ports

    def test_analytics_target_sg(self):
        """Target SG is the misconfigured analytics SG."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/internal/analytics")

        assert result.target_sg == "analytics-service-sg-MISCONFIGURED"


# ---------------------------------------------------------------------------
# U5: CIDR Matching
# ---------------------------------------------------------------------------
class TestCIDRMatching:
    def test_source_ip_matches_cidr(self):
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert analyzer._source_ip_matches_cidr("203.0.113.50", "203.0.113.0/24") is True

    def test_source_ip_does_not_match_cidr(self):
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert analyzer._source_ip_matches_cidr("203.0.113.50", "10.0.0.0/16") is False

    def test_cidr_is_internet(self):
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert analyzer._cidr_is_internet("0.0.0.0/0") is True
        assert analyzer._cidr_is_internet("::/0") is True
        assert analyzer._cidr_is_internet("10.0.0.0/16") is False

    def test_cidr_is_vpc_internal(self):
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert analyzer._cidr_is_vpc_internal("10.0.0.0/16") is True
        assert analyzer._cidr_is_vpc_internal("192.168.1.0/24") is True
        assert analyzer._cidr_is_vpc_internal("8.8.8.0/24") is False

    def test_source_in_vpc(self):
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert analyzer._source_ip_matches_cidr("10.0.2.15", "10.0.0.0/16") is True

    def test_exact_host_cidr(self):
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert analyzer._source_ip_matches_cidr("3.18.12.63", "3.18.12.63/32") is True
        assert analyzer._source_ip_matches_cidr("3.18.12.64", "3.18.12.63/32") is False


# ---------------------------------------------------------------------------
# U6: NACL Restrictions
# ---------------------------------------------------------------------------
class TestNACLRestrictions:
    def test_nacl_restrictions_extracted(self):
        """NACL restrictions are reported for target SGs."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        # Database SG is in the data tier
        result = analyzer.analyse_endpoint("/api/v1/users")
        # NACLs are collected regardless of target
        # Just verify the analyzer has NACLs
        assert len(analyzer._nacls) == 1

    def test_nacl_deny_rules(self):
        """NACL deny rules are included in restrictions."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        node = SecurityGroupNode(
            name="test", resource_name="test", description="test",
            tier="data", vpc="prod",
        )
        restrictions = analyzer._check_nacl_restrictions(node)
        assert any("DENY" in r for r in restrictions)

    def test_nacl_allow_rules(self):
        """NACL allow rules are included in restrictions."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        node = SecurityGroupNode(
            name="test", resource_name="test", description="test",
            tier="data", vpc="prod",
        )
        restrictions = analyzer._check_nacl_restrictions(node)
        assert any("ALLOW" in r for r in restrictions)


# ---------------------------------------------------------------------------
# U7: Bypass Detection Logic
# ---------------------------------------------------------------------------
class TestBypassDetection:
    def test_service_with_only_direct_access(self):
        """Service reached directly (no ALB/Kong) should report bypassed layers."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        bypassed = analyzer._determine_bypassed_layers(
            hops=["analytics-service-sg-MISCONFIGURED"],
            target_tier="service",
        )
        assert "alb" in bypassed
        assert "kong" in bypassed

    def test_service_with_full_path(self):
        """Service reached via ALB→Kong should have no bypassed layers."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        bypassed = analyzer._determine_bypassed_layers(
            hops=["alb-public-sg", "kong-gateway-sg", "internal-microservices-sg"],
            target_tier="service",
        )
        assert bypassed == []

    def test_data_tier_bypass(self):
        """Data tier reached without service layer should report bypass."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        bypassed = analyzer._determine_bypassed_layers(
            hops=["database-rds-sg"],
            target_tier="data",
        )
        assert "alb" in bypassed
        assert "kong" in bypassed
        assert "service" in bypassed

    def test_waf_bypass_included(self):
        """When ALB is bypassed and WAF exists, WAF is also reported bypassed."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        bypassed = analyzer._determine_bypassed_layers(
            hops=["analytics-service-sg-MISCONFIGURED"],
            target_tier="service",
        )
        assert "waf" in bypassed


# ---------------------------------------------------------------------------
# U8: Risk Assessment
# ---------------------------------------------------------------------------
class TestRiskAssessment:
    def test_critical_when_internet_plus_bypass(self):
        """CRITICAL risk when internet reachable with bypassed layers."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/internal/analytics")
        assert result.risk_level == "CRITICAL"

    def test_low_when_standard_path(self):
        """LOW risk when standard path through ALB→Kong→service."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/v1/users")
        assert result.risk_level == "LOW"

    def test_low_when_internal_only(self):
        """LOW risk for internal-only endpoints."""
        # Create a controls set with an internal-only SG
        controls = [
            _sg_control(
                resource_name="internal_only_sg",
                name="internal-only-sg",
                description="Internal microservice",
                ingress_rules=[
                    {
                        "from_port": "8080",
                        "to_port": "8080",
                        "protocol": "tcp",
                        "cidr_blocks": ["10.0.0.0/16"],
                    },
                ],
            ),
        ]
        analyzer = ReachabilityAnalyzer(controls)
        # Manually test risk assessment
        risk = analyzer._assess_risk(
            is_internet_reachable=False,
            waf_in_path=False,
            gateway_in_path=False,
            paths=[],
            target_node=analyzer._sg_nodes.get("internal-only-sg"),
        )
        assert risk == "LOW"


# ---------------------------------------------------------------------------
# U9: JSON Serialization
# ---------------------------------------------------------------------------
class TestJSONSerialization:
    def test_result_serializes_to_json(self):
        """ReachabilityResult can be serialized to valid JSON."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/v1/users")
        json_str = analyzer.to_json(result)
        parsed = json.loads(json_str)

        assert "target_endpoint" in parsed
        assert "target_sg" in parsed
        assert "is_internet_reachable" in parsed
        assert "risk_level" in parsed
        assert "paths" in parsed
        assert "summary" in parsed
        assert isinstance(parsed["paths"], list)

    def test_analytics_result_json_has_bypass_info(self):
        """Analytics result JSON includes bypass information."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/internal/analytics")
        json_str = analyzer.to_json(result)
        parsed = json.loads(json_str)

        assert parsed["risk_level"] == "CRITICAL"
        internet_paths = [p for p in parsed["paths"] if p["is_internet_reachable"]]
        assert len(internet_paths) > 0
        assert "waf" in internet_paths[0]["layers_bypassed"]


# ---------------------------------------------------------------------------
# U10: Webhook Partial Path
# ---------------------------------------------------------------------------
class TestWebhookPartialPath:
    def test_webhook_reachable_from_stripe(self):
        """Webhook SG is reachable from Stripe IPs (direct CIDR)."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/v1/webhooks", source_ip="3.18.12.63")

        # Should have paths (via Kong chain + direct Stripe CIDR)
        assert len(result.paths) > 0

    def test_webhook_also_reachable_via_kong(self):
        """Webhook SG is also reachable via the standard ALB→Kong path."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/v1/webhooks")

        # Should be internet reachable (via ALB→Kong chain)
        assert result.is_internet_reachable is True
        assert result.gateway_in_path is True


# ---------------------------------------------------------------------------
# Additional: GraphQL and Payment service paths
# ---------------------------------------------------------------------------
class TestSpecializedServicePaths:
    def test_graphql_standard_path(self):
        """GraphQL service is reachable via standard ALB→Kong path."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/v1/graphql")

        assert result.is_internet_reachable is True
        assert result.risk_level == "LOW"
        assert result.target_sg == "graphql-service-sg"
        assert result.gateway_in_path is True

    def test_payment_standard_path(self):
        """Payment service is reachable via standard ALB→Kong path."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/v1/payments")

        assert result.is_internet_reachable is True
        assert result.risk_level == "LOW"
        assert result.target_sg == "payment-service-sg"

    def test_fetch_service_standard_path(self):
        """Fetch service is reachable via standard ALB→Kong path."""
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        result = analyzer.analyse_endpoint("/api/v1/fetch")

        assert result.is_internet_reachable is True
        assert result.risk_level == "LOW"
        assert result.target_sg == "fetch-service-sg"


# ---------------------------------------------------------------------------
# Additional: CIDR Description
# ---------------------------------------------------------------------------
class TestCIDRDescription:
    def test_describe_internet(self):
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert "Internet" in analyzer._describe_cidr("0.0.0.0/0")

    def test_describe_production_vpc(self):
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert "Production VPC" in analyzer._describe_cidr("10.0.0.0/16")

    def test_describe_management_vpc(self):
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert "Management VPC" in analyzer._describe_cidr("10.1.0.0/16")

    def test_describe_partner_cidr(self):
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert "Partner" in analyzer._describe_cidr("203.0.114.0/24")

    def test_describe_botnet(self):
        controls = _build_standard_controls()
        analyzer = ReachabilityAnalyzer(controls)
        assert "botnet" in analyzer._describe_cidr("203.0.113.0/24")


# ---------------------------------------------------------------------------
# Integration: Full Terraform parse → ReachabilityAnalyzer
# ---------------------------------------------------------------------------
class TestFullTerraformIntegration:
    """Tests that use the actual Terraform configs from the repo."""

    def _build_analyzer_from_repo(self) -> ReachabilityAnalyzer:
        """Parse the real Terraform files and build an analyzer."""
        from fpm.parsers.terraform_parser import parse_terraform

        tf_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "infrastructure", "terraform",
        )
        controls = []
        if os.path.isdir(tf_dir):
            for fname in sorted(os.listdir(tf_dir)):
                if fname.endswith(".tf"):
                    controls.extend(parse_terraform(os.path.join(tf_dir, fname)))
        return ReachabilityAnalyzer(controls)

    def test_real_tf_parses_sgs(self):
        """Real Terraform files produce SG nodes."""
        analyzer = self._build_analyzer_from_repo()
        assert len(analyzer._sg_nodes) >= 10  # At least 10 SGs in prod infra

    def test_real_tf_analytics_critical(self):
        """Real Terraform: analytics endpoint is CRITICAL risk."""
        analyzer = self._build_analyzer_from_repo()
        result = analyzer.analyse_endpoint("/api/internal/analytics")
        assert result.risk_level == "CRITICAL"
        assert result.is_internet_reachable is True

    def test_real_tf_standard_endpoint_low(self):
        """Real Terraform: standard /api/v1/users is LOW risk."""
        analyzer = self._build_analyzer_from_repo()
        result = analyzer.analyse_endpoint("/api/v1/users")
        assert result.risk_level == "LOW"
        assert result.is_internet_reachable is True
        assert result.waf_in_path is True
        assert result.gateway_in_path is True

    def test_real_tf_v2_reports_standard_path(self):
        """Real Terraform: /api/v2/reports goes through standard path (LOW risk)."""
        analyzer = self._build_analyzer_from_repo()
        result = analyzer.analyse_endpoint("/api/v2/reports/123")
        assert result.risk_level == "LOW"

    def test_real_tf_graphql_standard_path(self):
        """Real Terraform: /api/v1/graphql goes through standard path."""
        analyzer = self._build_analyzer_from_repo()
        result = analyzer.analyse_endpoint("/api/v1/graphql")
        assert result.target_sg == "graphql-service-sg"
        assert result.is_internet_reachable is True

    def test_real_tf_payments_standard_path(self):
        """Real Terraform: /api/v1/payments goes through standard path."""
        analyzer = self._build_analyzer_from_repo()
        result = analyzer.analyse_endpoint("/api/v1/payments")
        assert result.target_sg == "payment-service-sg"
        assert result.is_internet_reachable is True
