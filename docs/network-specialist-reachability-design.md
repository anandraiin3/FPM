# Network Specialist Agent — Reachability Analysis Design Document

> Version 1.0 | April 2026

---

## 1. Overview

The Network Specialist Agent is one of three specialist agents in the FPM multi-agent system. Its original scope was limited to searching the knowledge base for Terraform security groups, NACLs, and WAF associations relevant to an alert. This document describes the **reachability analysis** enhancement that transforms the Network Specialist from a passive control-lookup agent into an active **network path tracer** that determines *whether* and *how* a target endpoint is reachable from a given source.

### 1.1 Problem

The original Network Specialist could find that a security group existed for a service, but it could not determine:

- Whether the attacker's traffic actually *traverses* that security group
- Whether there is a **bypass path** that skips critical security layers (WAF, ALB, Kong Gateway)
- Whether a misconfigured SG allows direct internet access to an internal service

This made it impossible to correctly classify alerts like **TP #38** (analytics service with a misconfigured SG that allows `0.0.0.0/0` inbound, bypassing all security layers).

### 1.2 Solution

The Network Specialist now has a **reachability analysis tool** (`analyse_reachability`) that builds a directed graph from Terraform security group configurations and traces all possible network paths from source to target. This enables the agent to report:

1. **Is the endpoint internet-reachable?**
2. **From exactly which sources (CIDRs) is it reachable?**
3. **What is the full traffic path?** (e.g., `Internet → ALB SG → Kong SG → Service SG`)
4. **Which security layers are in the path vs. bypassed?**
5. **What is the risk level based on exposure?**

---

## 2. Architecture

### 2.1 Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    FPM Orchestrator Agent                     │
│                                                               │
│  Calls all 3 specialists, synthesises findings into verdict   │
└───────────┬──────────────────┬──────────────────┬────────────┘
            │                  │                  │
   ┌────────▼───────┐  ┌──────▼────────┐  ┌──────▼──────────────┐
   │ WAF Specialist  │  │ Kong Gateway  │  │ Network Specialist   │
   │                 │  │ Specialist    │  │                      │
   │ Tools:          │  │ Tools:        │  │ Tools:               │
   │ • search_waf    │  │ • search_gw   │  │ • search_network     │
   │   _controls     │  │   _controls   │  │   _controls          │
   │                 │  │               │  │ • analyse_reachability│
   └─────────────────┘  └───────────────┘  └──────────┬───────────┘
                                                       │
                                              ┌────────▼──────────┐
                                              │  Reachability      │
                                              │  Analyzer          │
                                              │                    │
                                              │  • SG Graph        │
                                              │  • Path Tracer     │
                                              │  • Risk Assessor   │
                                              └────────┬───────────┘
                                                       │
                                              ┌────────▼──────────┐
                                              │  Terraform Parser  │
                                              │                    │
                                              │  Parsed controls:  │
                                              │  • Security Groups │
                                              │  • NACLs           │
                                              │  • WAF ACLs        │
                                              │  • Shield          │
                                              │  • VPC Endpoints   │
                                              │  • Transit Gateway │
                                              └───────────────────┘
```

### 2.2 Data Flow

```
1. FPM starts up
   │
   ├─► Terraform parser extracts all controls from main.tf
   │     └─► 12 Security Groups, 2 NACLs, 1 WAF ACL, 1 Shield,
   │         3 VPC Endpoints, 1 Transit Gateway, 2 IP Sets, 1 Regex Set
   │
   ├─► ReachabilityAnalyzer builds graph from parsed controls
   │     └─► Each SG becomes a node
   │     └─► Ingress rules (SG refs + CIDRs) become edges
   │     └─► Nodes classified into tiers: alb, kong, service, data, bastion
   │
   └─► Analyzer passed to Orchestrator → Network Specialist

2. Alert arrives (e.g., SSRF on /api/internal/analytics)
   │
   ├─► Orchestrator calls analyse_network_layer()
   │     │
   │     ├─► Network Specialist calls analyse_reachability(
   │     │     target_endpoint="/api/internal/analytics",
   │     │     source_ip="10.200.50.1"
   │     │   )
   │     │
   │     ├─► Analyzer maps endpoint → "analytics-service-sg-MISCONFIGURED"
   │     │
   │     ├─► Analyzer traces all paths to that SG:
   │     │     Path 1: Internet (0.0.0.0/0) → analytics-sg [DIRECT]
   │     │       └─► Bypasses: WAF, ALB, Kong Gateway
   │     │       └─► Risk: CRITICAL
   │     │
   │     └─► Returns structured JSON with paths, risk, bypassed layers
   │
   └─► Orchestrator weighs reachability: "Kong plugins are IRRELEVANT
       because traffic bypasses Kong entirely" → TRUE_POSITIVE
```

---

## 3. Reachability Graph Model

### 3.1 Nodes

Each security group in Terraform becomes a `SecurityGroupNode` with:

| Field | Description |
|-------|-------------|
| `name` | SG name (e.g., `alb-public-sg`) |
| `resource_name` | Terraform resource name (e.g., `alb_sg`) |
| `description` | Human-readable purpose |
| `tier` | Architecture tier: `alb`, `kong`, `service`, `data`, `bastion`, `infrastructure` |
| `vpc` | Which VPC: `prod` or `management` |
| `allows_from_sgs` | Upstream SGs that can send traffic to this SG |
| `allows_from_cidrs` | CIDR ranges allowed inbound |
| `ingress_ports` | Allowed port ranges |

### 3.2 Tier Classification

The analyzer classifies SGs into tiers using name and description heuristics:

```
alb-public-sg              → tier: alb
kong-gateway-sg            → tier: kong
internal-microservices-sg  → tier: service
graphql-service-sg         → tier: service
payment-service-sg         → tier: service
analytics-service-sg-*     → tier: service
database-sg                → tier: data
redis-cache-sg             → tier: data
bastion-host-sg            → tier: bastion
vpc-endpoints-sg           → tier: infrastructure
```

### 3.3 Edges

Edges are derived from SG ingress rules:

- **SG-to-SG references** (e.g., `security_groups = [aws_security_group.kong_sg.id]`) create a directed edge from the referenced SG to the current SG.
- **CIDR-based rules** (e.g., `cidr_blocks = ["0.0.0.0/0"]`) create an edge from that CIDR source to the current SG.

### 3.4 Standard Traffic Path

For a typical API request, the expected path through the architecture is:

```
Internet → WAF (associated with ALB) → ALB SG → Kong SG → Service SG → Data SG
```

Any path that deviates from this is flagged. For example:

```
Internet → analytics-sg  (BYPASSES: WAF, ALB, Kong)  →  CRITICAL RISK
```

---

## 4. Reachability Analysis Algorithm

### 4.1 Endpoint-to-SG Mapping

The analyzer maps API endpoints to their governing security group:

```python
# Known endpoint → SG mappings
/api/v1/graphql          → graphql-service-sg
/api/v1/webhooks         → webhook-receiver-sg
/api/v1/payments         → payment-service-sg
/api/v1/fetch            → fetch-service-sg
/api/internal/analytics  → analytics-service-sg-MISCONFIGURED
/api/v1/*  (default)     → internal-microservices-sg
/api/v2/*  (default)     → internal-microservices-sg
```

### 4.2 Path Tracing

For a given target SG, the analyzer:

1. **Check direct internet access**: Scan the target SG's ingress rules for `0.0.0.0/0`. If found, this is a direct bypass path.

2. **Trace SG chain upstream**: For each SG reference in the target's ingress rules, recursively trace upstream until reaching an SG with internet access (`0.0.0.0/0`) or a specific CIDR source.

3. **Check specific CIDR sources**: Identify non-internet CIDRs (VPC internal, partner IPs, corporate VPN) that can reach the target.

4. **Depth limiting**: Recursion is capped at 10 to prevent infinite loops in misconfigured graphs.

### 4.3 Pseudocode

```
function trace_all_paths(target_sg, source_ip):
    paths = []

    # 1. Direct internet access
    for cidr in target_sg.allows_from_cidrs:
        if cidr == "0.0.0.0/0":
            paths.add(Path(
                source="Internet",
                hops=[target_sg],
                bypassed=determine_bypassed_layers(["internet", target_sg]),
                risk="CRITICAL"
            ))

    # 2. Upstream SG chain
    for sg_ref in target_sg.allows_from_sgs:
        upstream_sg = resolve(sg_ref)
        upstream_paths = trace_upstream(upstream_sg, [target_sg], depth=0)
        paths.extend(upstream_paths)

    # 3. Specific CIDR sources
    for cidr in target_sg.allows_from_cidrs:
        if cidr != "0.0.0.0/0":
            paths.add(Path(source=describe(cidr), hops=[cidr, target_sg]))

    return paths

function determine_bypassed_layers(hops, target_tier):
    traversed = {node.tier for node in hops}
    if target_tier == "service":
        expected = ["alb", "kong"]
    return [layer for layer in expected if layer not in traversed]
```

### 4.4 Layer Bypass Detection

The critical insight: **a control that exists but is not in the traffic path provides no protection**.

| Scenario | Layers in Path | Layers Bypassed | Impact |
|----------|---------------|-----------------|--------|
| Normal `/api/v1/*` request | WAF, ALB, Kong, Service | None | All controls apply |
| Misconfigured analytics SG (`0.0.0.0/0`) | Service only | WAF, ALB, Kong | Kong auth plugins irrelevant. WAF rules irrelevant. Only SG rules apply. |
| Webhook from Stripe IP | Kong, Service | ALB (partial) | WAF may not apply if webhook bypasses ALB |
| Bastion SSH from VPN | Bastion | WAF, ALB, Kong | Expected — not a risk for bastion access |

---

## 5. Risk Assessment

### 5.1 Risk Levels

| Level | Criteria |
|-------|----------|
| **CRITICAL** | Internet-reachable AND bypasses 2+ security layers (WAF + Gateway) |
| **HIGH** | Internet-reachable AND bypasses Gateway (no auth/rate-limit at gateway) |
| **MEDIUM** | Internet-reachable through non-standard path with some controls |
| **LOW** | Standard path through all layers, OR only VPC-internal access |

### 5.2 Risk Examples from Our Infrastructure

| Endpoint | Target SG | Internet Reachable | Risk | Reason |
|----------|-----------|-------------------|------|--------|
| `/api/v1/users` | internal-microservices-sg | Yes (via ALB→Kong) | LOW | Standard path, all layers active |
| `/api/v1/graphql` | graphql-service-sg | Yes (via ALB→Kong) | LOW | Standard path, dedicated SG |
| `/api/v1/payments` | payment-service-sg | Yes (via ALB→Kong) | LOW | Standard path, strict egress |
| `/api/internal/analytics` | analytics-sg-MISCONFIGURED | **Yes (DIRECT)** | **CRITICAL** | Bypasses WAF, ALB, Kong |
| `/api/v1/admin/bulk` | internal-microservices-sg | Yes (via ALB→Kong) | LOW | Standard path (but missing ACL — detected by Gateway agent, not reachability) |

---

## 6. Integration with Orchestrator

### 6.1 How Reachability Changes Verdicts

The Orchestrator's updated instructions incorporate reachability awareness:

**Before reachability** (Phase 1):
```
WAF Agent:   "ModSecurity rules exist for this attack"     → mitigates
Kong Agent:  "No auth plugin on this route"                 → gap
Network:     "SG exists for analytics service"              → mitigates
Verdict:     PARTIAL_RISK (controls found, one gap)
```

**After reachability** (Phase 2):
```
WAF Agent:   "ModSecurity rules exist for this attack"     → mitigates
Kong Agent:  "No auth plugin on this route"                 → gap
Network:     "analytics-sg allows 0.0.0.0/0 on port 8098.
              Traffic path: Internet → analytics-sg.
              BYPASSES: WAF, ALB, Kong.
              Risk: CRITICAL"                               → CRITICAL bypass
Verdict:     TRUE_POSITIVE — WAF rules exist but are bypassed because
             traffic reaches the service directly without passing through
             the ALB (where WAF is attached) or Kong Gateway.
```

### 6.2 Verdict Output Schema

The orchestrator's JSON verdict now includes a `reachability` field:

```json
{
  "verdict": "TRUE_POSITIVE",
  "confidence": 0.95,
  "reasoning": "The analytics service is directly accessible from the internet...",
  "controls_found": [],
  "coverage_gaps": [
    "SG allows 0.0.0.0/0 inbound — should only allow from Kong SG",
    "No Kong auth plugins on analytics route",
    "WAF bypassed — traffic does not pass through ALB"
  ],
  "recommended_action": "Restrict analytics-sg ingress to Kong SG only. Add JWT auth plugin to analytics route in Kong.",
  "reachability": {
    "internet_reachable": true,
    "risk_level": "CRITICAL",
    "traffic_path": "Internet → analytics-service-sg-MISCONFIGURED",
    "layers_bypassed": ["waf", "alb", "kong"]
  }
}
```

---

## 7. Network Specialist Agent Tools

### 7.1 `search_network_controls`

**Purpose**: Search the knowledge base for Network-layer controls (security groups, NACLs, WAF ACLs).

**Input**: `query` (string) — natural language search query.

**Output**: JSON array of matching controls with control_id, text excerpt, and rerank score.

**When to use**: To find specific controls relevant to the alert (e.g., "security group for payment service egress rules").

### 7.2 `analyse_reachability`

**Purpose**: Perform full reachability analysis on a target endpoint.

**Input**:
- `target_endpoint` (string, required) — the API path (e.g., `/api/v1/graphql`)
- `source_ip` (string, optional) — source IP to check specific reachability from

**Output**: JSON object containing:
- `target_sg`: the security group governing the endpoint
- `is_internet_reachable`: boolean
- `reachable_from`: list of CIDR sources
- `risk_level`: LOW / MEDIUM / HIGH / CRITICAL
- `waf_in_path`: boolean
- `gateway_in_path`: boolean
- `paths`: array of path objects, each with:
  - `source`: human-readable source description
  - `hops`: ordered list of SG names traversed
  - `layers_traversed`: security layers in the path
  - `layers_bypassed`: security layers NOT in the path
  - `risk_notes`: warnings about the path
- `summary`: human-readable analysis

**When to use**: ALWAYS — the Network Specialist must call this for every alert to determine the actual traffic path.

---

## 8. MCP Exposure

The reachability analysis is also exposed as an MCP tool (`analyse_reachability`) for external clients:

```json
{
  "name": "analyse_reachability",
  "description": "Perform network reachability analysis on a target endpoint...",
  "inputSchema": {
    "type": "object",
    "properties": {
      "target_endpoint": { "type": "string" },
      "source_ip": { "type": "string" }
    },
    "required": ["target_endpoint"]
  }
}
```

This allows Claude Desktop or other MCP clients to query reachability independently of alert analysis.

---

## 9. Limitations and Future Work

### 9.1 Current Limitations

1. **Static endpoint-to-SG mapping**: The mapping from API endpoints to security groups is based on naming conventions and a hardcoded map. A more robust approach would parse Kong routes to determine which upstream service handles each endpoint, then map services to SGs.

2. **No dynamic route resolution**: The analyzer does not parse Kong YAML to determine which service handles a given endpoint. This is handled by the Kong Gateway Specialist separately.

3. **No cross-VPC path tracing**: While the Transit Gateway is parsed, the analyzer does not yet trace cross-VPC paths (e.g., management VPC → prod VPC via TGW).

4. **SG reference resolution assumes standard naming**: Terraform SG references like `aws_security_group.kong_sg.id` are resolved by matching the resource name portion. Complex references (e.g., via variables or modules) are not supported.

### 9.2 Future Enhancements

1. **Kong-aware endpoint resolution**: Integrate Kong parser output to dynamically map endpoints to services to SGs.

2. **NACL integration in path analysis**: Currently NACLs are reported separately. They should be evaluated as part of the path (a NACL deny rule on the subnet could block traffic even if the SG allows it).

3. **Egress analysis**: Trace outbound paths for SSRF detection — determine where a compromised service can reach (e.g., fetch-service-sg only allows egress to partner CIDR, preventing SSRF to internal IPs).

4. **Visual graph output**: Generate a network topology diagram showing all paths, color-coded by risk level.

5. **Temporal analysis**: Compare SG configurations over time (via Terraform state) to detect configuration drift that introduces bypass paths.

---

## 10. Appendix: Full SG Topology (Current Infrastructure)

```
                        ┌─────────────┐
                        │  Internet   │
                        │ 0.0.0.0/0   │
                        └──────┬──────┘
                               │
                    ┌──────────┼──────────────────────┐
                    │          │                       │
                    ▼          ▼                       ▼
          ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐
          │ WAF v2 ACL  │  │ Webhook SG   │  │ analytics-sg        │
          │ (on ALB)    │  │ (Stripe IPs) │  │ !! MISCONFIGURED !! │
          └──────┬──────┘  └──────┬───────┘  │ 0.0.0.0/0:8098     │
                 │                │           └─────────────────────┘
                 ▼                │              ⚠ BYPASSES ALL
          ┌─────────────┐        │
          │  ALB SG     │        │
          │ :443 :80    │        │
          └──────┬──────┘        │
                 │                │
                 ▼                │
          ┌─────────────┐        │
          │  Kong SG    │◄───────┘
          │ :8000 :8443 │
          │ :9080 (gRPC)│
          └──────┬──────┘
                 │
      ┌──────────┼────────────┬─────────────┬──────────────┐
      │          │            │             │              │
      ▼          ▼            ▼             ▼              ▼
┌──────────┐┌──────────┐┌──────────┐┌───────────┐┌────────────┐
│ Micro-   ││ GraphQL  ││ Payment  ││ Fetch     ││ Webhook    │
│ services ││ SG       ││ SG       ││ SG        ││ SG         │
│ SG       ││ :8095    ││ :8097    ││ :8085     ││ :8096      │
│:8080-8090││          ││          ││           ││            │
└────┬─────┘└────┬─────┘└────┬─────┘└───────────┘└────────────┘
     │           │           │
     ▼           ▼           ▼
┌──────────┐┌──────────┐
│ Database ││ Redis    │
│ SG       ││ SG       │
│ :5432    ││ :6379    │
│ :3306    ││          │
└──────────┘└──────────┘

Legend:
  ─── Standard path (all layers traversed)
  ⚠   Bypass path (security layers skipped)
```
