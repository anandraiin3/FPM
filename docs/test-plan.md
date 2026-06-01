# FPM System Test Plan

> Version 1.0 | April 2026

---

## 1. Objectives

This test plan validates the complete FPM system across five dimensions:

1. **Verdict Correctness** — Does the system return the right verdict (FP/TP) for each alert?
2. **Retrieval Quality** — Does the hybrid search return relevant infrastructure controls?
3. **Reachability Accuracy** — Does the Network Specialist correctly trace network paths and detect bypass routes?
4. **Agent Reasoning** — Do the specialist agents produce sound, evidence-based reasoning?
5. **System Reliability** — Does the end-to-end pipeline handle errors, edge cases, and restart gracefully?

---

## 2. Test Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                          Test Layers                            │
├──────────────┬──────────────┬─────────────┬────────────────────┤
│  Unit Tests  │  Component   │ Integration │  End-to-End (E2E)  │
│              │  Tests       │ Tests       │  + RAGAS Metrics    │
├──────────────┼──────────────┼─────────────┼────────────────────┤
│ Reachability │ Terraform    │ Mock Server │ Full pipeline:     │
│ graph logic  │ Parser →     │ + FPM       │ alert → verdict    │
│              │ Analyzer     │ orchestrator│ on all 38 alerts   │
│ Endpoint-to- │              │             │                    │
│ SG mapping   │ Knowledge    │ Polling     │ RAGAS evaluation   │
│              │ base build   │ loop retry  │ with ground truth  │
│ CIDR match   │ + retrieval  │ logic       │                    │
│ logic        │              │             │ Reachability        │
│              │ Agent tool   │ MCP server  │ accuracy metrics   │
│              │ invocation   │ tools       │                    │
└──────────────┴──────────────┴─────────────┴────────────────────┘
```

---

## 3. Test Data Design

### 3.1 Alert Categories

| Category | Count | Template IDs | Purpose |
|----------|-------|-------------|---------|
| Phase 1 FP (standard) | 20 | `fp-missing-auth-orders` through `fp-dos-regex-validate` | Basic attack types with clear compensating controls |
| Phase 2 FP (complex) | 15 | `fp-graphql-depth-attack` through `fp-payment-fraud` | Multi-layer, multi-control scenarios |
| Phase 1 TP (no controls) | 1 | `tp-missing-auth-v2-reports` | Route with no plugins at all |
| Phase 2 TP (broken auth) | 1 | `tp-broken-function-auth-admin-bulk` | JWT exists but no ACL — subtle gap |
| Phase 2 TP (network bypass) | 1 | `tp-ssrf-analytics-misconfigured` | Misconfigured SG bypasses all layers |

### 3.2 Test Data Matrix — Full 38 Alerts

Each row defines the expected behavior across all test dimensions:

| # | Template ID | Attack Type | Endpoint | Expected Verdict | Expected Confidence | Internet Reachable | Expected Risk | Expected Path | Key Controls |
|---|-------------|------------|----------|-----------------|--------------------|--------------------|--------------|---------------|-------------|
| 1 | `fp-missing-auth-orders` | MISSING_AUTHENTICATION | /api/v1/orders | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | Kong JWT plugin |
| 2 | `fp-inadequate-auth-config` | INADEQUATE_AUTHENTICATION | /api/v1/internal/config | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | Kong IP-restriction + key-auth |
| 3 | `fp-sqli-users` | SQL_INJECTION | /api/v1/users | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | ModSecurity 1001 + CRS 942 + WAF SQLi |
| 4 | `fp-xss-search` | XSS | /api/v1/search | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | ModSecurity CRS 941 + Kong request-validator |
| 5 | `fp-rate-abuse-login` | RATE_ABUSE | /api/v1/login | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | NGINX auth zone 10r/m + Kong rate-limiting |
| 6 | `fp-credential-stuffing-auth` | CREDENTIAL_STUFFING | /api/v1/auth | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | NGINX auth zone + Kong rate-limiting + IP restriction (deny 203.0.113.0/24) |
| 7 | `fp-unauth-access-admin` | UNAUTHORIZED_ACCESS | /api/v1/internal/admin | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | Kong IP-restriction + JWT + ACL |
| 8 | `fp-bot-traffic-products` | BOT_TRAFFIC | /api/v1/products | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | Kong bot-detection plugin |
| 9 | `fp-bola-users` | BOLA | /api/v1/users/{id} | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | Kong JWT (sub claim validation) |
| 10 | `fp-api-key-exposure-data` | API_KEY_EXPOSURE | /api/v1/data | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | Kong request-transformer (strip api_key) |
| 11 | `fp-oversized-payload-upload` | OVERSIZED_PAYLOAD | /api/v1/upload | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | NGINX 10MB + ModSecurity 1007 + Kong request-size-limiting |
| 12 | `fp-sqli-double-search` | SQL_INJECTION | /api/v1/search | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | ModSecurity 1001 + CRS 942 + Kong request-validator |
| 13 | `fp-path-traversal-files` | PATH_TRAVERSAL | /api/v1/files | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | ModSecurity 1003 + CRS 930 |
| 14 | `fp-command-injection-exec` | COMMAND_INJECTION | /api/v1/exec | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | ModSecurity 1004 + CRS 932 + Kong IP-restriction |
| 15 | `fp-ssrf-fetch` | SSRF | /api/v1/fetch | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → fetch-service-sg | fetch-service-sg egress restricted to partner CIDR only |
| 16 | `fp-brute-force-reset` | BRUTE_FORCE | /api/v1/reset-password | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | NGINX reset zone 3r/m + Kong rate-limiting 3/min |
| 17 | `fp-sensitive-data-export` | SENSITIVE_DATA_EXPOSURE | /api/v1/users/export | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | Kong OAuth2 (users:read:export scope) + IP restriction |
| 18 | `fp-xml-injection-xml` | XML_INJECTION | /api/v1/xml | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | ModSecurity 1006 + CRS 941 |
| 19 | `fp-verb-tampering-users` | HTTP_VERB_TAMPERING | /api/v1/users | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | Kong route method allow-list |
| 20 | `fp-dos-regex-validate` | DOS_REGEX | /api/v1/validate | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | NGINX validate zone 20r/m + Kong rate-limiting |
| 21 | `fp-graphql-depth-attack` | GRAPHQL_DEPTH_ATTACK | /api/v1/graphql | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → graphql-service-sg | ModSecurity 1016 + Kong request-validator + rate-limiting |
| 22 | `fp-http-smuggling` | HTTP_REQUEST_SMUGGLING | /api/v1/users | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | ModSecurity 1020/1021 + CRS 921 |
| 23 | `fp-prototype-pollution` | PROTOTYPE_POLLUTION | /api/v1/profile | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | ModSecurity 1010 + Kong JWT |
| 24 | `fp-mass-assignment` | MASS_ASSIGNMENT | /api/v1/profile | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | ModSecurity 1013 + Kong JWT |
| 25 | `fp-open-redirect` | OPEN_REDIRECT | /api/v1/sso | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | ModSecurity 1011 + Kong OIDC |
| 26 | `fp-cache-poisoning` | CACHE_POISONING | /api/v1/products | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | ModSecurity 1030 + Kong proxy-cache |
| 27 | `fp-session-hijacking` | SESSION_HIJACKING | /api/v1/sessions | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | ModSecurity 1025 + CRS 943 + Kong response-transformer |
| 28 | `fp-privilege-escalation` | PRIVILEGE_ESCALATION | /api/v1/roles | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | Kong JWT + ACL + IP-restriction + request-validator |
| 29 | `fp-geo-restricted` | GEO_RESTRICTED_ACCESS | /api/v1/payments | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → payment-service-sg | WAF geo-block (RU, CN, KP, IR) + NGINX GeoIP2 + Kong JWT |
| 30 | `fp-data-exfiltration` | DATA_EXFILTRATION | /api/v1/users/export | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | ModSecurity 1050/1051 (DLP) + CRS 950 + Kong OAuth2 |
| 31 | `fp-scanner-detection` | SCANNER_DETECTION | /api/v1/users | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | ModSecurity 1060 + CRS 913 + NGINX bad_bot + WAF regex UA |
| 32 | `fp-ssti` | SSTI | /api/v1/search | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | ModSecurity 1012 + Kong request-validator |
| 33 | `fp-cors-bypass` | CORS_BYPASS | /api/v1/profile | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | Kong CORS plugin + NGINX cors_origin map |
| 34 | `fp-deprecated-api` | DEPRECATED_API_ACCESS | /api/v0/users | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → microservices-sg | Kong request-termination (410) + NGINX 410 |
| 35 | `fp-payment-fraud` | PAYMENT_FRAUD | /api/v1/payments | FALSE_POSITIVE | >= 0.8 | Yes (via ALB→Kong) | LOW | Internet → ALB → Kong → payment-service-sg | Kong JWT + ACL + rate-limiting + request-validator + WAF geo-block |
| **36** | **`tp-missing-auth-v2-reports`** | **MISSING_AUTHENTICATION** | **/api/v2/reports/{id}** | **TRUE_POSITIVE** | **>= 0.8** | **Yes (via ALB→Kong)** | **LOW** | **Internet → ALB → Kong → microservices-sg** | **None — no Kong plugins on v2 reports route** |
| **37** | **`tp-broken-function-auth-admin-bulk`** | **BROKEN_FUNCTION_AUTHORIZATION** | **/api/v1/admin/bulk** | **TRUE_POSITIVE** | **>= 0.8** | **Yes (via ALB→Kong)** | **LOW** | **Internet → ALB → Kong → microservices-sg** | **JWT exists but no ACL — missing role enforcement** |
| **38** | **`tp-ssrf-analytics-misconfigured`** | **NETWORK_MISCONFIGURATION** | **/api/internal/analytics** | **TRUE_POSITIVE** | **>= 0.8** | **Yes (DIRECT — 0.0.0.0/0)** | **CRITICAL** | **Internet → analytics-sg (DIRECT)** | **None — SG allows 0.0.0.0/0, bypasses WAF + ALB + Kong** |

### 3.3 True Positive Test Data Details

These 3 alerts are the most important to verify — they must return TRUE_POSITIVE:

**TP #36 — Missing Auth on v2 Reports:**
- **Why TP**: The `/api/v2/reports` route was added to Kong with NO plugins (no JWT, no rate-limiting, nothing).
- **Reachability**: Standard path (ALB → Kong → microservices-sg). All layers are in the path, but Kong has no protective plugins for this specific route.
- **What the agent should identify**: Kong Gateway Specialist should report "no plugins found for this route". Network Specialist reachability should show standard path (LOW risk). The verdict is TP because gateway-layer controls are absent for this route, not because the network is misconfigured.

**TP #37 — Broken Function Auth (admin bulk):**
- **Why TP**: JWT auth plugin exists, but ACL plugin is missing. Any authenticated user (even role=viewer) can execute admin operations.
- **Reachability**: Standard path (LOW risk). All layers active.
- **What the agent should identify**: Kong Gateway Specialist should find JWT but note the absence of ACL. This is a subtle gap — authentication is present but authorization is not.

**TP #38 — Analytics Network Misconfiguration:**
- **Why TP**: `analytics-service-sg-MISCONFIGURED` allows `0.0.0.0/0` inbound on port 8098. Traffic reaches the service directly without passing through ALB or Kong.
- **Reachability**: **CRITICAL** — Internet → analytics-sg (direct). Bypasses WAF, ALB, and Kong Gateway entirely.
- **What the agent should identify**: Network Specialist reachability analysis should flag this as CRITICAL with bypassed layers `[waf, alb, kong]`. Even if WAF rules or Kong plugins exist for other routes, they are irrelevant because traffic never passes through those layers.

### 3.4 Reachability Test Data

Dedicated test cases for the reachability analyzer (unit-level, no LLM needed):

| Test Case | Target Endpoint | Source IP | Expected Internet Reachable | Expected Risk | Expected Path | Expected Bypassed |
|-----------|----------------|-----------|---------------------------|--------------|---------------|-------------------|
| R1: Standard microservice | /api/v1/users | 203.0.113.50 | Yes (via ALB→Kong chain) | LOW | ALB → Kong → microservices-sg | None |
| R2: GraphQL service | /api/v1/graphql | 45.227.88.10 | Yes (via ALB→Kong chain) | LOW | ALB → Kong → graphql-sg | None |
| R3: Payment service | /api/v1/payments | 45.227.88.10 | Yes (via ALB→Kong chain) | LOW | ALB → Kong → payment-sg | None |
| R4: Fetch service | /api/v1/fetch | 10.0.5.1 | Yes (via ALB→Kong chain) | LOW | ALB → Kong → fetch-service-sg | None |
| R5: Webhook (Stripe IP) | /api/v1/webhooks | 3.18.12.63 | Partial (Stripe IPs + Kong) | LOW | Stripe IP → webhook-sg OR Kong → webhook-sg | ALB (partial) |
| R6: **MISCONFIGURED analytics** | /api/internal/analytics | 198.51.100.200 | **Yes (DIRECT)** | **CRITICAL** | **Internet → analytics-sg** | **waf, alb, kong** |
| R7: VPC-internal only endpoint | /api/v1/internal/config | 10.0.3.22 | No (VPC internal) | LOW | VPC → Kong → microservices-sg | N/A |
| R8: Database tier | (direct DB access) | 203.0.113.50 | No | LOW | Blocked — only from microservices-sg | N/A |

---

## 4. Test Categories

### 4.1 Unit Tests — Reachability Analyzer

**File**: `tests/test_reachability.py`

These tests validate the graph-building and path-tracing logic without any LLM calls.

| Test ID | Test Name | Description | Pass Criteria |
|---------|-----------|-------------|---------------|
| U1 | `test_sg_graph_construction` | Build graph from Terraform controls, verify all 12 SGs are nodes | 12 nodes, correct tier classification |
| U2 | `test_endpoint_to_sg_mapping` | Map known endpoints to their SGs | `/api/v1/graphql` → `graphql-service-sg`, `/api/internal/analytics` → `analytics-service-sg-MISCONFIGURED` |
| U3 | `test_internet_reachability_standard` | Trace path for `/api/v1/users` | Internet reachable via ALB→Kong chain, risk=LOW |
| U4 | `test_internet_reachability_bypass` | Trace path for `/api/internal/analytics` | Internet reachable DIRECT, risk=CRITICAL, bypasses=[waf, alb, kong] |
| U5 | `test_cidr_matching` | Verify source IP matching against CIDRs | `203.0.113.50` matches `203.0.113.0/24`, does not match `10.0.0.0/16` |
| U6 | `test_nacl_restrictions` | Verify NACL rules are extracted | data-tier NACL denies all except app subnet ports |
| U7 | `test_bypass_detection` | Verify bypassed layers calculation | Service with only service-tier in path → bypassed=[alb, kong] |
| U8 | `test_risk_assessment` | Verify risk level assignment | CRITICAL when internet+bypass, LOW when standard path |
| U9 | `test_json_serialization` | Verify ReachabilityResult JSON output | Valid JSON with all required fields |
| U10 | `test_webhook_partial_path` | Trace path for webhook SG | Reachable from Stripe IPs directly + via Kong |

### 4.2 Component Tests — Retrieval Quality

| Test ID | Test Name | Description | Pass Criteria |
|---------|-----------|-------------|---------------|
| C1 | `test_waf_retrieval_sqli` | Search "SQL injection protection" | Returns ModSecurity CRS 942 + rule 1001 + WAF SQLi |
| C2 | `test_gateway_retrieval_auth` | Search "JWT authentication on orders" | Returns Kong JWT plugin for order-service |
| C3 | `test_network_retrieval_sg` | Search "analytics service security group" | Returns analytics-sg-MISCONFIGURED |
| C4 | `test_cross_layer_retrieval` | Search "credential stuffing protection" | Returns controls from WAF + Gateway + Network layers |
| C5 | `test_retrieval_ranking` | Verify reranker prioritization | Most relevant control ranked #1 for each query |

### 4.3 Integration Tests — Agent Reasoning

| Test ID | Test Name | Description | Pass Criteria |
|---------|-----------|-------------|---------------|
| I1 | `test_waf_specialist_sqli` | WAF agent on SQL injection alert | Finds ModSecurity + CRS rules, mitigates=true |
| I2 | `test_kong_specialist_no_plugins` | Kong agent on v2 reports alert | Reports no plugins found, mitigates=false |
| I3 | `test_network_specialist_standard` | Network agent on standard /api/v1/* alert | Reachability shows standard path, risk=LOW |
| I4 | `test_network_specialist_bypass` | Network agent on analytics alert | Reachability shows CRITICAL bypass, layers_bypassed=[waf, alb, kong] |
| I5 | `test_orchestrator_fp_verdict` | Full orchestrator on credential stuffing | Returns FALSE_POSITIVE with confidence >= 0.8 |
| I6 | `test_orchestrator_tp_verdict` | Full orchestrator on analytics misconfiguration | Returns TRUE_POSITIVE, reasoning mentions bypass |
| I7 | `test_orchestrator_subtle_tp` | Full orchestrator on admin bulk | Returns TRUE_POSITIVE, reasoning mentions missing ACL |

### 4.4 End-to-End Tests — Full Pipeline

| Test ID | Test Name | Description | Pass Criteria |
|---------|-----------|-------------|---------------|
| E1 | `test_mock_server_generates_alerts` | Start mock server, verify 38 alerts | GET /alerts/all returns 38 alerts |
| E2 | `test_fpm_processes_alert` | FPM processes 1 pending alert | Alert status changes to `analysed`, verdict posted |
| E3 | `test_full_38_alert_run` | FPM processes all 38 alerts | All 35 FP → FALSE_POSITIVE, all 3 TP → TRUE_POSITIVE |
| E4 | `test_dashboard_shows_verdicts` | Check dashboard after analysis | Verdict counts displayed correctly |
| E5 | `test_mcp_analyse_reachability` | MCP tool returns reachability JSON | Valid JSON with paths, risk_level, etc. |
| E6 | `test_restart_resilience` | Kill and restart FPM after 5 alerts | ChromaDB persists, resumes processing remaining alerts |

---

## 5. RAGAS Evaluation Metrics

### 5.1 Standard RAGAS Metrics

| Metric | What It Measures | Target | How Computed |
|--------|-----------------|--------|-------------|
| **Context Recall** | Do retrieved chunks contain the information needed to answer correctly? | >= 0.80 | Fraction of ground-truth controls that appear in retrieved context |
| **Context Precision** | Are the top-ranked chunks actually relevant? | >= 0.75 | Proportion of retrieved chunks that are relevant (measured by reranker score) |
| **Faithfulness** | Is the verdict reasoning grounded in the retrieved context? | >= 0.85 | Does the agent's reasoning reference actual controls from the context, not hallucinated ones? |
| **Answer Relevancy** | Is the reasoning relevant to the question? | >= 0.80 | Semantic similarity between the question (alert) and the answer (verdict reasoning) |

### 5.2 FPM-Specific Metrics

| Metric | What It Measures | Target | How Computed |
|--------|-----------------|--------|-------------|
| **Verdict Accuracy** | Overall correct verdicts | >= 95% (36/38) | `correct_verdicts / total_alerts` |
| **FP Accuracy** | False positive detection rate | 100% (35/35) | `correct_fp / total_fp` |
| **TP Accuracy** | True positive detection rate | 100% (3/3) | `correct_tp / total_tp` |
| **TP Recall** | No TPs missed (most critical) | 100% | `detected_tp / actual_tp` — missing a TP is catastrophic |
| **FP Precision** | FPs are actually false positives | >= 95% | `actual_fp_in_predicted_fp / predicted_fp` |
| **Average Confidence** | Agent confidence calibration | 0.80 - 0.95 | Mean confidence across all verdicts |
| **Confidence Calibration** | Does confidence match correctness? | Correct verdicts > 0.8, incorrect < 0.6 | Compare confidence for correct vs incorrect |

### 5.3 Reachability Metrics (New)

| Metric | What It Measures | Target | How Computed |
|--------|-----------------|--------|-------------|
| **Reachability Accuracy** | Correct internet reachability determination | 100% | Compare predicted vs expected `is_internet_reachable` for all 38 alerts |
| **Risk Level Accuracy** | Correct risk classification | >= 95% | Compare predicted vs expected risk level |
| **Bypass Detection Rate** | Correctly identifies bypassed layers | 100% for TP #38 | Did the analyzer detect waf/alb/kong bypass for analytics endpoint? |
| **Path Completeness** | Full path traced correctly | >= 90% | Does the path include all expected hops (ALB → Kong → Service)? |
| **Reachability Impact on Verdict** | Does reachability info improve TP detection? | TP #38 correctly flagged as TRUE_POSITIVE | Compare verdict with vs without reachability analysis |

### 5.4 Latency Metrics

| Metric | Target | Description |
|--------|--------|-------------|
| Average analysis time per alert | < 60s | End-to-end from alert receipt to verdict post |
| Reachability analysis time | < 100ms | Graph traversal is pure Python, no LLM |
| Knowledge base build time | < 5 min | Parse + chunk + enrich + embed all configs |
| Token usage per alert | < 5000 tokens | LLM cost efficiency |

---

## 6. RAGAS Evaluation Implementation

### 6.1 Ground Truth Structure

Each ground truth entry contains:

```python
{
    "template_id": "fp-sqli-users",
    "attack_type": "SQL_INJECTION",
    "target_endpoint": "/api/v1/users",
    "expected_verdict": "FALSE_POSITIVE",
    "expected_controls": ["modsec-rule:1001", "modsec-crs:REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "waf:api-waf-acl"],
    "reasoning": "ModSecurity CRS 942xxx rules and custom rule 1001 block SQL injection. AWS WAF also has SQLi managed rules.",
    # NEW fields for reachability:
    "expected_reachability": {
        "internet_reachable": True,
        "risk_level": "LOW",
        "expected_path_contains": ["alb", "kong", "service"],
        "expected_bypassed": [],
    },
}
```

### 6.2 RAGAS Dataset Format

The evaluation pipeline produces this dataset for RAGAS:

```python
{
    "question": [
        "Is alert fp-sqli-users (SQL_INJECTION on /api/v1/users) a false positive?",
        ...
    ],
    "answer": [
        "FALSE_POSITIVE: ModSecurity CRS 942 and custom rule 1001 detect and block UNION-based SQL injection...",
        ...
    ],
    "contexts": [
        ["ModSecurity rule 1001: ...", "CRS 942 SQLi: ...", "WAF ACL SQLi rules: ..."],
        ...
    ],
    "ground_truth": [
        "ModSecurity CRS 942xxx rules and custom rule 1001 block SQL injection. AWS WAF also has SQLi managed rules.",
        ...
    ],
}
```

### 6.3 Evaluation Report Output

```
======================================================================
FPM EVALUATION REPORT
======================================================================

Verdict Accuracy:        97.4% (37/38)
False Positive Accuracy: 100.0% (35/35)
True Positive Accuracy:  100.0% (3/3)
TP Recall:               100.0% (3/3) ← MOST CRITICAL
Average Confidence:      0.87
Context Recall:          82.5%

RAGAS Metrics:
  faithfulness:       0.891
  answer_relevancy:   0.845
  context_recall:     0.823
  context_precision:  0.779

Reachability Metrics:
  Reachability Accuracy:    100.0% (38/38)
  Risk Level Accuracy:      97.4% (37/38)
  Bypass Detection Rate:    100.0% (1/1 bypasses detected)
  Path Completeness:        94.7% (36/38 full paths traced)

----------------------------------------------------------------------
Per-Alert Results:
----------------------------------------------------------------------
  [PASS] fp-missing-auth-orders: expected=FALSE_POSITIVE, got=FALSE_POSITIVE (conf=0.90)
  [PASS] fp-sqli-users: expected=FALSE_POSITIVE, got=FALSE_POSITIVE (conf=0.92)
  ...
  [PASS] tp-missing-auth-v2-reports: expected=TRUE_POSITIVE, got=TRUE_POSITIVE (conf=0.88)
  [PASS] tp-broken-function-auth-admin-bulk: expected=TRUE_POSITIVE, got=TRUE_POSITIVE (conf=0.85)
  [PASS] tp-ssrf-analytics-misconfigured: expected=TRUE_POSITIVE, got=TRUE_POSITIVE (conf=0.95)

Full report saved to: evaluation/report.json
```

---

## 7. Test Execution Order

### Phase A — No LLM Required (fast, deterministic)
1. Unit tests for reachability analyzer (U1-U10)
2. Terraform parser tests (verify all 12 SGs, 2 NACLs, 1 WAF ACL parsed)
3. Endpoint-to-SG mapping tests

### Phase B — LLM Required (needs OPENAI_API_KEY)
4. Component tests: retrieval quality (C1-C5)
5. Integration tests: individual agent reasoning (I1-I7)
6. E2E: process 5 representative alerts (1 TP + 4 FP of different types)

### Phase C — Full Evaluation (expensive, ~38 LLM calls)
7. E2E: full 38-alert run (E3)
8. RAGAS evaluation with full metrics
9. Reachability metrics computation
10. Report generation

### Phase D — System Tests (operational)
11. Mock server alert generation (E1)
12. Dashboard verification (E4)
13. MCP server tools (E5)
14. Restart resilience (E6)

---

## 8. Pass/Fail Criteria

### Mandatory (must pass for release):
- [ ] All 35 FP alerts return FALSE_POSITIVE
- [ ] All 3 TP alerts return TRUE_POSITIVE (TP Recall = 100%)
- [ ] TP #38 reachability shows CRITICAL risk with bypassed layers
- [ ] Verdict accuracy >= 95%
- [ ] Average confidence >= 0.75

### Desired (should pass):
- [ ] Context recall >= 0.80
- [ ] Faithfulness >= 0.85
- [ ] Answer relevancy >= 0.80
- [ ] Reachability accuracy = 100%
- [ ] Average analysis latency < 60s per alert

### Informational (tracked but not blocking):
- [ ] Context precision
- [ ] Token usage per alert
- [ ] Confidence calibration
