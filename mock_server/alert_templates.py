"""
21 pre-defined alert templates: 20 false-positive scenarios + 1 true-positive.

Each template is a dict with all fields needed to generate a realistic alert.
The `template_id` field is used for idempotent generation.
"""

TEMPLATES: list[dict] = [
    # ── 1. MISSING_AUTHENTICATION (FP) ──
    {
        "template_id": "fp-missing-auth-orders",
        "attack_type": "MISSING_AUTHENTICATION",
        "target_endpoint": "/api/v1/orders",
        "http_method": "GET",
        "severity": "HIGH",
        "traceable_reason": "Endpoint /api/v1/orders appears to accept unauthenticated requests; no Authorization header observed in sampled traffic.",
        "payload_snippet": "GET /api/v1/orders HTTP/1.1 (no auth header)",
        "source_ip": "10.0.2.15",
        "http_request": {
            "method": "GET",
            "uri": "/api/v1/orders",
            "headers": {"Host": "api.internal.corp", "Accept": "application/json"},
            "body": None,
        },
        "http_response": {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": {"orders": []},
        },
    },
    # ── 2. INADEQUATE_AUTHENTICATION (FP) ──
    {
        "template_id": "fp-inadequate-auth-config",
        "attack_type": "INADEQUATE_AUTHENTICATION",
        "target_endpoint": "/api/v1/internal/config",
        "http_method": "GET",
        "severity": "CRITICAL",
        "traceable_reason": "Internal config endpoint uses Basic auth only; no MFA or token rotation observed.",
        "payload_snippet": "GET /api/v1/internal/config Authorization: Basic dXNlcjpwYXNz",
        "source_ip": "10.0.3.22",
        "http_request": {
            "method": "GET",
            "uri": "/api/v1/internal/config",
            "headers": {"Host": "api.internal.corp", "Authorization": "Basic dXNlcjpwYXNz"},
            "body": None,
        },
        "http_response": {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": {"config": {"debug": False}},
        },
    },
    # ── 3. SQL_INJECTION (FP) ──
    {
        "template_id": "fp-sqli-users",
        "attack_type": "SQL_INJECTION",
        "target_endpoint": "/api/v1/users",
        "http_method": "GET",
        "severity": "CRITICAL",
        "traceable_reason": "SQL injection pattern detected in query parameter: id=1 OR 1=1",
        "payload_snippet": "GET /api/v1/users?id=1%20OR%201%3D1",
        "source_ip": "203.0.113.45",
        "http_request": {
            "method": "GET",
            "uri": "/api/v1/users?id=1 OR 1=1",
            "headers": {"Host": "api.example.com", "Accept": "application/json"},
            "body": None,
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden"},
        },
    },
    # ── 4. XSS (FP) ──
    {
        "template_id": "fp-xss-search",
        "attack_type": "XSS",
        "target_endpoint": "/api/v1/search",
        "http_method": "GET",
        "severity": "HIGH",
        "traceable_reason": "Reflected XSS payload detected in search query parameter: q=<script>alert(1)</script>",
        "payload_snippet": "GET /api/v1/search?q=<script>alert(1)</script>",
        "source_ip": "198.51.100.77",
        "http_request": {
            "method": "GET",
            "uri": "/api/v1/search?q=<script>alert(1)</script>",
            "headers": {"Host": "api.example.com"},
            "body": None,
        },
        "http_response": {
            "status_code": 400,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Bad Request"},
        },
    },
    # ── 5. RATE_ABUSE (FP) ──
    {
        "template_id": "fp-rate-abuse-login",
        "attack_type": "RATE_ABUSE",
        "target_endpoint": "/api/v1/login",
        "http_method": "POST",
        "severity": "MEDIUM",
        "traceable_reason": "Excessive login attempts detected: 150 requests in 60 seconds from single IP.",
        "payload_snippet": "POST /api/v1/login (150 req/min from 203.0.113.10)",
        "source_ip": "203.0.113.10",
        "http_request": {
            "method": "POST",
            "uri": "/api/v1/login",
            "headers": {"Host": "api.example.com", "Content-Type": "application/json"},
            "body": {"username": "admin", "password": "test123"},
        },
        "http_response": {
            "status_code": 429,
            "headers": {"Content-Type": "application/json", "Retry-After": "60"},
            "body": {"error": "Too Many Requests"},
        },
    },
    # ── 6. CREDENTIAL_STUFFING (FP) ──
    {
        "template_id": "fp-credential-stuffing-auth",
        "attack_type": "CREDENTIAL_STUFFING",
        "target_endpoint": "/api/v1/auth",
        "http_method": "POST",
        "severity": "HIGH",
        "traceable_reason": "Multiple failed authentication attempts with rotating credentials from known botnet IP range.",
        "payload_snippet": "POST /api/v1/auth rotating user:pass combos from 203.0.113.0/24",
        "source_ip": "203.0.113.55",
        "http_request": {
            "method": "POST",
            "uri": "/api/v1/auth",
            "headers": {"Host": "api.example.com", "Content-Type": "application/json"},
            "body": {"username": "victim@corp.com", "password": "leaked_pass_42"},
        },
        "http_response": {
            "status_code": 429,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Too Many Requests"},
        },
    },
    # ── 7. UNAUTHORIZED_ACCESS (FP) ──
    {
        "template_id": "fp-unauth-access-admin",
        "attack_type": "UNAUTHORIZED_ACCESS",
        "target_endpoint": "/api/v1/internal/admin",
        "http_method": "GET",
        "severity": "CRITICAL",
        "traceable_reason": "External IP attempted access to internal admin endpoint without valid service credentials.",
        "payload_snippet": "GET /api/v1/internal/admin from external IP 198.51.100.33",
        "source_ip": "198.51.100.33",
        "http_request": {
            "method": "GET",
            "uri": "/api/v1/internal/admin",
            "headers": {"Host": "api.example.com"},
            "body": None,
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden"},
        },
    },
    # ── 8. BOT_TRAFFIC (FP) ──
    {
        "template_id": "fp-bot-traffic-products",
        "attack_type": "BOT_TRAFFIC",
        "target_endpoint": "/api/v1/products",
        "http_method": "GET",
        "severity": "MEDIUM",
        "traceable_reason": "Automated scraping pattern detected: rapid sequential requests with no session cookies and headless browser User-Agent.",
        "payload_snippet": "GET /api/v1/products UA: HeadlessChrome/120.0 (rapid enumeration)",
        "source_ip": "192.0.2.100",
        "http_request": {
            "method": "GET",
            "uri": "/api/v1/products?page=1",
            "headers": {"Host": "api.example.com", "User-Agent": "Mozilla/5.0 HeadlessChrome/120.0"},
            "body": None,
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden - Bot detected"},
        },
    },
    # ── 9. BOLA (FP) ──
    {
        "template_id": "fp-bola-users",
        "attack_type": "BOLA",
        "target_endpoint": "/api/v1/users/{id}",
        "http_method": "GET",
        "severity": "HIGH",
        "traceable_reason": "Broken Object Level Authorization: user 42 accessed profile of user 99 via /api/v1/users/99.",
        "payload_snippet": "GET /api/v1/users/99 with JWT for user_id=42",
        "source_ip": "10.0.5.8",
        "http_request": {
            "method": "GET",
            "uri": "/api/v1/users/99",
            "headers": {"Host": "api.example.com", "Authorization": "Bearer eyJ...user42"},
            "body": None,
        },
        "http_response": {
            "status_code": 401,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Unauthorized"},
        },
    },
    # ── 10. API_KEY_EXPOSURE (FP) ──
    {
        "template_id": "fp-api-key-exposure-data",
        "attack_type": "API_KEY_EXPOSURE",
        "target_endpoint": "/api/v1/data",
        "http_method": "GET",
        "severity": "HIGH",
        "traceable_reason": "API key transmitted in query string parameter, vulnerable to access-log exposure.",
        "payload_snippet": "GET /api/v1/data?api_key=sk_live_abc123...",
        "source_ip": "10.0.1.50",
        "http_request": {
            "method": "GET",
            "uri": "/api/v1/data?api_key=sk_live_abc123def456",
            "headers": {"Host": "api.example.com"},
            "body": None,
        },
        "http_response": {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": {"data": []},
        },
    },
    # ── 11. OVERSIZED_PAYLOAD (FP) ──
    {
        "template_id": "fp-oversized-payload-upload",
        "attack_type": "OVERSIZED_PAYLOAD",
        "target_endpoint": "/api/v1/upload",
        "http_method": "POST",
        "severity": "MEDIUM",
        "traceable_reason": "Request body exceeds 50MB; potential buffer overflow or resource exhaustion attempt.",
        "payload_snippet": "POST /api/v1/upload Content-Length: 52428800 (50MB file)",
        "source_ip": "192.0.2.200",
        "http_request": {
            "method": "POST",
            "uri": "/api/v1/upload",
            "headers": {"Host": "api.example.com", "Content-Type": "multipart/form-data", "Content-Length": "52428800"},
            "body": "<binary 50MB payload>",
        },
        "http_response": {
            "status_code": 413,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Payload Too Large"},
        },
    },
    # ── 12. SQL_INJECTION double layer (FP) ──
    {
        "template_id": "fp-sqli-double-search",
        "attack_type": "SQL_INJECTION",
        "target_endpoint": "/api/v1/search",
        "http_method": "POST",
        "severity": "CRITICAL",
        "traceable_reason": "Double-encoded SQL injection payload in search body: UNION SELECT detected after URL decode.",
        "payload_snippet": "POST /api/v1/search body: {\"q\": \"' UNION SELECT * FROM users--\"}",
        "source_ip": "203.0.113.88",
        "http_request": {
            "method": "POST",
            "uri": "/api/v1/search",
            "headers": {"Host": "api.example.com", "Content-Type": "application/json"},
            "body": {"q": "' UNION SELECT * FROM users--"},
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden"},
        },
    },
    # ── 13. PATH_TRAVERSAL (FP) ──
    {
        "template_id": "fp-path-traversal-files",
        "attack_type": "PATH_TRAVERSAL",
        "target_endpoint": "/api/v1/files",
        "http_method": "GET",
        "severity": "CRITICAL",
        "traceable_reason": "Path traversal attempt detected: ../../etc/passwd in file path parameter.",
        "payload_snippet": "GET /api/v1/files?path=../../etc/passwd",
        "source_ip": "198.51.100.99",
        "http_request": {
            "method": "GET",
            "uri": "/api/v1/files?path=../../etc/passwd",
            "headers": {"Host": "api.example.com"},
            "body": None,
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden"},
        },
    },
    # ── 14. COMMAND_INJECTION (FP) ──
    {
        "template_id": "fp-command-injection-exec",
        "attack_type": "COMMAND_INJECTION",
        "target_endpoint": "/api/v1/exec",
        "http_method": "POST",
        "severity": "CRITICAL",
        "traceable_reason": "OS command injection pattern detected in request body: semicolon followed by shell command.",
        "payload_snippet": "POST /api/v1/exec body: {\"cmd\": \"status; cat /etc/shadow\"}",
        "source_ip": "203.0.113.77",
        "http_request": {
            "method": "POST",
            "uri": "/api/v1/exec",
            "headers": {"Host": "api.example.com", "Content-Type": "application/json"},
            "body": {"cmd": "status; cat /etc/shadow"},
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden"},
        },
    },
    # ── 15. SSRF (FP) ──
    {
        "template_id": "fp-ssrf-fetch",
        "attack_type": "SSRF",
        "target_endpoint": "/api/v1/fetch",
        "http_method": "POST",
        "severity": "CRITICAL",
        "traceable_reason": "SSRF attempt: request body contains URL pointing to internal metadata endpoint (169.254.169.254).",
        "payload_snippet": "POST /api/v1/fetch body: {\"url\": \"http://169.254.169.254/latest/meta-data/\"}",
        "source_ip": "192.0.2.150",
        "http_request": {
            "method": "POST",
            "uri": "/api/v1/fetch",
            "headers": {"Host": "api.example.com", "Content-Type": "application/json"},
            "body": {"url": "http://169.254.169.254/latest/meta-data/"},
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden"},
        },
    },
    # ── 16. BRUTE_FORCE (FP) ──
    {
        "template_id": "fp-brute-force-reset",
        "attack_type": "BRUTE_FORCE",
        "target_endpoint": "/api/v1/reset-password",
        "http_method": "POST",
        "severity": "HIGH",
        "traceable_reason": "Brute-force attack on password reset: 200+ attempts in 5 minutes with sequential token guessing.",
        "payload_snippet": "POST /api/v1/reset-password token=000001..000200 in rapid succession",
        "source_ip": "203.0.113.30",
        "http_request": {
            "method": "POST",
            "uri": "/api/v1/reset-password",
            "headers": {"Host": "api.example.com", "Content-Type": "application/json"},
            "body": {"token": "000142", "new_password": "hacked123"},
        },
        "http_response": {
            "status_code": 429,
            "headers": {"Content-Type": "application/json", "Retry-After": "300"},
            "body": {"error": "Too Many Requests"},
        },
    },
    # ── 17. SENSITIVE_DATA_EXPOSURE (FP) ──
    {
        "template_id": "fp-sensitive-data-export",
        "attack_type": "SENSITIVE_DATA_EXPOSURE",
        "target_endpoint": "/api/v1/users/export",
        "http_method": "GET",
        "severity": "CRITICAL",
        "traceable_reason": "Bulk user data export endpoint accessed; response contains PII fields (email, phone, address).",
        "payload_snippet": "GET /api/v1/users/export — response includes PII for 10k users",
        "source_ip": "198.51.100.12",
        "http_request": {
            "method": "GET",
            "uri": "/api/v1/users/export",
            "headers": {"Host": "api.example.com", "Authorization": "Bearer eyJ...limited_scope"},
            "body": None,
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden - Insufficient scope"},
        },
    },
    # ── 18. XML_INJECTION (FP) ──
    {
        "template_id": "fp-xml-injection-xml",
        "attack_type": "XML_INJECTION",
        "target_endpoint": "/api/v1/xml",
        "http_method": "POST",
        "severity": "CRITICAL",
        "traceable_reason": "XML External Entity (XXE) injection detected: DOCTYPE declaration with SYSTEM entity referencing /etc/passwd.",
        "payload_snippet": "POST /api/v1/xml body: <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
        "source_ip": "203.0.113.60",
        "http_request": {
            "method": "POST",
            "uri": "/api/v1/xml",
            "headers": {"Host": "api.example.com", "Content-Type": "application/xml"},
            "body": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden"},
        },
    },
    # ── 19. HTTP_VERB_TAMPERING (FP) ──
    {
        "template_id": "fp-verb-tampering-users",
        "attack_type": "HTTP_VERB_TAMPERING",
        "target_endpoint": "/api/v1/users",
        "http_method": "DELETE",
        "severity": "HIGH",
        "traceable_reason": "Unexpected HTTP method DELETE used against user endpoint; only GET and POST are documented.",
        "payload_snippet": "DELETE /api/v1/users/42 — undocumented method",
        "source_ip": "198.51.100.44",
        "http_request": {
            "method": "DELETE",
            "uri": "/api/v1/users/42",
            "headers": {"Host": "api.example.com", "Authorization": "Bearer eyJ...user42"},
            "body": None,
        },
        "http_response": {
            "status_code": 405,
            "headers": {"Content-Type": "application/json", "Allow": "GET, POST"},
            "body": {"error": "Method Not Allowed"},
        },
    },
    # ── 20. DOS_REGEX (FP) ──
    {
        "template_id": "fp-dos-regex-validate",
        "attack_type": "DOS_REGEX",
        "target_endpoint": "/api/v1/validate",
        "http_method": "POST",
        "severity": "HIGH",
        "traceable_reason": "ReDoS pattern detected: input string designed to cause catastrophic backtracking in email regex validator.",
        "payload_snippet": "POST /api/v1/validate body: {\"email\": \"aaaaaa...@aaaa...a\"}",
        "source_ip": "192.0.2.75",
        "http_request": {
            "method": "POST",
            "uri": "/api/v1/validate",
            "headers": {"Host": "api.example.com", "Content-Type": "application/json"},
            "body": {"email": "a" * 50 + "@" + "a" * 50 + ".com"},
        },
        "http_response": {
            "status_code": 429,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Too Many Requests"},
        },
    },
    # ── 21. TRUE POSITIVE: MISSING_AUTHENTICATION on v2 reports ──
    {
        "template_id": "tp-missing-auth-v2-reports",
        "attack_type": "MISSING_AUTHENTICATION",
        "target_endpoint": "/api/v2/reports/{id}",
        "http_method": "GET",
        "severity": "CRITICAL",
        "traceable_reason": "Endpoint /api/v2/reports/1337 returns confidential financial report data with no authentication required.",
        "payload_snippet": "GET /api/v2/reports/1337 — no auth, returns full financial data",
        "source_ip": "198.51.100.200",
        "http_request": {
            "method": "GET",
            "uri": "/api/v2/reports/1337",
            "headers": {"Host": "api.example.com", "Accept": "application/json"},
            "body": None,
        },
        "http_response": {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": {
                "report_id": 1337,
                "type": "financial",
                "revenue": 12500000,
                "net_income": 3200000,
                "confidential": True,
            },
        },
    },
]

# Quick lookup
FALSE_POSITIVE_TEMPLATES = [t for t in TEMPLATES if t["template_id"].startswith("fp-")]
TRUE_POSITIVE_TEMPLATES = [t for t in TEMPLATES if t["template_id"].startswith("tp-")]
