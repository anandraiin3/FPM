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

    # ==========================================================================
    # PHASE 2 — Complex Scenarios
    # ==========================================================================

    # ── 22. GRAPHQL_DEPTH_ATTACK (FP) ──
    # Deep nested GraphQL query attempting resource exhaustion.
    # Mitigated by: Kong request-validator (maxLength), ModSecurity rule 1016
    # (depth >5 levels), NGINX graphql rate limit (30r/m), Kong rate-limiting.
    {
        "template_id": "fp-graphql-depth-attack",
        "attack_type": "GRAPHQL_DEPTH_ATTACK",
        "target_endpoint": "/api/v1/graphql",
        "http_method": "POST",
        "severity": "HIGH",
        "traceable_reason": "GraphQL query with excessive nesting depth (8 levels) detected; potential resource exhaustion or data exfiltration via nested relationship traversal.",
        "payload_snippet": "POST /api/v1/graphql body: {\"query\": \"{ users { orders { items { product { reviews { author { orders { items } } } } } } } }\"}",
        "source_ip": "198.51.100.90",
        "http_request": {
            "method": "POST",
            "uri": "/api/v1/graphql",
            "headers": {
                "Host": "api.example.com",
                "Content-Type": "application/json",
                "Authorization": "Bearer eyJ...valid_token",
            },
            "body": {
                "query": "{ users { orders { items { product { reviews { author { orders { items { id name price } } } } } } } } }",
                "operationName": "DeepQuery",
            },
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden - Query depth exceeds maximum allowed"},
        },
    },
    # ── 23. HTTP_REQUEST_SMUGGLING (FP) ──
    # CL/TE conflict attempt to bypass security controls.
    # Mitigated by: ModSecurity rule 1020 (CL/TE conflict), rule 1021
    # (obfuscated TE), NGINX ignore_invalid_headers, CRS 921 protocol attack rules.
    {
        "template_id": "fp-http-smuggling",
        "attack_type": "HTTP_REQUEST_SMUGGLING",
        "target_endpoint": "/api/v1/users",
        "http_method": "POST",
        "severity": "CRITICAL",
        "traceable_reason": "HTTP request smuggling attempt: conflicting Content-Length and Transfer-Encoding headers detected, potentially allowing request splitting to bypass security controls.",
        "payload_snippet": "POST /api/v1/users with Content-Length: 13 AND Transfer-Encoding: chunked (CL/TE desync)",
        "source_ip": "203.0.113.42",
        "http_request": {
            "method": "POST",
            "uri": "/api/v1/users",
            "headers": {
                "Host": "api.example.com",
                "Content-Type": "application/json",
                "Content-Length": "13",
                "Transfer-Encoding": "chunked",
            },
            "body": "0\r\n\r\nGET /api/v1/internal/admin HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
        },
        "http_response": {
            "status_code": 400,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Bad Request - Conflicting headers"},
        },
    },
    # ── 24. PROTOTYPE_POLLUTION (FP) ──
    # __proto__ injection in JSON body to manipulate object prototypes.
    # Mitigated by: ModSecurity rule 1010 (prototype pollution detection),
    # Kong request-validator (additionalProperties: false on strict routes).
    {
        "template_id": "fp-prototype-pollution",
        "attack_type": "PROTOTYPE_POLLUTION",
        "target_endpoint": "/api/v1/profile",
        "http_method": "PUT",
        "severity": "HIGH",
        "traceable_reason": "Prototype pollution attempt: __proto__ property detected in JSON request body, potentially allowing server-side object manipulation.",
        "payload_snippet": "PUT /api/v1/profile body: {\"name\": \"hacker\", \"__proto__\": {\"isAdmin\": true}}",
        "source_ip": "198.51.100.55",
        "http_request": {
            "method": "PUT",
            "uri": "/api/v1/profile",
            "headers": {
                "Host": "api.example.com",
                "Content-Type": "application/json",
                "Authorization": "Bearer eyJ...valid_user_token",
            },
            "body": {"name": "hacker", "__proto__": {"isAdmin": True, "role": "admin"}},
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden"},
        },
    },
    # ── 25. MASS_ASSIGNMENT (FP) ──
    # Attempting to inject privilege escalation fields into request body.
    # Mitigated by: ModSecurity rule 1013 (mass assignment detection),
    # Kong request-validator with strict body_schema (additionalProperties: false).
    {
        "template_id": "fp-mass-assignment",
        "attack_type": "MASS_ASSIGNMENT",
        "target_endpoint": "/api/v1/profile",
        "http_method": "PUT",
        "severity": "HIGH",
        "traceable_reason": "Mass assignment vulnerability exploit: request body contains unauthorized fields (is_admin, role) attempting privilege escalation via profile update endpoint.",
        "payload_snippet": "PUT /api/v1/profile body: {\"name\": \"user\", \"is_admin\": true, \"role\": \"admin\"}",
        "source_ip": "10.0.5.22",
        "http_request": {
            "method": "PUT",
            "uri": "/api/v1/profile",
            "headers": {
                "Host": "api.example.com",
                "Content-Type": "application/json",
                "Authorization": "Bearer eyJ...regular_user",
            },
            "body": {"name": "John Doe", "is_admin": True, "role": "admin", "access_level": "superuser"},
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden - Unauthorized fields in request body"},
        },
    },
    # ── 26. OPEN_REDIRECT (FP) ──
    # Attempting to redirect users to an external malicious site.
    # Mitigated by: ModSecurity rule 1011 (open redirect detection),
    # CRS protocol enforcement rules.
    {
        "template_id": "fp-open-redirect",
        "attack_type": "OPEN_REDIRECT",
        "target_endpoint": "/api/v1/sso",
        "http_method": "GET",
        "severity": "MEDIUM",
        "traceable_reason": "Open redirect vulnerability: redirect_url parameter points to external domain (evil.com) instead of whitelisted application domain.",
        "payload_snippet": "GET /api/v1/sso?redirect_url=https://evil.com/phishing",
        "source_ip": "192.0.2.88",
        "http_request": {
            "method": "GET",
            "uri": "/api/v1/sso?redirect_url=https://evil.com/phishing",
            "headers": {
                "Host": "api.example.com",
                "Accept": "text/html",
            },
            "body": None,
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden - Invalid redirect URL"},
        },
    },
    # ── 27. CACHE_POISONING (FP) ──
    # Injecting unkeyed headers to poison the CDN/proxy cache.
    # Mitigated by: ModSecurity rule 1030 (cache poisoning via unkeyed headers),
    # NGINX drop_invalid_header_fields, Kong proxy-cache with vary_headers.
    {
        "template_id": "fp-cache-poisoning",
        "attack_type": "CACHE_POISONING",
        "target_endpoint": "/api/v1/products",
        "http_method": "GET",
        "severity": "HIGH",
        "traceable_reason": "Cache poisoning attempt: X-Forwarded-Host header injected with attacker-controlled domain to poison cached responses.",
        "payload_snippet": "GET /api/v1/products with X-Forwarded-Host: evil.com and X-Original-URL: /admin",
        "source_ip": "198.51.100.77",
        "http_request": {
            "method": "GET",
            "uri": "/api/v1/products",
            "headers": {
                "Host": "api.example.com",
                "X-Forwarded-Host": "evil.com",
                "X-Original-URL": "/api/v1/internal/admin",
                "Accept": "application/json",
            },
            "body": None,
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden - Invalid headers"},
        },
    },
    # ── 28. SESSION_HIJACKING (FP) ──
    # Attempting to fixate/inject a session cookie.
    # Mitigated by: ModSecurity rule 1025 (session fixation via cookie injection),
    # CRS 943 session fixation rules, Kong session service with HttpOnly/Secure/SameSite.
    {
        "template_id": "fp-session-hijacking",
        "attack_type": "SESSION_HIJACKING",
        "target_endpoint": "/api/v1/sessions",
        "http_method": "POST",
        "severity": "CRITICAL",
        "traceable_reason": "Session hijacking attempt: crafted cookie injection with attacker-controlled session_id value to fixate victim's session.",
        "payload_snippet": "POST /api/v1/sessions with Cookie: session_id='attacker_controlled_value'",
        "source_ip": "203.0.113.65",
        "http_request": {
            "method": "POST",
            "uri": "/api/v1/sessions",
            "headers": {
                "Host": "api.example.com",
                "Content-Type": "application/json",
                "Cookie": "session_id='s3cr3t_injected_session'",
            },
            "body": {"username": "victim@corp.com", "password": "password123"},
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden - Session fixation detected"},
        },
    },
    # ── 29. PRIVILEGE_ESCALATION (FP) ──
    # Attempting to modify role assignment without admin privileges.
    # Mitigated by: Kong JWT (role claim), ACL (admin-group), IP restriction
    # (internal only), request-validator (strict enum for role field).
    {
        "template_id": "fp-privilege-escalation",
        "attack_type": "PRIVILEGE_ESCALATION",
        "target_endpoint": "/api/v1/roles",
        "http_method": "PUT",
        "severity": "CRITICAL",
        "traceable_reason": "Privilege escalation attempt: regular user JWT attempting to modify role assignment to 'admin' via roles management endpoint.",
        "payload_snippet": "PUT /api/v1/roles body: {\"user_id\": \"42\", \"role\": \"admin\"} with non-admin JWT",
        "source_ip": "10.0.5.33",
        "http_request": {
            "method": "PUT",
            "uri": "/api/v1/roles",
            "headers": {
                "Host": "api.example.com",
                "Content-Type": "application/json",
                "Authorization": "Bearer eyJ...regular_user_no_admin_role",
            },
            "body": {"user_id": "42", "role": "admin", "permissions": ["read", "write", "delete", "admin"]},
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden - Admin role required"},
        },
    },
    # ── 30. GEO_RESTRICTED_ACCESS (FP) ──
    # Access from blocked country (geo-blocked at WAF + NGINX level).
    # Mitigated by: AWS WAF geo_match_statement (RU, CN, KP, IR),
    # NGINX geoip2 map $blocked_country, WAF IP reputation list.
    {
        "template_id": "fp-geo-restricted",
        "attack_type": "GEO_RESTRICTED_ACCESS",
        "target_endpoint": "/api/v1/payments",
        "http_method": "POST",
        "severity": "HIGH",
        "traceable_reason": "Access from geo-restricted region: source IP geolocated to sanctioned country (Russia) attempting payment endpoint access.",
        "payload_snippet": "POST /api/v1/payments from 91.234.55.10 (geo: RU) — blocked by geo-restriction policy",
        "source_ip": "91.234.55.10",
        "http_request": {
            "method": "POST",
            "uri": "/api/v1/payments",
            "headers": {
                "Host": "api.example.com",
                "Content-Type": "application/json",
                "Authorization": "Bearer eyJ...stolen_token",
            },
            "body": {"amount": 99999.99, "currency": "USD", "description": "Wire transfer"},
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden - Access denied from your region"},
        },
    },
    # ── 31. DATA_EXFILTRATION (FP) ──
    # Response body contains patterns that look like credit card numbers.
    # Mitigated by: ModSecurity rule 1050 (credit card DLP), rule 1051 (SSN DLP),
    # SecResponseBodyAccess On, CRS RESPONSE-950 data leakage rules.
    {
        "template_id": "fp-data-exfiltration",
        "attack_type": "DATA_EXFILTRATION",
        "target_endpoint": "/api/v1/users/export",
        "http_method": "GET",
        "severity": "CRITICAL",
        "traceable_reason": "Potential data exfiltration: response body contains patterns matching credit card numbers (Visa/Mastercard) and SSN-like patterns in bulk user export.",
        "payload_snippet": "GET /api/v1/users/export — response body flagged for PII (credit cards, SSNs detected)",
        "source_ip": "198.51.100.12",
        "http_request": {
            "method": "GET",
            "uri": "/api/v1/users/export?format=csv&include=payment_info",
            "headers": {
                "Host": "api.example.com",
                "Authorization": "Bearer eyJ...export_scope_token",
            },
            "body": None,
        },
        "http_response": {
            "status_code": 500,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Internal Server Error - Response blocked by DLP policy"},
        },
    },
    # ── 32. SCANNER_DETECTION (FP) ──
    # Security scanner tool detected via User-Agent and header patterns.
    # Mitigated by: ModSecurity rule 1060 (scanner tool detection),
    # CRS 913 scanner detection rules, NGINX $is_bad_bot map,
    # AWS WAF suspicious-user-agents regex pattern set.
    {
        "template_id": "fp-scanner-detection",
        "attack_type": "SCANNER_DETECTION",
        "target_endpoint": "/api/v1/users",
        "http_method": "GET",
        "severity": "MEDIUM",
        "traceable_reason": "Automated security scanner detected: User-Agent matches known vulnerability scanner (sqlmap/1.7), request pattern consistent with automated enumeration.",
        "payload_snippet": "GET /api/v1/users UA: sqlmap/1.7#stable — automated SQL injection scanner",
        "source_ip": "192.0.2.180",
        "http_request": {
            "method": "GET",
            "uri": "/api/v1/users?id=1",
            "headers": {
                "Host": "api.example.com",
                "User-Agent": "sqlmap/1.7#stable (https://sqlmap.org)",
                "Accept": "*/*",
            },
            "body": None,
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden"},
        },
    },
    # ── 33. SSTI (Server-Side Template Injection) (FP) ──
    # Template expression in input parameters.
    # Mitigated by: ModSecurity rule 1012 (SSTI detection),
    # Kong request-validator (maxLength + content type enforcement).
    {
        "template_id": "fp-ssti",
        "attack_type": "SSTI",
        "target_endpoint": "/api/v1/search",
        "http_method": "POST",
        "severity": "CRITICAL",
        "traceable_reason": "Server-side template injection detected: Jinja2 template expression {{config}} found in search query, potentially exposing server configuration.",
        "payload_snippet": "POST /api/v1/search body: {\"q\": \"{{config.__class__.__init__.__globals__['os'].popen('id').read()}}\"}",
        "source_ip": "203.0.113.91",
        "http_request": {
            "method": "POST",
            "uri": "/api/v1/search",
            "headers": {
                "Host": "api.example.com",
                "Content-Type": "application/json",
            },
            "body": {"q": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"},
        },
        "http_response": {
            "status_code": 403,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Forbidden - Template expression blocked"},
        },
    },
    # ── 34. CORS_BYPASS (FP) ──
    # Cross-origin request from unauthorized domain.
    # Mitigated by: Kong CORS plugin (strict origin whitelist),
    # NGINX $cors_origin map (only app.example.com, admin.example.com),
    # security headers (X-Frame-Options: DENY).
    {
        "template_id": "fp-cors-bypass",
        "attack_type": "CORS_BYPASS",
        "target_endpoint": "/api/v1/profile",
        "http_method": "OPTIONS",
        "severity": "MEDIUM",
        "traceable_reason": "CORS policy bypass attempt: preflight request from unauthorized origin (https://evil-site.com) attempting cross-origin access to user profile endpoint.",
        "payload_snippet": "OPTIONS /api/v1/profile Origin: https://evil-site.com — CORS preflight from non-whitelisted domain",
        "source_ip": "192.0.2.120",
        "http_request": {
            "method": "OPTIONS",
            "uri": "/api/v1/profile",
            "headers": {
                "Host": "api.example.com",
                "Origin": "https://evil-site.com",
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
            "body": None,
        },
        "http_response": {
            "status_code": 204,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "",
            },
            "body": None,
        },
    },
    # ── 35. DEPRECATED_API_ACCESS (FP) ──
    # Client accessing deprecated v0 API that has been terminated.
    # Mitigated by: Kong request-termination plugin (410 Gone),
    # NGINX location /api/v0/ returns 410.
    {
        "template_id": "fp-deprecated-api",
        "attack_type": "DEPRECATED_API_ACCESS",
        "target_endpoint": "/api/v0/users",
        "http_method": "GET",
        "severity": "LOW",
        "traceable_reason": "Access to deprecated API version: client attempting to use decommissioned v0 endpoint which may have known vulnerabilities.",
        "payload_snippet": "GET /api/v0/users — deprecated API version, known auth bypass in v0",
        "source_ip": "10.0.5.44",
        "http_request": {
            "method": "GET",
            "uri": "/api/v0/users?page=1",
            "headers": {
                "Host": "api.example.com",
                "Accept": "application/json",
            },
            "body": None,
        },
        "http_response": {
            "status_code": 410,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "API v0 has been deprecated and removed. Please migrate to /api/v1/ or /api/v2/."},
        },
    },
    # ── 36. PAYMENT_FRAUD (FP) ──
    # Suspicious high-value payment from geo-restricted region with rate abuse.
    # Mitigated by: Kong JWT + ACL (payments-group), rate-limiting (5/min),
    # request-validator (amount max 100000, strict schema), NGINX payment rate limit,
    # AWS WAF geo-block, payment SG strict egress.
    {
        "template_id": "fp-payment-fraud",
        "attack_type": "PAYMENT_FRAUD",
        "target_endpoint": "/api/v1/payments",
        "http_method": "POST",
        "severity": "CRITICAL",
        "traceable_reason": "Suspicious payment attempt: high-value transaction ($99,999.99) with rapid submission pattern (5 attempts in 60s), source IP flagged by threat intelligence.",
        "payload_snippet": "POST /api/v1/payments body: {\"amount\": 99999.99} — 5 rapid attempts from flagged IP",
        "source_ip": "45.227.88.10",
        "http_request": {
            "method": "POST",
            "uri": "/api/v1/payments",
            "headers": {
                "Host": "api.example.com",
                "Content-Type": "application/json",
                "Authorization": "Bearer eyJ...compromised_token",
            },
            "body": {"amount": 99999.99, "currency": "USD", "description": "urgent wire transfer"},
        },
        "http_response": {
            "status_code": 429,
            "headers": {"Content-Type": "application/json", "Retry-After": "60"},
            "body": {"error": "Too Many Requests"},
        },
    },

    # ==========================================================================
    # PHASE 2 — New True Positive Scenarios
    # ==========================================================================

    # ── 37. TRUE POSITIVE: BROKEN_FUNCTION_AUTH on admin bulk operations ──
    # JWT auth exists but ACL plugin is missing — any authenticated user
    # can perform admin bulk operations (delete users, reset passwords, etc.)
    {
        "template_id": "tp-broken-function-auth-admin-bulk",
        "attack_type": "BROKEN_FUNCTION_AUTHORIZATION",
        "target_endpoint": "/api/v1/admin/bulk",
        "http_method": "POST",
        "severity": "CRITICAL",
        "traceable_reason": "Broken Function Level Authorization: regular user (role=viewer) successfully performed bulk admin operation (mass password reset) via /api/v1/admin/bulk. JWT auth present but no role-based access control enforced.",
        "payload_snippet": "POST /api/v1/admin/bulk body: {\"action\": \"reset_passwords\", \"user_ids\": [1,2,3,...,100]} with viewer-role JWT — SUCCESS (200 OK)",
        "source_ip": "10.0.5.15",
        "http_request": {
            "method": "POST",
            "uri": "/api/v1/admin/bulk",
            "headers": {
                "Host": "api.example.com",
                "Content-Type": "application/json",
                "Authorization": "Bearer eyJ...viewer_role_token",
            },
            "body": {
                "action": "reset_passwords",
                "user_ids": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                "notify": False,
            },
        },
        "http_response": {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": {
                "status": "completed",
                "affected_users": 10,
                "action": "reset_passwords",
            },
        },
    },
    # ── 38. TRUE POSITIVE: SSRF via misconfigured analytics service ──
    # Analytics service has a misconfigured SG (allows 0.0.0.0/0 inbound)
    # and no Kong auth plugins. An attacker can bypass all security layers
    # by directly hitting the service IP, exfiltrating internal data.
    {
        "template_id": "tp-ssrf-analytics-misconfigured",
        "attack_type": "NETWORK_MISCONFIGURATION",
        "target_endpoint": "/api/internal/analytics",
        "http_method": "GET",
        "severity": "CRITICAL",
        "traceable_reason": "Network security misconfiguration: analytics service accessible from internet due to misconfigured security group (allows 0.0.0.0/0). No authentication plugins applied. Attacker can directly access internal analytics data bypassing WAF and API gateway.",
        "payload_snippet": "GET /api/internal/analytics?report=revenue&year=2026 — no auth required, SG allows internet access (MISCONFIGURED)",
        "source_ip": "198.51.100.200",
        "http_request": {
            "method": "GET",
            "uri": "/api/internal/analytics?report=revenue&year=2026&include=raw_data",
            "headers": {
                "Host": "10.0.10.90",
                "Accept": "application/json",
            },
            "body": None,
        },
        "http_response": {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": {
                "report": "revenue",
                "year": 2026,
                "total_revenue": 45000000,
                "customer_count": 125000,
                "avg_transaction": 360.00,
                "top_customers": [
                    {"id": 1001, "name": "Acme Corp", "revenue": 2500000},
                    {"id": 1002, "name": "Globex Inc", "revenue": 1800000},
                ],
                "confidential": True,
            },
        },
    },
]

# Quick lookup
FALSE_POSITIVE_TEMPLATES = [t for t in TEMPLATES if t["template_id"].startswith("fp-")]
TRUE_POSITIVE_TEMPLATES = [t for t in TEMPLATES if t["template_id"].startswith("tp-")]
