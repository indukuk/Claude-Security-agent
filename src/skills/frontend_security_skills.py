from __future__ import annotations

"""
Frontend Security Skills
=========================
Client-side security analysis for the compliance platform's vanilla JS SPA.

This frontend:
- Vanilla JS (no React/Vue/Angular)
- auth.js handles Cognito token lifecycle
- Tokens stored in sessionStorage
- API endpoints hardcoded in JS
- No build step (raw JS served directly)
- CORS * on some backends
"""


# =============================================================================
# SKILL 1: Client-Side Vulnerability Patterns
# =============================================================================

FRONTEND_VULNERABILITIES = [
    {
        "id": "FE-AUTH-001",
        "title": "API endpoint hardcoded in client-side JavaScript",
        "severity": "MEDIUM",
        "cwe": "CWE-798",
        "description": "API Gateway URL and API key visible in frontend source code. "
                     "Any user can extract these to make direct API calls outside the UI.",
        "detection": """
            Search for patterns:
            - AUTH_API: 'https://...'
            - API_KEY: '...'
            - fetch('https://...')
            - X-Api-Key header values
        """,
        "impact": "Attacker can automate API abuse, bypass UI-level rate limiting, "
                 "script enumeration attacks. API key is shared across all users.",
        "remediation": "Use Cognito tokens as primary auth (not API key). "
                     "If API key is needed for throttling, generate per-user keys. "
                     "Never embed secrets in client code."
    },
    {
        "id": "FE-AUTH-002",
        "title": "Token stored in sessionStorage",
        "severity": "LOW",
        "cwe": "CWE-922",
        "description": "JWT tokens stored in sessionStorage. While better than localStorage "
                     "(cleared on tab close), still accessible to XSS.",
        "detection": """
            Search for:
            - sessionStorage.setItem('token', ...)
            - sessionStorage.setItem('refreshToken', ...)
            - sessionStorage.getItem('token')
        """,
        "impact": "If XSS exists, attacker can steal tokens. sessionStorage is per-tab "
                 "so impact is limited vs localStorage, but still a concern.",
        "remediation": "Consider HttpOnly cookies with SameSite=Strict for token storage. "
                     "Alternatively, use short-lived tokens (already 1hr) with secure refresh flow.",
        "mitigating_factor": "No XSS vectors identified in this vanilla JS app (no innerHTML, "
                           "no dynamic script injection). Risk is theoretical without XSS."
    },
    {
        "id": "FE-AUTH-003",
        "title": "No Content Security Policy (CSP) header",
        "severity": "MEDIUM",
        "cwe": "CWE-1021",
        "description": "Frontend served without CSP headers. If XSS is found, no mitigation.",
        "detection": """
            Check HTTP response headers for:
            - Content-Security-Policy
            - X-Content-Type-Options
            - X-Frame-Options
            - Strict-Transport-Security

            In CDK: check CloudFront distribution response headers policy.
        """,
        "remediation": """
            Add CloudFront response headers policy:
            cloudfront.ResponseHeadersPolicy(
                security_headers_behavior=cloudfront.ResponseSecurityHeadersBehavior(
                    content_security_policy=cloudfront.ResponseHeadersContentSecurityPolicy(
                        content_security_policy="default-src 'self'; script-src 'self'; connect-src https://*.amazonaws.com",
                        override=True
                    ),
                    strict_transport_security=cloudfront.ResponseHeadersStrictTransportSecurity(
                        access_control_max_age=Duration.days(365),
                        include_subdomains=True,
                        override=True
                    )
                )
            )
        """
    },
    {
        "id": "FE-XSS-001",
        "title": "Dynamic content insertion without sanitization",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "description": "User-generated content (compliance evaluations, messages) "
                     "inserted into DOM without escaping.",
        "detection": """
            Search for:
            - element.innerHTML = data
            - document.write(data)
            - element.insertAdjacentHTML('beforeend', data)

            Where 'data' originates from API responses containing user content.
        """,
        "safe_patterns": [
            "element.textContent = data  (safe — no HTML parsing)",
            "element.innerText = data    (safe — no HTML parsing)",
        ],
        "unsafe_patterns": [
            "element.innerHTML = response.evaluation  (unsafe if evaluation contains user text)",
            "chatBox.innerHTML += `<div>${message}</div>`  (unsafe if message is user input)",
        ],
    },
    {
        "id": "FE-AUTH-004",
        "title": "Refresh token handling without rotation",
        "severity": "LOW",
        "cwe": "CWE-384",
        "description": "If refresh tokens are not rotated on use, a stolen refresh token "
                     "provides persistent access for its full validity period (30 days).",
        "detection": """
            Check auth.js:
            - Does /auth/refresh return a new refresh token?
            - Is the old refresh token invalidated?
            - What is the refresh token validity? (30 days in this codebase)
        """,
        "remediation": "Enable refresh token rotation in Cognito: each refresh grants "
                     "a new refresh token and invalidates the old one."
    },
    {
        "id": "FE-REDIRECT-001",
        "title": "Open redirect after login",
        "severity": "LOW",
        "cwe": "CWE-601",
        "description": "If the app redirects to a URL parameter after login, attacker can "
                     "craft a link that redirects the user to a phishing page post-auth.",
        "detection": """
            Search for:
            - window.location = param
            - window.location.href = searchParams.get('redirect')
            - history.pushState with user-controlled path
        """,
    },
]


# =============================================================================
# SKILL 2: Frontend-to-Backend Security Boundary Checks
# =============================================================================

FRONTEND_BACKEND_BOUNDARY = {
    "principle": "Never trust client-side enforcement. Every security check in the frontend "
               "must be duplicated server-side. The frontend is for UX, not security.",
    "checks": [
        {
            "id": "FB-001",
            "check": "Role-based UI hiding vs server-side enforcement",
            "question": "Does the frontend hide admin buttons for non-admin users?",
            "risk": "If the API doesn't also check permissions, hiding the button is meaningless. "
                   "User can call the API directly.",
            "verify": "For each frontend role check, confirm the backend Lambda also checks.",
        },
        {
            "id": "FB-002",
            "check": "Input validation in frontend vs backend",
            "question": "Does the frontend validate inputs before sending?",
            "risk": "Client-side validation can be bypassed. Backend must re-validate.",
            "verify": "Pydantic models in backend handlers should enforce all constraints.",
        },
        {
            "id": "FB-003",
            "check": "Token expiry handling",
            "question": "What happens when the access token expires mid-session?",
            "risk": "If frontend doesn't handle 401 gracefully, it might expose error details "
                   "or leave the user in an inconsistent state.",
            "verify": "Check for 401 handler in fetch wrapper that triggers refresh flow.",
        },
    ],
}


# =============================================================================
# SKILL 3: Static Asset Security
# =============================================================================

STATIC_ASSET_CHECKS = [
    {
        "id": "SA-001",
        "check": "Source maps exposed in production",
        "detection": "Look for .map files in deployment assets or sourceMappingURL comments",
        "risk": "Source maps reveal original source code structure to attackers",
    },
    {
        "id": "SA-002",
        "check": "Sensitive comments in production JS",
        "detection": "Search for TODO, HACK, FIXME, password, secret, key in served JS files",
        "risk": "Comments may reveal internal logic, temporary workarounds, or credentials",
    },
    {
        "id": "SA-003",
        "check": "Unminified JavaScript in production",
        "detection": "Check if JS files are minified/bundled or served as-is",
        "risk": "Readable code makes reverse engineering trivial. Not a vulnerability itself "
               "but increases attack surface knowledge.",
        "note": "This codebase serves raw JS — acceptable for internal tools, risky for public SaaS.",
    },
]
