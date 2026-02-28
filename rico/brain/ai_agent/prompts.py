"""Prompts for AI-powered security analysis."""

CLASSIFICATION_PROMPT = """Analyze this API endpoint and classify it:

Endpoint: {method} {path}
Parameters: {parameters}

Classify into one of these types:
- auth: Authentication/login endpoints
- resource: CRUD operations on resources (users, posts, etc.)
- admin: Administrative/privileged operations
- public: Public endpoints (no auth needed)

Determine sensitivity level:
- low: Public data, no security risk
- medium: User data, moderate risk
- high: Sensitive data, admin operations

Respond in JSON format:
{{
  "type": "auth|resource|admin|public",
  "sensitivity": "low|medium|high",
  "reason": "brief explanation"
}}"""

ATTACK_PLANNER_PROMPT = """Given this endpoint classification, recommend security tests:

Endpoint: {method} {path}
Type: {endpoint_type}
Sensitivity: {sensitivity}

Available tests:
- IDOR: Insecure Direct Object Reference
- Missing Auth: Authentication bypass
- SQL Injection: Database injection attacks

Recommend which tests to run and why.

Respond in JSON format:
{{
  "attacks": ["IDOR", "Missing Auth", "SQL Injection"],
  "reasoning": "brief explanation for each"
}}"""

EXPLANATION_PROMPT = """Explain why this security test is relevant:

Endpoint: {method} {path}
Attack Type: {attack_type}
Classification: {classification}

Provide a concise explanation (1-2 sentences) of why this attack is relevant for this endpoint.

Response format: Plain text explanation."""
