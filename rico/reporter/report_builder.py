from __future__ import annotations
"""Report generation module for RICO security testing."""
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path
import json
from jinja2 import Environment, FileSystemLoader, select_autoescape


# CVSS Score mapping for different attack types
CVSS_MAP = {
    "SQL Injection": 9.0,
    "SSRF": 9.0,
    "Command Injection": 9.0,
    "IDOR": 8.0,
    "Missing Auth": 7.5,
    "Business Logic Flaw": 7.0,
    "CSRF": 6.5,
    "Information Disclosure": 5.0,
}

# Strict severity weights for production-grade scoring
SEVERITY_WEIGHTS = {
    "Critical": 40,
    "High": 25,
    "Medium": 15,
    "Low": 5,
    "Info": 0
}

# Attack type to severity mapping (deterministic)
ATTACK_SEVERITY_MAP = {
    "SQL Injection": "Critical",
    "SSRF": "Critical",
    "Command Injection": "Critical",
    "IDOR": "High",
    "Missing Auth": "High",  # For sensitive endpoints
    "Business Logic Flaw": "High",
    "CSRF": "Medium",
    "Information Disclosure": "Medium",
}


def get_cvss_score(attack_type: str) -> float:
    """
    Get CVSS score for an attack type.
    
    Args:
        attack_type: Type of attack
        
    Returns:
        CVSS score (0.0-10.0)
    """
    return CVSS_MAP.get(attack_type, 5.0)


def compute_security_score(report_items: List[ReportItem]) -> Tuple[int, str]:
    """
    Compute overall security score based on vulnerabilities found.
    
    PRODUCTION-GRADE FORMULA:
    score = 100 - sum(severity_weights)
    
    Severity Weights:
    - Critical: 40 points
    - High: 25 points
    - Medium: 15 points
    - Low: 5 points
    
    SUSPICIOUS findings are weighted at 40% of their severity
    
    Risk levels (STRICT):
    - score >= 80: LOW
    - score >= 60: MEDIUM
    - score >= 40: HIGH
    - score < 40: CRITICAL
    
    Args:
        report_items: List of ReportItem objects
        
    Returns:
        Tuple of (score, risk_level)
    """
    # Count vulnerabilities by severity and status
    critical_count = 0.0
    high_count = 0.0
    medium_count = 0.0
    low_count = 0.0
    
    for item in report_items:
        # Determine weight based on status
        if item.status == "VULNERABLE":
            weight = 1.0  # 100% weight for confirmed vulnerabilities
        elif item.status == "SUSPICIOUS":
            weight = 0.4  # 40% weight for suspicious findings
        else:
            weight = 0.0  # No weight for safe findings
        
        # Apply weighted count
        if weight > 0:
            if item.severity == "Critical":
                critical_count += weight
            elif item.severity == "High":
                high_count += weight
            elif item.severity == "Medium":
                medium_count += weight
            elif item.severity == "Low":
                low_count += weight
    
    # Calculate score with STRICT severity weights
    score = 100 - (
        critical_count * SEVERITY_WEIGHTS["Critical"] +
        high_count * SEVERITY_WEIGHTS["High"] +
        medium_count * SEVERITY_WEIGHTS["Medium"] +
        low_count * SEVERITY_WEIGHTS["Low"]
    )
    score = max(0, score)  # Floor at 0
    
    # Determine risk level (STRICT THRESHOLDS)
    if score >= 80:
        risk_level = "LOW"
    elif score >= 60:
        risk_level = "MEDIUM"
    elif score >= 40:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"
    
    return int(score), risk_level


def find_top_issue(report_items: List[ReportItem]) -> str:
    """
    Find the top vulnerability issue.
    
    Args:
        report_items: List of ReportItem objects
        
    Returns:
        Description of top issue or "None" if no vulnerabilities
    """
    vulnerabilities = [
        item for item in report_items 
        if item.status in ["VULNERABLE", "SUSPICIOUS"]
    ]
    
    if not vulnerabilities:
        return "None"
    
    # Sort by severity priority and CVSS score
    severity_priority = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    
    top_vuln = max(
        vulnerabilities,
        key=lambda x: (severity_priority.get(x.severity, 0), x.cvss_score, x.confidence)
    )
    
    return f"{top_vuln.attack_type} in {top_vuln.endpoint}"


class ReportItem:
    """Data model for a security test result."""
    
    def __init__(
        self,
        endpoint: str,
        attack_type: str,
        status: str,
        confidence: int,
        description: str,
        poc_curl: str,
        fix_suggestion: str,
        severity: str,
        cvss_score: float,
        details: Optional[Dict[str, Any]] = None,
        reasoning: Optional[str] = None
    ):
        self.endpoint = endpoint
        self.attack_type = attack_type
        self.status = status
        self.confidence = confidence
        self.description = description
        self.poc_curl = poc_curl
        self.fix_suggestion = fix_suggestion
        self.severity = severity
        self.cvss_score = cvss_score
        self.details = details or {}
        self.reasoning = reasoning
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "endpoint": self.endpoint,
            "attack_type": self.attack_type,
            "status": self.status,
            "confidence": self.confidence,
            "description": self.description,
            "poc_curl": self.poc_curl,
            "fix_suggestion": self.fix_suggestion,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "details": self.details,
            "reasoning": self.reasoning
        }


def determine_severity(attack_type: str, confidence: int, vulnerable: bool) -> str:
    """
    Determine severity level based on attack type and confidence.
    
    PRODUCTION-GRADE SEVERITY MAPPING:
    - SQL Injection → CRITICAL
    - SSRF → CRITICAL
    - Command Injection → CRITICAL
    - IDOR → HIGH
    - Missing Auth (sensitive) → HIGH
    - Business Logic Flaw → HIGH
    - CSRF → MEDIUM
    - Information Disclosure → MEDIUM
    
    Args:
        attack_type: Type of attack
        confidence: Confidence score (0-100)
        vulnerable: Whether vulnerability was detected
        
    Returns:
        Severity level: Critical, High, Medium, Low, or Info
    """
    if not vulnerable or confidence < 60:
        return "Info"
    
    # Use strict attack type to severity mapping
    if attack_type in ATTACK_SEVERITY_MAP:
        base_severity = ATTACK_SEVERITY_MAP[attack_type]
        
        # For high confidence (>80%), use the mapped severity
        if confidence > 80:
            return base_severity
        
        # For medium confidence (60-80%), downgrade by one level
        if confidence > 60:
            if base_severity == "Critical":
                return "High"
            elif base_severity == "High":
                return "Medium"
            else:
                return base_severity
    
    # Fallback for unknown attack types
    if confidence > 80:
        return "High"
    elif confidence > 60:
        return "Medium"
    
    return "Low"


def get_fix_suggestion(attack_type: str) -> str:
    """
    Get fix suggestion based on attack type.
    
    Args:
        attack_type: Type of attack
        
    Returns:
        Fix suggestion text
    """
    fix_suggestions = {
        "IDOR": (
            "Implement proper authorization checks:\n"
            "1. Verify the authenticated user owns the requested resource\n"
            "2. Use indirect object references (e.g., UUIDs instead of sequential IDs)\n"
            "3. Implement access control lists (ACLs)\n"
            "4. Log all access attempts for audit trails"
        ),
        "Missing Auth": (
            "Add authentication middleware:\n"
            "1. Require valid authentication tokens for all protected endpoints\n"
            "2. Implement JWT or session-based authentication\n"
            "3. Return 401 Unauthorized for unauthenticated requests\n"
            "4. Use role-based access control (RBAC) for different user levels"
        ),
        "SQL Injection": (
            "Use parameterized queries and input validation:\n"
            "1. Always use prepared statements with parameterized queries\n"
            "2. Use ORM frameworks (e.g., SQLAlchemy, Django ORM)\n"
            "3. Validate and sanitize all user inputs\n"
            "4. Apply principle of least privilege to database accounts\n"
            "5. Use stored procedures where appropriate\n"
            "6. Implement Web Application Firewall (WAF) rules"
        )
    }
    
    return fix_suggestions.get(attack_type, "Review and implement security best practices for this endpoint.")


def build_curl(
    endpoint: str,
    base_url: str,
    method: str = "GET",
    token: Optional[str] = None,
    payload: Optional[str] = None
) -> str:
    """
    Build a curl command for proof-of-concept.
    
    Args:
        endpoint: Endpoint path
        base_url: Base URL
        method: HTTP method
        token: Optional auth token
        payload: Optional payload for injection
        
    Returns:
        Formatted curl command
    """
    url = base_url.rstrip('/') + endpoint
    
    # Replace payload if provided
    if payload:
        url = url.replace('{id}', payload)
    else:
        url = url.replace('{id}', '1')
    
    curl_parts = [f'curl -X {method} "{url}"']
    
    if token:
        curl_parts.append(f'  -H "Authorization: Bearer {token}"')
    
    curl_parts.append('  -H "Content-Type: application/json"')
    
    return ' \\\n'.join(curl_parts)


def convert_results_to_report_items(
    results: List[Dict[str, Any]],
    base_url: str,
    token: Optional[str] = None
) -> List[ReportItem]:
    """
    Convert attack results to ReportItem objects.
    
    Args:
        results: List of attack results
        base_url: Base URL of tested API
        token: Optional auth token
        
    Returns:
        List of ReportItem objects
    """
    report_items = []
    
    for result in results:
        endpoint = result.get("endpoint", "Unknown")
        attack_type = result.get("attack_type", "Unknown")
        vulnerable = result.get("vulnerable", False)
        confidence = result.get("confidence", 0)
        details = result.get("details", "No details available")
        reasoning = result.get("reasoning", None)
        
        # Determine status
        if vulnerable and confidence > 80:
            status = "VULNERABLE"
        elif vulnerable and confidence > 60:
            status = "SUSPICIOUS"
        else:
            status = "SAFE"
        
        # Determine severity
        severity = determine_severity(attack_type, confidence, vulnerable)
        
        # Get CVSS score
        cvss_score = get_cvss_score(attack_type)
        
        # Build PoC curl command
        method = "GET"  # Default, could be extracted from result
        poc_curl = build_curl(endpoint, base_url, method, token)
        
        # Get fix suggestion
        fix_suggestion = get_fix_suggestion(attack_type)
        
        report_item = ReportItem(
            endpoint=endpoint,
            attack_type=attack_type,
            status=status,
            confidence=confidence,
            description=details,
            poc_curl=poc_curl,
            fix_suggestion=fix_suggestion,
            severity=severity,
            cvss_score=cvss_score,
            details=result,
            reasoning=reasoning
        )
        
        report_items.append(report_item)
    
    return report_items


def check_severity_threshold(report_items: List[ReportItem], threshold: str) -> bool:
    """
    Check if any vulnerabilities meet or exceed severity threshold.
    
    Args:
        report_items: List of ReportItem objects
        threshold: Severity threshold (critical/high/medium/low)
        
    Returns:
        True if should fail build, False otherwise
    """
    severity_levels = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0
    }
    
    threshold_level = severity_levels.get(threshold.lower(), 0)
    
    for item in report_items:
        if item.status in ["VULNERABLE", "SUSPICIOUS"]:
            item_level = severity_levels.get(item.severity.lower(), 0)
            if item_level >= threshold_level:
                return True
    
    return False


def generate_markdown_report(
    report_items: List[ReportItem],
    base_url: str,
    output_path: str
) -> None:
    """
    Generate a Markdown security report.
    
    Args:
        report_items: List of ReportItem objects
        base_url: Base URL of tested API
        output_path: Path to save the report
    """
    # Calculate statistics
    total_tests = len(report_items)
    vulnerabilities = [item for item in report_items if item.status in ["VULNERABLE", "SUSPICIOUS"]]
    critical = [item for item in vulnerabilities if item.severity == "Critical"]
    high = [item for item in vulnerabilities if item.severity == "High"]
    medium = [item for item in vulnerabilities if item.severity == "Medium"]
    safe = [item for item in report_items if item.status == "SAFE"]
    
    # Compute security score
    security_score, risk_level = compute_security_score(report_items)
    top_issue = find_top_issue(report_items)
    
    # Build markdown content
    md_lines = [
        "# RICO Security Report",
        "",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Target API:** {base_url}",
        f"**Total Tests:** {total_tests}",
        f"**Vulnerabilities Found:** {len(vulnerabilities)}",
        "",
        "## Executive Summary",
        "",
        f"### Security Score: {security_score}/100",
        f"**Risk Level:** {risk_level}",
        f"**Top Issue:** {top_issue}",
        "",
        "### Vulnerability Breakdown",
        f"- 🔴 Critical: {len(critical)}",
        f"- 🟠 High: {len(high)}",
        f"- 🟡 Medium: {len(medium)}",
        f"- 🟢 Safe: {len(safe)}",
        "",
        "---",
        ""
    ]
    
    # Add vulnerabilities section
    if vulnerabilities:
        md_lines.extend([
            "## Vulnerabilities Detected",
            ""
        ])
        
        for idx, item in enumerate(vulnerabilities, 1):
            severity_emoji = {
                "Critical": "🔴",
                "High": "🟠",
                "Medium": "🟡",
                "Low": "🔵"
            }.get(item.severity, "⚪")
            
            md_lines.extend([
                f"### {idx}. {item.endpoint}",
                "",
                f"**Attack Type:** {item.attack_type}",
                f"**Severity:** {severity_emoji} {item.severity} (CVSS: {item.cvss_score})",
                f"**Confidence:** {item.confidence}%",
                f"**Status:** {item.status}",
                ""
            ])
            
            if item.reasoning:
                md_lines.extend([
                    f"**AI Reasoning:** {item.reasoning}",
                    ""
                ])
            
            md_lines.extend([
                "**Description:**",
                "",
                item.description,
                "",
                "**Proof of Concept:**",
                "",
                "```bash",
                item.poc_curl,
                "```",
                "",
                "**Fix Suggestion:**",
                "",
                item.fix_suggestion,
                "",
                "---",
                ""
            ])
    
    # Add safe endpoints section
    if safe:
        md_lines.extend([
            "## Safe Endpoints",
            "",
            "The following endpoints passed security tests:",
            ""
        ])
        
        safe_by_endpoint = {}
        for item in safe:
            if item.endpoint not in safe_by_endpoint:
                safe_by_endpoint[item.endpoint] = []
            safe_by_endpoint[item.endpoint].append(item.attack_type)
        
        for endpoint, attacks in safe_by_endpoint.items():
            md_lines.append(f"- `{endpoint}` - Tested: {', '.join(attacks)}")
        
        md_lines.append("")
    
    # Add footer
    md_lines.extend([
        "---",
        "",
        "## Recommendations",
        "",
        "1. **Prioritize Critical and High severity vulnerabilities** for immediate remediation",
        "2. **Implement security testing** in your CI/CD pipeline",
        "3. **Conduct regular security audits** of your API endpoints",
        "4. **Follow OWASP API Security Top 10** guidelines",
        "5. **Enable logging and monitoring** for security events",
        "",
        "---",
        "",
        f"*Report generated by RICO - AI-Powered API Security Testing*"
    ])
    
    # Write to file
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(md_lines))


def generate_html_report(
    report_items: List[ReportItem],
    base_url: str,
    output_path: str
) -> None:
    """
    Generate an HTML security report using Jinja2.
    
    Args:
        report_items: List of ReportItem objects
        base_url: Base URL of tested API
        output_path: Path to save the report
    """
    # Calculate statistics
    total_tests = len(report_items)
    vulnerabilities = [item for item in report_items if item.status in ["VULNERABLE", "SUSPICIOUS"]]
    critical = [item for item in vulnerabilities if item.severity == "Critical"]
    high = [item for item in vulnerabilities if item.severity == "High"]
    medium = [item for item in vulnerabilities if item.severity == "Medium"]
    safe = [item for item in report_items if item.status == "SAFE"]
    
    # Compute security score
    security_score, risk_level = compute_security_score(report_items)
    top_issue = find_top_issue(report_items)
    
    # Setup Jinja2 environment
    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(['html', 'xml'])
    )
    
    template = env.get_template('report.html')
    
    # Render template
    html_content = template.render(
        generated_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        base_url=base_url,
        total_tests=total_tests,
        vulnerabilities_count=len(vulnerabilities),
        critical_count=len(critical),
        high_count=len(high),
        medium_count=len(medium),
        safe_count=len(safe),
        security_score=security_score,
        risk_level=risk_level,
        top_issue=top_issue,
        vulnerabilities=vulnerabilities,
        safe_endpoints=safe,
        report_items=report_items
    )
    
    # Write to file
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
