"""
Generate unified report in reports/report.html
"""

from rico.reporting.report_builder import ReportBuilder
from datetime import datetime

# Sample vulnerabilities for demonstration
sample_vulnerabilities = [
    {
        "id": "RICO-001",
        "type": "SQL Injection",
        "endpoint": "/users/search",
        "method": "GET",
        "severity": "Critical",
        "confidence": 0.95,
        "description": "SQL injection vulnerability detected in search parameter. Attacker can execute arbitrary SQL queries.",
        "poc": {
            "curl": "curl -X GET 'http://localhost:8000/users/search?q=' OR 1=1--'"
        }
    },
    {
        "id": "RICO-002",
        "type": "IDOR",
        "endpoint": "/users/{user_id}/orders",
        "method": "GET",
        "severity": "High",
        "confidence": 0.85,
        "description": "Insecure Direct Object Reference allows accessing other users' orders by manipulating the user_id parameter.",
        "poc": {
            "curl": "curl -X GET 'http://localhost:8000/users/999/orders'"
        }
    },
    {
        "id": "RICO-003",
        "type": "Missing Authentication",
        "endpoint": "/admin/users",
        "method": "GET",
        "severity": "Critical",
        "confidence": 0.90,
        "description": "Admin endpoint accessible without authentication. Exposes sensitive user data.",
        "poc": {
            "curl": "curl -X GET 'http://localhost:8000/admin/users'"
        }
    },
    {
        "id": "RICO-004",
        "type": "IDOR",
        "endpoint": "/users/{user_id}",
        "method": "GET",
        "severity": "Medium",
        "confidence": 0.75,
        "description": "User profile endpoint allows accessing other users' information.",
        "poc": {
            "curl": "curl -X GET 'http://localhost:8000/users/123'"
        }
    },
    {
        "id": "RICO-005",
        "type": "CSRF",
        "endpoint": "/users/update",
        "method": "POST",
        "severity": "Medium",
        "confidence": 0.70,
        "description": "Missing CSRF protection on user update endpoint.",
        "poc": {
            "curl": "curl -X POST 'http://localhost:8000/users/update' -d 'email=attacker@evil.com'"
        }
    }
]

# Metadata
metadata = {
    "target_url": "http://localhost:8000",
    "scan_timestamp": datetime.utcnow().isoformat()
}

# Build report
print("Generating unified report in reports/report.html...")
builder = ReportBuilder(sample_vulnerabilities, metadata)

# Export individual files to reports directory
builder.export_json("reports/report.json")
builder.export_markdown("reports/report.md")
builder.export_html("reports/report.html")

print("\n[OK] Unified report generated successfully!")
print("\nGenerated files:")
print("  - reports/report.json")
print("  - reports/report.md")
print("  - reports/report.html")
print("\nOpen the report with: start reports/report.html")
