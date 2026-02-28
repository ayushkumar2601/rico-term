"""
HTML Exporter - Generates unified minimalist HTML security reports

Combines:
- Minimalist black/white UI design with dark mode
- Interactive Chart.js visualizations
- Executive summary and risk metrics
- Expandable vulnerability details
"""

from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path
import json


class HTMLExporter:
    """Exports security reports in unified minimalist HTML format."""
    
    def __init__(self, vulnerabilities: List[Dict[str, Any]], metadata: Dict[str, Any]):
        """
        Initialize HTML exporter.
        
        Args:
            vulnerabilities: List of enriched vulnerabilities
            metadata: Scan metadata
        """
        self.vulnerabilities = vulnerabilities
        self.metadata = metadata
    
    def generate(self, summary_stats: Dict[str, Any], executive_summary: str) -> str:
        """
        Generate complete unified HTML report.
        
        Args:
            summary_stats: Summary statistics
            executive_summary: Executive summary text
            
        Returns:
            HTML string
        """
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RICO Security Assessment Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        {self._get_css()}
    </style>
</head>
<body>
    <div class="container">
        {self._generate_header()}
        {self._generate_meta_bar(summary_stats)}
        <hr class="section-separator">
        <div class="content">
            {self._generate_executive_summary_section(summary_stats, executive_summary)}
            {self._generate_charts_section(summary_stats)}
            {self._generate_vulnerabilities_section()}
            {self._generate_recommendations()}
        </div>
        <hr class="section-separator">
        {self._generate_footer()}
    </div>
    <script>
        {self._generate_javascript(summary_stats)}
    </script>
</body>
</html>"""
    
    def _get_css(self) -> str:
        """Get minimalist CSS styles with dark mode support."""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            line-height: 1.6;
            color: #1a1a1a;
            background: #ffffff;
            transition: background-color 0.3s, color 0.3s;
        }
        
        body.dark-mode {
            background: #111111;
            color: #e5e5e5;
        }
        
        .container {
            max-width: 210mm;
            margin: 0 auto;
            background: #ffffff;
            border: 1px solid #e0e0e0;
            transition: background-color 0.3s, border-color 0.3s;
        }
        
        body.dark-mode .container {
            background: #111111;
            border-color: #333333;
        }
        
        .header {
            background: #ffffff;
            border-bottom: 3px solid #000000;
            padding: 40px;
            position: relative;
        }
        
        body.dark-mode .header {
            background: #1a1a1a;
            border-color: #ffffff;
        }
        
        .header h1 {
            font-size: 28px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 8px;
            color: #000000;
        }
        
        body.dark-mode .header h1 {
            color: #ffffff;
        }
        
        .header .subtitle {
            font-size: 14px;
            color: #666666;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        body.dark-mode .header .subtitle {
            color: #999999;
        }
        
        .theme-toggle {
            position: absolute;
            top: 20px;
            right: 40px;
            background: #000000;
            color: #ffffff;
            border: 1px solid #000000;
            padding: 8px 16px;
            cursor: pointer;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .theme-toggle:hover {
            background: #333333;
        }
        
        body.dark-mode .theme-toggle {
            background: #ffffff;
            color: #000000;
            border-color: #ffffff;
        }
        
        body.dark-mode .theme-toggle:hover {
            background: #e0e0e0;
        }
        
        .meta-bar {
            background: #f5f5f5;
            padding: 20px 40px;
            border-bottom: 1px solid #e0e0e0;
            font-size: 13px;
        }
        
        body.dark-mode .meta-bar {
            background: #1a1a1a;
            border-color: #333333;
        }
        
        .meta-bar table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .meta-bar td {
            padding: 4px 0;
            border: none;
        }
        
        .meta-bar td:first-child {
            font-weight: 600;
            width: 150px;
        }
        
        .section-separator {
            border: none;
            border-top: 2px solid #000000;
            margin: 0;
        }
        
        body.dark-mode .section-separator {
            border-color: #ffffff;
        }
        
        .content {
            padding: 40px;
        }
        
        .section-title {
            font-size: 18px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin: 40px 0 20px 0;
            padding-bottom: 8px;
            border-bottom: 2px solid #000000;
        }
        
        body.dark-mode .section-title {
            border-color: #ffffff;
        }
        
        .section-title:first-child {
            margin-top: 0;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            border: 1px solid #000000;
            margin: 20px 0;
            font-size: 13px;
        }
        
        body.dark-mode table {
            border-color: #ffffff;
        }
        
        th {
            background: #f5f5f5;
            font-weight: 700;
            text-align: left;
            padding: 12px;
            border: 1px solid #000000;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-size: 11px;
        }
        
        body.dark-mode th {
            background: #1a1a1a;
            border-color: #ffffff;
        }
        
        td {
            padding: 12px;
            border: 1px solid #000000;
            vertical-align: top;
        }
        
        body.dark-mode td {
            border-color: #ffffff;
        }
        
        tbody tr:nth-child(even) {
            background: #fafafa;
        }
        
        body.dark-mode tbody tr:nth-child(even) {
            background: #0a0a0a;
        }
        
        .summary-table td:first-child {
            font-weight: 600;
            width: 200px;
        }
        
        .summary-table td:last-child {
            font-weight: 700;
            font-size: 16px;
        }
        
        .severity-critical {
            color: #dc3545;
            font-weight: 700;
        }
        
        .severity-high {
            color: #fd7e14;
            font-weight: 700;
        }
        
        .severity-medium {
            color: #ffc107;
            font-weight: 700;
        }
        
        .severity-low {
            color: #17a2b8;
            font-weight: 700;
        }
        
        .risk-critical { color: #dc3545; }
        .risk-high { color: #fd7e14; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #17a2b8; }
        .risk-minimal { color: #28a745; }
        
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 30px;
            margin: 20px 0;
        }
        
        .chart-container {
            position: relative;
            height: 300px;
            background: #fafafa;
            padding: 20px;
            border: 1px solid #000000;
        }
        
        body.dark-mode .chart-container {
            background: #0a0a0a;
            border-color: #ffffff;
        }
        
        .chart-container h3 {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 15px;
            font-weight: 700;
        }
        
        .vuln-row {
            cursor: pointer;
        }
        
        .vuln-row:hover {
            background: #f0f0f0 !important;
        }
        
        body.dark-mode .vuln-row:hover {
            background: #222222 !important;
        }
        
        .vuln-details {
            display: none;
            background: #fafafa;
            border: 1px solid #e0e0e0;
            padding: 20px;
            margin: 10px 0;
        }
        
        body.dark-mode .vuln-details {
            background: #0a0a0a;
            border-color: #333333;
        }
        
        .vuln-details.active {
            display: block;
        }
        
        .detail-section {
            margin-bottom: 20px;
        }
        
        .detail-section:last-child {
            margin-bottom: 0;
        }
        
        .detail-section h4 {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
            font-weight: 700;
        }
        
        .detail-section p {
            font-size: 13px;
            line-height: 1.6;
        }
        
        .code-block {
            background: #f5f5f5;
            border: 1px solid #e0e0e0;
            padding: 12px;
            font-family: 'Courier New', monospace;
            font-size: 11px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        
        body.dark-mode .code-block {
            background: #0a0a0a;
            border-color: #333333;
        }
        
        .footer {
            background: #f5f5f5;
            border-top: 3px solid #000000;
            padding: 30px 40px;
            text-align: center;
            font-size: 12px;
        }
        
        body.dark-mode .footer {
            background: #1a1a1a;
            border-color: #ffffff;
        }
        
        .footer p {
            margin: 5px 0;
        }
        
        .text-center {
            text-align: center;
        }
        
        .font-mono {
            font-family: 'Courier New', monospace;
        }
        
        .expand-icon {
            float: right;
            font-size: 10px;
            transition: transform 0.3s;
        }
        
        .expand-icon.active {
            transform: rotate(180deg);
        }
        
        @media print {
            @page {
                size: A4;
                margin: 20mm;
            }
            
            body {
                background: white;
                color: black;
            }
            
            .container {
                border: none;
                max-width: 100%;
            }
            
            .theme-toggle {
                display: none;
            }
            
            .vuln-details {
                display: block !important;
            }
        }
        """
    
    def _generate_header(self) -> str:
        """Generate header section."""
        return """
        <div class="header">
            <button class="theme-toggle" onclick="toggleTheme()">Toggle Theme</button>
            <h1>🛡️ RICO Security Assessment Report</h1>
            <p class="subtitle">Enterprise API Security Assessment</p>
        </div>
        """
    
    def _generate_meta_bar(self, stats: Dict[str, Any]) -> str:
        """Generate meta information bar."""
        target = self.metadata.get("target_url", "Unknown")
        timestamp = self.metadata.get("scan_timestamp", datetime.utcnow().isoformat())
        total = stats["total_vulnerabilities"]
        
        return f"""
        <div class="meta-bar">
            <table>
                <tr>
                    <td>Generated:</td>
                    <td>{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")}</td>
                </tr>
                <tr>
                    <td>Target API:</td>
                    <td>{target}</td>
                </tr>
                <tr>
                    <td>Scan Date:</td>
                    <td>{timestamp}</td>
                </tr>
                <tr>
                    <td>Total Vulnerabilities:</td>
                    <td>{total}</td>
                </tr>
            </table>
        </div>
        """
    
    def _generate_executive_summary_section(self, stats: Dict[str, Any], summary: str) -> str:
        """Generate executive summary section."""
        total = stats["total_vulnerabilities"]
        risk_score = stats["risk_score"]
        risk_level = stats["risk_level"]
        severity_dist = stats["severity_distribution"]
        
        risk_class = f"risk-{risk_level.lower()}"
        
        return f"""
        <h2 class="section-title">Section 1: Executive Summary</h2>
        <table class="summary-table">
            <thead>
                <tr>
                    <th>Metric</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Risk Score</td>
                    <td class="{risk_class}">{risk_score:.1f} / 100</td>
                </tr>
                <tr>
                    <td>Risk Level</td>
                    <td class="{risk_class}">{risk_level.upper()}</td>
                </tr>
                <tr>
                    <td>Total Vulnerabilities</td>
                    <td>{total}</td>
                </tr>
                <tr>
                    <td>Critical Vulnerabilities</td>
                    <td class="severity-critical">{severity_dist.get('Critical', 0)}</td>
                </tr>
                <tr>
                    <td>High Vulnerabilities</td>
                    <td class="severity-high">{severity_dist.get('High', 0)}</td>
                </tr>
                <tr>
                    <td>Medium Vulnerabilities</td>
                    <td class="severity-medium">{severity_dist.get('Medium', 0)}</td>
                </tr>
            </tbody>
        </table>
        <p style="margin-top: 20px; font-size: 14px; line-height: 1.8;">{summary}</p>
        """
    
    def _generate_charts_section(self, stats: Dict[str, Any]) -> str:
        """Generate charts section."""
        return """
        <h2 class="section-title">Section 2: Risk Analysis</h2>
        <div class="charts-grid">
            <div class="chart-container">
                <h3>Severity Distribution</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>OWASP API Top 10 Coverage</h3>
                <canvas id="owaspChart"></canvas>
            </div>
        </div>
        """
    
    def _generate_vulnerabilities_section(self) -> str:
        """Generate vulnerabilities section."""
        if not self.vulnerabilities:
            return """
            <h2 class="section-title">Section 3: Identified Vulnerabilities</h2>
            <p>No vulnerabilities detected. The API appears to follow security best practices.</p>
            """
        
        vulns_html = []
        for idx, vuln in enumerate(self.vulnerabilities, 1):
            vulns_html.append(self._format_vulnerability_html(vuln, idx))
        
        return f"""
        <h2 class="section-title">Section 3: Identified Vulnerabilities</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 40%;">Endpoint</th>
                    <th style="width: 15%;">Type</th>
                    <th style="width: 15%;">Severity</th>
                    <th style="width: 10%;">Confidence</th>
                    <th style="width: 10%;" class="text-center">Details</th>
                </tr>
            </thead>
            <tbody>
                {''.join(vulns_html)}
            </tbody>
        </table>
        """
    
    def _format_vulnerability_html(self, vuln: Dict[str, Any], index: int) -> str:
        """Format a single vulnerability as HTML."""
        vuln_type = vuln.get("type", "Unknown")
        endpoint = vuln.get("endpoint", "Unknown")
        method = vuln.get("method", "")
        severity = vuln.get("severity", "Low")
        confidence = vuln.get("confidence", 0)
        description = vuln.get("description", "No description available.")
        
        severity_class = f"severity-{severity.lower()}"
        
        # Build PoC section
        poc_html = ""
        poc = vuln.get("poc")
        if poc and isinstance(poc, dict):
            poc_content = poc.get("curl", poc.get("request", ""))
            if poc_content:
                poc_html = f'<div class="detail-section"><h4>🔬 Proof of Concept</h4><div class="code-block">{self._escape_html(poc_content)}</div></div>'
        
        # Build compliance info
        compliance_html = ""
        if vuln.get("owasp_category") or vuln.get("cwe_id"):
            compliance_parts = []
            if vuln.get("cwe_id"):
                compliance_parts.append(f"<strong>CWE:</strong> {vuln['cwe_id']}")
            if vuln.get("owasp_category"):
                compliance_parts.append(f"<strong>OWASP:</strong> {vuln['owasp_category']}")
            if vuln.get("owasp_name"):
                compliance_parts.append(f"({vuln['owasp_name']})")
            compliance_html = f'<div class="detail-section"><h4>📋 Compliance Mapping</h4><p>{" | ".join(compliance_parts)}</p></div>'
        
        return f"""
                <tr class="vuln-row" onclick="toggleDetails({index})">
                    <td class="font-mono">{method} {endpoint}</td>
                    <td>{vuln_type}</td>
                    <td class="{severity_class}">{severity}</td>
                    <td class="text-center">{confidence:.0%}</td>
                    <td class="text-center">
                        <span class="expand-icon" id="icon-{index}">▼</span>
                    </td>
                </tr>
                <tr>
                    <td colspan="5" style="padding: 0; border: none;">
                        <div class="vuln-details" id="details-{index}">
                            <div class="detail-section">
                                <h4>📋 Description</h4>
                                <p>{description}</p>
                            </div>
                            {compliance_html}
                            {poc_html}
                        </div>
                    </td>
                </tr>
        """
    
    def _generate_recommendations(self) -> str:
        """Generate recommendations section."""
        return """
        <h2 class="section-title">Section 4: Recommendations</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 5%;">#</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td class="text-center">1</td>
                    <td>Prioritize Critical and High severity vulnerabilities for immediate remediation</td>
                </tr>
                <tr>
                    <td class="text-center">2</td>
                    <td>Implement input validation and parameterized queries to prevent injection attacks</td>
                </tr>
                <tr>
                    <td class="text-center">3</td>
                    <td>Enforce proper authorization checks on all resource endpoints (IDOR prevention)</td>
                </tr>
                <tr>
                    <td class="text-center">4</td>
                    <td>Implement security testing in CI/CD pipeline using RICO automated scans</td>
                </tr>
                <tr>
                    <td class="text-center">5</td>
                    <td>Conduct regular security audits following OWASP API Security Top 10 guidelines</td>
                </tr>
                <tr>
                    <td class="text-center">6</td>
                    <td>Enable comprehensive logging and monitoring for security events</td>
                </tr>
            </tbody>
        </table>
        """
    
    def _generate_footer(self) -> str:
        """Generate footer section."""
        return f"""
        <div class="footer">
            <p><strong>RICO Security Testing Framework</strong></p>
            <p>AI-Powered API Security Assessment Tool</p>
            <p style="margin-top: 10px;">Report Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
            <p style="margin-top: 5px; font-size: 10px;">This report is confidential and intended for authorized personnel only.</p>
        </div>
        """
    
    def _generate_javascript(self, stats: Dict[str, Any]) -> str:
        """Generate JavaScript for charts and interactions."""
        severity_dist = stats["severity_distribution"]
        owasp_dist = stats["owasp_distribution"]
        
        return f"""
        // Theme Toggle
        function toggleTheme() {{
            const body = document.body;
            body.classList.toggle('dark-mode');
            const isDark = body.classList.contains('dark-mode');
            localStorage.setItem('theme', isDark ? 'dark' : 'light');
        }}
        
        // Load saved theme
        document.addEventListener('DOMContentLoaded', function() {{
            const savedTheme = localStorage.getItem('theme');
            if (savedTheme === 'dark') {{
                document.body.classList.add('dark-mode');
            }}
        }});
        
        // Toggle vulnerability details
        function toggleDetails(index) {{
            const details = document.getElementById('details-' + index);
            const icon = document.getElementById('icon-' + index);
            
            if (details.classList.contains('active')) {{
                details.classList.remove('active');
                icon.classList.remove('active');
            }} else {{
                details.classList.add('active');
                icon.classList.add('active');
            }}
        }}
        
        // Severity Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    data: [
                        {severity_dist.get('Critical', 0)},
                        {severity_dist.get('High', 0)},
                        {severity_dist.get('Medium', 0)},
                        {severity_dist.get('Low', 0)},
                        {severity_dist.get('Info', 0)}
                    ],
                    backgroundColor: [
                        '#dc3545',
                        '#fd7e14',
                        '#ffc107',
                        '#17a2b8',
                        '#28a745'
                    ]
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});
        
        // OWASP Chart
        const owaspCtx = document.getElementById('owaspChart').getContext('2d');
        new Chart(owaspCtx, {{
            type: 'bar',
            data: {{
                labels: {json.dumps(list(owasp_dist.keys()))},
                datasets: [{{
                    label: 'Vulnerabilities',
                    data: {json.dumps(list(owasp_dist.values()))},
                    backgroundColor: '#000000'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{
                            stepSize: 1
                        }}
                    }}
                }}
            }}
        }});
        """
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;"))
    
    def export_to_file(self, filepath: str, summary_stats: Dict[str, Any], executive_summary: str) -> None:
        """
        Export report to HTML file.
        
        Args:
            filepath: Output file path
            summary_stats: Summary statistics
            executive_summary: Executive summary text
        """
        report = self.generate(summary_stats, executive_summary)
        
        output_path = Path(filepath)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)
    
    def export_to_string(self, summary_stats: Dict[str, Any], executive_summary: str) -> str:
        """
        Export report to HTML string.
        
        Args:
            summary_stats: Summary statistics
            executive_summary: Executive summary text
            
        Returns:
            HTML string
        """
        return self.generate(summary_stats, executive_summary)
