"""
Markdown Exporter - Generates security reports in Markdown format

Provides human-readable documentation including:
- Executive summary
- Severity distribution
- OWASP mapping
- Detailed findings
"""

from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path


class MarkdownExporter:
    """Exports security reports in Markdown format."""
    
    def __init__(self, vulnerabilities: List[Dict[str, Any]], metadata: Dict[str, Any]):
        """
        Initialize Markdown exporter.
        
        Args:
            vulnerabilities: List of enriched vulnerabilities
            metadata: Scan metadata
        """
        self.vulnerabilities = vulnerabilities
        self.metadata = metadata
    
    def generate(self, summary_stats: Dict[str, Any], executive_summary: str) -> str:
        """
        Generate complete Markdown report.
        
        Args:
            summary_stats: Summary statistics
            executive_summary: Executive summary text
            
        Returns:
            Markdown report string
        """
        sections = []
        
        # Header
        sections.append(self._generate_header())
        
        # Executive Summary
        sections.append(self._generate_executive_summary(executive_summary, summary_stats))
        
        # Severity Distribution
        sections.append(self._generate_severity_distribution(summary_stats))
        
        # OWASP Mapping
        sections.append(self._generate_owasp_mapping())
        
        # CWE Mapping
        sections.append(self._generate_cwe_mapping())
        
        # Detailed Findings
        sections.append(self._generate_detailed_findings())
        
        # Footer
        sections.append(self._generate_footer())
        
        return "\n\n".join(sections)
    
    def _generate_header(self) -> str:
        """Generate report header."""
        target = self.metadata.get("target_url", "Unknown")
        timestamp = self.metadata.get("scan_timestamp", datetime.utcnow().isoformat())
        
        return f"""# RICO Security Assessment Report

**Target:** `{target}`  
**Scan Date:** {timestamp}  
**Report Generated:** {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}  
**Tool:** RICO Security Scanner v1.0.0

---"""
    
    def _generate_executive_summary(self, summary: str, stats: Dict[str, Any]) -> str:
        """Generate executive summary section."""
        total = stats["total_vulnerabilities"]
        risk_score = stats["risk_score"]
        risk_level = stats["risk_level"]
        
        return f"""## Executive Summary

{summary}

**Overall Risk Assessment:** {risk_level} (Score: {risk_score:.1f}/100)

### Key Metrics

- **Total Vulnerabilities:** {total}
- **Highest Severity:** {stats["highest_severity"]}
- **Risk Level:** {risk_level}"""
    
    def _generate_severity_distribution(self, stats: Dict[str, Any]) -> str:
        """Generate severity distribution section."""
        dist = stats["severity_distribution"]
        
        lines = ["## Severity Distribution", ""]
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        
        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            count = dist.get(severity, 0)
            emoji = self._get_severity_emoji(severity)
            lines.append(f"| {emoji} {severity} | {count} |")
        
        return "\n".join(lines)
    
    def _generate_owasp_mapping(self) -> str:
        """Generate OWASP API Top 10 mapping section."""
        owasp_map = {}
        
        for vuln in self.vulnerabilities:
            owasp_cat = vuln.get("owasp_category")
            if owasp_cat:
                if owasp_cat not in owasp_map:
                    owasp_map[owasp_cat] = {
                        "name": vuln.get("owasp_name", ""),
                        "count": 0
                    }
                owasp_map[owasp_cat]["count"] += 1
        
        if not owasp_map:
            return "## OWASP API Top 10 Mapping\n\nNo OWASP mappings available."
        
        lines = ["## OWASP API Top 10 (2023) Mapping", ""]
        lines.append("| Category | Name | Count |")
        lines.append("|----------|------|-------|")
        
        for category in sorted(owasp_map.keys()):
            data = owasp_map[category]
            lines.append(f"| {category} | {data['name']} | {data['count']} |")
        
        return "\n".join(lines)
    
    def _generate_cwe_mapping(self) -> str:
        """Generate CWE mapping section."""
        cwe_map = {}
        
        for vuln in self.vulnerabilities:
            cwe_id = vuln.get("cwe_id")
            if cwe_id:
                if cwe_id not in cwe_map:
                    cwe_map[cwe_id] = {
                        "description": vuln.get("cwe_description", ""),
                        "count": 0
                    }
                cwe_map[cwe_id]["count"] += 1
        
        if not cwe_map:
            return "## CWE Mapping\n\nNo CWE mappings available."
        
        lines = ["## CWE (Common Weakness Enumeration) Mapping", ""]
        lines.append("| CWE ID | Description | Count |")
        lines.append("|--------|-------------|-------|")
        
        for cwe_id in sorted(cwe_map.keys()):
            data = cwe_map[cwe_id]
            lines.append(f"| {cwe_id} | {data['description']} | {data['count']} |")
        
        return "\n".join(lines)
    
    def _generate_detailed_findings(self) -> str:
        """Generate detailed findings section."""
        if not self.vulnerabilities:
            return "## Detailed Findings\n\nNo vulnerabilities detected."
        
        lines = ["## Detailed Findings", ""]
        
        # Group by severity
        by_severity = {}
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "Unknown")
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln)
        
        # Output in severity order
        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            if severity not in by_severity:
                continue
            
            vulns = by_severity[severity]
            emoji = self._get_severity_emoji(severity)
            lines.append(f"### {emoji} {severity} Severity ({len(vulns)})")
            lines.append("")
            
            for idx, vuln in enumerate(vulns, 1):
                lines.append(self._format_vulnerability(vuln, idx))
                lines.append("")
        
        return "\n".join(lines)
    
    def _format_vulnerability(self, vuln: Dict[str, Any], index: int) -> str:
        """Format a single vulnerability."""
        lines = []
        
        vuln_id = vuln.get("id", f"VULN-{index}")
        vuln_type = vuln.get("type", "Unknown")
        endpoint = vuln.get("endpoint", "Unknown")
        method = vuln.get("method", "")
        
        lines.append(f"#### {index}. {vuln_type} - `{method} {endpoint}`")
        lines.append("")
        lines.append(f"**ID:** {vuln_id}  ")
        lines.append(f"**Confidence:** {vuln.get('confidence', 0):.0%}  ")
        
        if vuln.get("cwe_id"):
            lines.append(f"**CWE:** {vuln['cwe_id']}  ")
        
        if vuln.get("owasp_category"):
            lines.append(f"**OWASP:** {vuln['owasp_category']} - {vuln.get('owasp_name', '')}  ")
        
        lines.append("")
        lines.append(f"**Description:**  ")
        lines.append(vuln.get("description", "No description available."))
        
        # PoC if available
        poc = vuln.get("poc")
        if poc and isinstance(poc, dict):
            lines.append("")
            lines.append("**Proof of Concept:**")
            lines.append("```bash")
            if "curl" in poc:
                lines.append(poc["curl"])
            elif "request" in poc:
                lines.append(poc["request"])
            lines.append("```")
        
        lines.append("")
        lines.append("---")
        
        return "\n".join(lines)
    
    def _generate_footer(self) -> str:
        """Generate report footer."""
        return f"""---

**Report Generated by RICO Security Scanner**  
*Automated API Security Testing Tool*

For more information, visit: https://github.com/rico-security"""
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level."""
        emojis = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢",
            "Info": "🔵"
        }
        return emojis.get(severity, "⚪")
    
    def export_to_file(self, filepath: str, summary_stats: Dict[str, Any], executive_summary: str) -> None:
        """
        Export report to Markdown file.
        
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
        Export report to Markdown string.
        
        Args:
            summary_stats: Summary statistics
            executive_summary: Executive summary text
            
        Returns:
            Markdown string
        """
        return self.generate(summary_stats, executive_summary)
