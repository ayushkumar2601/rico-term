"""
JSON Exporter - Exports security reports in structured JSON format

Provides machine-readable output for:
- CI/CD integration
- Programmatic analysis
- Data warehousing
- Third-party tool integration
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path


class JSONExporter:
    """Exports security reports in JSON format."""
    
    def __init__(self, vulnerabilities: List[Dict[str, Any]], metadata: Dict[str, Any]):
        """
        Initialize JSON exporter.
        
        Args:
            vulnerabilities: List of enriched vulnerabilities
            metadata: Scan metadata (target, timestamp, etc.)
        """
        self.vulnerabilities = vulnerabilities
        self.metadata = metadata
    
    def generate(self, summary_stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate complete JSON report structure.
        
        Args:
            summary_stats: Summary statistics from RiskAggregator
            
        Returns:
            Complete report dictionary
        """
        report = {
            "report_metadata": {
                "tool": "RICO Security Scanner",
                "version": "1.0.0",
                "report_type": "API Security Assessment",
                "generated_at": datetime.utcnow().isoformat() + "Z",
                **self.metadata
            },
            "summary": {
                "total_vulnerabilities": summary_stats["total_vulnerabilities"],
                "risk_score": round(summary_stats["risk_score"], 2),
                "risk_level": summary_stats["risk_level"],
                "highest_severity": summary_stats["highest_severity"],
                "severity_distribution": summary_stats["severity_distribution"],
                "owasp_distribution": summary_stats["owasp_distribution"],
                "cwe_distribution": summary_stats["cwe_distribution"],
                "key_exposure_areas": summary_stats["key_exposure_areas"]
            },
            "vulnerabilities": self.vulnerabilities,
            "compliance": {
                "owasp_api_top_10_2023": self._generate_owasp_compliance(),
                "cwe_coverage": self._generate_cwe_coverage()
            }
        }
        
        return report
    
    def _generate_owasp_compliance(self) -> List[Dict[str, Any]]:
        """Generate OWASP API Top 10 compliance section."""
        owasp_items = {}
        
        for vuln in self.vulnerabilities:
            owasp_cat = vuln.get("owasp_category")
            if owasp_cat:
                if owasp_cat not in owasp_items:
                    owasp_items[owasp_cat] = {
                        "category": owasp_cat,
                        "name": vuln.get("owasp_name", ""),
                        "count": 0,
                        "highest_severity": "Low"
                    }
                
                owasp_items[owasp_cat]["count"] += 1
                
                # Update highest severity
                current_severity = vuln.get("severity", "Low")
                if self._severity_rank(current_severity) > self._severity_rank(owasp_items[owasp_cat]["highest_severity"]):
                    owasp_items[owasp_cat]["highest_severity"] = current_severity
        
        return sorted(owasp_items.values(), key=lambda x: x["category"])
    
    def _generate_cwe_coverage(self) -> List[Dict[str, Any]]:
        """Generate CWE coverage section."""
        cwe_items = {}
        
        for vuln in self.vulnerabilities:
            cwe_id = vuln.get("cwe_id")
            if cwe_id:
                if cwe_id not in cwe_items:
                    cwe_items[cwe_id] = {
                        "cwe_id": cwe_id,
                        "description": vuln.get("cwe_description", ""),
                        "count": 0,
                        "vulnerability_types": set()
                    }
                
                cwe_items[cwe_id]["count"] += 1
                cwe_items[cwe_id]["vulnerability_types"].add(vuln.get("type", "Unknown"))
        
        # Convert sets to lists for JSON serialization
        result = []
        for cwe_data in cwe_items.values():
            cwe_data["vulnerability_types"] = list(cwe_data["vulnerability_types"])
            result.append(cwe_data)
        
        return sorted(result, key=lambda x: x["cwe_id"])
    
    def _severity_rank(self, severity: str) -> int:
        """Get numeric rank for severity comparison."""
        ranks = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        return ranks.get(severity, 0)
    
    def export_to_file(self, filepath: str, summary_stats: Dict[str, Any], indent: int = 2) -> None:
        """
        Export report to JSON file.
        
        Args:
            filepath: Output file path
            summary_stats: Summary statistics
            indent: JSON indentation level
        """
        report = self.generate(summary_stats)
        
        output_path = Path(filepath)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=indent, ensure_ascii=False)
    
    def export_to_string(self, summary_stats: Dict[str, Any], indent: int = 2) -> str:
        """
        Export report to JSON string.
        
        Args:
            summary_stats: Summary statistics
            indent: JSON indentation level
            
        Returns:
            JSON string
        """
        report = self.generate(summary_stats)
        return json.dumps(report, indent=indent, ensure_ascii=False)
