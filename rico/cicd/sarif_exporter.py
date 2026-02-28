"""
SARIF Exporter - GitHub-Compatible Security Report Format

Generates SARIF 2.1.0 compliant reports for GitHub Code Scanning integration.
No external dependencies - pure JSON generation.
"""

import json
from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path


class SARIFExporter:
    """Exports security findings in SARIF 2.1.0 format."""
    
    # SARIF severity level mapping
    SEVERITY_TO_LEVEL = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }
    
    # SARIF security severity mapping (for GitHub)
    SEVERITY_TO_SECURITY_SEVERITY = {
        "critical": "9.0",
        "high": "7.0",
        "medium": "5.0",
        "low": "3.0",
        "info": "1.0",
    }
    
    def __init__(self, tool_name: str = "RICO", tool_version: str = "1.0.0"):
        """
        Initialize SARIF exporter.
        
        Args:
            tool_name: Name of the security tool
            tool_version: Version of the security tool
        """
        self.tool_name = tool_name
        self.tool_version = tool_version
    
    def create_sarif_report(
        self,
        vulnerabilities: List[Dict[str, Any]],
        target_url: str = "",
        scan_timestamp: str = None
    ) -> Dict[str, Any]:
        """
        Create SARIF 2.1.0 compliant report.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            target_url: Base URL of the scanned API
            scan_timestamp: ISO timestamp of scan
            
        Returns:
            SARIF report as dictionary
        """
        if scan_timestamp is None:
            scan_timestamp = datetime.utcnow().isoformat() + "Z"
        
        # Extract unique rules from vulnerabilities
        rules = self._create_rules(vulnerabilities)
        
        # Create results from vulnerabilities
        results = self._create_results(vulnerabilities, target_url)
        
        # Build SARIF structure
        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "informationUri": "https://github.com/yourusername/rico",
                            "rules": rules
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": scan_timestamp
                        }
                    ],
                    "properties": {
                        "targetUrl": target_url,
                        "scanTimestamp": scan_timestamp
                    }
                }
            ]
        }
        
        return sarif_report
    
    def _create_rules(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Create SARIF rules from vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            List of SARIF rule objects
        """
        # Track unique vulnerability types
        seen_types = set()
        rules = []
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "Unknown")
            vuln_id = vuln.get("id", f"RICO-{vuln_type.replace(' ', '-')}")
            
            # Skip if we've already created a rule for this type
            if vuln_type in seen_types:
                continue
            
            seen_types.add(vuln_type)
            
            # Map severity
            severity = vuln.get("severity", "medium").lower()
            
            # Create rule
            rule = {
                "id": vuln_id,
                "name": vuln_type,
                "shortDescription": {
                    "text": f"{vuln_type} vulnerability detected"
                },
                "fullDescription": {
                    "text": vuln.get("description", f"{vuln_type} vulnerability in API endpoint")
                },
                "defaultConfiguration": {
                    "level": self.SEVERITY_TO_LEVEL.get(severity, "warning")
                },
                "properties": {
                    "tags": ["security", "api", vuln_type.lower().replace(" ", "-")],
                    "precision": "high",
                    "security-severity": self.SEVERITY_TO_SECURITY_SEVERITY.get(severity, "5.0")
                }
            }
            
            # Add CWE if available
            if "cwe_id" in vuln:
                rule["properties"]["cwe"] = vuln["cwe_id"]
            
            # Add OWASP if available
            if "owasp_category" in vuln:
                rule["properties"]["owasp"] = vuln["owasp_category"]
            
            rules.append(rule)
        
        return rules
    
    def _create_results(
        self,
        vulnerabilities: List[Dict[str, Any]],
        target_url: str
    ) -> List[Dict[str, Any]]:
        """
        Create SARIF results from vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            target_url: Base URL of the scanned API
            
        Returns:
            List of SARIF result objects
        """
        results = []
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "Unknown")
            vuln_id = vuln.get("id", f"RICO-{vuln_type.replace(' ', '-')}")
            endpoint = vuln.get("endpoint", "/unknown")
            method = vuln.get("method", "GET")
            severity = vuln.get("severity", "medium").lower()
            description = vuln.get("description", f"{vuln_type} vulnerability detected")
            
            # Create result
            result = {
                "ruleId": vuln_id,
                "level": self.SEVERITY_TO_LEVEL.get(severity, "warning"),
                "message": {
                    "text": f"{vuln_type} vulnerability in {method} {endpoint}: {description}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": endpoint,
                                "uriBaseId": target_url
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1
                            }
                        },
                        "logicalLocations": [
                            {
                                "name": endpoint,
                                "kind": "resource"
                            }
                        ]
                    }
                ],
                "properties": {
                    "method": method,
                    "endpoint": endpoint,
                    "severity": severity.upper(),
                    "confidence": vuln.get("confidence", 0.0)
                }
            }
            
            # Add PoC if available
            if "poc" in vuln and isinstance(vuln["poc"], dict):
                poc_curl = vuln["poc"].get("curl", "")
                if poc_curl:
                    result["properties"]["proofOfConcept"] = poc_curl
            
            # Add fix suggestion if available
            if "fix_suggestion" in vuln:
                result["fixes"] = [
                    {
                        "description": {
                            "text": vuln["fix_suggestion"]
                        }
                    }
                ]
            
            results.append(result)
        
        return results
    
    def export_to_file(
        self,
        filepath: str,
        vulnerabilities: List[Dict[str, Any]],
        target_url: str = "",
        scan_timestamp: str = None
    ) -> None:
        """
        Export SARIF report to file.
        
        Args:
            filepath: Output file path
            vulnerabilities: List of vulnerability dictionaries
            target_url: Base URL of the scanned API
            scan_timestamp: ISO timestamp of scan
        """
        sarif_report = self.create_sarif_report(vulnerabilities, target_url, scan_timestamp)
        
        output_path = Path(filepath)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_report, f, indent=2)
    
    def export_to_string(
        self,
        vulnerabilities: List[Dict[str, Any]],
        target_url: str = "",
        scan_timestamp: str = None
    ) -> str:
        """
        Export SARIF report to JSON string.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            target_url: Base URL of the scanned API
            scan_timestamp: ISO timestamp of scan
            
        Returns:
            SARIF report as JSON string
        """
        sarif_report = self.create_sarif_report(vulnerabilities, target_url, scan_timestamp)
        return json.dumps(sarif_report, indent=2)


def convert_to_sarif_format(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Convenience function to ensure vulnerabilities have required SARIF fields.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        
    Returns:
        List of vulnerabilities with SARIF-compatible fields
    """
    sarif_vulns = []
    
    for idx, vuln in enumerate(vulnerabilities, 1):
        sarif_vuln = vuln.copy()
        
        # Ensure required fields exist
        if "id" not in sarif_vuln:
            vuln_type = sarif_vuln.get("type", "Unknown").replace(" ", "-")
            sarif_vuln["id"] = f"RICO-{vuln_type}-{idx:03d}"
        
        if "severity" not in sarif_vuln:
            sarif_vuln["severity"] = "medium"
        
        if "description" not in sarif_vuln:
            sarif_vuln["description"] = f"{sarif_vuln.get('type', 'Unknown')} vulnerability detected"
        
        sarif_vulns.append(sarif_vuln)
    
    return sarif_vulns
