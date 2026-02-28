"""
Risk Aggregator - Computes risk scores and aggregates vulnerability data

This module provides risk scoring and aggregation capabilities:
- Severity-based scoring
- Confidence-weighted calculations
- Distribution analysis
- Executive summary generation
"""

from typing import Dict, List, Any
from collections import Counter


class RiskAggregator:
    """Aggregates vulnerability data and computes risk scores."""
    
    # Severity weights for risk scoring
    SEVERITY_WEIGHTS = {
        "Critical": 10,
        "High": 7,
        "Medium": 4,
        "Low": 1,
        "Info": 0.5
    }
    
    # Risk score thresholds
    RISK_LEVELS = {
        "Critical": 80,
        "High": 50,
        "Medium": 20,
        "Low": 10,
        "Minimal": 0
    }
    
    def __init__(self, vulnerabilities: List[Dict[str, Any]]):
        """
        Initialize risk aggregator with vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
        """
        self.vulnerabilities = vulnerabilities
        self._cache = {}
    
    def get_total_count(self) -> int:
        """Get total number of vulnerabilities."""
        return len(self.vulnerabilities)
    
    def get_severity_distribution(self) -> Dict[str, int]:
        """
        Get count of vulnerabilities by severity.
        
        Returns:
            Dictionary mapping severity to count
        """
        if "severity_dist" in self._cache:
            return self._cache["severity_dist"]
        
        distribution = Counter()
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "Unknown")
            distribution[severity] += 1
        
        # Ensure all severity levels are present
        for severity in self.SEVERITY_WEIGHTS.keys():
            if severity not in distribution:
                distribution[severity] = 0
        
        result = dict(distribution)
        self._cache["severity_dist"] = result
        return result
    
    def get_owasp_distribution(self) -> Dict[str, int]:
        """
        Get count of vulnerabilities by OWASP category.
        
        Returns:
            Dictionary mapping OWASP category to count
        """
        if "owasp_dist" in self._cache:
            return self._cache["owasp_dist"]
        
        distribution = Counter()
        for vuln in self.vulnerabilities:
            owasp_cat = vuln.get("owasp_category")
            if owasp_cat:
                distribution[owasp_cat] += 1
        
        result = dict(distribution)
        self._cache["owasp_dist"] = result
        return result
    
    def get_cwe_distribution(self) -> Dict[str, int]:
        """
        Get count of vulnerabilities by CWE.
        
        Returns:
            Dictionary mapping CWE ID to count
        """
        if "cwe_dist" in self._cache:
            return self._cache["cwe_dist"]
        
        distribution = Counter()
        for vuln in self.vulnerabilities:
            cwe_id = vuln.get("cwe_id")
            if cwe_id:
                distribution[cwe_id] += 1
        
        result = dict(distribution)
        self._cache["cwe_dist"] = result
        return result
    
    def calculate_risk_score(self) -> float:
        """
        Calculate overall risk score based on severity and confidence.
        
        Formula: sum(severity_weight × confidence) for all vulnerabilities
        
        Returns:
            Risk score (0-100+)
        """
        if "risk_score" in self._cache:
            return self._cache["risk_score"]
        
        total_score = 0.0
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "Low")
            confidence = vuln.get("confidence", 0.5)
            
            weight = self.SEVERITY_WEIGHTS.get(severity, 1)
            total_score += weight * confidence
        
        # Normalize to 0-100 scale (assuming max ~10 critical vulns)
        normalized_score = min(total_score, 100)
        
        self._cache["risk_score"] = normalized_score
        return normalized_score
    
    def get_risk_level(self) -> str:
        """
        Get risk level based on risk score.
        
        Returns:
            Risk level string (Critical, High, Medium, Low, Minimal)
        """
        score = self.calculate_risk_score()
        
        for level, threshold in sorted(self.RISK_LEVELS.items(), 
                                      key=lambda x: x[1], 
                                      reverse=True):
            if score >= threshold:
                return level
        
        return "Minimal"
    
    def get_highest_severity(self) -> str:
        """
        Get the highest severity level found.
        
        Returns:
            Severity string
        """
        severity_order = ["Critical", "High", "Medium", "Low", "Info"]
        
        for severity in severity_order:
            if any(v.get("severity") == severity for v in self.vulnerabilities):
                return severity
        
        return "None"
    
    def get_key_exposure_areas(self) -> List[str]:
        """
        Identify key exposure areas based on vulnerability types.
        
        Returns:
            List of exposure area descriptions
        """
        areas = []
        
        # Count by vulnerability type
        type_counts = Counter()
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get("type", "Unknown")
            type_counts[vuln_type] += 1
        
        # Get top 3 vulnerability types
        top_types = type_counts.most_common(3)
        
        for vuln_type, count in top_types:
            if count > 0:
                areas.append(f"{vuln_type} ({count} instance{'s' if count > 1 else ''})")
        
        return areas
    
    def generate_executive_summary(self, target_url: str = None) -> str:
        """
        Generate executive summary paragraph.
        
        Args:
            target_url: Target URL that was scanned
            
        Returns:
            Executive summary string
        """
        total = self.get_total_count()
        severity_dist = self.get_severity_distribution()
        risk_level = self.get_risk_level()
        highest_severity = self.get_highest_severity()
        key_areas = self.get_key_exposure_areas()
        
        if total == 0:
            return "No vulnerabilities were detected during this security assessment. The API appears to follow security best practices for the tested attack vectors."
        
        # Build summary
        summary_parts = []
        
        # Opening statement
        critical_count = severity_dist.get("Critical", 0)
        high_count = severity_dist.get("High", 0)
        
        if critical_count > 0:
            summary_parts.append(
                f"This scan identified {total} vulnerabilit{'y' if total == 1 else 'ies'} "
                f"including {critical_count} critical issue{'s' if critical_count > 1 else ''}."
            )
        elif high_count > 0:
            summary_parts.append(
                f"This scan identified {total} vulnerabilit{'y' if total == 1 else 'ies'} "
                f"including {high_count} high-severity issue{'s' if high_count > 1 else ''}."
            )
        else:
            summary_parts.append(
                f"This scan identified {total} vulnerabilit{'y' if total == 1 else 'ies'}."
            )
        
        # Key exposure areas
        if key_areas:
            areas_text = ", ".join(key_areas[:2])
            summary_parts.append(
                f"The most significant risks relate to {areas_text}."
            )
        
        # Recommendation
        if risk_level in ["Critical", "High"]:
            summary_parts.append(
                "Immediate remediation is recommended for publicly exposed endpoints."
            )
        elif risk_level == "Medium":
            summary_parts.append(
                "Remediation should be prioritized based on endpoint exposure and data sensitivity."
            )
        else:
            summary_parts.append(
                "Review and address identified issues as part of regular security maintenance."
            )
        
        return " ".join(summary_parts)
    
    def get_summary_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive summary statistics.
        
        Returns:
            Dictionary with all summary statistics
        """
        return {
            "total_vulnerabilities": self.get_total_count(),
            "severity_distribution": self.get_severity_distribution(),
            "owasp_distribution": self.get_owasp_distribution(),
            "cwe_distribution": self.get_cwe_distribution(),
            "risk_score": self.calculate_risk_score(),
            "risk_level": self.get_risk_level(),
            "highest_severity": self.get_highest_severity(),
            "key_exposure_areas": self.get_key_exposure_areas(),
        }
