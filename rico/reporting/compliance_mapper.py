"""
Compliance Mapper - Maps vulnerabilities to OWASP API Top 10 and CWE

This module provides automatic mapping of detected vulnerabilities to:
- OWASP API Security Top 10 (2023)
- Common Weakness Enumeration (CWE)
"""

from typing import Dict, Optional, Tuple


class ComplianceMapper:
    """Maps vulnerability types to compliance frameworks."""
    
    # OWASP API Security Top 10 (2023) Mapping
    OWASP_MAPPING = {
        "IDOR": {
            "category": "API1:2023",
            "name": "Broken Object Level Authorization",
            "description": "APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues."
        },
        "Missing Authentication": {
            "category": "API2:2023",
            "name": "Broken Authentication",
            "description": "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or exploit implementation flaws."
        },
        "SQL Injection": {
            "category": "API8:2023",
            "name": "Security Misconfiguration",
            "description": "APIs and systems supporting them typically contain complex configurations meant to make them more customizable, leaving them vulnerable to various attacks."
        },
        "CSRF": {
            "category": "API2:2023",
            "name": "Broken Authentication",
            "description": "Lack of CSRF protection allows attackers to perform unauthorized actions on behalf of authenticated users."
        },
        "XSS": {
            "category": "API8:2023",
            "name": "Security Misconfiguration",
            "description": "Cross-site scripting vulnerabilities allow injection of malicious scripts."
        },
        "Broken Access Control": {
            "category": "API1:2023",
            "name": "Broken Object Level Authorization",
            "description": "Insufficient access controls allow unauthorized access to resources."
        },
        "Sensitive Data Exposure": {
            "category": "API3:2023",
            "name": "Broken Object Property Level Authorization",
            "description": "APIs tend to expose all object properties without considering their individual sensitivity."
        },
        "Rate Limiting": {
            "category": "API4:2023",
            "name": "Unrestricted Resource Consumption",
            "description": "APIs do not impose restrictions on the size or number of resources that can be requested."
        },
        "Mass Assignment": {
            "category": "API6:2023",
            "name": "Unrestricted Access to Sensitive Business Flows",
            "description": "APIs vulnerable to mass assignment allow attackers to modify object properties they should not have access to."
        },
        "Server Side Request Forgery": {
            "category": "API7:2023",
            "name": "Server Side Request Forgery",
            "description": "SSRF flaws occur when an API fetches a remote resource without validating the user-supplied URL."
        }
    }
    
    # CWE (Common Weakness Enumeration) Mapping
    CWE_MAPPING = {
        "IDOR": "CWE-639",  # Authorization Bypass Through User-Controlled Key
        "Missing Authentication": "CWE-306",  # Missing Authentication for Critical Function
        "SQL Injection": "CWE-89",  # SQL Injection
        "CSRF": "CWE-352",  # Cross-Site Request Forgery
        "XSS": "CWE-79",  # Cross-site Scripting
        "Broken Access Control": "CWE-284",  # Improper Access Control
        "Sensitive Data Exposure": "CWE-200",  # Exposure of Sensitive Information
        "Rate Limiting": "CWE-770",  # Allocation of Resources Without Limits
        "Mass Assignment": "CWE-915",  # Improperly Controlled Modification of Dynamically-Determined Object Attributes
        "Server Side Request Forgery": "CWE-918",  # Server-Side Request Forgery
        "Command Injection": "CWE-78",  # OS Command Injection
        "Path Traversal": "CWE-22",  # Path Traversal
        "XXE": "CWE-611",  # XML External Entity
        "Insecure Deserialization": "CWE-502",  # Deserialization of Untrusted Data
    }
    
    # CWE Descriptions
    CWE_DESCRIPTIONS = {
        "CWE-639": "Authorization Bypass Through User-Controlled Key",
        "CWE-306": "Missing Authentication for Critical Function",
        "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command",
        "CWE-352": "Cross-Site Request Forgery (CSRF)",
        "CWE-79": "Improper Neutralization of Input During Web Page Generation",
        "CWE-284": "Improper Access Control",
        "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
        "CWE-770": "Allocation of Resources Without Limits or Throttling",
        "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
        "CWE-918": "Server-Side Request Forgery (SSRF)",
        "CWE-78": "Improper Neutralization of Special Elements used in an OS Command",
        "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory",
        "CWE-611": "Improper Restriction of XML External Entity Reference",
        "CWE-502": "Deserialization of Untrusted Data",
    }
    
    @classmethod
    def map_to_owasp(cls, vulnerability_type: str) -> Optional[Dict[str, str]]:
        """
        Map vulnerability type to OWASP API Top 10 category.
        
        Args:
            vulnerability_type: Type of vulnerability (e.g., "SQL Injection")
            
        Returns:
            Dictionary with OWASP category info or None
        """
        return cls.OWASP_MAPPING.get(vulnerability_type)
    
    @classmethod
    def map_to_cwe(cls, vulnerability_type: str) -> Optional[str]:
        """
        Map vulnerability type to CWE ID.
        
        Args:
            vulnerability_type: Type of vulnerability
            
        Returns:
            CWE ID string (e.g., "CWE-89") or None
        """
        return cls.CWE_MAPPING.get(vulnerability_type)
    
    @classmethod
    def get_cwe_description(cls, cwe_id: str) -> Optional[str]:
        """
        Get description for a CWE ID.
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-89")
            
        Returns:
            CWE description or None
        """
        return cls.CWE_DESCRIPTIONS.get(cwe_id)
    
    @classmethod
    def enrich_vulnerability(cls, vulnerability: Dict) -> Dict:
        """
        Enrich vulnerability with OWASP and CWE mappings.
        
        Args:
            vulnerability: Vulnerability dictionary
            
        Returns:
            Enriched vulnerability dictionary
        """
        vuln_type = vulnerability.get("type", "")
        
        # Add OWASP mapping
        owasp_info = cls.map_to_owasp(vuln_type)
        if owasp_info:
            vulnerability["owasp_category"] = owasp_info["category"]
            vulnerability["owasp_name"] = owasp_info["name"]
            vulnerability["owasp_description"] = owasp_info["description"]
        else:
            vulnerability["owasp_category"] = None
            vulnerability["owasp_name"] = None
            vulnerability["owasp_description"] = None
        
        # Add CWE mapping
        cwe_id = cls.map_to_cwe(vuln_type)
        if cwe_id:
            vulnerability["cwe_id"] = cwe_id
            vulnerability["cwe_description"] = cls.get_cwe_description(cwe_id)
        else:
            vulnerability["cwe_id"] = None
            vulnerability["cwe_description"] = None
        
        return vulnerability
    
    @classmethod
    def get_all_owasp_categories(cls) -> Dict[str, int]:
        """
        Get all OWASP categories with their counts.
        
        Returns:
            Dictionary mapping OWASP categories to counts
        """
        categories = {}
        for vuln_type, owasp_info in cls.OWASP_MAPPING.items():
            category = owasp_info["category"]
            categories[category] = categories.get(category, 0)
        return categories
