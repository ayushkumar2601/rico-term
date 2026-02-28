"""
RICO Scan Service - Core scanning logic decoupled from CLI

Provides programmatic access to RICO scanning functionality.
"""

import asyncio
import time
import uuid
from typing import Optional, Dict, Any, List
from pathlib import Path
from dataclasses import dataclass, asdict

from rico.brain.openapi_parser import parse_openapi
from rico.attacks.idor import test_idor
from rico.attacks.missing_auth import test_missing_auth
from rico.attacks.sqli import test_sqli
from rico.reporter.report_builder import (
    convert_results_to_report_items,
    compute_security_score,
    find_top_issue,
    generate_markdown_report,
    generate_html_report
)
from rico.brain.ai_agent.classifier import classify_endpoint
from rico.brain.ai_agent.planner import plan_attacks
from rico.brain.ai_agent.explainer import explain_attack
from rico.brain.ai_agent.config import load_ai_config, get_provider_name


@dataclass
class ScanResult:
    """Structured scan result."""
    scan_id: str
    target_url: str
    risk_score: int
    risk_level: str
    total_vulnerabilities: int
    vulnerabilities: List[Dict[str, Any]]
    total_endpoints: int
    endpoints_tested: int
    duration: float
    status: str
    security_score: int
    top_issue: str
    severity_distribution: Dict[str, int]
    timestamp: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


async def _execute_scan_async(
    spec_path: str,
    base_url: str,
    token: Optional[str] = None,
    max_endpoints: Optional[int] = None,
    use_ai: bool = False,
    use_agentic_ai: bool = False,
    output_dir: str = "reports",
    report_formats: Optional[Dict[str, str]] = None,
) -> ScanResult:
    """
    Internal async scan execution.
    
    Args:
        spec_path: Path to OpenAPI specification file
        base_url: Base URL of the API to test
        token: Optional authentication token
        max_endpoints: Maximum number of endpoints to test
        use_ai: Enable AI-powered attack planning
        use_agentic_ai: Enable agentic AI reasoning
        output_dir: Output directory for reports
        report_formats: Dictionary of report formats to generate
        
    Returns:
        ScanResult object with complete scan results
    """
    from rico.db.snowflake_client import is_snowflake_enabled
    from rico.db.insert import insert_scan, insert_vulnerability
    from rico.attacks.adaptive import create_adaptive_engine
    from datetime import datetime
    
    scan_start_time = time.time()
    scan_id = str(uuid.uuid4())
    adaptive_engine = None
    api_framework = "Unknown"
    
    # Initialize Snowflake integration if enabled
    if is_snowflake_enabled():
        # Determine API framework
        if spec_path and base_url:
            if "fastapi" in spec_path.lower() or "fastapi" in base_url.lower():
                api_framework = "FastAPI"
            elif "flask" in spec_path.lower() or "flask" in base_url.lower():
                api_framework = "Flask"
            elif "express" in spec_path.lower():
                api_framework = "Express"
        
        adaptive_engine = create_adaptive_engine(scan_id)
    
    # Parse the OpenAPI spec
    endpoints = parse_openapi(spec_path)
    
    if not endpoints:
        raise ValueError("No endpoints found in the specification")
    
    total_endpoints = len(endpoints)
    
    # Limit number of endpoints if specified
    if max_endpoints is not None and max_endpoints > 0:
        endpoints = endpoints[:max_endpoints]
    
    # Load AI config if needed
    ai_config = None
    provider_name = None
    if use_ai:
        ai_config = load_ai_config()
        provider_name = get_provider_name(ai_config)
    
    all_results = []
    
    # Initialize payload logging for Snowflake
    payload_logger = None
    if adaptive_engine and scan_id:
        def log_payload(vuln_type, payload, endpoint_path, response_code, response_time, success):
            try:
                adaptive_engine.log_payload_result(
                    vulnerability_type=vuln_type,
                    payload=payload,
                    endpoint_path=endpoint_path,
                    response_code=response_code,
                    response_time_ms=response_time * 1000,
                    response_text="",
                    exploit_success=success,
                    api_framework=api_framework,
                    auth_type="JWT" if token else "None"
                )
            except Exception:
                pass  # Silent fail for logging
        
        payload_logger = log_payload
    
    # Test each endpoint
    for endpoint in endpoints:
        # AI Classification and Planning
        attacks_to_run = ["IDOR", "Missing Auth", "SQL Injection"]
        classification = None
        
        if use_ai and provider_name:
            try:
                # Classify endpoint
                classification = await classify_endpoint(
                    endpoint.method,
                    endpoint.path,
                    endpoint.parameters
                )
                
                # Plan attacks
                attack_plan = await plan_attacks(
                    classification["type"],
                    classification["sensitivity"],
                    endpoint.method,
                    endpoint.path
                )
                
                attacks_to_run = attack_plan["attacks"]
            except Exception:
                pass  # Fall back to default tests
        
        # Run selected attack tests
        try:
            # IDOR Test
            if "IDOR" in attacks_to_run:
                idor_result = await test_idor(
                    endpoint=endpoint.path,
                    base_url=base_url,
                    method=endpoint.method
                )
                
                # Log payload if Snowflake enabled
                if payload_logger:
                    payload_logger(
                        "IDOR",
                        f"ID manipulation on {endpoint.path}",
                        endpoint.path,
                        idor_result.get("status_code", 0),
                        idor_result.get("response_time", 0),
                        idor_result.get("vulnerable", False)
                    )
                
                # Add AI reasoning if enabled
                if use_ai and classification:
                    try:
                        reasoning = await explain_attack(
                            "IDOR",
                            classification.get("type", "resource"),
                            endpoint.method,
                            endpoint.path
                        )
                        idor_result["reasoning"] = reasoning
                    except:
                        pass
                
                all_results.append(idor_result)
            
            # Missing Auth Test
            if "Missing Auth" in attacks_to_run:
                auth_result = await test_missing_auth(
                    endpoint=endpoint.path,
                    base_url=base_url,
                    method=endpoint.method,
                    token=token
                )
                
                # Log payload if Snowflake enabled
                if payload_logger:
                    payload_logger(
                        "Missing Authentication",
                        f"Auth bypass attempt on {endpoint.path}",
                        endpoint.path,
                        auth_result.get("status_code", 0),
                        auth_result.get("response_time", 0),
                        auth_result.get("vulnerable", False)
                    )
                
                # Add AI reasoning if enabled
                if use_ai and classification:
                    try:
                        reasoning = await explain_attack(
                            "Missing Auth",
                            classification.get("type", "resource"),
                            endpoint.method,
                            endpoint.path
                        )
                        auth_result["reasoning"] = reasoning
                    except:
                        pass
                
                all_results.append(auth_result)
            
            # SQL Injection Test
            if "SQL Injection" in attacks_to_run:
                sqli_result = await test_sqli(
                    endpoint=endpoint.path,
                    base_url=base_url,
                    method=endpoint.method,
                    parameters=endpoint.parameters
                )
                
                # Log payload if Snowflake enabled
                if payload_logger:
                    payload_used = sqli_result.get("payload_used", "' OR '1'='1")
                    payload_logger(
                        "SQL Injection",
                        payload_used,
                        endpoint.path,
                        sqli_result.get("status_code", 0),
                        sqli_result.get("response_time", 0),
                        sqli_result.get("vulnerable", False)
                    )
                
                # Add AI reasoning if enabled
                if use_ai and classification:
                    try:
                        reasoning = await explain_attack(
                            "SQL Injection",
                            classification.get("type", "resource"),
                            endpoint.method,
                            endpoint.path
                        )
                        sqli_result["reasoning"] = reasoning
                    except:
                        pass
                
                all_results.append(sqli_result)
        
        except Exception:
            continue  # Skip failed endpoint tests
    
    # Convert results to report items
    report_items = convert_results_to_report_items(all_results, base_url, token)
    
    # Compute security score
    security_score, risk_level = compute_security_score(report_items)
    top_issue = find_top_issue(report_items)
    
    # Calculate scan duration
    scan_duration = time.time() - scan_start_time
    
    # Generate reports if requested
    if report_formats:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate Markdown report
        if "md" in report_formats:
            md_path = report_formats["md"]
            generate_markdown_report(report_items, base_url, str(md_path))
        
        # Generate HTML report
        if "html" in report_formats:
            html_path = report_formats["html"]
            generate_html_report(report_items, base_url, str(html_path))
        
        # Generate JSON report
        if "json" in report_formats:
            from rico.reporting.report_builder import ReportBuilder
            
            vulnerabilities = []
            for item in report_items:
                if item.status in ["VULNERABLE", "SUSPICIOUS"]:
                    vuln = {
                        "id": f"RICO-{len(vulnerabilities)+1:03d}",
                        "type": item.attack_type,
                        "endpoint": item.endpoint,
                        "method": item.method if hasattr(item, 'method') else "GET",
                        "severity": item.severity,
                        "confidence": item.confidence,
                        "description": item.description,
                        "poc": {"curl": item.poc_curl} if item.poc_curl else None
                    }
                    vulnerabilities.append(vuln)
            
            metadata = {
                "target_url": base_url,
                "scan_timestamp": datetime.utcnow().isoformat()
            }
            
            builder = ReportBuilder(vulnerabilities, metadata)
            builder.export_json(report_formats["json"])
        
        # Generate SARIF report
        if "sarif" in report_formats:
            from rico.cicd.sarif_exporter import SARIFExporter
            
            vulnerabilities = []
            for item in report_items:
                if item.status in ["VULNERABLE", "SUSPICIOUS"]:
                    vuln = {
                        "id": f"RICO-{len(vulnerabilities)+1:03d}",
                        "type": item.attack_type,
                        "endpoint": item.endpoint,
                        "method": item.method if hasattr(item, 'method') else "GET",
                        "severity": item.severity,
                        "confidence": item.confidence,
                        "description": item.description,
                        "poc": {"curl": item.poc_curl} if item.poc_curl else None,
                        "cwe_id": getattr(item, 'cwe_id', None),
                        "owasp_category": getattr(item, 'owasp_category', None),
                        "fix_suggestion": item.fix_suggestion if hasattr(item, 'fix_suggestion') else None
                    }
                    vulnerabilities.append(vuln)
            
            sarif_exporter = SARIFExporter(tool_name="RICO", tool_version="1.0.0")
            sarif_exporter.export_to_file(
                filepath=report_formats["sarif"],
                vulnerabilities=vulnerabilities,
                target_url=base_url,
                scan_timestamp=datetime.utcnow().isoformat() + "Z"
            )
    
    # Store scan results in Snowflake
    if is_snowflake_enabled():
        try:
            # Insert scan record
            snowflake_scan_id = insert_scan({
                "api_name": base_url.split("//")[-1].split("/")[0],
                "api_base_url": base_url,
                "framework": api_framework,
                "total_endpoints": len(endpoints),
                "total_vulnerabilities": sum(1 for r in all_results if r.get("vulnerable", False)),
                "risk_score": security_score,
                "scan_duration_seconds": scan_duration
            })
            
            # Store vulnerabilities
            if snowflake_scan_id:
                for item in report_items:
                    if item.status in ["VULNERABLE", "SUSPICIOUS"]:
                        insert_vulnerability({
                            "scan_id": snowflake_scan_id,
                            "endpoint_path": item.endpoint,
                            "vulnerability_type": item.attack_type,
                            "severity": item.severity,
                            "confidence": item.confidence,
                            "cvss_score": item.cvss_score,
                            "description": item.description,
                            "poc_curl": item.poc_curl or "",
                            "fix_suggestion": item.fix_suggestion or ""
                        })
        except Exception:
            pass  # Don't fail scan if Snowflake storage fails
    
    # Agentic AI Analysis
    if use_agentic_ai:
        try:
            from rico.ai.groq_client import GroqClient
            from rico.ai.agent import RicoAgent
            import os
            
            api_key = os.getenv("GROQ_API_KEY")
            if api_key:
                groq_client = GroqClient(api_key=api_key)
                agent = RicoAgent(groq_client=groq_client)
                
                scan_results = {
                    "target_url": base_url,
                    "total_endpoints": len(endpoints),
                    "security_score": security_score,
                    "risk_level": risk_level,
                    "vulnerabilities": [item.to_dict() for item in report_items if item.status in ["VULNERABLE", "SUSPICIOUS"]],
                    "endpoints_tested": [{"method": ep.method, "path": ep.path} for ep in endpoints]
                }
                
                ai_analysis = await agent.analyze_scan(scan_results)
                
                # Save AI analysis
                import json
                output_path = Path(output_dir)
                output_path.mkdir(parents=True, exist_ok=True)
                ai_analysis_path = output_path / "agentic_analysis.json"
                with open(ai_analysis_path, 'w', encoding='utf-8') as f:
                    json.dump(ai_analysis, f, indent=2)
        except Exception:
            pass  # Don't fail scan if AI analysis fails
    
    # Build vulnerability list
    vulnerabilities = []
    severity_distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    
    for item in report_items:
        if item.status in ["VULNERABLE", "SUSPICIOUS"]:
            vuln = {
                "type": item.attack_type,
                "endpoint": item.endpoint,
                "method": item.method if hasattr(item, 'method') else "GET",
                "severity": item.severity,
                "confidence": item.confidence,
                "description": item.description,
                "cvss_score": item.cvss_score,
                "status": item.status
            }
            vulnerabilities.append(vuln)
            
            # Update severity distribution
            if item.severity in severity_distribution:
                severity_distribution[item.severity] += 1
    
    # Create scan result
    result = ScanResult(
        scan_id=scan_id,
        target_url=base_url,
        risk_score=100 - security_score,  # Invert for risk score
        risk_level=risk_level,
        total_vulnerabilities=len(vulnerabilities),
        vulnerabilities=vulnerabilities,
        total_endpoints=total_endpoints,
        endpoints_tested=len(endpoints),
        duration=scan_duration,
        status="completed",
        security_score=security_score,
        top_issue=top_issue,
        severity_distribution=severity_distribution,
        timestamp=datetime.utcnow().isoformat() + "Z"
    )
    
    return result


def run_scan(
    spec_path: str,
    base_url: str,
    token: Optional[str] = None,
    max_endpoints: Optional[int] = None,
    use_ai: bool = False,
    use_agentic_ai: bool = False,
    output_dir: str = "reports",
    report_formats: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Execute RICO security scan programmatically.
    
    This function provides programmatic access to RICO's scanning capabilities
    without CLI dependencies. It does NOT print output or call sys.exit().
    
    Args:
        spec_path: Path to OpenAPI specification file
        base_url: Base URL of the API to test
        token: Optional authentication token
        max_endpoints: Maximum number of endpoints to test (None = all)
        use_ai: Enable AI-powered attack planning
        use_agentic_ai: Enable agentic AI reasoning layer
        output_dir: Output directory for reports
        report_formats: Dictionary mapping format to filepath:
            {"json": "report.json", "html": "report.html", "md": "report.md", "sarif": "rico.sarif"}
    
    Returns:
        Dictionary containing scan results:
        {
            "scan_id": str,
            "target_url": str,
            "risk_score": int,
            "risk_level": str,
            "total_vulnerabilities": int,
            "vulnerabilities": list,
            "total_endpoints": int,
            "endpoints_tested": int,
            "duration": float,
            "status": str,
            "security_score": int,
            "top_issue": str,
            "severity_distribution": dict,
            "timestamp": str
        }
    
    Raises:
        FileNotFoundError: If spec file doesn't exist
        ValueError: If spec is invalid or no endpoints found
        Exception: For other scan errors
    
    Example:
        >>> result = run_scan(
        ...     spec_path="openapi.yaml",
        ...     base_url="http://localhost:8000",
        ...     use_ai=True,
        ...     report_formats={"html": "reports/report.html"}
        ... )
        >>> print(f"Risk Score: {result['risk_score']}")
    """
    # Validate inputs
    spec_file = Path(spec_path)
    if not spec_file.exists():
        raise FileNotFoundError(f"OpenAPI spec file not found: {spec_path}")
    
    # Run async scan
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result = loop.run_until_complete(
            _execute_scan_async(
                spec_path=spec_path,
                base_url=base_url,
                token=token,
                max_endpoints=max_endpoints,
                use_ai=use_ai,
                use_agentic_ai=use_agentic_ai,
                output_dir=output_dir,
                report_formats=report_formats
            )
        )
        return result.to_dict()
    finally:
        loop.close()
