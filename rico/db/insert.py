"""Insert functions for storing scan results in Snowflake."""
import uuid
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from .snowflake_client import get_connection

# Setup logger
logger = logging.getLogger("rico.snowflake.insert")


def insert_scan(scan_data: Dict[str, Any]) -> Optional[str]:
    """
    Insert a scan record into the SCANS table.
    
    Args:
        scan_data: Dictionary containing scan information:
            - api_name: Name of the API being scanned
            - api_base_url: Base URL of the API
            - framework: API framework (FastAPI, Flask, etc.)
            - total_endpoints: Number of endpoints tested
            - total_vulnerabilities: Number of vulnerabilities found
            - risk_score: Security score (0-100)
            - scan_duration_seconds: Duration of the scan
            
    Returns:
        str: Scan ID (UUID) if successful, None if failed
    """
    scan_id = str(uuid.uuid4())
    
    try:
        conn = get_connection()
        cur = conn.cursor()
        
        logger.info(f"Inserting scan record: {scan_id}")
        
        cur.execute("""
            INSERT INTO SCANS
            (SCAN_ID, API_NAME, API_BASE_URL, FRAMEWORK,
             TOTAL_ENDPOINTS, TOTAL_VULNERABILITIES,
             RISK_SCORE, SCAN_DURATION_SECONDS, SCAN_TIMESTAMP)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            scan_id,
            scan_data.get("api_name", "Unknown API"),
            scan_data.get("api_base_url", ""),
            scan_data.get("framework", "Unknown"),
            scan_data.get("total_endpoints", 0),
            scan_data.get("total_vulnerabilities", 0),
            scan_data.get("risk_score", 0),
            scan_data.get("scan_duration_seconds", 0.0),
            datetime.utcnow()
        ))
        
        conn.commit()
        logger.info(f"[OK] Scan record inserted successfully: {scan_id}")
        
        return scan_id
        
    except Exception as e:
        logger.error(f"✗ Failed to insert scan record: {str(e)}")
        return None
        
    finally:
        try:
            cur.close()
            conn.close()
        except:
            pass


def insert_payload_result(data: Dict[str, Any]) -> Optional[str]:
    """
    Insert a payload test result into the PAYLOAD_RESULTS table.
    
    This function stores intelligence about each exploit attempt,
    enabling the adaptive attack loop to learn from successful payloads.
    
    Args:
        data: Dictionary containing payload test information:
            - scan_id: Parent scan ID
            - vulnerability_type: Type of vulnerability (SQLi, IDOR, etc.)
            - payload: The actual payload used
            - api_framework: Framework of the target API
            - auth_type: Authentication type (JWT, Basic, None, etc.)
            - endpoint_path: Endpoint path tested
            - response_code: HTTP response code
            - response_time_ms: Response time in milliseconds
            - exploit_success: Boolean indicating if exploit succeeded
            
    Returns:
        str: Payload ID (UUID) if successful, None if failed
    """
    payload_id = str(uuid.uuid4())
    
    try:
        conn = get_connection()
        cur = conn.cursor()
        
        logger.debug(f"Inserting payload result: {payload_id}")
        
        cur.execute("""
            INSERT INTO PAYLOAD_RESULTS
            (PAYLOAD_ID, SCAN_ID, VULNERABILITY_TYPE,
             PAYLOAD, API_FRAMEWORK, AUTH_TYPE,
             ENDPOINT_PATH, RESPONSE_CODE,
             RESPONSE_TIME_MS, EXPLOIT_SUCCESS, RESULT_TIMESTAMP)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            payload_id,
            data.get("scan_id", ""),
            data.get("vulnerability_type", ""),
            data.get("payload", ""),
            data.get("api_framework", "Unknown"),
            data.get("auth_type", "None"),
            data.get("endpoint_path", ""),
            data.get("response_code", 0),
            data.get("response_time_ms", 0.0),
            data.get("exploit_success", False),
            datetime.utcnow()
        ))
        
        conn.commit()
        
        if data.get("exploit_success"):
            logger.info(f"[OK] Successful payload logged: {data.get('vulnerability_type')} on {data.get('endpoint_path')}")
        else:
            logger.debug(f"Payload result logged: {payload_id}")
        
        return payload_id
        
    except Exception as e:
        logger.error(f"✗ Failed to insert payload result: {str(e)}")
        return None
        
    finally:
        try:
            cur.close()
            conn.close()
        except:
            pass


def insert_vulnerability(vuln_data: Dict[str, Any]) -> Optional[str]:
    """
    Insert a detected vulnerability into the VULNERABILITIES table.
    
    Args:
        vuln_data: Dictionary containing vulnerability information:
            - scan_id: Parent scan ID
            - endpoint_path: Vulnerable endpoint
            - vulnerability_type: Type of vulnerability
            - severity: Severity level (Critical, High, Medium, Low)
            - confidence: Confidence percentage (0-100)
            - cvss_score: CVSS score
            - description: Vulnerability description
            - poc_curl: Proof of concept curl command
            - fix_suggestion: Remediation advice
            
    Returns:
        str: Vulnerability ID (UUID) if successful, None if failed
    """
    vuln_id = str(uuid.uuid4())
    
    try:
        conn = get_connection()
        cur = conn.cursor()
        
        logger.info(f"Inserting vulnerability: {vuln_data.get('vulnerability_type')} on {vuln_data.get('endpoint_path')}")
        
        cur.execute("""
            INSERT INTO VULNERABILITIES
            (VULN_ID, SCAN_ID, ENDPOINT_PATH, VULNERABILITY_TYPE,
             SEVERITY, CONFIDENCE, CVSS_SCORE, DESCRIPTION,
             POC_CURL, FIX_SUGGESTION, VULN_TIMESTAMP)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            vuln_id,
            vuln_data.get("scan_id", ""),
            vuln_data.get("endpoint_path", ""),
            vuln_data.get("vulnerability_type", ""),
            vuln_data.get("severity", "Medium"),
            vuln_data.get("confidence", 0),
            vuln_data.get("cvss_score", 0.0),
            vuln_data.get("description", ""),
            vuln_data.get("poc_curl", ""),
            vuln_data.get("fix_suggestion", ""),
            datetime.utcnow()
        ))
        
        conn.commit()
        logger.info(f"[OK] Vulnerability record inserted: {vuln_id}")
        
        return vuln_id
        
    except Exception as e:
        logger.error(f"✗ Failed to insert vulnerability: {str(e)}")
        return None
        
    finally:
        try:
            cur.close()
            conn.close()
        except:
            pass
