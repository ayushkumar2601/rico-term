"""Retrieval layer for RAG (Retrieval-Augmented Generation) from Snowflake."""
import logging
from typing import List, Dict, Any, Optional
from .snowflake_client import get_connection

# Setup logger
logger = logging.getLogger("rico.snowflake.retrieve")


def get_top_successful_payloads(
    vulnerability_type: str,
    limit: int = 5,
    api_framework: Optional[str] = None
) -> List[str]:
    """
    Retrieve the most recent successful payloads for a vulnerability type.
    
    This enables the adaptive attack loop by learning from historical successes.
    
    Args:
        vulnerability_type: Type of vulnerability (SQLi, IDOR, etc.)
        limit: Maximum number of payloads to retrieve
        api_framework: Optional filter by API framework
        
    Returns:
        List[str]: List of successful payloads
    """
    try:
        conn = get_connection()
        cur = conn.cursor()
        
        logger.info(f"Retrieving top {limit} successful {vulnerability_type} payloads")
        
        if api_framework:
            cur.execute("""
                SELECT PAYLOAD, ENDPOINT_PATH, RESPONSE_CODE, RESPONSE_TIME_MS
                FROM PAYLOAD_RESULTS
                WHERE VULNERABILITY_TYPE = %s
                AND EXPLOIT_SUCCESS = TRUE
                AND API_FRAMEWORK = %s
                ORDER BY RESULT_TIMESTAMP DESC
                LIMIT %s
            """, (vulnerability_type, api_framework, limit))
        else:
            cur.execute("""
                SELECT PAYLOAD, ENDPOINT_PATH, RESPONSE_CODE, RESPONSE_TIME_MS
                FROM PAYLOAD_RESULTS
                WHERE VULNERABILITY_TYPE = %s
                AND EXPLOIT_SUCCESS = TRUE
                ORDER BY RESULT_TIMESTAMP DESC
                LIMIT %s
            """, (vulnerability_type, limit))
        
        rows = cur.fetchall()
        payloads = [row[0] for row in rows]
        
        logger.info(f"[OK] Retrieved {len(payloads)} successful payloads")
        
        return payloads
        
    except Exception as e:
        logger.error(f"✗ Failed to retrieve payloads: {str(e)}")
        return []
        
    finally:
        try:
            cur.close()
            conn.close()
        except:
            pass


def get_payload_statistics(vulnerability_type: str) -> Dict[str, Any]:
    """
    Get statistics about payload success rates for a vulnerability type.
    
    Args:
        vulnerability_type: Type of vulnerability
        
    Returns:
        Dict with statistics (total_attempts, successful, success_rate, etc.)
    """
    try:
        conn = get_connection()
        cur = conn.cursor()
        
        logger.info(f"Retrieving payload statistics for {vulnerability_type}")
        
        cur.execute("""
            SELECT 
                COUNT(*) as total_attempts,
                SUM(CASE WHEN EXPLOIT_SUCCESS = TRUE THEN 1 ELSE 0 END) as successful,
                AVG(RESPONSE_TIME_MS) as avg_response_time,
                COUNT(DISTINCT ENDPOINT_PATH) as unique_endpoints,
                COUNT(DISTINCT API_FRAMEWORK) as unique_frameworks
            FROM PAYLOAD_RESULTS
            WHERE VULNERABILITY_TYPE = %s
        """, (vulnerability_type,))
        
        row = cur.fetchone()
        
        if row:
            total = row[0] or 0
            successful = row[1] or 0
            success_rate = (successful / total * 100) if total > 0 else 0.0
            
            stats = {
                "total_attempts": total,
                "successful": successful,
                "success_rate": round(success_rate, 2),
                "avg_response_time_ms": round(row[2] or 0, 2),
                "unique_endpoints": row[3] or 0,
                "unique_frameworks": row[4] or 0
            }
            
            logger.info(f"[OK] Statistics: {stats}")
            return stats
        else:
            return {
                "total_attempts": 0,
                "successful": 0,
                "success_rate": 0.0,
                "avg_response_time_ms": 0.0,
                "unique_endpoints": 0,
                "unique_frameworks": 0
            }
        
    except Exception as e:
        logger.error(f"✗ Failed to retrieve statistics: {str(e)}")
        return {}
        
    finally:
        try:
            cur.close()
            conn.close()
        except:
            pass


def get_vulnerable_endpoints_by_type(
    vulnerability_type: str,
    limit: int = 10
) -> List[Dict[str, Any]]:
    """
    Get endpoints that have been found vulnerable to a specific attack type.
    
    Args:
        vulnerability_type: Type of vulnerability
        limit: Maximum number of endpoints to retrieve
        
    Returns:
        List of dictionaries with endpoint information
    """
    try:
        conn = get_connection()
        cur = conn.cursor()
        
        logger.info(f"Retrieving vulnerable endpoints for {vulnerability_type}")
        
        cur.execute("""
            SELECT 
                v.ENDPOINT_PATH,
                v.SEVERITY,
                v.CONFIDENCE,
                v.CVSS_SCORE,
                s.API_BASE_URL,
                s.FRAMEWORK,
                v.VULN_TIMESTAMP
            FROM VULNERABILITIES v
            JOIN SCANS s ON v.SCAN_ID = s.SCAN_ID
            WHERE v.VULNERABILITY_TYPE = %s
            ORDER BY v.CVSS_SCORE DESC, v.VULN_TIMESTAMP DESC
            LIMIT %s
        """, (vulnerability_type, limit))
        
        rows = cur.fetchall()
        
        endpoints = []
        for row in rows:
            endpoints.append({
                "endpoint_path": row[0],
                "severity": row[1],
                "confidence": row[2],
                "cvss_score": row[3],
                "api_base_url": row[4],
                "framework": row[5],
                "timestamp": str(row[6])
            })
        
        logger.info(f"[OK] Retrieved {len(endpoints)} vulnerable endpoints")
        return endpoints
        
    except Exception as e:
        logger.error(f"✗ Failed to retrieve vulnerable endpoints: {str(e)}")
        return []
        
    finally:
        try:
            cur.close()
            conn.close()
        except:
            pass


def get_scan_history(api_base_url: str, limit: int = 5) -> List[Dict[str, Any]]:
    """
    Get scan history for a specific API.
    
    Args:
        api_base_url: Base URL of the API
        limit: Maximum number of scans to retrieve
        
    Returns:
        List of scan records
    """
    try:
        conn = get_connection()
        cur = conn.cursor()
        
        logger.info(f"Retrieving scan history for {api_base_url}")
        
        cur.execute("""
            SELECT 
                SCAN_ID,
                API_NAME,
                FRAMEWORK,
                TOTAL_ENDPOINTS,
                TOTAL_VULNERABILITIES,
                RISK_SCORE,
                SCAN_DURATION_SECONDS,
                SCAN_TIMESTAMP
            FROM SCANS
            WHERE API_BASE_URL = %s
            ORDER BY SCAN_TIMESTAMP DESC
            LIMIT %s
        """, (api_base_url, limit))
        
        rows = cur.fetchall()
        
        scans = []
        for row in rows:
            scans.append({
                "scan_id": row[0],
                "api_name": row[1],
                "framework": row[2],
                "total_endpoints": row[3],
                "total_vulnerabilities": row[4],
                "risk_score": row[5],
                "scan_duration_seconds": row[6],
                "timestamp": str(row[7])
            })
        
        logger.info(f"[OK] Retrieved {len(scans)} scan records")
        return scans
        
    except Exception as e:
        logger.error(f"✗ Failed to retrieve scan history: {str(e)}")
        return []
        
    finally:
        try:
            cur.close()
            conn.close()
        except:
            pass


def get_framework_specific_payloads(
    vulnerability_type: str,
    api_framework: str,
    limit: int = 10
) -> List[Dict[str, Any]]:
    """
    Get successful payloads specific to an API framework.
    
    This enables framework-specific attack optimization.
    
    Args:
        vulnerability_type: Type of vulnerability
        api_framework: API framework (FastAPI, Flask, Express, etc.)
        limit: Maximum number of payloads to retrieve
        
    Returns:
        List of payload records with metadata
    """
    try:
        conn = get_connection()
        cur = conn.cursor()
        
        logger.info(f"Retrieving {api_framework}-specific {vulnerability_type} payloads")
        
        cur.execute("""
            SELECT 
                PAYLOAD,
                ENDPOINT_PATH,
                RESPONSE_CODE,
                RESPONSE_TIME_MS,
                AUTH_TYPE,
                RESULT_TIMESTAMP
            FROM PAYLOAD_RESULTS
            WHERE VULNERABILITY_TYPE = %s
            AND API_FRAMEWORK = %s
            AND EXPLOIT_SUCCESS = TRUE
            ORDER BY RESULT_TIMESTAMP DESC
            LIMIT %s
        """, (vulnerability_type, api_framework, limit))
        
        rows = cur.fetchall()
        
        payloads = []
        for row in rows:
            payloads.append({
                "payload": row[0],
                "endpoint_path": row[1],
                "response_code": row[2],
                "response_time_ms": row[3],
                "auth_type": row[4],
                "timestamp": str(row[5])
            })
        
        logger.info(f"[OK] Retrieved {len(payloads)} framework-specific payloads")
        return payloads
        
    except Exception as e:
        logger.error(f"✗ Failed to retrieve framework-specific payloads: {str(e)}")
        return []
        
    finally:
        try:
            cur.close()
            conn.close()
        except:
            pass
