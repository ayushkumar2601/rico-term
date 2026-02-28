"""Centralized vulnerability detection engine for RICO."""
import re
import logging
from typing import Dict, Any, Optional, Tuple
from difflib import SequenceMatcher
import json

# Setup logger
logger = logging.getLogger("rico.detector")


class DetectionResult:
    """Container for detection results."""
    
    def __init__(
        self,
        vulnerable: bool,
        confidence: int,
        reason: str,
        attack_type: str,
        endpoint: str,
        details: Optional[Dict[str, Any]] = None
    ):
        self.vulnerable = vulnerable
        self.confidence = confidence
        self.reason = reason
        self.attack_type = attack_type
        self.endpoint = endpoint
        self.details = details or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "vulnerable": self.vulnerable,
            "confidence": self.confidence,
            "reason": self.reason,
            "attack_type": self.attack_type,
            "endpoint": self.endpoint,
            "details": self.details
        }


def compare_responses(
    resp1: str,
    resp2: str,
    threshold: float = 0.3
) -> Tuple[bool, float, str]:
    """
    Compare two responses to detect significant differences.
    Uses normalized JSON comparison when possible.
    
    Args:
        resp1: First response text
        resp2: Second response text
        threshold: Difference threshold (0.0 to 1.0)
        
    Returns:
        Tuple of (is_suspicious, difference_score, reason)
    """
    if not resp1 or not resp2:
        return True, 1.0, "One or both responses are empty"
    
    # Import normalization utilities
    from rico.attacks.utils import normalize_response, compare_json_deep
    
    # Normalize responses
    norm1 = normalize_response(resp1)
    norm2 = normalize_response(resp2)
    
    # If both are JSON, use deep comparison
    if norm1["is_json"] and norm2["is_json"]:
        try:
            structural_changes, value_diff_pct, details = compare_json_deep(
                norm1["normalized"],
                norm2["normalized"]
            )
            
            # Determine if suspicious based on structural changes or value differences
            is_suspicious = (
                structural_changes >= 1 or 
                value_diff_pct >= 20.0
            )
            
            # Calculate overall difference score
            # Structural changes are weighted more heavily
            structure_score = min(structural_changes * 0.3, 0.7)
            value_score = min(value_diff_pct / 100.0, 0.3)
            difference_score = structure_score + value_score
            
            # Build reason
            reason_parts = []
            if structural_changes > 0:
                reason_parts.append(f"{structural_changes} structural changes")
            if value_diff_pct > 0:
                reason_parts.append(f"{value_diff_pct:.1f}% value differences")
            
            if details["missing_keys"]:
                reason_parts.append(f"Missing keys: {len(details['missing_keys'])}")
            if details["extra_keys"]:
                reason_parts.append(f"Extra keys: {len(details['extra_keys'])}")
            
            reason = "; ".join(reason_parts) if reason_parts else "Responses identical"
            
            return is_suspicious, difference_score, reason
            
        except Exception as e:
            logger.warning(f"JSON comparison failed: {e}, falling back to text comparison")
            # Fall through to text comparison
    
    # Fall back to text comparison for non-JSON responses
    len1, len2 = len(resp1), len(resp2)
    if len1 == 0 or len2 == 0:
        return True, 1.0, "Empty response detected"
    
    # Calculate length difference ratio
    max_len = max(len1, len2)
    min_len = min(len1, len2)
    length_diff = abs(len1 - len2) / max_len
    
    # Text similarity using SequenceMatcher
    similarity = SequenceMatcher(None, resp1[:1000], resp2[:1000]).ratio()
    difference_score = 1.0 - similarity
    
    # Combine scores
    final_score = max(difference_score, length_diff)
    is_suspicious = final_score > threshold
    
    reason = f"Text similarity: {similarity:.2f}, Length diff: {length_diff:.2f}"
    
    return is_suspicious, final_score, reason


def detect_sql_error(response_text: str) -> Tuple[bool, str]:
    """
    Detect SQL errors in response text using regex patterns.
    
    Args:
        response_text: Response text to check
        
    Returns:
        Tuple of (error_found, error_type)
    """
    if not response_text:
        return False, ""
    
    response_lower = response_text.lower()
    
    # Comprehensive SQL error patterns
    sql_patterns = {
        "MySQL": [
            r"you have an error in your sql syntax",
            r"warning: mysql",
            r"valid mysql result",
            r"mysqlclient\.",
            r"mysql_fetch",
            r"mysql_query",
            r"mysql_num_rows",
        ],
        "PostgreSQL": [
            r"postgresql.*error",
            r"pg_query\(\)",
            r"pg_exec\(\)",
            r"pg_fetch",
            r"unterminated quoted string",
        ],
        "SQLite": [
            r"sqlite.*error",
            r"sqlite3::",
            r"sqlite_query",
            r"sqlite_fetch",
            r"unrecognized token",
        ],
        "MSSQL": [
            r"microsoft sql native client error",
            r"odbc sql server driver",
            r"sqlserver.*error",
            r"unclosed quotation mark",
        ],
        "Oracle": [
            r"ora-\d{5}",
            r"oracle.*error",
            r"oracle.*driver",
        ],
        "Generic": [
            r"sql syntax.*error",
            r"syntax error.*sql",
            r"database error",
            r"sqlstate\[",
            r"quoted string not properly terminated",
            r"sql command not properly ended",
        ]
    }
    
    for db_type, patterns in sql_patterns.items():
        for pattern in patterns:
            if re.search(pattern, response_lower, re.IGNORECASE):
                logger.warning(f"SQL error detected: {db_type} - Pattern: {pattern}")
                return True, f"{db_type} SQL error detected"
    
    return False, ""


def detect_status_issue(
    status1: int,
    status2: int,
    context: str = ""
) -> Tuple[bool, int, str]:
    """
    Detect status code mismatches that indicate vulnerabilities.
    
    Args:
        status1: First status code (e.g., without auth)
        status2: Second status code (e.g., with auth)
        context: Context description (e.g., "auth comparison")
        
    Returns:
        Tuple of (is_issue, confidence, reason)
    """
    # Missing authentication detection
    if context == "auth_comparison":
        # Both requests succeed - possible missing auth
        if 200 <= status1 < 300 and 200 <= status2 < 300:
            return True, 85, "Both authenticated and unauthenticated requests succeeded"
        
        # Unauthenticated succeeds, authenticated fails - unusual
        if 200 <= status1 < 300 and status2 >= 400:
            return True, 70, "Unauthenticated request succeeded but authenticated failed"
        
        # Proper auth enforcement
        if status1 in [401, 403] and 200 <= status2 < 300:
            return False, 10, "Authentication properly enforced"
        
        # Unauthenticated fails with auth error
        if status1 in [401, 403]:
            return False, 5, "Proper authentication required"
    
    # IDOR detection
    elif context == "idor_comparison":
        # Different IDs return success with different data
        if 200 <= status1 < 300 and 200 <= status2 < 300:
            return True, 75, "Different resources accessible without authorization"
        
        # One succeeds, one fails - might be proper access control
        if (200 <= status1 < 300) != (200 <= status2 < 300):
            return False, 30, "Different access levels detected"
    
    # SQL injection detection
    elif context == "sqli_comparison":
        # Payload changes status to success
        if status1 >= 400 and 200 <= status2 < 300:
            return True, 80, "SQL payload changed error to success"
        
        # Both succeed but might have different content
        if 200 <= status1 < 300 and 200 <= status2 < 300:
            return True, 50, "Both requests succeeded - check response content"
    
    return False, 0, "No status code issue detected"


def detect_timing_issue(
    time1: float,
    time2: float,
    threshold: float = 2.0
) -> Tuple[bool, int, str]:
    """
    Detect timing anomalies that might indicate blind SQL injection or heavy queries.
    
    Args:
        time1: First response time in seconds
        time2: Second response time in seconds
        threshold: Multiplier threshold for anomaly detection
        
    Returns:
        Tuple of (is_anomaly, confidence, reason)
    """
    if time1 <= 0 or time2 <= 0:
        return False, 0, "Invalid timing data"
    
    # Calculate ratio
    ratio = max(time1, time2) / min(time1, time2)
    
    if ratio > threshold:
        slower_time = max(time1, time2)
        confidence = min(int((ratio - 1) * 30), 70)  # Cap at 70%
        
        if slower_time > 5.0:
            reason = f"Significant delay detected ({slower_time:.2f}s) - possible blind SQLi or heavy query"
        else:
            reason = f"Response time differs by {ratio:.1f}x - possible timing attack vector"
        
        logger.info(f"Timing anomaly detected: {time1:.3f}s vs {time2:.3f}s (ratio: {ratio:.2f})")
        return True, confidence, reason
    
    return False, 0, f"Response times similar ({time1:.3f}s vs {time2:.3f}s)"


def detect_boolean_blind_sqli(
    baseline_response: Optional[Dict[str, Any]],
    true_response: Optional[Dict[str, Any]],
    false_response: Optional[Dict[str, Any]],
    additional_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Detect boolean-based blind SQL injection vulnerabilities.
    
    PRODUCTION-GRADE ALGORITHM:
    1. Normalize responses (remove dynamic fields, sort JSON)
    2. Calculate structural delta (length difference)
    3. Extract record counts (if list response)
    4. Apply strict confidence thresholds
    
    Confidence Logic:
    - ≥30% structural delta → 85-95% confidence
    - 20-30% delta → 70% confidence
    - <20% delta → 40% confidence (not flagged)
    
    Args:
        baseline_response: Normal request response
        true_response: TRUE condition payload response
        false_response: FALSE condition payload response
        additional_data: Additional context (payloads, description)
        
    Returns:
        Dict with vulnerable, confidence, reason, and delta
    """
    additional_data = additional_data or {}
    
    # Extract response data
    baseline_text = baseline_response.get("text", "") if baseline_response else ""
    baseline_status = baseline_response.get("status", 0) if baseline_response else 0
    
    true_text = true_response.get("text", "") if true_response else ""
    true_status = true_response.get("status", 0) if true_response else 0
    
    false_text = false_response.get("text", "") if false_response else ""
    false_status = false_response.get("status", 0) if false_response else 0
    
    # Validate we have all required responses
    if not baseline_text or not true_text or not false_text:
        return {
            "vulnerable": False,
            "confidence": 0,
            "reason": "Insufficient response data for boolean analysis",
            "delta": 0
        }
    
    # PHASE 2 UPGRADE: Response Normalization
    from rico.attacks.utils import normalize_response
    
    norm_baseline = normalize_response(baseline_text)
    norm_true = normalize_response(true_text)
    norm_false = normalize_response(false_text)
    
    # PHASE 2 UPGRADE: Structural Comparison
    baseline_len = len(baseline_text)
    true_len = len(true_text)
    false_len = len(false_text)
    
    # Calculate structural delta (TRUE vs FALSE)
    max_len = max(true_len, false_len)
    if max_len > 0:
        structural_delta = abs(true_len - false_len) / max_len
    else:
        structural_delta = 0.0
    
    # PHASE 2 UPGRADE: Record Count Delta (if list response)
    result_count_baseline = 0
    result_count_true = 0
    result_count_false = 0
    record_count_delta = False
    
    try:
        baseline_json = json.loads(baseline_text)
        true_json = json.loads(true_text)
        false_json = json.loads(false_text)
        
        # Extract result counts from JSON
        if isinstance(baseline_json, dict):
            result_count_baseline = (
                baseline_json.get("count", 0) or
                baseline_json.get("total", 0) or
                len(baseline_json.get("results", [])) or
                len(baseline_json.get("data", [])) or
                len(baseline_json.get("items", []))
            )
        elif isinstance(baseline_json, list):
            result_count_baseline = len(baseline_json)
        
        if isinstance(true_json, dict):
            result_count_true = (
                true_json.get("count", 0) or
                true_json.get("total", 0) or
                len(true_json.get("results", [])) or
                len(true_json.get("data", [])) or
                len(true_json.get("items", []))
            )
        elif isinstance(true_json, list):
            result_count_true = len(true_json)
        
        if isinstance(false_json, dict):
            result_count_false = (
                false_json.get("count", 0) or
                false_json.get("total", 0) or
                len(false_json.get("results", [])) or
                len(false_json.get("data", [])) or
                len(false_json.get("items", []))
            )
        elif isinstance(false_json, list):
            result_count_false = len(false_json)
        
        # CRITICAL: Record count delta detection
        if result_count_true > result_count_false:
            record_count_delta = True
            
    except (json.JSONDecodeError, TypeError):
        # Not JSON, rely on structural comparison
        pass
    
    # PHASE 2 UPGRADE: Final Confidence Logic
    confidence = 0
    reasons = []
    
    # Check status codes are consistent
    status_codes_consistent = (
        baseline_status == true_status and 
        200 <= baseline_status < 300 and 
        200 <= true_status < 300
    )
    
    if not status_codes_consistent:
        return {
            "vulnerable": False,
            "confidence": 0,
            "reason": "Status codes inconsistent - not boolean blind SQLi",
            "delta": 0
        }
    
    # STRICT CONFIDENCE THRESHOLDS
    if structural_delta >= 0.30:
        # ≥30% structural delta → 85-95% confidence
        confidence = 85
        reasons.append(f"Structural delta: {structural_delta:.1%}")
        
        if record_count_delta:
            confidence = 95
            reasons.append(f"Record count delta: TRUE={result_count_true}, FALSE={result_count_false}")
    
    elif structural_delta >= 0.20:
        # 20-30% delta → 70% confidence
        confidence = 70
        reasons.append(f"Moderate structural delta: {structural_delta:.1%}")
        
        if record_count_delta:
            confidence = 85
            reasons.append(f"Record count delta: TRUE={result_count_true}, FALSE={result_count_false}")
    
    elif structural_delta >= 0.10:
        # 10-20% delta → 40% confidence (not flagged)
        confidence = 40
        reasons.append(f"Low structural delta: {structural_delta:.1%}")
    
    else:
        # <10% delta → no detection
        return {
            "vulnerable": False,
            "confidence": 0,
            "reason": f"Insufficient structural difference (delta: {structural_delta:.1%})",
            "delta": int(structural_delta * 100)
        }
    
    # Only flag if confidence >= 60%
    is_vulnerable = confidence >= 60
    
    if is_vulnerable:
        description = additional_data.get("description", "Boolean comparison")
        main_reason = (
            f"Boolean-based blind SQL injection detected ({description}). "
            f"{'; '.join(reasons)}"
        )
        
        logger.warning(
            f"Boolean blind SQLi detected: structural_delta={structural_delta:.1%}, "
            f"confidence={confidence}%"
        )
        
        return {
            "vulnerable": True,
            "confidence": confidence,
            "reason": main_reason,
            "delta": int(structural_delta * 100)
        }
    else:
        return {
            "vulnerable": False,
            "confidence": confidence,
            "reason": f"Structural delta below threshold ({structural_delta:.1%})",
            "delta": int(structural_delta * 100)
        }


def detect_vulnerability(
    attack_type: str,
    endpoint: str,
    mode: str = "error",
    baseline_response: Optional[Dict[str, Any]] = None,
    test_response: Optional[Dict[str, Any]] = None,
    true_response: Optional[Dict[str, Any]] = None,
    false_response: Optional[Dict[str, Any]] = None,
    additional_data: Optional[Dict[str, Any]] = None
) -> DetectionResult:
    """
    Unified vulnerability detection function.
    
    Combines multiple detection methods to determine if a vulnerability exists.
    
    Args:
        attack_type: Type of attack (IDOR, Missing Auth, SQL Injection)
        endpoint: Endpoint being tested
        mode: Detection mode ("error", "boolean", "time")
        baseline_response: Baseline response data (status, text, time)
        test_response: Test response data (status, text, time) - for error mode
        true_response: TRUE payload response data - for boolean mode
        false_response: FALSE payload response data - for boolean mode
        additional_data: Additional context data
        
    Returns:
        DetectionResult with vulnerability assessment
    """
    additional_data = additional_data or {}
    confidence_scores = []
    reasons = []
    
    # Extract response data
    baseline_status = baseline_response.get("status", 0) if baseline_response else 0
    baseline_text = baseline_response.get("text", "") if baseline_response else ""
    baseline_time = baseline_response.get("time", 0.0) if baseline_response else 0.0
    
    test_status = test_response.get("status", 0) if test_response else 0
    test_text = test_response.get("text", "") if test_response else ""
    test_time = test_response.get("time", 0.0) if test_response else 0.0
    
    # Attack-specific detection
    if attack_type == "IDOR":
        # Check status codes
        if baseline_status and test_status:
            status_issue, status_conf, status_reason = detect_status_issue(
                baseline_status, test_status, "idor_comparison"
            )
            if status_issue:
                confidence_scores.append(status_conf)
                reasons.append(status_reason)
        
        # Check response differences
        if baseline_text and test_text:
            is_different, diff_score, diff_reason = compare_responses(
                baseline_text, test_text, threshold=0.2
            )
            if is_different:
                confidence_scores.append(min(int(diff_score * 100), 90))
                reasons.append(f"Response content differs: {diff_reason}")
    
    elif attack_type == "Missing Auth":
        # Check status codes
        if baseline_status and test_status:
            status_issue, status_conf, status_reason = detect_status_issue(
                baseline_status, test_status, "auth_comparison"
            )
            confidence_scores.append(status_conf)
            reasons.append(status_reason)
            
            # If both succeed, check if responses are similar
            if 200 <= baseline_status < 300 and 200 <= test_status < 300:
                if baseline_text and test_text:
                    is_different, diff_score, diff_reason = compare_responses(
                        baseline_text, test_text, threshold=0.1
                    )
                    if not is_different:
                        # Same response without auth - high confidence vulnerability
                        confidence_scores.append(95)
                        reasons.append("Identical response with and without authentication")
    
    elif attack_type == "SQL Injection":
        # Mode-specific detection
        if mode == "boolean":
            # Boolean-based blind SQL injection detection
            boolean_detection = detect_boolean_blind_sqli(
                baseline_response=baseline_response,
                true_response=true_response,
                false_response=false_response,
                additional_data=additional_data
            )
            
            if boolean_detection["vulnerable"]:
                confidence_scores.append(boolean_detection["confidence"])
                reasons.append(boolean_detection["reason"])
        
        else:
            # Error-based and generic detection (mode="error" or default)
            # Check for SQL errors
            if test_text:
                has_error, error_type = detect_sql_error(test_text)
                if has_error:
                    confidence_scores.append(95)
                    reasons.append(f"SQL error detected: {error_type}")
            
            # Check status code changes
            if baseline_status and test_status:
                status_issue, status_conf, status_reason = detect_status_issue(
                    baseline_status, test_status, "sqli_comparison"
                )
                if status_issue:
                    confidence_scores.append(status_conf)
                    reasons.append(status_reason)
            
            # Check response differences
            if baseline_text and test_text:
                is_different, diff_score, diff_reason = compare_responses(
                    baseline_text, test_text, threshold=0.3
                )
                if is_different and diff_score > 0.5:
                    confidence_scores.append(min(int(diff_score * 80), 75))
                    reasons.append(f"Significant response change: {diff_reason}")
            
            # Check timing anomalies
            if baseline_time and test_time:
                timing_issue, timing_conf, timing_reason = detect_timing_issue(
                    baseline_time, test_time
                )
                if timing_issue:
                    confidence_scores.append(timing_conf)
                    reasons.append(timing_reason)
    
    # Calculate final confidence
    if confidence_scores:
        final_confidence = max(confidence_scores)
    else:
        final_confidence = 0
    
    # Determine vulnerability (only flag if confidence > 60%)
    is_vulnerable = final_confidence > 60
    
    # Combine reasons
    final_reason = "; ".join(reasons) if reasons else "No vulnerability indicators detected"
    
    # Log if vulnerable
    if is_vulnerable:
        logger.warning(
            f"VULNERABILITY DETECTED - {attack_type} on {endpoint} "
            f"(Confidence: {final_confidence}%): {final_reason}"
        )
    
    return DetectionResult(
        vulnerable=is_vulnerable,
        confidence=final_confidence,
        reason=final_reason,
        attack_type=attack_type,
        endpoint=endpoint,
        details={
            "baseline_status": baseline_status,
            "test_status": test_status,
            "confidence_scores": confidence_scores
        }
    )
