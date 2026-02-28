"""Unit tests for the vulnerability detector."""
import pytest
from rico.attacks.detector import (
    compare_responses,
    detect_sql_error,
    detect_status_issue,
    detect_timing_issue,
    detect_vulnerability
)


class TestCompareResponses:
    """Test response comparison functionality."""
    
    def test_identical_responses(self):
        """Test that identical responses are not flagged as suspicious."""
        resp1 = '{"id": 1, "name": "John"}'
        resp2 = '{"id": 1, "name": "John"}'
        is_suspicious, score, reason = compare_responses(resp1, resp2)
        assert not is_suspicious
        assert score < 0.3
    
    def test_different_responses(self):
        """Test that different responses are flagged as suspicious."""
        resp1 = '{"id": 1, "name": "John"}'
        resp2 = '{"id": 2, "name": "Jane"}'
        is_suspicious, score, reason = compare_responses(resp1, resp2)
        assert is_suspicious
        assert score > 0.3
    
    def test_empty_response(self):
        """Test handling of empty responses."""
        resp1 = ""
        resp2 = '{"id": 1}'
        is_suspicious, score, reason = compare_responses(resp1, resp2)
        assert is_suspicious
        assert score == 1.0
    
    def test_length_difference(self):
        """Test detection of significant length differences."""
        resp1 = "short"
        resp2 = "this is a much longer response with more content"
        is_suspicious, score, reason = compare_responses(resp1, resp2, threshold=0.2)
        assert is_suspicious


class TestDetectSQLError:
    """Test SQL error detection functionality."""
    
    def test_mysql_error(self):
        """Test detection of MySQL errors."""
        response = "You have an error in your SQL syntax near 'SELECT'"
        has_error, error_type = detect_sql_error(response)
        assert has_error
        assert "MySQL" in error_type
    
    def test_postgresql_error(self):
        """Test detection of PostgreSQL errors."""
        response = "PostgreSQL error: unterminated quoted string"
        has_error, error_type = detect_sql_error(response)
        assert has_error
        assert "PostgreSQL" in error_type
    
    def test_sqlite_error(self):
        """Test detection of SQLite errors."""
        response = "SQLite error: unrecognized token"
        has_error, error_type = detect_sql_error(response)
        assert has_error
        assert "SQLite" in error_type
    
    def test_oracle_error(self):
        """Test detection of Oracle errors."""
        response = "ORA-00933: SQL command not properly ended"
        has_error, error_type = detect_sql_error(response)
        assert has_error
        assert "Oracle" in error_type
    
    def test_no_error(self):
        """Test that normal responses don't trigger false positives."""
        response = '{"status": "success", "data": []}'
        has_error, error_type = detect_sql_error(response)
        assert not has_error
        assert error_type == ""
    
    def test_case_insensitive(self):
        """Test that detection is case-insensitive."""
        response = "Warning: mysql_fetch_array() error"
        has_error, error_type = detect_sql_error(response)
        assert has_error


class TestDetectStatusIssue:
    """Test status code mismatch detection."""
    
    def test_missing_auth_both_succeed(self):
        """Test detection when both auth and no-auth succeed."""
        is_issue, confidence, reason = detect_status_issue(200, 200, "auth_comparison")
        assert is_issue
        assert confidence > 80
        assert "authenticated and unauthenticated" in reason.lower()
    
    def test_proper_auth_enforcement(self):
        """Test that proper auth enforcement is recognized."""
        is_issue, confidence, reason = detect_status_issue(401, 200, "auth_comparison")
        assert not is_issue
        assert confidence < 20
    
    def test_idor_different_resources(self):
        """Test IDOR detection with different resources."""
        is_issue, confidence, reason = detect_status_issue(200, 200, "idor_comparison")
        assert is_issue
        assert confidence > 70
    
    def test_sqli_status_change(self):
        """Test SQLi detection when payload changes status."""
        is_issue, confidence, reason = detect_status_issue(400, 200, "sqli_comparison")
        assert is_issue
        assert confidence > 75


class TestDetectTimingIssue:
    """Test timing anomaly detection."""
    
    def test_significant_delay(self):
        """Test detection of significant timing differences."""
        is_anomaly, confidence, reason = detect_timing_issue(0.5, 6.0)
        assert is_anomaly
        assert confidence > 0
        assert "delay" in reason.lower() or "timing" in reason.lower()
    
    def test_similar_timing(self):
        """Test that similar timings don't trigger false positives."""
        is_anomaly, confidence, reason = detect_timing_issue(0.5, 0.6)
        assert not is_anomaly
        assert confidence == 0
    
    def test_moderate_difference(self):
        """Test moderate timing differences."""
        is_anomaly, confidence, reason = detect_timing_issue(0.5, 1.5)
        assert is_anomaly  # 3x ratio triggers detection
        assert confidence > 0
    
    def test_invalid_timing(self):
        """Test handling of invalid timing data."""
        is_anomaly, confidence, reason = detect_timing_issue(0, 1.0)
        assert not is_anomaly
        assert confidence == 0


class TestDetectVulnerability:
    """Test unified vulnerability detection."""
    
    def test_idor_vulnerability(self):
        """Test IDOR vulnerability detection."""
        result = detect_vulnerability(
            attack_type="IDOR",
            endpoint="/users/{id}",
            baseline_response={
                "status": 200,
                "text": '{"id": 1, "name": "John", "email": "john@example.com"}',
                "time": 0.5
            },
            test_response={
                "status": 200,
                "text": '{"id": 2, "name": "Jane", "email": "jane@example.com"}',
                "time": 0.5
            }
        )
        assert result.vulnerable
        assert result.confidence > 60
        assert result.attack_type == "IDOR"
    
    def test_missing_auth_vulnerability(self):
        """Test missing authentication detection."""
        result = detect_vulnerability(
            attack_type="Missing Auth",
            endpoint="/admin",
            baseline_response={
                "status": 200,
                "text": '{"admin": true}',
                "time": 0.5
            },
            test_response={
                "status": 200,
                "text": '{"admin": true}',
                "time": 0.5
            }
        )
        assert result.vulnerable
        assert result.confidence > 60
    
    def test_sqli_vulnerability(self):
        """Test SQL injection detection."""
        result = detect_vulnerability(
            attack_type="SQL Injection",
            endpoint="/login",
            baseline_response={
                "status": 401,
                "text": '{"error": "Invalid credentials"}',
                "time": 0.5
            },
            test_response={
                "status": 200,
                "text": 'MySQL error: You have an error in your SQL syntax',
                "time": 0.5
            }
        )
        assert result.vulnerable
        assert result.confidence > 60
    
    def test_safe_endpoint(self):
        """Test that safe endpoints are not flagged."""
        result = detect_vulnerability(
            attack_type="Missing Auth",
            endpoint="/users/{id}",
            baseline_response={
                "status": 401,  # Unauthorized
                "text": '{"error": "Unauthorized"}',
                "time": 0.5
            },
            test_response={
                "status": 200,  # Authorized with token
                "text": '{"id": 1, "name": "John"}',
                "time": 0.5
            }
        )
        assert not result.vulnerable
        assert result.confidence <= 60
    
    def test_confidence_threshold(self):
        """Test that only high-confidence findings are flagged."""
        result = detect_vulnerability(
            attack_type="SQL Injection",
            endpoint="/search",
            baseline_response={
                "status": 200,
                "text": '{"results": []}',
                "time": 0.5
            },
            test_response={
                "status": 200,
                "text": '{"results": []}',  # No change
                "time": 0.5
            }
        )
        assert not result.vulnerable
        assert result.confidence <= 60


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
