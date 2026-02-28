"""Tests for security score and CVSS functionality."""
import pytest
from rico.reporter.report_builder import (
    ReportItem,
    compute_security_score,
    find_top_issue,
    get_cvss_score,
    CVSS_MAP
)


class TestCVSSScores:
    """Test CVSS score mapping."""
    
    def test_sql_injection_cvss(self):
        """SQL Injection should have CVSS 9.0."""
        assert get_cvss_score("SQL Injection") == 9.0
    
    def test_idor_cvss(self):
        """IDOR should have CVSS 8.0."""
        assert get_cvss_score("IDOR") == 8.0
    
    def test_missing_auth_cvss(self):
        """Missing Auth should have CVSS 7.5."""
        assert get_cvss_score("Missing Auth") == 7.5
    
    def test_csrf_cvss(self):
        """CSRF should have CVSS 6.5."""
        assert get_cvss_score("CSRF") == 6.5
    
    def test_unknown_attack_cvss(self):
        """Unknown attack types should default to 5.0."""
        assert get_cvss_score("Unknown Attack") == 5.0
        assert get_cvss_score("XSS") == 5.0


class TestSecurityScore:
    """Test security score computation."""
    
    def test_perfect_score(self):
        """No vulnerabilities should give 100/100 with LOW risk."""
        items = [
            ReportItem(
                endpoint="/api/users",
                attack_type="IDOR",
                status="SAFE",
                confidence=50,
                description="No vulnerability",
                poc_curl="curl http://test.com",
                fix_suggestion="N/A",
                severity="Info",
                cvss_score=8.0
            )
        ]
        
        score, risk_level = compute_security_score(items)
        assert score == 100
        assert risk_level == "LOW"
    
    def test_one_critical_vulnerability(self):
        """One critical vulnerability should reduce score by 30."""
        items = [
            ReportItem(
                endpoint="/api/users",
                attack_type="SQL Injection",
                status="VULNERABLE",
                confidence=90,
                description="SQL injection found",
                poc_curl="curl http://test.com",
                fix_suggestion="Use parameterized queries",
                severity="Critical",
                cvss_score=9.0
            )
        ]
        
        score, risk_level = compute_security_score(items)
        assert score == 70
        assert risk_level == "MEDIUM"
    
    def test_one_high_vulnerability(self):
        """One high vulnerability should reduce score by 20."""
        items = [
            ReportItem(
                endpoint="/api/users",
                attack_type="IDOR",
                status="VULNERABLE",
                confidence=85,
                description="IDOR found",
                poc_curl="curl http://test.com",
                fix_suggestion="Add authorization checks",
                severity="High",
                cvss_score=8.0
            )
        ]
        
        score, risk_level = compute_security_score(items)
        assert score == 80
        assert risk_level == "LOW"
    
    def test_one_medium_vulnerability(self):
        """One medium vulnerability should reduce score by 10."""
        items = [
            ReportItem(
                endpoint="/api/users",
                attack_type="Missing Auth",
                status="SUSPICIOUS",
                confidence=70,
                description="Possible missing auth",
                poc_curl="curl http://test.com",
                fix_suggestion="Add authentication",
                severity="Medium",
                cvss_score=7.5
            )
        ]
        
        score, risk_level = compute_security_score(items)
        assert score == 90
        assert risk_level == "LOW"
    
    def test_multiple_vulnerabilities(self):
        """Multiple vulnerabilities should compound score reduction."""
        items = [
            ReportItem(
                endpoint="/api/users",
                attack_type="SQL Injection",
                status="VULNERABLE",
                confidence=90,
                description="SQL injection",
                poc_curl="curl http://test.com",
                fix_suggestion="Fix",
                severity="Critical",
                cvss_score=9.0
            ),
            ReportItem(
                endpoint="/api/posts",
                attack_type="IDOR",
                status="VULNERABLE",
                confidence=85,
                description="IDOR",
                poc_curl="curl http://test.com",
                fix_suggestion="Fix",
                severity="High",
                cvss_score=8.0
            ),
            ReportItem(
                endpoint="/api/comments",
                attack_type="Missing Auth",
                status="VULNERABLE",
                confidence=75,
                description="Missing auth",
                poc_curl="curl http://test.com",
                fix_suggestion="Fix",
                severity="Medium",
                cvss_score=7.5
            )
        ]
        
        # Score = 100 - (1*30 + 1*20 + 1*10) = 40
        score, risk_level = compute_security_score(items)
        assert score == 40
        assert risk_level == "HIGH"
    
    def test_score_minimum_zero(self):
        """Score should not go below 0."""
        items = [
            ReportItem(
                endpoint=f"/api/endpoint{i}",
                attack_type="SQL Injection",
                status="VULNERABLE",
                confidence=90,
                description="SQL injection",
                poc_curl="curl http://test.com",
                fix_suggestion="Fix",
                severity="Critical",
                cvss_score=9.0
            )
            for i in range(10)  # 10 critical = 300 points
        ]
        
        score, risk_level = compute_security_score(items)
        assert score == 0
        assert risk_level == "HIGH"
    
    def test_risk_level_boundaries(self):
        """Test risk level boundary conditions."""
        # Score 80 = LOW
        items_80 = [
            ReportItem(
                endpoint="/api/test",
                attack_type="IDOR",
                status="VULNERABLE",
                confidence=85,
                description="Test",
                poc_curl="curl http://test.com",
                fix_suggestion="Fix",
                severity="High",
                cvss_score=8.0
            )
        ]
        score, risk_level = compute_security_score(items_80)
        assert score == 80
        assert risk_level == "LOW"
        
        # Score 60 = MEDIUM
        items_60 = [
            ReportItem(
                endpoint=f"/api/test{i}",
                attack_type="IDOR",
                status="VULNERABLE",
                confidence=85,
                description="Test",
                poc_curl="curl http://test.com",
                fix_suggestion="Fix",
                severity="High",
                cvss_score=8.0
            )
            for i in range(2)  # 2 high = 40 points, score = 60
        ]
        score, risk_level = compute_security_score(items_60)
        assert score == 60
        assert risk_level == "MEDIUM"
        
        # Score 59 = HIGH
        items_59 = [
            ReportItem(
                endpoint=f"/api/test{i}",
                attack_type="IDOR",
                status="VULNERABLE",
                confidence=85,
                description="Test",
                poc_curl="curl http://test.com",
                fix_suggestion="Fix",
                severity="High",
                cvss_score=8.0
            )
            for i in range(2)  # 2 high = 40 points
        ] + [
            ReportItem(
                endpoint="/api/test3",
                attack_type="Missing Auth",
                status="VULNERABLE",
                confidence=70,
                description="Test",
                poc_curl="curl http://test.com",
                fix_suggestion="Fix",
                severity="Medium",
                cvss_score=7.5
            )
        ]  # +1 medium = 10 points, total 50, score = 50
        score, risk_level = compute_security_score(items_59)
        assert score == 50
        assert risk_level == "HIGH"
    
    def test_safe_endpoints_ignored(self):
        """Safe endpoints should not affect score."""
        items = [
            ReportItem(
                endpoint="/api/safe1",
                attack_type="IDOR",
                status="SAFE",
                confidence=50,
                description="Safe",
                poc_curl="curl http://test.com",
                fix_suggestion="N/A",
                severity="Info",
                cvss_score=8.0
            ),
            ReportItem(
                endpoint="/api/safe2",
                attack_type="SQL Injection",
                status="SAFE",
                confidence=40,
                description="Safe",
                poc_curl="curl http://test.com",
                fix_suggestion="N/A",
                severity="Info",
                cvss_score=9.0
            )
        ]
        
        score, risk_level = compute_security_score(items)
        assert score == 100
        assert risk_level == "LOW"


class TestTopIssue:
    """Test top issue identification."""
    
    def test_no_vulnerabilities(self):
        """Should return 'None' when no vulnerabilities."""
        items = [
            ReportItem(
                endpoint="/api/users",
                attack_type="IDOR",
                status="SAFE",
                confidence=50,
                description="Safe",
                poc_curl="curl http://test.com",
                fix_suggestion="N/A",
                severity="Info",
                cvss_score=8.0
            )
        ]
        
        top_issue = find_top_issue(items)
        assert top_issue == "None"
    
    def test_single_vulnerability(self):
        """Should return the single vulnerability."""
        items = [
            ReportItem(
                endpoint="/api/users",
                attack_type="SQL Injection",
                status="VULNERABLE",
                confidence=90,
                description="SQL injection",
                poc_curl="curl http://test.com",
                fix_suggestion="Fix",
                severity="Critical",
                cvss_score=9.0
            )
        ]
        
        top_issue = find_top_issue(items)
        assert top_issue == "SQL Injection in /api/users"
    
    def test_highest_severity_wins(self):
        """Critical should be prioritized over High."""
        items = [
            ReportItem(
                endpoint="/api/posts",
                attack_type="IDOR",
                status="VULNERABLE",
                confidence=95,
                description="IDOR",
                poc_curl="curl http://test.com",
                fix_suggestion="Fix",
                severity="High",
                cvss_score=8.0
            ),
            ReportItem(
                endpoint="/api/users",
                attack_type="SQL Injection",
                status="VULNERABLE",
                confidence=85,
                description="SQL injection",
                poc_curl="curl http://test.com",
                fix_suggestion="Fix",
                severity="Critical",
                cvss_score=9.0
            )
        ]
        
        top_issue = find_top_issue(items)
        assert top_issue == "SQL Injection in /api/users"
    
    def test_cvss_tiebreaker(self):
        """Higher CVSS should win when severity is same."""
        items = [
            ReportItem(
                endpoint="/api/posts",
                attack_type="Missing Auth",
                status="VULNERABLE",
                confidence=85,
                description="Missing auth",
                poc_curl="curl http://test.com",
                fix_suggestion="Fix",
                severity="High",
                cvss_score=7.5
            ),
            ReportItem(
                endpoint="/api/users",
                attack_type="IDOR",
                status="VULNERABLE",
                confidence=85,
                description="IDOR",
                poc_curl="curl http://test.com",
                fix_suggestion="Fix",
                severity="High",
                cvss_score=8.0
            )
        ]
        
        top_issue = find_top_issue(items)
        assert top_issue == "IDOR in /api/users"
    
    def test_confidence_tiebreaker(self):
        """Higher confidence should win when severity and CVSS are same."""
        items = [
            ReportItem(
                endpoint="/api/posts",
                attack_type="IDOR",
                status="VULNERABLE",
                confidence=80,
                description="IDOR",
                poc_curl="curl http://test.com",
                fix_suggestion="Fix",
                severity="High",
                cvss_score=8.0
            ),
            ReportItem(
                endpoint="/api/users",
                attack_type="IDOR",
                status="VULNERABLE",
                confidence=95,
                description="IDOR",
                poc_curl="curl http://test.com",
                fix_suggestion="Fix",
                severity="High",
                cvss_score=8.0
            )
        ]
        
        top_issue = find_top_issue(items)
        assert top_issue == "IDOR in /api/users"
    
    def test_suspicious_status_included(self):
        """SUSPICIOUS status should be included in top issue search."""
        items = [
            ReportItem(
                endpoint="/api/users",
                attack_type="Missing Auth",
                status="SUSPICIOUS",
                confidence=75,
                description="Possible missing auth",
                poc_curl="curl http://test.com",
                fix_suggestion="Fix",
                severity="Medium",
                cvss_score=7.5
            )
        ]
        
        top_issue = find_top_issue(items)
        assert top_issue == "Missing Auth in /api/users"


class TestReportItemWithCVSS:
    """Test ReportItem with CVSS score."""
    
    def test_report_item_includes_cvss(self):
        """ReportItem should store CVSS score."""
        item = ReportItem(
            endpoint="/api/users",
            attack_type="SQL Injection",
            status="VULNERABLE",
            confidence=90,
            description="SQL injection found",
            poc_curl="curl http://test.com",
            fix_suggestion="Use parameterized queries",
            severity="Critical",
            cvss_score=9.0
        )
        
        assert item.cvss_score == 9.0
    
    def test_report_item_to_dict_includes_cvss(self):
        """ReportItem.to_dict() should include CVSS score."""
        item = ReportItem(
            endpoint="/api/users",
            attack_type="IDOR",
            status="VULNERABLE",
            confidence=85,
            description="IDOR found",
            poc_curl="curl http://test.com",
            fix_suggestion="Add authorization",
            severity="High",
            cvss_score=8.0
        )
        
        item_dict = item.to_dict()
        assert "cvss_score" in item_dict
        assert item_dict["cvss_score"] == 8.0
