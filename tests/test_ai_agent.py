"""Unit tests for AI agent modules."""

import pytest
import asyncio
from rico.brain.ai_agent.classifier import classify_endpoint_heuristic, classify_endpoint
from rico.brain.ai_agent.planner import plan_attacks_heuristic, plan_attacks
from rico.brain.ai_agent.explainer import explain_attack_template, explain_attack


class TestClassifier:
    """Tests for endpoint classification."""
    
    def test_classify_auth_endpoint(self):
        """Test classification of authentication endpoints."""
        result = classify_endpoint_heuristic("POST", "/api/login", [])
        assert result["type"] == "auth"
        assert result["sensitivity"] == "high"
        assert "auth" in result["reason"].lower() or "credential" in result["reason"].lower()
    
    def test_classify_admin_endpoint(self):
        """Test classification of admin endpoints."""
        result = classify_endpoint_heuristic("GET", "/admin/users", [])
        assert result["type"] == "admin"
        assert result["sensitivity"] == "high"
        assert "admin" in result["reason"].lower() or "privilege" in result["reason"].lower()
    
    def test_classify_resource_endpoint_with_id(self):
        """Test classification of resource endpoints with ID."""
        result = classify_endpoint_heuristic("GET", "/users/{id}", ["id (path)"])
        assert result["type"] == "resource"
        assert result["sensitivity"] == "medium"
        assert "idor" in result["reason"].lower() or "id" in result["reason"].lower()
    
    def test_classify_public_endpoint(self):
        """Test classification of public endpoints."""
        result = classify_endpoint_heuristic("GET", "/health", [])
        assert result["type"] == "public"
        assert result["sensitivity"] == "low"
        assert "public" in result["reason"].lower()
    
    def test_classify_post_resource(self):
        """Test classification of POST resource endpoints."""
        result = classify_endpoint_heuristic("POST", "/users", [])
        assert result["type"] == "resource"
        assert result["sensitivity"] == "medium"
        assert "authorization" in result["reason"].lower() or "resource" in result["reason"].lower()
    
    @pytest.mark.asyncio
    async def test_classify_endpoint_fallback(self):
        """Test that classify_endpoint falls back to heuristic when no API key."""
        result = await classify_endpoint("GET", "/users/{id}", ["id (path)"])
        assert "type" in result
        assert "sensitivity" in result
        assert "reason" in result
        assert result["type"] in ["auth", "resource", "admin", "public"]


class TestPlanner:
    """Tests for attack planning."""
    
    def test_plan_attacks_auth_endpoint(self):
        """Test attack planning for auth endpoints."""
        result = plan_attacks_heuristic("auth", "high", "POST")
        assert "SQL Injection" in result["attacks"]
        assert len(result["reasoning"]) > 0
    
    def test_plan_attacks_resource_endpoint(self):
        """Test attack planning for resource endpoints."""
        result = plan_attacks_heuristic("resource", "medium", "GET")
        assert "IDOR" in result["attacks"]
        assert "Missing Auth" in result["attacks"]
        assert len(result["reasoning"]) > 0
    
    def test_plan_attacks_admin_endpoint(self):
        """Test attack planning for admin endpoints."""
        result = plan_attacks_heuristic("admin", "high", "GET")
        assert "Missing Auth" in result["attacks"]
        assert "IDOR" in result["attacks"]
        assert "SQL Injection" in result["attacks"]
        assert len(result["reasoning"]) > 0
    
    def test_plan_attacks_public_endpoint(self):
        """Test attack planning for public endpoints."""
        result = plan_attacks_heuristic("public", "low", "GET")
        # Public endpoints should still be tested for SQLi
        assert "SQL Injection" in result["attacks"]
    
    @pytest.mark.asyncio
    async def test_plan_attacks_fallback(self):
        """Test that plan_attacks falls back to heuristic when no API key."""
        result = await plan_attacks("resource", "medium", "GET", "/users/{id}")
        assert "attacks" in result
        assert "reasoning" in result
        assert isinstance(result["attacks"], list)
        assert len(result["attacks"]) > 0


class TestExplainer:
    """Tests for attack explanation."""
    
    def test_explain_idor_resource(self):
        """Test explanation for IDOR on resource endpoint."""
        result = explain_attack_template("IDOR", "resource", "GET", "/users/{id}")
        assert len(result) > 0
        assert "idor" in result.lower() or "id" in result.lower()
    
    def test_explain_missing_auth_admin(self):
        """Test explanation for Missing Auth on admin endpoint."""
        result = explain_attack_template("Missing Auth", "admin", "GET", "/admin/config")
        assert len(result) > 0
        assert "admin" in result.lower() or "auth" in result.lower()
    
    def test_explain_sqli_auth(self):
        """Test explanation for SQLi on auth endpoint."""
        result = explain_attack_template("SQL Injection", "auth", "POST", "/login")
        assert len(result) > 0
        assert "sql" in result.lower() or "database" in result.lower()
    
    def test_explain_all_attack_types(self):
        """Test that all attack types have explanations."""
        attack_types = ["IDOR", "Missing Auth", "SQL Injection"]
        endpoint_types = ["auth", "resource", "admin", "public"]
        
        for attack in attack_types:
            for endpoint_type in endpoint_types:
                result = explain_attack_template(attack, endpoint_type, "GET", "/test")
                assert len(result) > 0
                assert isinstance(result, str)
    
    @pytest.mark.asyncio
    async def test_explain_attack_fallback(self):
        """Test that explain_attack falls back to template when no API key."""
        result = await explain_attack("IDOR", "resource", "GET", "/users/{id}")
        assert len(result) > 0
        assert isinstance(result, str)


class TestIntegration:
    """Integration tests for AI agent workflow."""
    
    @pytest.mark.asyncio
    async def test_full_workflow_auth_endpoint(self):
        """Test full AI workflow for auth endpoint."""
        # Classify
        classification = await classify_endpoint("POST", "/api/login", [])
        assert classification["type"] == "auth"
        
        # Plan
        plan = await plan_attacks(
            classification["type"],
            classification["sensitivity"],
            "POST",
            "/api/login"
        )
        assert "SQL Injection" in plan["attacks"]
        
        # Explain
        for attack in plan["attacks"]:
            explanation = await explain_attack(
                attack,
                classification["type"],
                "POST",
                "/api/login"
            )
            assert len(explanation) > 0
    
    @pytest.mark.asyncio
    async def test_full_workflow_resource_endpoint(self):
        """Test full AI workflow for resource endpoint."""
        # Classify
        classification = await classify_endpoint("GET", "/users/{id}", ["id (path)"])
        assert classification["type"] == "resource"
        
        # Plan
        plan = await plan_attacks(
            classification["type"],
            classification["sensitivity"],
            "GET",
            "/users/{id}"
        )
        assert "IDOR" in plan["attacks"]
        
        # Explain
        for attack in plan["attacks"]:
            explanation = await explain_attack(
                attack,
                classification["type"],
                "GET",
                "/users/{id}"
            )
            assert len(explanation) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
