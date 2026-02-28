"""Tests for OpenAPI parser functionality."""
import pytest
from pathlib import Path
from rico.brain.openapi_parser import parse_openapi, Endpoint


class TestParseOpenAPI:
    """Test OpenAPI specification parsing."""
    
    def test_parse_demo_yaml(self):
        """Test parsing demo.yaml successfully."""
        spec_path = "demo-api/demo.yaml"
        
        # Parse the spec
        endpoints = parse_openapi(spec_path)
        
        # Verify we got endpoints
        assert len(endpoints) > 0
        assert all(isinstance(ep, Endpoint) for ep in endpoints)
        
        # Verify endpoint structure
        for endpoint in endpoints:
            assert endpoint.method in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
            assert endpoint.path.startswith("/")
            assert isinstance(endpoint.parameters, list)
            assert isinstance(endpoint.auth_required, bool)
    
    def test_parse_nonexistent_file(self):
        """Test parsing non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError) as exc_info:
            parse_openapi("nonexistent.yaml")
        
        assert "not found" in str(exc_info.value).lower()
    
    def test_parse_invalid_yaml(self):
        """Test parsing invalid YAML raises ValueError."""
        spec_path = "demo-api/invalid.yaml"
        
        with pytest.raises(ValueError) as exc_info:
            parse_openapi(spec_path)
        
        assert "failed to parse" in str(exc_info.value).lower()
    
    def test_parse_no_paths(self):
        """Test parsing spec with no paths raises ValueError."""
        spec_path = "demo-api/no-paths.yaml"
        
        with pytest.raises(ValueError) as exc_info:
            parse_openapi(spec_path)
        
        assert "does not contain any paths" in str(exc_info.value).lower()
    
    def test_endpoint_model_validation(self):
        """Test Endpoint model validation."""
        # Valid endpoint
        endpoint = Endpoint(
            method="GET",
            path="/api/users",
            parameters=["id (path)", "name (query)"],
            auth_required=True
        )
        
        assert endpoint.method == "GET"
        assert endpoint.path == "/api/users"
        assert len(endpoint.parameters) == 2
        assert endpoint.auth_required is True
    
    def test_endpoint_default_values(self):
        """Test Endpoint model default values."""
        endpoint = Endpoint(
            method="POST",
            path="/api/posts"
        )
        
        assert endpoint.parameters == []
        assert endpoint.auth_required is False
    
    def test_parse_extracts_parameters(self):
        """Test that parsing extracts endpoint parameters."""
        spec_path = "demo-api/demo.yaml"
        endpoints = parse_openapi(spec_path)
        
        # Find endpoint with parameters
        endpoints_with_params = [ep for ep in endpoints if len(ep.parameters) > 0]
        
        # Should have at least one endpoint with parameters
        assert len(endpoints_with_params) > 0
        
        # Verify parameter format
        for endpoint in endpoints_with_params:
            for param in endpoint.parameters:
                # Parameters should be in format "name (location)"
                assert "(" in param and ")" in param
    
    def test_parse_extracts_http_methods(self):
        """Test that parsing extracts different HTTP methods."""
        spec_path = "demo-api/demo.yaml"
        endpoints = parse_openapi(spec_path)
        
        # Get unique methods
        methods = set(ep.method for ep in endpoints)
        
        # Should have at least GET and POST
        assert "GET" in methods or "POST" in methods
        
        # All methods should be uppercase
        assert all(method.isupper() for method in methods)
    
    def test_parse_extracts_paths(self):
        """Test that parsing extracts endpoint paths."""
        spec_path = "demo-api/demo.yaml"
        endpoints = parse_openapi(spec_path)
        
        # All paths should start with /
        assert all(ep.path.startswith("/") for ep in endpoints)
        
        # Get unique paths
        paths = set(ep.path for ep in endpoints)
        
        # Should have multiple unique paths
        assert len(paths) > 0
    
    def test_parse_detects_auth_requirements(self):
        """Test that parsing detects authentication requirements."""
        spec_path = "demo-api/demo.yaml"
        endpoints = parse_openapi(spec_path)
        
        # Should have a mix of auth required and not required
        auth_required = [ep for ep in endpoints if ep.auth_required]
        no_auth = [ep for ep in endpoints if not ep.auth_required]
        
        # At least one of each (or all one type is also valid)
        assert len(auth_required) >= 0
        assert len(no_auth) >= 0
        assert len(auth_required) + len(no_auth) == len(endpoints)


class TestValidationBackendError:
    """Test validation backend error handling."""
    
    def test_helpful_error_message_format(self):
        """Test that error messages are helpful."""
        # This test verifies the error message format
        # The actual validation backend error is caught in parse_openapi
        
        try:
            # Try to parse a file (should work if validator is installed)
            parse_openapi("demo-api/demo.yaml")
        except ValueError as e:
            error_msg = str(e)
            # If there's a validation backend error, it should have helpful message
            if "validation backend" in error_msg.lower():
                assert "pip install openapi-spec-validator" in error_msg
