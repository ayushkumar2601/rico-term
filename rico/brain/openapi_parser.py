"""OpenAPI specification parser for RICO."""

from pathlib import Path
from typing import Any, Optional
from pydantic import BaseModel, Field
import prance


class Endpoint(BaseModel):
    """Model representing an API endpoint."""

    method: str = Field(..., description="HTTP method (GET, POST, etc.)")
    path: str = Field(..., description="Endpoint path")
    parameters: list[str] = Field(
        default_factory=list, description="List of parameters"
    )
    auth_required: bool = Field(
        default=False, description="Whether authentication is required"
    )


def parse_openapi(spec_path: str) -> list[Endpoint]:
    """
    Parse an OpenAPI specification file and extract endpoint information.

    Args:
        spec_path: Path to the OpenAPI YAML or JSON file

    Returns:
        List of Endpoint objects containing parsed endpoint information

    Raises:
        FileNotFoundError: If the spec file doesn't exist
        ValueError: If the spec is invalid or cannot be parsed
    """
    # Validate file exists
    file_path = Path(spec_path)
    if not file_path.exists():
        raise FileNotFoundError(f"OpenAPI spec file not found: {spec_path}")

    # Parse the OpenAPI spec
    try:
        parser = prance.ResolvingParser(str(file_path))
        spec = parser.specification
    except Exception as e:
        error_msg = str(e)
        # Check if it's a validation backend error
        if "validation backend" in error_msg.lower() or "no validation backend" in error_msg.lower():
            raise ValueError(
                f"Failed to parse OpenAPI spec: {error_msg}\n"
                "OpenAPI validator missing. Run: pip install openapi-spec-validator"
            )
        raise ValueError(f"Failed to parse OpenAPI spec: {error_msg}")

    # Validate spec has paths
    if "paths" not in spec or not spec["paths"]:
        raise ValueError("OpenAPI spec does not contain any paths")

    endpoints = []

    # Extract endpoint information
    for path, path_item in spec["paths"].items():
        # Iterate through HTTP methods
        for method in ["get", "post", "put", "delete", "patch", "options", "head"]:
            if method not in path_item:
                continue

            operation = path_item[method]

            # Extract parameters
            parameters = []
            if "parameters" in operation:
                for param in operation["parameters"]:
                    param_name = param.get("name", "")
                    param_in = param.get("in", "")
                    parameters.append(f"{param_name} ({param_in})")

            # Also check path-level parameters
            if "parameters" in path_item:
                for param in path_item["parameters"]:
                    param_name = param.get("name", "")
                    param_in = param.get("in", "")
                    param_str = f"{param_name} ({param_in})"
                    if param_str not in parameters:
                        parameters.append(param_str)

            # Check if authentication is required
            auth_required = False
            if "security" in operation:
                auth_required = len(operation["security"]) > 0
            elif "security" in spec:
                # Check global security
                auth_required = len(spec["security"]) > 0

            # Create endpoint object
            endpoint = Endpoint(
                method=method.upper(),
                path=path,
                parameters=parameters,
                auth_required=auth_required,
            )
            endpoints.append(endpoint)

    return endpoints
