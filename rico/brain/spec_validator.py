"""OpenAPI specification validation and synchronization."""

import httpx
import json
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path
import tempfile
from rich.console import Console

console = Console()


async def fetch_live_spec(base_url: str, timeout: float = 10.0) -> Optional[Dict[str, Any]]:
    """
    Fetch live OpenAPI specification from target API.
    
    Tries common OpenAPI spec endpoints:
    - /openapi.json
    - /openapi.yaml
    - /api/openapi.json
    - /docs/openapi.json
    
    Args:
        base_url: Base URL of the API
        timeout: Request timeout in seconds
        
    Returns:
        OpenAPI spec dict or None if not found
    """
    base_url = base_url.rstrip('/')
    
    # Common OpenAPI spec endpoints
    spec_endpoints = [
        '/openapi.json',
        '/openapi.yaml',
        '/api/openapi.json',
        '/docs/openapi.json',
        '/swagger.json',
        '/api-docs',
    ]
    
    async with httpx.AsyncClient(timeout=timeout) as client:
        for endpoint in spec_endpoints:
            try:
                url = f"{base_url}{endpoint}"
                response = await client.get(url)
                
                if response.status_code == 200:
                    # Try to parse as JSON
                    try:
                        spec = response.json()
                        # Validate it's an OpenAPI spec
                        if 'openapi' in spec or 'swagger' in spec:
                            console.print(f"[dim]✓ Found live spec at: {endpoint}[/dim]")
                            return spec
                    except json.JSONDecodeError:
                        continue
            except (httpx.TimeoutException, httpx.ConnectError):
                continue
            except Exception:
                continue
    
    return None


def extract_endpoints_from_spec(spec: Dict[str, Any]) -> List[str]:
    """
    Extract endpoint paths from OpenAPI spec.
    
    Args:
        spec: OpenAPI specification dict
        
    Returns:
        List of endpoint paths
    """
    endpoints = []
    
    if 'paths' in spec:
        for path in spec['paths'].keys():
            endpoints.append(path)
    
    return sorted(endpoints)


def compare_specs(
    local_spec: Dict[str, Any],
    live_spec: Dict[str, Any]
) -> Tuple[List[str], List[str], List[str]]:
    """
    Compare local and live OpenAPI specifications.
    
    Args:
        local_spec: Local OpenAPI spec
        live_spec: Live OpenAPI spec from target
        
    Returns:
        Tuple of (common_endpoints, local_only, live_only)
    """
    local_endpoints = set(extract_endpoints_from_spec(local_spec))
    live_endpoints = set(extract_endpoints_from_spec(live_spec))
    
    common = sorted(local_endpoints & live_endpoints)
    local_only = sorted(local_endpoints - live_endpoints)
    live_only = sorted(live_endpoints - local_endpoints)
    
    return common, local_only, live_only


def calculate_coverage(
    local_endpoints: List[str],
    live_endpoints: List[str]
) -> Tuple[int, int, float]:
    """
    Calculate endpoint coverage percentage.
    
    Args:
        local_endpoints: Endpoints in local spec
        live_endpoints: Endpoints in live spec
        
    Returns:
        Tuple of (covered_count, total_count, percentage)
    """
    local_set = set(local_endpoints)
    live_set = set(live_endpoints)
    
    covered = len(local_set & live_set)
    total = len(live_set)
    percentage = (covered / total * 100) if total > 0 else 0.0
    
    return covered, total, percentage


async def validate_spec_coverage(
    spec_path: str,
    base_url: str,
    demo_mode: bool = False
) -> Tuple[bool, Dict[str, Any]]:
    """
    Validate local spec coverage against live API.
    
    Args:
        spec_path: Path to local OpenAPI spec
        base_url: Base URL of target API
        demo_mode: Whether to suppress warnings
        
    Returns:
        Tuple of (is_valid, validation_info)
    """
    validation_info = {
        "has_live_spec": False,
        "coverage_percentage": 100.0,
        "covered_endpoints": 0,
        "total_endpoints": 0,
        "missing_endpoints": [],
        "extra_endpoints": [],
        "warnings": []
    }
    
    # Try to fetch live spec
    live_spec = await fetch_live_spec(base_url)
    
    if not live_spec:
        if not demo_mode:
            console.print("[yellow]⚠ Could not fetch live OpenAPI spec from target[/yellow]")
            console.print("[dim]Proceeding with local spec only[/dim]\n")
        validation_info["warnings"].append("Live spec not available")
        return True, validation_info
    
    validation_info["has_live_spec"] = True
    
    # Load local spec
    try:
        from rico.brain.openapi_parser import parse_openapi
        import prance
        
        parser = prance.ResolvingParser(spec_path)
        local_spec = parser.specification
    except Exception as e:
        if not demo_mode:
            console.print(f"[red]✗ Failed to load local spec: {e}[/red]")
        validation_info["warnings"].append(f"Failed to load local spec: {e}")
        return False, validation_info
    
    # Compare specs
    common, local_only, live_only = compare_specs(local_spec, live_spec)
    
    # Calculate coverage
    live_endpoints = extract_endpoints_from_spec(live_spec)
    covered, total, percentage = calculate_coverage(
        extract_endpoints_from_spec(local_spec),
        live_endpoints
    )
    
    validation_info["coverage_percentage"] = percentage
    validation_info["covered_endpoints"] = covered
    validation_info["total_endpoints"] = total
    validation_info["missing_endpoints"] = live_only
    validation_info["extra_endpoints"] = local_only
    
    # Display coverage
    if percentage == 100.0:
        console.print(f"[green]✓ Spec Coverage: {covered}/{total} endpoints (100%)[/green]\n")
    else:
        console.print(f"[yellow]⚠ Spec Coverage: {covered}/{total} endpoints ({percentage:.0f}%)[/yellow]")
        
        if live_only:
            console.print(f"[yellow]  Missing from local spec: {len(live_only)} endpoint(s)[/yellow]")
            for endpoint in live_only[:5]:  # Show first 5
                console.print(f"[dim]    - {endpoint}[/dim]")
            if len(live_only) > 5:
                console.print(f"[dim]    ... and {len(live_only) - 5} more[/dim]")
        
        if local_only:
            console.print(f"[dim]  Extra in local spec: {len(local_only)} endpoint(s)[/dim]")
        
        console.print()
    
    return True, validation_info


async def sync_spec(
    base_url: str,
    output_path: Optional[str] = None
) -> Optional[str]:
    """
    Download live OpenAPI spec and save to file.
    
    Args:
        base_url: Base URL of target API
        output_path: Optional output path (defaults to temp file)
        
    Returns:
        Path to downloaded spec file or None if failed
    """
    console.print("[cyan]Fetching live OpenAPI spec...[/cyan]")
    
    live_spec = await fetch_live_spec(base_url)
    
    if not live_spec:
        console.print("[red]✗ Could not fetch live spec from target[/red]")
        return None
    
    # Determine output path
    if output_path is None:
        # Create temp file
        temp_file = tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.json',
            prefix='rico_spec_',
            delete=False
        )
        output_path = temp_file.name
        temp_file.close()
    
    # Save spec
    try:
        with open(output_path, 'w') as f:
            json.dump(live_spec, f, indent=2)
        
        console.print(f"[green]✓ Live spec saved to: {output_path}[/green]\n")
        return output_path
    except Exception as e:
        console.print(f"[red]✗ Failed to save spec: {e}[/red]")
        return None


def print_coverage_summary(validation_info: Dict[str, Any], demo_mode: bool = False):
    """
    Print endpoint coverage summary.
    
    Args:
        validation_info: Validation information dict
        demo_mode: Whether to use clean demo formatting
    """
    if not validation_info["has_live_spec"]:
        return
    
    covered = validation_info["covered_endpoints"]
    total = validation_info["total_endpoints"]
    percentage = validation_info["coverage_percentage"]
    
    if demo_mode:
        # Clean demo output
        if percentage == 100.0:
            console.print(f"[bold green]✓ Spec Coverage: {covered}/{total} endpoints (100%)[/bold green]")
        else:
            console.print(f"[bold yellow]⚠ Spec Coverage: {covered}/{total} endpoints ({percentage:.0f}%)[/bold yellow]")
            if validation_info["missing_endpoints"]:
                console.print(f"[yellow]  {len(validation_info['missing_endpoints'])} endpoint(s) not in local spec[/yellow]")
    else:
        # Detailed output
        console.print(f"\n[bold cyan]Endpoint Coverage Analysis[/bold cyan]")
        console.print(f"Covered: {covered}/{total} ({percentage:.1f}%)")
        
        if validation_info["missing_endpoints"]:
            console.print(f"\n[yellow]Missing from local spec:[/yellow]")
            for endpoint in validation_info["missing_endpoints"]:
                console.print(f"  - {endpoint}")
        
        if validation_info["extra_endpoints"]:
            console.print(f"\n[dim]Extra in local spec:[/dim]")
            for endpoint in validation_info["extra_endpoints"]:
                console.print(f"  - {endpoint}")
