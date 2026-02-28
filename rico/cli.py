import typer
import asyncio
from rich import print
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from pathlib import Path
import json
from rico.docs import show_docs

from rico.brain.openapi_parser import parse_openapi, Endpoint
from rico.executor.http_runner import run_request
from rico.attacks.idor import test_idor
from rico.attacks.missing_auth import test_missing_auth
from rico.attacks.sqli import test_sqli
from rico.attacks.utils import create_results_table
from rico.reporter.report_builder import (
    convert_results_to_report_items,
    generate_markdown_report,
    generate_html_report
)
from rico.brain.ai_agent.classifier import classify_endpoint
from rico.brain.ai_agent.planner import plan_attacks
from rico.brain.ai_agent.explainer import explain_attack
from rico.brain.ai_agent.config import load_ai_config, get_provider_name
import httpx

app = typer.Typer()
console = Console()


@app.command()
def init():
    """Initialize RICO"""
    print("[bold green]RICO initialized successfully! 🚀[/bold green]")

@app.command()
def docs():
    """Show RICO documentation"""
    show_docs()

@app.command()
def version():
    """Show RICO version"""
    print("[blue]RICO v0.1.0[/blue]")


@app.command()
def parse(spec: str = typer.Option(..., "--spec", help="Path to OpenAPI spec file")):
    """Parse an OpenAPI specification and display endpoints"""
    try:
        # Parse the OpenAPI spec
        endpoints = parse_openapi(spec)

        if not endpoints:
            console.print("[yellow]No endpoints found in the specification[/yellow]")
            return

        # Create a rich table
        table = Table(
            title=f"[bold cyan]Endpoints from {Path(spec).name}[/bold cyan]",
            show_lines=True,
        )
        table.add_column("Method", style="bold magenta", no_wrap=True)
        table.add_column("Path", style="cyan")
        table.add_column("Parameters", style="yellow")
        table.add_column("Auth Required", style="green", justify="center")

        # Add rows for each endpoint
        for endpoint in endpoints:
            params_str = "\n".join(endpoint.parameters) if endpoint.parameters else "-"
            auth_str = "✓" if endpoint.auth_required else "✗"

            table.add_row(endpoint.method, endpoint.path, params_str, auth_str)

        # Display the table
        console.print(table)
        console.print(
            f"\n[bold green]Total endpoints found: {len(endpoints)}[/bold green]"
        )

    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        raise typer.Exit(code=1)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]Unexpected error:[/bold red] {str(e)}")
        raise typer.Exit(code=1)


@app.command()
def call(
    url: str = typer.Option(..., "--url", help="Target URL for the request"),
    method: str = typer.Option(
        "GET", "--method", help="HTTP method (GET, POST, PUT, DELETE)"
    ),
    token: str = typer.Option(None, "--token", help="Authorization token"),
    timeout: float = typer.Option(30.0, "--timeout", help="Request timeout in seconds"),
):
    """Send an HTTP request to an API endpoint"""

    async def make_request():
        try:
            console.print(f"\n[cyan]Sending {method.upper()} request to:[/cyan] {url}")
            if token:
                console.print(
                    f"[cyan]Using authorization token:[/cyan] {token[:10]}..."
                )

            # Make the request
            result = await run_request(
                method=method, url=url, token=token, timeout=timeout
            )

            # Display success
            console.print("\n[bold green]✓ Request sent successfully![/bold green]")

            # Display status code with color
            status_color = (
                "green"
                if 200 <= result.status_code < 300
                else "yellow" if 300 <= result.status_code < 400 else "red"
            )
            console.print(
                f"\n[bold {status_color}]Status Code:[/bold {status_color}] {result.status_code}"
            )

            # Display response time
            console.print(
                f"[bold cyan]Response Time:[/bold cyan] {result.response_time:.3f}s"
            )

            # Try to format as JSON if possible
            try:
                json_data = json.loads(result.response_text)
                json_str = json.dumps(json_data, indent=2)

                # Limit to first 500 chars
                if len(json_str) > 500:
                    json_str = json_str[:500] + "\n... (truncated)"

                syntax = Syntax(json_str, "json", theme="monokai", line_numbers=False)
                console.print("\n[bold cyan]Response Preview:[/bold cyan]")
                console.print(Panel(syntax, border_style="cyan"))
            except json.JSONDecodeError:
                # Not JSON, display as plain text
                preview = result.response_text[:500]
                if len(result.response_text) > 500:
                    preview += "\n... (truncated)"
                console.print("\n[bold cyan]Response Preview:[/bold cyan]")
                console.print(Panel(preview, border_style="cyan"))

            # Log file notification
            console.print(f"\n[dim]✓ Request logged to rico.log[/dim]")

        except httpx.TimeoutException as e:
            console.print(f"\n[bold red]✗ Timeout Error:[/bold red] {str(e)}")
            console.print("[yellow]The request took too long to complete.[/yellow]")
            raise typer.Exit(code=1)

        except httpx.ConnectError as e:
            console.print(f"\n[bold red]✗ Connection Error:[/bold red] {str(e)}")
            console.print(
                "[yellow]Could not connect to the server. Check if the URL is correct and the server is running.[/yellow]"
            )
            raise typer.Exit(code=1)

        except ValueError as e:
            console.print(f"\n[bold red]✗ Invalid Request:[/bold red] {str(e)}")
            raise typer.Exit(code=1)

        except Exception as e:
            console.print(f"\n[bold red]✗ Unexpected Error:[/bold red] {str(e)}")
            raise typer.Exit(code=1)

    # Run the async function
    asyncio.run(make_request())


@app.command()
def attack(
    spec: str = typer.Option(..., "--spec", help="Path to OpenAPI spec file"),
    url: str = typer.Option(..., "--url", help="Base URL of the API to test"),
    token: str = typer.Option(None, "--token", help="Optional authentication token"),
    max_endpoints: int = typer.Option(
        None, "--max-endpoints", help="Maximum endpoints to test (default: all)"
    ),
    use_ai: bool = typer.Option(False, "--ai", help="Enable AI-powered attack planning"),
):
    """Run security attack tests on API endpoints"""

    # Display warning
    console.print("\n[bold yellow]⚠ WARNING: Security Testing Tool[/bold yellow]")
    console.print(
        "[yellow]Only run these tests on APIs you own or have explicit permission to test.[/yellow]"
    )
    console.print("[yellow]Unauthorized security testing may be illegal.[/yellow]\n")

    async def run_attacks():
        try:
            # Parse the OpenAPI spec
            console.print(f"[cyan]Parsing OpenAPI spec:[/cyan] {spec}")
            endpoints = parse_openapi(spec)

            if not endpoints:
                console.print(
                    "[yellow]No endpoints found in the specification[/yellow]"
                )
                return

            # Display total endpoints found
            total_endpoints = len(endpoints)
            console.print(
                f"[cyan]Found {total_endpoints} endpoint(s) in specification[/cyan]"
            )
            
            # Limit number of endpoints if specified
            if max_endpoints is not None and max_endpoints > 0:
                endpoints = endpoints[:max_endpoints]
                console.print(
                    f"[yellow]Limiting to {len(endpoints)} endpoint(s) (--max-endpoints={max_endpoints})[/yellow]"
                )
            
            console.print(
                f"[cyan]Testing {len(endpoints)} endpoint(s) against:[/cyan] {url}\n"
            )
            
            if use_ai:
                # Load AI config and show provider
                ai_config = load_ai_config()
                provider_name = get_provider_name(ai_config)
                
                if provider_name:
                    console.print(f"[blue]🤖 AI-powered attack planning enabled[/blue]")
                    console.print(f"[blue]Using AI Provider: {provider_name}[/blue]")
                    
                    # Show API key info (masked)
                    if ai_config.get("groq_key"):
                        key = ai_config["groq_key"]
                        console.print(f"[dim]GROQ API Key: {key[:10]}...{key[-4:]}[/dim]")
                    elif ai_config.get("openai_key"):
                        key = ai_config["openai_key"]
                        console.print(f"[dim]OpenAI API Key: {key[:10]}...{key[-4:]}[/dim]")
                    elif ai_config.get("anthropic_key"):
                        key = ai_config["anthropic_key"]
                        console.print(f"[dim]Anthropic API Key: {key[:10]}...{key[-4:]}[/dim]")
                    
                    console.print()
                else:
                    console.print("[yellow]⚠ No AI API key found - using heuristic rules[/yellow]\n")

            # Display enumeration summary
            console.print("[bold cyan]Endpoint Enumeration Summary[/bold cyan]")
            console.print(f"Total endpoints to test: [bold]{len(endpoints)}[/bold]")
            
            # Show first 10 endpoints as preview
            console.print("\n[dim]Endpoints to be tested:[/dim]")
            for idx, ep in enumerate(endpoints[:10], 1):
                console.print(f"[dim]  {idx}. {ep.method} {ep.path}[/dim]")
            if len(endpoints) > 10:
                console.print(f"[dim]  ... and {len(endpoints) - 10} more[/dim]")
            console.print()

            all_results = []

            # Test each endpoint
            for idx, endpoint in enumerate(endpoints, 1):
                console.print(
                    f"[cyan]Testing {idx}/{len(endpoints)}:[/cyan] [bold]{endpoint.method} {endpoint.path}[/bold]"
                )

                # AI Classification and Planning
                attacks_to_run = ["IDOR", "Missing Auth", "SQL Injection"]
                
                if use_ai:
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
                        console.print(f"[dim]  AI Classification: {classification['type']} ({classification['sensitivity']} sensitivity)[/dim]")
                        console.print(f"[dim]  Planned attacks: {', '.join(attacks_to_run)}[/dim]")
                    except Exception as e:
                        console.print(f"[yellow]  AI planning failed, using default tests: {str(e)}[/yellow]")

                # Run selected attack tests
                try:
                    # IDOR Test
                    if "IDOR" in attacks_to_run:
                        idor_result = await test_idor(
                            endpoint=endpoint.path, base_url=url, method=endpoint.method
                        )
                        
                        # Add AI reasoning if enabled
                        if use_ai:
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
                            base_url=url,
                            method=endpoint.method,
                            token=token,
                        )
                        
                        # Add AI reasoning if enabled
                        if use_ai:
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
                            base_url=url, 
                            method=endpoint.method,
                            parameters=endpoint.parameters
                        )
                        
                        # Add AI reasoning if enabled
                        if use_ai:
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

                except Exception as e:
                    console.print(f"[red]Error testing {endpoint.path}: {str(e)}[/red]")
                    continue

            # Display results
            console.print("\n")
            table = create_results_table(all_results, show_reasoning=use_ai)
            console.print(table)

            # Summary
            vulnerable_count = sum(1 for r in all_results if r.get("vulnerable", False))
            total_tests = len(all_results)

            console.print(f"\n[bold]Summary:[/bold]")
            console.print(f"Total tests: {total_tests}")
            console.print(f"Vulnerabilities found: [red]{vulnerable_count}[/red]")
            console.print(f"Safe: [green]{total_tests - vulnerable_count}[/green]")

            if vulnerable_count > 0:
                console.print(
                    "\n[bold red]⚠ Vulnerabilities detected! Review the results above.[/bold red]"
                )
            else:
                console.print(
                    "\n[bold green]✓ No vulnerabilities detected in basic tests.[/bold green]"
                )
                console.print(
                    "[dim]Note: These are basic tests. Manual security review is still recommended.[/dim]"
                )

        except FileNotFoundError as e:
            console.print(f"[bold red]Error:[/bold red] {str(e)}")
            raise typer.Exit(code=1)
        except ValueError as e:
            console.print(f"[bold red]Error:[/bold red] {str(e)}")
            raise typer.Exit(code=1)
        except Exception as e:
            console.print(f"[bold red]Unexpected error:[/bold red] {str(e)}")
            raise typer.Exit(code=1)

    # Run the async function
    asyncio.run(run_attacks())


@app.command()
def report(
    spec: str = typer.Option(..., "--spec", help="Path to OpenAPI spec file"),
    url: str = typer.Option(..., "--url", help="Base URL of the API to test"),
    token: str = typer.Option(None, "--token", help="Optional authentication token"),
    max_endpoints: int = typer.Option(None, "--max-endpoints", help="Maximum endpoints to test (default: all)"),
    output_dir: str = typer.Option("reports", "--output", help="Output directory for reports"),
    use_ai: bool = typer.Option(False, "--ai", help="Enable AI-powered attack planning"),
    agentic_ai: bool = typer.Option(False, "--agentic-ai", help="Enable agentic AI reasoning layer"),
    fail_on: str = typer.Option(None, "--fail-on", help="Fail build on severity level (critical/high/medium/low)"),
    report_sarif: str = typer.Option(None, "--report-sarif", help="Generate SARIF report for GitHub integration"),
    report_json: str = typer.Option(None, "--report-json", help="Generate JSON report"),
    report_html: str = typer.Option(None, "--report-html", help="Generate HTML report"),
    report_md: str = typer.Option(None, "--report-md", help="Generate Markdown report"),
):
    """Run security tests and generate comprehensive reports"""
    _run_security_scan(
        spec=spec,
        url=url,
        token=token,
        max_endpoints=max_endpoints,
        output_dir=output_dir,
        use_ai=use_ai,
        agentic_ai=agentic_ai,
        fail_on=fail_on,
        report_sarif=report_sarif,
        report_json=report_json,
        report_html=report_html,
        report_md=report_md
    )


@app.command()
def scan(
    spec: str = typer.Option(..., "--spec", help="Path to OpenAPI spec file"),
    url: str = typer.Option(..., "--url", help="Base URL of the API to test"),
    token: str = typer.Option(None, "--token", help="Optional authentication token"),
    max_endpoints: int = typer.Option(None, "--max-endpoints", help="Maximum endpoints to test (default: all)"),
    output_dir: str = typer.Option("reports", "--output", help="Output directory for reports"),
    use_ai: bool = typer.Option(False, "--ai", help="Enable AI-powered attack planning"),
    agentic_ai: bool = typer.Option(False, "--agentic-ai", help="Enable agentic AI reasoning layer"),
    fail_on: str = typer.Option(None, "--fail-on", help="Fail build on severity level (critical/high/medium/low)"),
    report_sarif: str = typer.Option(None, "--report-sarif", help="Generate SARIF report for GitHub integration"),
    report_json: str = typer.Option(None, "--report-json", help="Generate JSON report"),
    report_html: str = typer.Option(None, "--report-html", help="Generate HTML report"),
    report_md: str = typer.Option(None, "--report-md", help="Generate Markdown report"),
):
    """Run security scan (alias for report command)"""
    _run_security_scan(
        spec=spec,
        url=url,
        token=token,
        max_endpoints=max_endpoints,
        output_dir=output_dir,
        use_ai=use_ai,
        agentic_ai=agentic_ai,
        fail_on=fail_on,
        report_sarif=report_sarif,
        report_json=report_json,
        report_html=report_html,
        report_md=report_md
    )


def _run_security_scan(
    spec: str,
    url: str,
    token: str = None,
    max_endpoints: int = None,
    output_dir: str = "reports",
    use_ai: bool = False,
    agentic_ai: bool = False,
    fail_on: str = None,
    report_sarif: str = None,
    report_json: str = None,
    report_html: str = None,
    report_md: str = None,
):
    """Run security tests and generate comprehensive reports"""
    from rico.services.scan_service import run_scan
    from pathlib import Path
    
    # Display warning
    console.print("\n[bold yellow]⚠ WARNING: Security Testing Tool[/bold yellow]")
    console.print("[yellow]Only run these tests on APIs you own or have explicit permission to test.[/yellow]")
    console.print("[yellow]Unauthorized security testing may be illegal.[/yellow]\n")
    
    # Prepare report formats
    report_formats = {}
    if report_json:
        report_formats["json"] = report_json
    if report_html:
        report_formats["html"] = report_html
    if report_md:
        report_formats["md"] = report_md
    if report_sarif:
        report_formats["sarif"] = report_sarif
    
    # If no specific formats requested, use defaults
    if not report_formats:
        output_path = Path(output_dir)
        report_formats = {
            "html": str(output_path / "report.html"),
            "md": str(output_path / "report.md")
        }
    
    try:
        console.print(f"[cyan]Starting security scan...[/cyan]")
        console.print(f"[cyan]Target:[/cyan] {url}")
        console.print(f"[cyan]Spec:[/cyan] {spec}\n")
        
        # Run scan using service layer
        result = run_scan(
            spec_path=spec,
            base_url=url,
            token=token,
            max_endpoints=max_endpoints,
            use_ai=use_ai,
            use_agentic_ai=agentic_ai,
            output_dir=output_dir,
            report_formats=report_formats
        )
        
        # Display results
        console.print(f"\n[bold]Scan Complete![/bold]")
        console.print(f"[cyan]Scan ID:[/cyan] {result['scan_id']}")
        console.print(f"[cyan]Duration:[/cyan] {result['duration']:.2f}s")
        console.print(f"[cyan]Endpoints Tested:[/cyan] {result['endpoints_tested']}/{result['total_endpoints']}")
        
        # Display security metrics
        risk_color = "green" if result['risk_level'] == "LOW" else "yellow" if result['risk_level'] == "MEDIUM" else "red"
        console.print(f"\n[bold]Security Score:[/bold] {result['security_score']}/100")
        console.print(f"[bold {risk_color}]Risk Level:[/bold {risk_color}] {result['risk_level']}")
        console.print(f"[bold]Total Vulnerabilities:[/bold] {result['total_vulnerabilities']}")
        
        # Display severity distribution
        if result['total_vulnerabilities'] > 0:
            console.print(f"\n[bold]Severity Distribution:[/bold]")
            dist = result['severity_distribution']
            if dist.get('Critical', 0) > 0:
                console.print(f"  [red]Critical:[/red] {dist['Critical']}")
            if dist.get('High', 0) > 0:
                console.print(f"  [yellow]High:[/yellow] {dist['High']}")
            if dist.get('Medium', 0) > 0:
                console.print(f"  [yellow]Medium:[/yellow] {dist['Medium']}")
            if dist.get('Low', 0) > 0:
                console.print(f"  [blue]Low:[/blue] {dist['Low']}")
        
        console.print(f"\n[bold]Top Issue:[/bold] {result['top_issue']}")
        
        # Display generated reports
        console.print(f"\n[cyan]Generated Reports:[/cyan]")
        for format_type, filepath in report_formats.items():
            console.print(f"  [green]✓[/green] {format_type.upper()}: {filepath}")
        
        # Pipeline enforcement
        if fail_on:
            from rico.cicd.pipeline_enforcer import PipelineEnforcer
            
            console.print(f"\n[cyan]Checking pipeline policy: --fail-on {fail_on}[/cyan]")
            
            try:
                enforcer = PipelineEnforcer(fail_on)
                enforcer.enforce(result['vulnerabilities'], console=console)
            except ValueError as e:
                console.print(f"[bold red]Error:[/bold red] {str(e)}")
                raise typer.Exit(code=1)
        
        if result['total_vulnerabilities'] > 0:
            console.print("\n[bold red]⚠ Vulnerabilities detected! Review the reports for details.[/bold red]")
        else:
            console.print("\n[bold green]✓ No vulnerabilities detected in basic tests.[/bold green]")
            console.print("[dim]Note: These are basic tests. Manual security review is still recommended.[/dim]")
    
    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        raise typer.Exit(code=1)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]Unexpected error:[/bold red] {str(e)}")
        import traceback
        traceback.print_exc()
        raise typer.Exit(code=1)
    
    async def run_tests_and_generate_reports():
        import time
        from rico.db.snowflake_client import is_snowflake_enabled
        from rico.db.insert import insert_scan
        from rico.attacks.adaptive import create_adaptive_engine
        
        scan_start_time = time.time()
        scan_id = None
        adaptive_engine = None
        api_framework = "Unknown"
        
        # Initialize Snowflake integration if enabled
        if is_snowflake_enabled():
            console.print("[blue]❄️  Snowflake Intelligence Warehouse enabled[/blue]")
            
            # Determine API framework early
            if spec and url:
                if "fastapi" in spec.lower() or "fastapi" in url.lower():
                    api_framework = "FastAPI"
                elif "flask" in spec.lower() or "flask" in url.lower():
                    api_framework = "Flask"
                elif "express" in spec.lower():
                    api_framework = "Express"
            
            # Create scan_id early so we can use it for payload logging
            import uuid
            scan_id = str(uuid.uuid4())
            adaptive_engine = create_adaptive_engine(scan_id)
        else:
            console.print("[dim]Snowflake integration disabled (no credentials)[/dim]")
        
        try:
            # Parse the OpenAPI spec
            console.print(f"[cyan]Parsing OpenAPI spec:[/cyan] {spec}")
            endpoints = parse_openapi(spec)
            
            if not endpoints:
                console.print("[yellow]No endpoints found in the specification[/yellow]")
                return
            
            # Display total endpoints found
            total_endpoints = len(endpoints)
            console.print(
                f"[cyan]Found {total_endpoints} endpoint(s) in specification[/cyan]"
            )
            
            # Limit number of endpoints if specified
            if max_endpoints is not None and max_endpoints > 0:
                endpoints = endpoints[:max_endpoints]
                console.print(
                    f"[yellow]Limiting to {len(endpoints)} endpoint(s) (--max-endpoints={max_endpoints})[/yellow]"
                )
            
            console.print(f"[cyan]Testing {len(endpoints)} endpoint(s) against:[/cyan] {url}\n")
            
            if use_ai:
                # Load AI config and show provider
                ai_config = load_ai_config()
                provider_name = get_provider_name(ai_config)
                
                if provider_name:
                    console.print(f"[blue]🤖 AI-powered attack planning enabled[/blue]")
                    console.print(f"[blue]Using AI Provider: {provider_name}[/blue]")
                    
                    # Show API key info (masked)
                    if ai_config.get("groq_key"):
                        key = ai_config["groq_key"]
                        console.print(f"[dim]GROQ API Key: {key[:10]}...{key[-4:]}[/dim]")
                    elif ai_config.get("openai_key"):
                        key = ai_config["openai_key"]
                        console.print(f"[dim]OpenAI API Key: {key[:10]}...{key[-4:]}[/dim]")
                    elif ai_config.get("anthropic_key"):
                        key = ai_config["anthropic_key"]
                        console.print(f"[dim]Anthropic API Key: {key[:10]}...{key[-4:]}[/dim]")
                    
                    console.print()
                else:
                    console.print("[yellow]⚠ No AI API key found - using heuristic rules[/yellow]\n")
            
            # Display enumeration summary
            console.print("[bold cyan]Endpoint Enumeration Summary[/bold cyan]")
            console.print(f"Total endpoints to test: [bold]{len(endpoints)}[/bold]")
            
            # Show first 10 endpoints as preview
            console.print("\n[dim]Endpoints to be tested:[/dim]")
            for idx, ep in enumerate(endpoints[:10], 1):
                console.print(f"[dim]  {idx}. {ep.method} {ep.path}[/dim]")
            if len(endpoints) > 10:
                console.print(f"[dim]  ... and {len(endpoints) - 10} more[/dim]")
            console.print()
            
            all_results = []
            
            # Initialize payload logging for Snowflake
            payload_logger = None
            if adaptive_engine and scan_id:
                # Create a simple payload logger
                def log_payload(vuln_type, payload, endpoint_path, response_code, response_time, success):
                    try:
                        adaptive_engine.log_payload_result(
                            vulnerability_type=vuln_type,
                            payload=payload,
                            endpoint_path=endpoint_path,
                            response_code=response_code,
                            response_time_ms=response_time * 1000,  # Convert to ms
                            response_text="",
                            exploit_success=success,
                            api_framework=api_framework if 'api_framework' in locals() else "Unknown",
                            auth_type="JWT" if token else "None"
                        )
                    except Exception as e:
                        pass  # Silent fail for logging
                
                payload_logger = log_payload
            
            # Test each endpoint
            for idx, endpoint in enumerate(endpoints, 1):
                console.print(f"[cyan]Testing {idx}/{len(endpoints)}:[/cyan] [bold]{endpoint.method} {endpoint.path}[/bold]")
                
                # AI Classification and Planning
                attacks_to_run = ["IDOR", "Missing Auth", "SQL Injection"]
                classification = None
                
                if use_ai:
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
                        console.print(f"[dim]  AI Classification: {classification['type']} ({classification['sensitivity']} sensitivity)[/dim]")
                        console.print(f"[dim]  Planned attacks: {', '.join(attacks_to_run)}[/dim]")
                    except Exception as e:
                        console.print(f"[yellow]  AI planning failed, using default tests: {str(e)}[/yellow]")
                
                # Run selected attack tests
                try:
                    # IDOR Test
                    if "IDOR" in attacks_to_run:
                        idor_result = await test_idor(
                            endpoint=endpoint.path,
                            base_url=url,
                            method=endpoint.method
                        )
                        
                        # Log payload if Snowflake enabled
                        if payload_logger and scan_id:
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
                            base_url=url,
                            method=endpoint.method,
                            token=token
                        )
                        
                        # Log payload if Snowflake enabled
                        if payload_logger and scan_id:
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
                            base_url=url,
                            method=endpoint.method,
                            parameters=endpoint.parameters
                        )
                        
                        # Log payload if Snowflake enabled
                        if payload_logger and scan_id:
                            # Log the SQL injection attempt
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
                    
                except Exception as e:
                    console.print(f"[red]Error testing {endpoint.path}: {str(e)}[/red]")
                    continue
            
            # Display results table
            console.print("\n")
            table = create_results_table(all_results, show_reasoning=use_ai)
            console.print(table)
            
            # Summary
            vulnerable_count = sum(1 for r in all_results if r.get("vulnerable", False))
            total_tests = len(all_results)
            
            console.print(f"\n[bold]Summary:[/bold]")
            console.print(f"Total tests: {total_tests}")
            console.print(f"Vulnerabilities found: [red]{vulnerable_count}[/red]")
            console.print(f"Safe: [green]{total_tests - vulnerable_count}[/green]")
            
            # Calculate scan duration
            scan_duration = time.time() - scan_start_time
            
            # Generate reports
            console.print(f"\n[cyan]Generating reports...[/cyan]")
            
            # Convert results to report items
            report_items = convert_results_to_report_items(all_results, url, token)
            
            # Compute security score
            from rico.reporter.report_builder import compute_security_score, find_top_issue
            security_score, risk_level = compute_security_score(report_items)
            top_issue = find_top_issue(report_items)
            
            # Create output directory
            from pathlib import Path
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Generate Markdown report
            md_path = report_md if report_md else output_path / "report.md"
            generate_markdown_report(report_items, url, str(md_path))
            console.print(f"[green]✓[/green] Markdown report: {md_path}")
            
            # Generate HTML report
            html_path = report_html if report_html else output_path / "report.html"
            generate_html_report(report_items, url, str(html_path))
            console.print(f"[green]✓[/green] HTML report: {html_path}")
            
            # Generate JSON report if requested
            if report_json:
                from rico.reporting.report_builder import ReportBuilder
                from datetime import datetime
                
                # Convert report items to vulnerability format
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
                    "target_url": url,
                    "scan_timestamp": datetime.utcnow().isoformat()
                }
                
                builder = ReportBuilder(vulnerabilities, metadata)
                builder.export_json(report_json)
                console.print(f"[green]✓[/green] JSON report: {report_json}")
            
            # Generate SARIF report if requested
            if report_sarif:
                from rico.cicd.sarif_exporter import SARIFExporter
                from datetime import datetime
                
                console.print(f"[cyan]Generating SARIF report for GitHub integration...[/cyan]")
                
                # Convert report items to vulnerability format for SARIF
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
                    filepath=report_sarif,
                    vulnerabilities=vulnerabilities,
                    target_url=url,
                    scan_timestamp=datetime.utcnow().isoformat() + "Z"
                )
                console.print(f"[green]✓[/green] SARIF report: {report_sarif}")
            
            console.print(f"\n[bold green]Reports generated successfully![/bold green]")
            console.print(f"[dim]Open {html_path} in your browser to view the interactive report.[/dim]")
            
            # Display security score
            risk_color = "green" if risk_level == "LOW" else "yellow" if risk_level == "MEDIUM" else "red"
            console.print(f"\n[bold]Security Score:[/bold] {security_score}/100")
            console.print(f"[bold {risk_color}]Risk Level:[/bold {risk_color}] {risk_level}")
            console.print(f"[bold]Top Issue:[/bold] {top_issue}")
            
            # Store scan results in Snowflake
            if is_snowflake_enabled():
                console.print("\n[blue]❄️  Storing scan results in Snowflake...[/blue]")
                try:
                    # Determine API framework from spec or URL
                    api_framework = "Unknown"
                    if "fastapi" in spec.lower() or "fastapi" in url.lower():
                        api_framework = "FastAPI"
                    elif "flask" in spec.lower() or "flask" in url.lower():
                        api_framework = "Flask"
                    elif "express" in spec.lower():
                        api_framework = "Express"
                    
                    # Insert scan record
                    scan_id = insert_scan({
                        "api_name": url.split("//")[-1].split("/")[0],
                        "api_base_url": url,
                        "framework": api_framework,
                        "total_endpoints": len(endpoints),
                        "total_vulnerabilities": vulnerable_count,
                        "risk_score": security_score,
                        "scan_duration_seconds": scan_duration
                    })
                    
                    if scan_id:
                        console.print(f"[green]✓[/green] Scan stored in Snowflake: {scan_id[:8]}...")
                        console.print(f"[dim]Logged {total_tests} payload attempts[/dim]")
                        
                        # Store vulnerabilities
                        from rico.db.insert import insert_vulnerability
                        vuln_stored = 0
                        for item in report_items:
                            if item.status in ["VULNERABLE", "SUSPICIOUS"]:
                                vuln_id = insert_vulnerability({
                                    "scan_id": scan_id,
                                    "endpoint_path": item.endpoint,
                                    "vulnerability_type": item.attack_type,
                                    "severity": item.severity,
                                    "confidence": item.confidence,
                                    "cvss_score": item.cvss_score,
                                    "description": item.description,
                                    "poc_curl": item.poc_curl or "",
                                    "fix_suggestion": item.fix_suggestion or ""
                                })
                                if vuln_id:
                                    vuln_stored += 1
                        
                        if vuln_stored > 0:
                            console.print(f"[green]✓[/green] Stored {vuln_stored} vulnerability/vulnerabilities")
                        
                        console.print("[dim]Intelligence will be used in future scans[/dim]")
                    else:
                        console.print("[yellow]⚠ Failed to store scan in Snowflake[/yellow]")
                        
                except Exception as e:
                    console.print(f"[yellow]⚠ Snowflake storage failed: {str(e)}[/yellow]")
                    console.print("[dim]Continuing without Snowflake integration[/dim]")
            
            # Agentic AI Analysis
            if agentic_ai:
                console.print("\n[bold cyan]🤖 Running Agentic AI Analysis...[/bold cyan]")
                
                try:
                    from rico.ai.groq_client import GroqClient
                    from rico.ai.agent import RicoAgent
                    import os
                    
                    # Check for API key
                    api_key = os.getenv("GROQ_API_KEY")
                    if not api_key:
                        console.print("[bold red]Error:[/bold red] GROQ_API_KEY environment variable not set")
                        console.print("[yellow]Set it with: export GROQ_API_KEY=your_key (Linux/Mac) or setx GROQ_API_KEY \"your_key\" (Windows)[/yellow]")
                    else:
                        # Initialize AI client and agent
                        groq_client = GroqClient(api_key=api_key)
                        agent = RicoAgent(groq_client=groq_client)
                        
                        # Prepare scan results for AI analysis
                        scan_results = {
                            "target_url": url,
                            "total_endpoints": len(endpoints),
                            "security_score": security_score,
                            "risk_level": risk_level,
                            "vulnerabilities": [item.to_dict() for item in report_items if item.status in ["VULNERABLE", "SUSPICIOUS"]],
                            "endpoints_tested": [{"method": ep.method, "path": ep.path} for ep in endpoints]
                        }
                        
                        # Run AI analysis
                        ai_analysis = await agent.analyze_scan(scan_results)
                        
                        # Display AI analysis
                        console.print("\n")
                        analysis_text = agent.format_analysis_for_display(ai_analysis)
                        console.print(analysis_text)
                        
                        # Save AI analysis to file
                        import json
                        ai_analysis_path = output_path / "agentic_analysis.json"
                        with open(ai_analysis_path, 'w', encoding='utf-8') as f:
                            json.dump(ai_analysis, f, indent=2)
                        
                        console.print(f"\n[green]✓[/green] Agentic AI analysis saved: {ai_analysis_path}")
                        
                except ImportError as e:
                    console.print(f"[bold red]Error:[/bold red] Failed to import AI modules: {str(e)}")
                except ValueError as e:
                    console.print(f"[bold red]AI Analysis Error:[/bold red] {str(e)}")
                except Exception as e:
                    console.print(f"[bold red]AI Analysis Failed:[/bold red] {str(e)}")
                    console.print("[yellow]Continuing without AI analysis...[/yellow]")
            
            if vulnerable_count > 0:
                console.print("\n[bold red]⚠ Vulnerabilities detected! Review the reports for details.[/bold red]")
            else:
                console.print("\n[bold green]✓ No vulnerabilities detected in basic tests.[/bold green]")
                console.print("[dim]Note: These are basic tests. Manual security review is still recommended.[/dim]")
            
            # Pipeline enforcement - MUST RUN LAST
            if fail_on:
                from rico.cicd.pipeline_enforcer import PipelineEnforcer
                
                console.print(f"\n[cyan]Checking pipeline policy: --fail-on {fail_on}[/cyan]")
                
                try:
                    # Convert report items to vulnerability format
                    vulnerabilities = []
                    for item in report_items:
                        if item.status in ["VULNERABLE", "SUSPICIOUS"]:
                            vuln = {
                                "type": item.attack_type,
                                "endpoint": item.endpoint,
                                "severity": item.severity,
                                "confidence": item.confidence,
                                "description": item.description
                            }
                            vulnerabilities.append(vuln)
                    
                    # Create enforcer and check
                    enforcer = PipelineEnforcer(fail_on)
                    enforcer.enforce(vulnerabilities, console=console)
                    
                except ValueError as e:
                    console.print(f"[bold red]Error:[/bold red] {str(e)}")
                    raise typer.Exit(code=1)
            
        except FileNotFoundError as e:
            console.print(f"[bold red]Error:[/bold red] {str(e)}")
            raise typer.Exit(code=1)
        except ValueError as e:
            console.print(f"[bold red]Error:[/bold red] {str(e)}")
            raise typer.Exit(code=1)
        except Exception as e:
            console.print(f"[bold red]Unexpected error:[/bold red] {str(e)}")
            import traceback
            traceback.print_exc()
            raise typer.Exit(code=1)

def main():
    app()


if __name__ == "__main__":
    main()
