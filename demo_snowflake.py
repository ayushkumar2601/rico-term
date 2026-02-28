#!/usr/bin/env python3
"""
Demo script to showcase RICO Snowflake integration.

This script demonstrates:
1. Snowflake connection
2. Adaptive payload retrieval
3. Cortex LLM reasoning
4. Intelligence storage
"""
import asyncio
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from dotenv import load_dotenv

console = Console()

async def main():
    """Main demo function."""
    console.print("\n[bold cyan]RICO Snowflake Integration Demo[/bold cyan]\n")
    
    # Load environment
    load_dotenv()
    
    # Step 1: Test Connection
    console.print("[yellow]Step 1:[/yellow] Testing Snowflake connection...")
    
    try:
        from rico.db.snowflake_client import test_connection, is_snowflake_enabled
        
        if not is_snowflake_enabled():
            console.print("[bold red]✗ Snowflake credentials not configured![/bold red]")
            console.print("\nPlease set up your .env file with Snowflake credentials.")
            console.print("Run: [cyan]python setup_snowflake.py[/cyan]")
            return
        
        if test_connection():
            console.print("[green]✓[/green] Connected to Snowflake!\n")
        else:
            console.print("[bold red]✗ Connection failed![/bold red]")
            return
            
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")
        return
    
    # Step 2: Retrieve Historical Intelligence
    console.print("[yellow]Step 2:[/yellow] Retrieving historical payload intelligence...")
    
    try:
        from rico.db.retrieve import get_top_successful_payloads, get_payload_statistics
        
        # Get SQL injection payloads
        sqli_payloads = get_top_successful_payloads("SQL Injection", limit=5)
        
        if sqli_payloads:
            console.print(f"[green]✓[/green] Found {len(sqli_payloads)} successful SQL injection payloads")
            
            table = Table(title="Historical Successful Payloads")
            table.add_column("#", style="cyan")
            table.add_column("Payload", style="yellow")
            
            for idx, payload in enumerate(sqli_payloads, 1):
                table.add_row(str(idx), payload[:80] + "..." if len(payload) > 80 else payload)
            
            console.print(table)
            console.print()
            
            # Get statistics
            stats = get_payload_statistics("SQL Injection")
            console.print(f"[dim]Total attempts: {stats.get('total_attempts', 0)}[/dim]")
            console.print(f"[dim]Successful: {stats.get('successful', 0)}[/dim]")
            console.print(f"[dim]Success rate: {stats.get('success_rate', 0)}%[/dim]\n")
        else:
            console.print("[yellow]No historical payloads found (database empty)[/yellow]")
            console.print("[dim]Run a scan first to populate intelligence[/dim]\n")
            
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] {e}\n")
    
    # Step 3: Cortex LLM Demo
    console.print("[yellow]Step 3:[/yellow] Testing Snowflake Cortex LLM...")
    
    try:
        from rico.ai.cortex import cortex_complete
        
        prompt = """You are a cybersecurity expert. In one sentence, explain what SQL injection is."""
        
        console.print("[dim]Sending prompt to Cortex...[/dim]")
        response = cortex_complete(prompt, model="llama3-70b", max_tokens=100)
        
        if response:
            console.print("[green]✓[/green] Cortex LLM response received!")
            console.print(Panel(response, title="Cortex Response", border_style="cyan"))
            console.print()
        else:
            console.print("[yellow]Cortex LLM not available or failed[/yellow]\n")
            
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] {e}\n")
    
    # Step 4: Adaptive Engine Demo
    console.print("[yellow]Step 4:[/yellow] Testing Adaptive Attack Engine...")
    
    try:
        from rico.attacks.adaptive import AdaptiveAttackEngine
        
        engine = AdaptiveAttackEngine(scan_id="demo-scan-001")
        
        # Get adaptive payloads
        console.print("[dim]Generating adaptive payloads...[/dim]")
        payloads = engine.get_adaptive_payloads(
            vulnerability_type="SQL Injection",
            endpoint_path="/api/search",
            api_framework="FastAPI",
            base_payloads=["' OR '1'='1", "' UNION SELECT NULL--"]
        )
        
        if payloads:
            console.print(f"[green]✓[/green] Generated {len(payloads)} adaptive payloads")
            
            table = Table(title="Adaptive Payloads")
            table.add_column("#", style="cyan")
            table.add_column("Payload", style="yellow")
            table.add_column("Source", style="green")
            
            for idx, payload in enumerate(payloads[:5], 1):
                source = "Cortex AI" if idx == 1 else "Historical" if idx <= 3 else "Base"
                table.add_row(str(idx), payload[:80] + "..." if len(payload) > 80 else payload, source)
            
            console.print(table)
            console.print()
        else:
            console.print("[yellow]Using base payloads only[/yellow]\n")
            
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] {e}\n")
    
    # Step 5: Query Analytics
    console.print("[yellow]Step 5:[/yellow] Querying scan analytics...")
    
    try:
        from rico.db.retrieve import get_scan_history
        
        scans = get_scan_history("http://localhost:8000", limit=5)
        
        if scans:
            console.print(f"[green]✓[/green] Found {len(scans)} previous scans")
            
            table = Table(title="Scan History")
            table.add_column("Date", style="cyan")
            table.add_column("API", style="yellow")
            table.add_column("Endpoints", style="green")
            table.add_column("Vulns", style="red")
            table.add_column("Risk Score", style="magenta")
            
            for scan in scans:
                table.add_row(
                    scan['timestamp'][:19],
                    scan['api_name'],
                    str(scan['total_endpoints']),
                    str(scan['total_vulnerabilities']),
                    f"{scan['risk_score']}/100"
                )
            
            console.print(table)
            console.print()
        else:
            console.print("[yellow]No scan history found[/yellow]\n")
            
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] {e}\n")
    
    # Summary
    console.print(Panel.fit(
        "[bold green]✓ Snowflake Integration Demo Complete![/bold green]\n\n"
        "The adaptive attack engine is ready to:\n"
        "  • Learn from historical successful payloads\n"
        "  • Generate advanced attacks with Cortex LLM\n"
        "  • Store intelligence for future scans\n"
        "  • Provide analytics and insights\n\n"
        "Run a real scan:\n"
        "  [cyan]rico report --spec demo-api/openapi.yaml --url http://localhost:8000[/cyan]",
        title="Demo Complete",
        border_style="green"
    ))


if __name__ == "__main__":
    asyncio.run(main())
