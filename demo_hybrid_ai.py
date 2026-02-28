"""
Demo script for RICO Hybrid Adaptive Intelligence Architecture

Architecture:
- Snowflake: Security Intelligence Warehouse (storage + retrieval)
- AI Provider: LLM Reasoning Engine (Groq or Cortex)
  - Current: Groq (due to regional Cortex availability)
  - Future: Seamless migration to Snowflake Cortex

This demonstrates:
1. Snowflake stores historical payload intelligence
2. AI provider generates adaptive payloads based on historical success
3. Results are stored back in Snowflake for continuous learning
"""
import asyncio
import os
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rico.ai.adaptive_payloads import AdaptivePayloadGenerator
from rico.ai.provider import get_provider_info, log_provider_status
from rico.db.retrieve import get_top_successful_payloads, get_payload_statistics
from rico.db.snowflake_client import is_snowflake_enabled

console = Console()

load_dotenv()


async def demo_hybrid_intelligence():
    """Demonstrate hybrid adaptive intelligence architecture."""
    
    console.print("\n[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]  RICO Hybrid Adaptive Intelligence Demo                  [/bold cyan]")
    console.print("[bold cyan]  Snowflake Intelligence Warehouse + AI Reasoning Engine  [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]\n")
    
    # Display architecture configuration
    provider_info = get_provider_info()
    
    console.print("[bold]Architecture Configuration:[/bold]")
    console.print(f"  Intelligence Warehouse: [cyan]Snowflake[/cyan]")
    console.print(f"  Reasoning Engine: [cyan]{provider_info['reasoning_engine']}[/cyan]")
    console.print(f"  AI Provider: [cyan]{provider_info['provider']}[/cyan]")
    
    # Check Snowflake
    if not is_snowflake_enabled():
        console.print("\n[red]✗ Snowflake Intelligence Warehouse: NOT CONFIGURED[/red]")
        console.print("[yellow]Set SNOWFLAKE_USER, SNOWFLAKE_PASSWORD, SNOWFLAKE_ACCOUNT in .env[/yellow]\n")
        return
    
    console.print(f"  Snowflake Status: [green]ENABLED[/green]")
    
    # Check AI Provider
    if not provider_info['groq_configured'] and not provider_info['cortex_enabled']:
        console.print(f"  AI Provider Status: [red]NOT CONFIGURED[/red]")
        console.print("\n[yellow]Set GROQ_API_KEY in .env or enable Cortex[/yellow]\n")
        return
    
    console.print(f"  AI Provider Status: [green]ENABLED[/green]")
    
    # Display Cortex availability note
    if not provider_info['cortex_enabled']:
        console.print(f"  Cortex Available: [yellow]False (Region Restriction)[/yellow]")
        console.print(f"  [dim]Note: Using Groq as reasoning engine. Modular architecture[/dim]")
        console.print(f"  [dim]      allows seamless Cortex migration when available.[/dim]")
    
    console.print()
    
    # Initialize generator
    generator = AdaptivePayloadGenerator()
    
    # Demo 1: SQL Injection Intelligence
    console.print(Panel.fit(
        "[bold]Demo 1: SQL Injection Adaptive Payloads[/bold]",
        border_style="cyan"
    ))
    
    # Retrieve historical intelligence from Snowflake
    console.print("\n[cyan]Step 1:[/cyan] Retrieving historical intelligence from Snowflake...")
    historical_sqli = get_top_successful_payloads("SQL Injection", limit=5)
    stats_sqli = get_payload_statistics("SQL Injection")
    
    if historical_sqli:
        table = Table(title="Historical Successful SQL Injection Payloads", show_header=True)
        table.add_column("#", style="dim")
        table.add_column("Payload", style="yellow")
        
        for idx, payload in enumerate(historical_sqli, 1):
            table.add_row(str(idx), payload[:80] + "..." if len(payload) > 80 else payload)
        
        console.print(table)
        
        if stats_sqli:
            console.print(f"\n[dim]Statistics:[/dim]")
            console.print(f"  Total attempts: {stats_sqli.get('total_attempts', 0)}")
            console.print(f"  Successful: {stats_sqli.get('successful', 0)}")
            console.print(f"  Success rate: {stats_sqli.get('success_rate', 0)}%")
    else:
        console.print("[yellow]No historical SQL injection payloads found in Snowflake[/yellow]")
    
    # Generate adaptive payload using AI provider
    console.print(f"\n[cyan]Step 2:[/cyan] Generating adaptive payload using {provider_info['provider']}...")
    
    adaptive_sqli = generator.generate_adaptive_sqli_payload(
        api_framework="FastAPI",
        endpoint_context="GET /users/{id}"
    )
    
    if adaptive_sqli:
        console.print(Panel(
            f"[bold green]{adaptive_sqli}[/bold green]",
            title=f"[bold]{provider_info['provider']}-Generated Adaptive Payload[/bold]",
            border_style="green"
        ))
        console.print("[dim]This payload was generated by analyzing historical success patterns[/dim]")
    else:
        console.print("[yellow]Could not generate adaptive payload[/yellow]")
    
    # Demo 2: IDOR Intelligence
    console.print("\n\n" + "─" * 60 + "\n")
    console.print(Panel.fit(
        "[bold]Demo 2: IDOR Adaptive Strategy[/bold]",
        border_style="cyan"
    ))
    
    # Retrieve historical IDOR intelligence
    console.print("\n[cyan]Step 1:[/cyan] Retrieving historical IDOR patterns from Snowflake...")
    historical_idor = get_top_successful_payloads("IDOR", limit=5)
    stats_idor = get_payload_statistics("IDOR")
    
    if historical_idor:
        table = Table(title="Historical Successful IDOR Patterns", show_header=True)
        table.add_column("#", style="dim")
        table.add_column("Pattern", style="yellow")
        
        for idx, pattern in enumerate(historical_idor, 1):
            table.add_row(str(idx), pattern[:80] + "..." if len(pattern) > 80 else pattern)
        
        console.print(table)
        
        if stats_idor:
            console.print(f"\n[dim]Statistics:[/dim]")
            console.print(f"  Total attempts: {stats_idor.get('total_attempts', 0)}")
            console.print(f"  Successful: {stats_idor.get('successful', 0)}")
            console.print(f"  Success rate: {stats_idor.get('success_rate', 0)}%")
    else:
        console.print("[yellow]No historical IDOR patterns found in Snowflake[/yellow]")
    
    # Generate adaptive IDOR strategy using AI provider
    console.print(f"\n[cyan]Step 2:[/cyan] Generating adaptive IDOR strategy using {provider_info['provider']}...")
    
    adaptive_idor = generator.generate_adaptive_idor_payload(
        api_framework="FastAPI",
        endpoint_context="GET /users/{user_id}/orders"
    )
    
    if adaptive_idor:
        strategy_text = adaptive_idor.get("strategy", "N/A")
        test_ids = adaptive_idor.get("test_ids", [])
        
        console.print(Panel(
            f"[bold]Strategy:[/bold] {strategy_text}\n\n"
            f"[bold]Test IDs:[/bold] {', '.join(map(str, test_ids))}",
            title=f"[bold]{provider_info['provider']}-Generated IDOR Strategy[/bold]",
            border_style="green"
        ))
        console.print("[dim]This strategy was generated by analyzing historical IDOR success patterns[/dim]")
    else:
        console.print("[yellow]Could not generate adaptive IDOR strategy[/yellow]")
    
    # Summary
    console.print("\n\n" + "═" * 60)
    console.print("\n[bold green]✓ Hybrid Adaptive Intelligence Working![/bold green]\n")
    
    console.print("[bold]Architecture:[/bold]")
    console.print("  1. [cyan]Snowflake[/cyan] stores historical exploit intelligence")
    console.print(f"  2. [cyan]{provider_info['provider']}[/cyan] analyzes patterns and generates adaptive payloads")
    console.print("  3. [cyan]RICO[/cyan] executes payloads and stores results back in Snowflake")
    console.print("  4. [cyan]Continuous Learning[/cyan] - system improves over time\n")
    
    console.print("[bold]Design Principles:[/bold]")
    console.print("  • [cyan]Separation of Concerns[/cyan]: Snowflake = Storage, AI = Reasoning")
    console.print("  • [cyan]Modular Architecture[/cyan]: Easy provider switching via abstraction layer")
    console.print("  • [cyan]Future-Proof[/cyan]: Ready for Snowflake Cortex when available in region")
    console.print("  • [cyan]Production-Ready[/cyan]: Graceful degradation and error handling\n")
    
    console.print("[bold]Next Steps:[/bold]")
    console.print("  • Run scans to populate Snowflake with more intelligence")
    console.print("  • Adaptive payloads will automatically improve as data grows")
    console.print("  • Monitor success rates in Snowflake analytics")
    console.print("  • Seamlessly migrate to Cortex when available (set USE_CORTEX=true)\n")


if __name__ == "__main__":
    asyncio.run(demo_hybrid_intelligence())
