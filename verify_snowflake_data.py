#!/usr/bin/env python3
"""Quick script to verify data was stored in Snowflake."""
from rich.console import Console
from rich.table import Table
from dotenv import load_dotenv

console = Console()
load_dotenv()

def main():
    console.print("\n[bold cyan]Verifying Snowflake Data Storage[/bold cyan]\n")
    
    try:
        from rico.db.snowflake_client import get_connection
        
        conn = get_connection()
        cur = conn.cursor()
        
        # Check SCANS table
        console.print("[yellow]1. Checking SCANS table...[/yellow]")
        cur.execute("SELECT COUNT(*) FROM SCANS")
        scan_count = cur.fetchone()[0]
        console.print(f"   [green]✓[/green] Found {scan_count} scan(s)")
        
        if scan_count > 0:
            cur.execute("SELECT scan_id, api_name, total_endpoints, total_vulnerabilities, risk_score FROM SCANS ORDER BY scan_timestamp DESC LIMIT 1")
            row = cur.fetchone()
            console.print(f"   Latest scan: {row[1]} - {row[2]} endpoints, {row[3]} vulns, score: {row[4]}/100\n")
        
        # Check PAYLOAD_RESULTS table
        console.print("[yellow]2. Checking PAYLOAD_RESULTS table...[/yellow]")
        cur.execute("SELECT COUNT(*) FROM PAYLOAD_RESULTS")
        payload_count = cur.fetchone()[0]
        console.print(f"   [green]✓[/green] Found {payload_count} payload result(s)")
        
        if payload_count > 0:
            cur.execute("""
                SELECT vulnerability_type, COUNT(*) as count, 
                       SUM(CASE WHEN exploit_success = TRUE THEN 1 ELSE 0 END) as successful
                FROM PAYLOAD_RESULTS 
                GROUP BY vulnerability_type
            """)
            
            table = Table(title="Payload Statistics")
            table.add_column("Vulnerability Type", style="cyan")
            table.add_column("Total Attempts", style="yellow")
            table.add_column("Successful", style="green")
            
            for row in cur.fetchall():
                table.add_row(row[0], str(row[1]), str(row[2]))
            
            console.print(table)
            console.print()
        
        # Check VULNERABILITIES table
        console.print("[yellow]3. Checking VULNERABILITIES table...[/yellow]")
        cur.execute("SELECT COUNT(*) FROM VULNERABILITIES")
        vuln_count = cur.fetchone()[0]
        console.print(f"   [green]✓[/green] Found {vuln_count} vulnerability/vulnerabilities\n")
        
        cur.close()
        conn.close()
        
        console.print("[bold green]✓ Data successfully stored in Snowflake![/bold green]")
        console.print("\n[dim]You can now query this data in Snowflake SQL:[/dim]")
        console.print("[dim]  SELECT * FROM SCANS;[/dim]")
        console.print("[dim]  SELECT * FROM PAYLOAD_RESULTS;[/dim]")
        console.print("[dim]  SELECT * FROM PAYLOAD_SUCCESS_RATES;[/dim]")
        
    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")

if __name__ == "__main__":
    main()
