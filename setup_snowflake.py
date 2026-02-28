#!/usr/bin/env python3
"""
Setup script for Snowflake integration with RICO.

This script:
1. Validates Snowflake credentials
2. Tests connection
3. Creates required tables and views
4. Displays setup status
"""
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

def main():
    """Main setup function."""
    console.print("\n[bold cyan]RICO Snowflake Integration Setup[/bold cyan]\n")
    
    # Load environment variables
    load_dotenv()
    
    # Check credentials
    console.print("[yellow]Step 1:[/yellow] Checking Snowflake credentials...")
    
    user = os.getenv("SNOWFLAKE_USER")
    password = os.getenv("SNOWFLAKE_PASSWORD")
    account = os.getenv("SNOWFLAKE_ACCOUNT")
    warehouse = os.getenv("SNOWFLAKE_WAREHOUSE")
    
    if not all([user, password, account, warehouse]):
        console.print("[bold red]✗ Missing Snowflake credentials![/bold red]\n")
        console.print("Please set the following environment variables in your .env file:")
        console.print("  - SNOWFLAKE_USER")
        console.print("  - SNOWFLAKE_PASSWORD")
        console.print("  - SNOWFLAKE_ACCOUNT")
        console.print("  - SNOWFLAKE_WAREHOUSE")
        console.print("\nExample .env file:")
        console.print(Panel("""SNOWFLAKE_USER=your_username
SNOWFLAKE_PASSWORD=your_password
SNOWFLAKE_ACCOUNT=DAAGYVQ-MX75757
SNOWFLAKE_WAREHOUSE=COMPUTE_WH""", title=".env", border_style="yellow"))
        sys.exit(1)
    
    console.print(f"[green]✓[/green] Credentials found")
    console.print(f"  Account: {account}")
    console.print(f"  User: {user}")
    console.print(f"  Warehouse: {warehouse}\n")
    
    # Test connection
    console.print("[yellow]Step 2:[/yellow] Testing Snowflake connection...")
    
    try:
        from rico.db.snowflake_client import test_connection
        
        if test_connection():
            console.print("[green]✓[/green] Connection successful!\n")
        else:
            console.print("[bold red]✗ Connection failed![/bold red]")
            console.print("Please check your credentials and network connection.")
            sys.exit(1)
            
    except ImportError as e:
        console.print(f"[bold red]✗ Import error:[/bold red] {e}")
        console.print("\nPlease install required dependencies:")
        console.print("  pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]✗ Connection error:[/bold red] {e}")
        sys.exit(1)
    
    # Create tables
    console.print("[yellow]Step 3:[/yellow] Creating Snowflake tables...")
    
    try:
        from rico.db.snowflake_client import get_connection
        
        # Read SQL setup file
        sql_file = Path(__file__).parent / "rico" / "db" / "setup_tables.sql"
        
        if not sql_file.exists():
            console.print(f"[bold red]✗ SQL file not found:[/bold red] {sql_file}")
            sys.exit(1)
        
        with open(sql_file, 'r') as f:
            sql_content = f.read()
        
        # Split into individual statements
        statements = [s.strip() for s in sql_content.split(';') if s.strip() and not s.strip().startswith('--')]
        
        conn = get_connection()
        cur = conn.cursor()
        
        created_tables = []
        created_views = []
        
        for statement in statements:
            if not statement:
                continue
                
            try:
                cur.execute(statement)
                
                # Track what was created
                if 'CREATE TABLE' in statement.upper():
                    table_name = statement.split('TABLE')[1].split('(')[0].strip().split()[0]
                    created_tables.append(table_name)
                elif 'CREATE OR REPLACE VIEW' in statement.upper():
                    view_name = statement.split('VIEW')[1].split('AS')[0].strip()
                    created_views.append(view_name)
                    
            except Exception as e:
                # Ignore "already exists" errors
                if "already exists" not in str(e).lower():
                    console.print(f"[yellow]Warning:[/yellow] {e}")
        
        conn.commit()
        cur.close()
        conn.close()
        
        console.print(f"[green]✓[/green] Tables and views created successfully!\n")
        
        # Display summary
        if created_tables:
            console.print("[bold]Tables:[/bold]")
            for table in created_tables:
                console.print(f"  • {table}")
            console.print()
        
        if created_views:
            console.print("[bold]Views:[/bold]")
            for view in created_views:
                console.print(f"  • {view}")
            console.print()
        
    except Exception as e:
        console.print(f"[bold red]✗ Table creation failed:[/bold red] {e}")
        sys.exit(1)
    
    # Display success message
    console.print(Panel.fit(
        "[bold green]✓ Snowflake Integration Setup Complete![/bold green]\n\n"
        "You can now use RICO with Snowflake intelligence:\n\n"
        "  [cyan]rico report --spec api.yaml --url http://localhost:8000[/cyan]\n\n"
        "The adaptive attack engine will automatically:\n"
        "  • Store scan results in Snowflake\n"
        "  • Learn from successful payloads\n"
        "  • Use Cortex LLM for advanced reasoning\n"
        "  • Generate adaptive attack payloads",
        title="Setup Complete",
        border_style="green"
    ))
    
    # Display next steps
    console.print("\n[bold]Next Steps:[/bold]")
    console.print("1. Run a security scan to populate the intelligence warehouse")
    console.print("2. View analytics in Snowflake:")
    console.print("   [dim]SELECT * FROM PAYLOAD_SUCCESS_RATES;[/dim]")
    console.print("3. Check scan history:")
    console.print("   [dim]SELECT * FROM SCAN_SUMMARY;[/dim]")
    console.print()


if __name__ == "__main__":
    main()
