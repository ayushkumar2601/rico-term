# docs_cli.py
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

console = Console()

def show_docs():
    # Header panel
    console.print(Panel("[bold blue]RICO CLI[/bold blue]\nAutomated API Security Scanner", expand=False))

    # Description and synopsis
    console.print(Markdown("""
    # Synopsis
    rico [OPTIONS] COMMAND [ARGS]

    # Description
    RICO is a command-line interface for testing APIs for security vulnerabilities.
    It supports OpenAPI specifications, live API endpoints, AI-assisted scanning,
    and generates reports in markdown and HTML formats.
    """))

    # Global options table
    table_options = Table(title="Global Options")
    table_options.add_column("Option", style="cyan", no_wrap=True)
    table_options.add_column("Description", style="white")
    table_options.add_row("--install-completion", "Install shell completion for the current shell")
    table_options.add_row("--show-completion", "Show shell completion code")
    table_options.add_row("--help, -h", "Show help message and exit")
    console.print(table_options)

    # Commands table
    table_cmds = Table(title="Commands")
    table_cmds.add_column("Command", style="green", no_wrap=True)
    table_cmds.add_column("Description", style="white")
    table_cmds.add_row("init", "Initialize RICO for first-time use")
    table_cmds.add_row("version", "Display the current version")
    table_cmds.add_row("parse", "Parse an OpenAPI specification file")
    table_cmds.add_row("call", "Send individual API calls to test endpoints")
    table_cmds.add_row("attack", "Run automated security tests on endpoints")
    table_cmds.add_row("report", "Generate reports based on scans")
    console.print(table_cmds)

    # Command-specific options examples
    console.print(Markdown("""
    # Command Options

    ## parse
    --spec [path] : Path to OpenAPI spec file [required]
    --help : Show help for parse command

    ## call
    --url [url] : Base URL of the API [required]
    --method [HTTP method] : HTTP method to use (GET, POST, etc.)
    --token [auth token] : Authentication token if required
    --timeout [seconds] : Request timeout (default: 30.0)
    --help : Show help for call command

    ## attack
    --spec : OpenAPI spec file to use for attacks
    --url : Base URL of the API
    --token : Authentication token
    --max-endpoints : Maximum number of endpoints to test
    --ai : Enable AI-assisted testing
    --help : Show help for attack command

    ## report
    --spec : OpenAPI spec file used for scan
    --url : Base URL of the API
    --token : Authentication token
    --max-endpoints : Maximum number of endpoints included
    --output : Directory to save reports (default: ./reports)
    --ai : Enable AI-assisted report generation
    --agentic-ai : Enable agentic AI features
    --fail-on : Set severity threshold to fail build (low, medium, high, critical)
    --help : Show help for report command
    """))

    # Examples panel
    console.print(Panel("[bold yellow]Examples[/bold yellow]", expand=False))
    console.print(Markdown("""
    - Scan a local OpenAPI spec:
    rico attack --spec demo-api/openapi.yaml --url http://localhost:8000

    - Call a single endpoint:
    rico call --url http://localhost:8000/users --method GET --token ABC123

    - Generate reports:
    rico report --spec demo-api/openapi.yaml --url http://localhost:8000 --output ./reports
    """))

    # See also
    console.print(Markdown("""
    # See Also
    python(1), pip(1)
    """))

if __name__ == "__main__":
    show_docs()