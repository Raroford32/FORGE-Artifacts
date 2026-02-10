FORGE = """
[bold gold3]
 ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
 ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
 █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
 ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
 ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
 ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
[/bold gold3]"""

import os
import click
import dotenv
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from loguru import logger

from extractor.extract_processor import ExtractProcessor
from classifier.map_processor import ClassifyProcessor
from fetcher.fetch_processor import FetchProcessor
from builder.build_processor import BuildProcessor
from discovery.discovery_processor import DiscoveryProcessor

from core.invoker import *

console = Console()

TAGLINE = "[green]Automating the Foundation of Smart Contract Research[/green]"


def display_header():
    """Display the FORGE ASCII art and tagline"""
    console.print(Panel(f"{FORGE}", border_style="yellow", expand=False))


def common_options(function):
    """Common options for all commands"""
    function = click.option(
        "--log", "-l", help="Path to the log directory", default="logs"
    )(function)
    function = click.option(
        "--config", "-c", help="Path to the config.yaml", default="config.yaml"
    )(function)
    return function


@click.group(invoke_without_command=True)
@click.pass_context
@common_options
def cli(ctx, log, config):
    """FORGE: Automated Smart Contract Vulnerability Dataset Builder"""
    display_header()

    if ctx.invoked_subcommand is None:
        # If no subcommand is provided, show help
        console.print("[bold]Available Commands:[/bold]")
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Command")
        table.add_column("Description")

        table.add_row(
            "extract", "Extract vulnerability and project info from security docs"
        )
        table.add_row("classify", "Classify vulnerabilities to CWE categories")
        table.add_row("fetch", "Fetch source code from extracted JSON")
        table.add_row(
            "forge", "Complete pipeline: FORGE dataset from security documents"
        )
        table.add_row(
            "discover",
            "Generate 0-day discovery prompts & guides from smart contracts",
        )

        console.print(table)
        console.print(
            "\nRun [bold cyan]python main.py COMMAND --help[/bold cyan] for command-specific help."
        )


@cli.command()
@click.option(
    "--target", "-t", required=True, help="Path to security document file or directory"
)
@click.option(
    "--output", "-o", required=False, help="Path to output directory", default="."
)
@common_options
def extract(target, output, log, config):
    """Extract vulnerability and project info from security documents"""
    console.print(f"[bold green]Extracting[/bold green] from {target} to {output}")

    extract_processor = ExtractProcessor("extract", target, output, log, config)
    extract_processor.run()


@cli.command()
@click.option(
    "--target",
    "-t",
    required=True,
    help="Path to JSON Formatted file or directory containing vuln_findings JSON files.",
)
@click.option(
    "--output",
    "-o",
    required=False,
    help="Path to output directory, default overwrite if not provided",
    default="!<OVERWRITE>!",
)
@common_options
def classify(target, output, log, config):
    """classify vulnerabilities to CWE categories"""
    console.print(
        f"[bold green]classifying[/bold green] vulnerabilities from {target} to {output}"
    )
    if output == "!<OVERWRITE>!":
        output = os.path.dirname(target)
    classify_processor = ClassifyProcessor("classify", target, output, log, config)
    classify_processor.run()


@cli.command()
@click.option(
    "--target",
    "-t",
    required=True,
    help="Path to JSON Formatted file or directory containing project_info JSON files.",
)
@click.option(
    "--output",
    "-o",
    required=False,
    help="Path to output directory, default overwrite if not provided",
    default="!<OVERWRITE>!",
)
@common_options
def fetch(target, output, log, config):
    """Fetch source code from extracted JSON"""
    console.print(f"[bold green]Fetching[/bold green] source code from {target}")
    if output == "!<OVERWRITE>!":
        output = os.path.dirname(target)
    fetch_processor = FetchProcessor("fetch", target, output, log, config)
    fetch_processor.run()


@cli.command()
@click.option(
    "--target",
    "-t",
    required=True,
    help="Target path to directory containing security docs",
)
@click.option("--output", "-o", required=True, help="Path to output directory")
@common_options
def forge(target, output, log, config):
    """Complete pipeline: forge dataset from security documents"""
    console.print(
        f"[bold green]Forging[/bold green] complete dataset from {target} to {output}"
    )
    build_processor = BuildProcessor("forge", target, output, log, config)
    build_processor.run()
    # Your extract_then_classify implementation here


def _detect_default_target():
    """Same pattern as access_reports.ipynb: data is expected to already be there."""
    for candidate in [
        os.path.join("..", "dataset", "results"),
        os.path.join("dataset", "results"),
    ]:
        if os.path.isdir(candidate):
            return candidate
    return None


@cli.command()
@click.option(
    "--target",
    "-t",
    required=False,
    default=None,
    help=(
        "FORGE JSON, directory of JSONs, .sol file/dir, or audit doc. "
        "Defaults to dataset/results/ when available."
    ),
)
@click.option(
    "--output",
    "-o",
    required=False,
    default="discovery_output",
    help="Output directory (default: discovery_output/)",
)
@common_options
def discover(target, output, log, config):
    """Generate 0-day discovery prompts and investigation guides.

    Works exactly like the forge command — point at the data and run.
    When no target is given, uses dataset/results/ automatically.

    \b
    Typical usage (just configure .env with API_KEY, then):
      python main.py discover
      python main.py discover -t dataset/results/project.pdf.json
      python main.py discover -t audit_report.pdf -o output/
    """
    if target is None:
        target = _detect_default_target()
        if target is None:
            console.print(
                "[bold red]No target specified and dataset/results/ not found.[/bold red]\n"
                "Provide a target with -t or ensure dataset/results/ exists."
            )
            return
        console.print(f"[cyan]Auto-detected target:[/cyan] {target}")

    console.print(
        Panel(
            f"[bold red]0-Day Discovery Pipeline[/bold red]\n"
            f"Target: {target}\n"
            f"Output: {output}",
            border_style="red",
            expand=False,
        )
    )
    console.print(
        "[yellow]Stages: Decompose -> Attack Surface -> Hypothesize -> Synthesize Prompts[/yellow]"
    )
    discovery_processor = DiscoveryProcessor("discover", target, output, log, config)
    discovery_processor.run()
    console.print(
        f"[bold green]Discovery report(s) written to {output}[/bold green]"
    )


if __name__ == "__main__":
    cli()
