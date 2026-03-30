"""CLI entry point for agent-inject."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

app = typer.Typer(
    name="agent-inject",
    help="Offensive testing framework for AI agent systems.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Target agent endpoint or config file")],
    attacks: Annotated[list[str] | None, typer.Option("--attack", "-a", help="Attack modules to run")] = None,
    output: Annotated[Path, typer.Option("--output", "-o", help="Output file for results")] = Path("results.json"),
    config: Annotated[Path | None, typer.Option("--config", "-c", help="YAML config file")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose output")] = False,
) -> None:
    """Run attack suite against target agent."""
    console.print("[bold]agent-inject[/bold] v0.1.0")
    console.print(f"Target: {target}")
    console.print(f"Attacks: {attacks or 'all'}")
    console.print(f"Output: {output}")
    if config:
        console.print(f"Config: {config}")
    if verbose:
        console.print("Verbose mode enabled")


@app.command()
def list_attacks() -> None:
    """List all available attack modules."""
    from agent_inject.attacks.registry import get_all_attacks

    attacks = get_all_attacks()
    if not attacks:
        console.print("[dim]No attacks registered.[/dim]")
        return
    for name, cls in sorted(attacks.items()):
        console.print(f"  [bold]{name}[/bold] - {cls.__doc__ or 'No description'}")


@app.command()
def list_adapters() -> None:
    """List available target adapters."""
    console.print("[dim]No adapters registered yet.[/dim]")


@app.command()
def version() -> None:
    """Print version information."""
    from agent_inject import __version__

    console.print(f"agent-inject {__version__}")
