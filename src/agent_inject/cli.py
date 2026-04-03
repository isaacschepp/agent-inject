# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""CLI entry point for agent-inject."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import re
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

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Target agent endpoint URL")],
    goal: Annotated[str, typer.Option("--goal", "-g", help="Injection objective")],
    attacks: Annotated[list[str] | None, typer.Option("--attack", "-a", help="Attack names to run")] = None,
    output: Annotated[Path, typer.Option("--output", "-o", help="Output JSON file")] = Path("results.json"),
    max_concurrent: Annotated[int, typer.Option("--concurrency", help="Max parallel sends")] = 5,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose output")] = False,
    env_file: Annotated[
        Path | None,
        typer.Option("--env-file", help="Path to .env file (not loaded from CWD by default)"),
    ] = None,
) -> None:
    """Run attack suite against target agent."""
    from agent_inject.config import warn_if_cwd_dotenv

    if env_file is not None and not env_file.is_file():
        console.print(f"[red]Error:[/red] env file not found: {env_file}")
        raise typer.Exit(code=1)

    warn_if_cwd_dotenv(env_file_provided=env_file is not None)

    try:
        asyncio.run(_async_scan(target, goal, attacks, output, max_concurrent, verbose))
    except KeyError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from None


async def _async_scan(
    target: str,
    goal: str,
    attack_names: list[str] | None,
    output: Path,
    max_concurrent: int,
    verbose: bool,
) -> None:
    """Async scan implementation."""
    from agent_inject.attacks.registry import get_all_attacks, get_attack
    from agent_inject.engine import run_scan
    from agent_inject.harness.adapters.rest import RestAdapter
    from agent_inject.scorers.base import BaseScorer, CanaryMatchScorer, SubstringMatchScorer

    # Resolve attacks
    if attack_names:
        resolved_attacks = [get_attack(name)() for name in attack_names]
    else:
        all_attacks = get_all_attacks()
        if not all_attacks:
            console.print(
                "[yellow]No attacks registered. Add YAML payloads to data/payloads/ or use --attack.[/yellow]"
            )
            return
        resolved_attacks = [cls() for cls in all_attacks.values()]

    if verbose:
        console.print(f"Target: {target}")
        console.print(f"Goal: {goal}")
        console.print(f"Attacks: {[a.name for a in resolved_attacks]}")
        console.print(f"Concurrency: {max_concurrent}")

    scorers: list[BaseScorer] = [CanaryMatchScorer(), SubstringMatchScorer()]

    async with RestAdapter(target) as adapter:
        result = await run_scan(
            adapter,
            attacks=resolved_attacks,
            scorers=scorers,
            goal=goal,
            max_concurrent=max_concurrent,
        )

    output.write_text(json.dumps(dataclasses.asdict(result), indent=2, default=str))  # noqa: ASYNC240
    console.print(
        f"[bold green]Scan complete:[/bold green] "
        f"{result.successful_attacks}/{result.total_payloads} successful "
        f"in {result.duration_seconds}s"
    )
    console.print(f"Results written to {output}")


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
