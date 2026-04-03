# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""CLI entry point for agent-inject."""

from __future__ import annotations

import asyncio
import dataclasses
import json
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer
from rich.console import Console

if TYPE_CHECKING:
    from agent_inject.config import AgentInjectConfig
    from agent_inject.harness.base import BaseAdapter
    from agent_inject.scorers.base import BaseScorer

app = typer.Typer(
    name="agent-inject",
    help="Offensive testing framework for AI agent systems.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Target agent endpoint URL")],
    goal: Annotated[str, typer.Option("--goal", "-g", help="Injection objective")],
    attacks: Annotated[list[str] | None, typer.Option("--attack", "-a", help="Attack names to run")] = None,
    output: Annotated[Path, typer.Option("--output", "-o", help="Output JSON file")] = Path("results.json"),
    max_concurrent: Annotated[int | None, typer.Option("--concurrency", help="Max parallel sends")] = None,
    timeout: Annotated[float | None, typer.Option("--timeout", help="Request timeout in seconds")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose output")] = False,
    env_file: Annotated[
        Path | None,
        typer.Option("--env-file", help="Path to .env file (not loaded from CWD by default)"),
    ] = None,
) -> None:
    """Run attack suite against target agent."""
    from agent_inject.config import AgentInjectConfig, warn_if_cwd_dotenv

    if env_file is not None and not env_file.is_file():
        console.print(f"[red]Error:[/red] env file not found: {env_file}")
        raise typer.Exit(code=1)

    warn_if_cwd_dotenv(env_file_provided=env_file is not None)

    # Build config: CLI args > env vars > defaults.
    # Only pass CLI params that were explicitly provided so env vars can fill the rest.
    overrides: dict[str, Any] = {"target_url": target, "verbose": verbose}
    if max_concurrent is not None:
        overrides["max_concurrent"] = max_concurrent
    if timeout is not None:
        overrides["timeout_seconds"] = timeout

    config = AgentInjectConfig(**overrides, _env_file=env_file)  # pyright: ignore[reportCallIssue]

    try:
        asyncio.run(_async_scan(config, goal, attacks, output))
    except KeyError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from None


async def _async_scan(
    config: AgentInjectConfig,
    goal: str,
    attack_names: list[str] | None,
    output: Path,
) -> None:
    """Async scan implementation."""
    from agent_inject.attacks.registry import get_all_attacks, get_attack
    from agent_inject.engine import run_scan

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

    if config.verbose:
        console.print(f"Target: {config.target_url}")
        console.print(f"Adapter: {config.target_adapter}")
        console.print(f"Goal: {goal}")
        console.print(f"Attacks: {[a.name for a in resolved_attacks]}")
        console.print(f"Timeout: {config.timeout_seconds}s")
        console.print(f"Concurrency: {config.max_concurrent}")
        console.print(f"Canary threshold: {config.canary_match_threshold}")

    adapter = _create_adapter(config)
    scorers = _create_scorers(config)

    async with adapter:
        result = await run_scan(
            adapter,
            attacks=resolved_attacks,
            scorers=scorers,
            goal=goal,
            max_concurrent=config.max_concurrent,
        )

    output.write_text(json.dumps(dataclasses.asdict(result), indent=2, default=str))  # noqa: ASYNC240
    console.print(
        f"[bold green]Scan complete:[/bold green] "
        f"{result.successful_attacks}/{result.total_payloads} successful "
        f"in {result.duration_seconds}s"
    )
    console.print(f"Results written to {output}")


def _create_adapter(config: AgentInjectConfig) -> BaseAdapter:
    """Create adapter from config."""
    from agent_inject.harness.adapters.rest import RestAdapter

    if config.target_adapter != "rest":
        msg = f"Unknown adapter: {config.target_adapter!r}. Available: ['rest']"
        raise ValueError(msg)
    return RestAdapter(config.target_url, timeout=config.timeout_seconds)


def _create_scorers(config: AgentInjectConfig) -> list[BaseScorer]:
    """Create scorers from config."""
    from agent_inject.scorers.base import CanaryMatchScorer, SubstringMatchScorer

    return [
        CanaryMatchScorer(threshold=config.canary_match_threshold),
        SubstringMatchScorer(),
    ]


@app.command()
def list_attacks() -> None:
    """List all available attack modules."""
    from agent_inject.attacks.registry import get_all_attacks

    attacks = get_all_attacks()
    if not attacks:
        console.print("[dim]No attacks registered.[/dim]")
        return
    for name, cls in sorted(attacks.items()):
        desc = getattr(cls, "description", "") or cls.__doc__ or "No description"
        console.print(f"  [bold]{name}[/bold] - {desc}")


@app.command()
def list_adapters() -> None:
    """List available target adapters."""
    console.print("  [bold]rest[/bold] - Generic REST/HTTP adapter (httpx)")


@app.command()
def version() -> None:
    """Print version information."""
    from agent_inject import __version__

    console.print(f"agent-inject {__version__}")
