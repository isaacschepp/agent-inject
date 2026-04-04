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
    config_file: Annotated[
        Path | None,
        typer.Option("--config", help="Path to TOML config file"),
    ] = None,
) -> None:
    """Run attack suite against target agent."""
    from agent_inject.config import (
        AgentInjectConfig,
        set_toml_override,
        warn_if_cwd_dotenv,
        warn_unknown_env_vars,
    )

    if env_file is not None and not env_file.is_file():
        console.print(f"[red]Error:[/red] env file not found: {env_file}")
        raise typer.Exit(code=1)

    if config_file is not None and not config_file.is_file():
        console.print(f"[red]Error:[/red] config file not found: {config_file}")
        raise typer.Exit(code=1)

    warn_if_cwd_dotenv(env_file_provided=env_file is not None)

    # Set TOML override before constructing config (consumed by settings_customise_sources).
    set_toml_override(config_file)

    # Build config: CLI args > env vars > .env > TOML > defaults.
    # Only pass CLI params that were explicitly provided so env vars can fill the rest.
    # Nested dicts are coerced to sub-models by pydantic.
    target_overrides: dict[str, Any] = {"url": target}
    if timeout is not None:
        target_overrides["timeout_seconds"] = timeout

    overrides: dict[str, Any] = {
        "target": target_overrides,
        "output": {"verbose": verbose},
    }
    if max_concurrent is not None:
        overrides["engine"] = {"max_concurrent": max_concurrent}

    config = AgentInjectConfig(**overrides, _env_file=env_file)  # pyright: ignore[reportCallIssue]

    warn_unknown_env_vars()

    # Configure logging from config.
    import logging as _logging

    _logging.basicConfig(
        level=getattr(_logging, config.output.log_level),
        format="%(levelname)s: %(message)s",
        force=True,
    )

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

    if config.output.verbose:
        console.print(f"Target: {config.target.url}")
        console.print(f"Adapter: {config.target.adapter}")
        console.print(f"Goal: {goal}")
        console.print(f"Attacks: {[a.name for a in resolved_attacks]}")
        console.print(f"Timeout: {config.target.timeout_seconds}s")
        console.print(f"Concurrency: {config.engine.max_concurrent}")
        console.print(f"Canary threshold: {config.scoring.canary_match_threshold}")

    adapter = _create_adapter(config)
    scorers = _create_scorers(config)

    async with adapter:
        if config.output.verbose:
            result = await _scan_with_progress(
                adapter,
                resolved_attacks,
                scorers,
                goal,
                config,
            )
        else:
            result = await run_scan(
                adapter,
                attacks=resolved_attacks,
                scorers=scorers,
                goal=goal,
                max_concurrent=config.engine.max_concurrent,
                max_retries=config.engine.max_retries,
                retry_backoff_seconds=config.engine.retry_backoff_seconds,
                parallel_scoring=config.engine.parallel_scoring,
            )

    output.write_text(json.dumps(dataclasses.asdict(result), indent=2, default=_json_default))  # noqa: ASYNC240
    console.print(
        f"[bold green]Scan complete:[/bold green] "
        f"{result.successful_attacks}/{result.total_payloads} successful "
        f"in {result.duration_seconds}s"
    )
    console.print(f"Results written to {output}")


async def _scan_with_progress(
    adapter: BaseAdapter,
    attacks: list[Any],
    scorers: list[BaseScorer],
    goal: str,
    config: AgentInjectConfig,
) -> Any:
    """Run scan with a Rich progress bar updated via ``on_progress``."""
    from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeRemainingColumn

    from agent_inject.engine import ScanProgress, run_scan

    completed = 0

    def _update_progress(p: ScanProgress) -> None:
        nonlocal completed
        completed += 1
        asr = p.successful_so_far / completed * 100 if completed > 0 else 0
        task_progress.update(
            task_id,
            completed=completed,
            total=p.total,
            description=f"[cyan]{p.successful_so_far} succeeded  ASR {asr:.1f}%[/cyan]",
        )

    with Progress(
        TextColumn("[bold blue]Scanning[/bold blue]"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        TextColumn("{task.description}"),
        console=console,
        transient=True,
    ) as task_progress:
        task_id = task_progress.add_task("Scanning...", total=None)
        result = await run_scan(
            adapter,
            attacks=attacks,
            scorers=scorers,
            goal=goal,
            max_concurrent=config.engine.max_concurrent,
            max_retries=config.engine.max_retries,
            retry_backoff_seconds=config.engine.retry_backoff_seconds,
            parallel_scoring=config.engine.parallel_scoring,
            on_progress=_update_progress,
        )
    return result  # noqa: RET504 — must exit Progress context before returning


def _json_default(obj: object) -> object:
    """JSON serializer fallback for ``MappingProxyType`` and other non-standard types."""
    import types

    if isinstance(obj, types.MappingProxyType):
        return dict(obj)  # pyright: ignore[reportUnknownArgumentType,reportUnknownVariableType]
    return str(obj)


def _create_adapter(config: AgentInjectConfig) -> BaseAdapter:
    """Create adapter from config.

    ``target.adapter`` is constrained to ``Literal["rest"]`` at the config
    level, so the match below is exhaustive.  Extend the Literal and add
    a new case when a second adapter ships.
    """
    from agent_inject.harness.adapters.rest import RestAdapter

    if config.target.adapter == "rest":
        return RestAdapter(
            config.target.url,
            timeout=config.target.timeout_seconds,
            message_field=config.target.message_field,
            response_field=config.target.response_field,
            headers=dict(config.target.headers),
        )
    # Should be unreachable thanks to Literal constraint; guard for direct API callers.
    msg = f"Unknown adapter: {config.target.adapter!r}"  # pragma: no cover
    raise ValueError(msg)  # pragma: no cover


def _create_scorers(config: AgentInjectConfig) -> list[BaseScorer]:
    """Create scorers from config."""
    from agent_inject.scorers.base import CanaryMatchScorer, SubstringMatchScorer

    scorers: list[BaseScorer] = [
        CanaryMatchScorer(threshold=config.scoring.canary_match_threshold),
        SubstringMatchScorer(),
    ]

    if config.scoring.judge.enabled:
        from agent_inject.scorers.llm_judge import LlmJudgeScorer

        provider = config.scoring.judge.model.split(":")[0] if ":" in config.scoring.judge.model else "openai"
        api_key = (
            config.secrets.openai_api_key if provider == "openai" else config.secrets.anthropic_api_key
        ).get_secret_value()
        scorers.append(LlmJudgeScorer(config.scoring.judge, api_key))

    return scorers


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
def config_schema() -> None:
    """Export configuration JSON Schema."""
    import json
    import warnings

    from pydantic.json_schema import PydanticJsonSchemaWarning

    from agent_inject.config import AgentInjectConfig

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=PydanticJsonSchemaWarning)
        schema = AgentInjectConfig.model_json_schema()
    # Use print() instead of console.print() to avoid Rich escaping JSON control chars.
    print(json.dumps(schema, indent=2))  # noqa: T201


@app.command()
def version() -> None:
    """Print version information."""
    from agent_inject import __version__

    console.print(f"agent-inject {__version__}")
