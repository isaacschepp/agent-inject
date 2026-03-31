"""Scan engine: orchestrates attacks, evasion, delivery, and scoring."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agent_inject.attacks.base import BaseAttack
from agent_inject.evasion.transforms import TransformChain, apply_evasion_chains
from agent_inject.harness.base import BaseAdapter
from agent_inject.models import AttackResult, DeliveryVector, PayloadInstance, Score
from agent_inject.scorers.base import BaseScorer

_logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Immutable result of a complete scan run."""

    results: tuple[AttackResult, ...]
    scores: tuple[tuple[AttackResult, tuple[Score, ...]], ...]
    total_payloads: int
    successful_attacks: int
    duration_seconds: float


async def run_scan(
    adapter: BaseAdapter,
    attacks: list[BaseAttack],
    scorers: list[BaseScorer],
    *,
    goal: str,
    evasion_chains: list[TransformChain] | None = None,
    delivery_vector: DeliveryVector = DeliveryVector.DIRECT,
    max_concurrent: int = 5,
    on_result: Callable[[AttackResult], Any] | None = None,
) -> ScanResult:
    """Run a complete scan: generate -> evade -> deliver -> score.

    Args:
        adapter: Target agent adapter (should be used as async context manager by caller).
        attacks: List of attacks to run.
        scorers: List of scorers to evaluate results.
        goal: The injection objective.
        evasion_chains: Optional evasion transforms to apply (Tier 4 fan-out).
        delivery_vector: How payloads are delivered.
        max_concurrent: Maximum concurrent payload deliveries.
        on_result: Optional callback invoked after each result is scored.

    Returns:
        ScanResult with all results and scores.
    """
    start = time.monotonic()

    # 1. Health check
    if not await adapter.health_check():
        _logger.warning("Adapter health check failed for %s", adapter.name)

    # 2. Generate payloads
    instances: list[PayloadInstance] = []
    for attack in attacks:
        instances.extend(attack.generate_payloads(goal, delivery_vector))
    _logger.info("Generated %d payloads from %d attacks", len(instances), len(attacks))

    # 3. Apply evasion transforms
    if evasion_chains:
        instances = apply_evasion_chains(instances, evasion_chains)
        _logger.info("After evasion fan-out: %d payloads", len(instances))

    # 4. Deliver concurrently
    results = await _send_all(adapter, instances, max_concurrent)

    # 5. Score
    scored: list[tuple[AttackResult, tuple[Score, ...]]] = []
    successful = 0
    for result in results:
        result_scores: list[Score] = []
        for scorer in scorers:
            score = await scorer.score(result)
            result_scores.append(score)
        if any(s.passed for s in result_scores):
            result.attack_success = True
            successful += 1
        scored.append((result, tuple(result_scores)))
        if on_result:
            on_result(result)

    duration = time.monotonic() - start
    _logger.info(
        "Scan complete: %d/%d successful in %.1fs",
        successful,
        len(results),
        duration,
    )

    return ScanResult(
        results=tuple(results),
        scores=tuple(scored),
        total_payloads=len(results),
        successful_attacks=successful,
        duration_seconds=round(duration, 2),
    )


async def _send_all(
    adapter: BaseAdapter,
    instances: list[PayloadInstance],
    max_concurrent: int,
) -> list[AttackResult]:
    """Send all payloads concurrently with bounded parallelism."""
    sem = asyncio.Semaphore(max_concurrent)

    async def _send_one(instance: PayloadInstance) -> AttackResult:
        async with sem:
            try:
                return await adapter.send_payload(instance)
            except Exception as e:
                _logger.warning("Send failed for %s: %s", instance.payload.id, e)
                return AttackResult(payload_instance=instance, error=str(e))

    async with asyncio.TaskGroup() as tg:
        tasks = [tg.create_task(_send_one(inst)) for inst in instances]
    return [t.result() for t in tasks]
