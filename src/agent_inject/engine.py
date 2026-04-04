# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Scan engine: orchestrates attacks, evasion, delivery, and scoring."""

from __future__ import annotations

import asyncio
import email.utils
import logging
import random
import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from agent_inject.evasion.transforms import TransformChain, apply_evasion_chains
from agent_inject.models import AttackResult, DeliveryVector, PayloadInstance, Score

if TYPE_CHECKING:
    from collections.abc import Callable

    from agent_inject.attacks.base import BaseAttack
    from agent_inject.harness.base import BaseAdapter
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


async def _safe_score(scorer: BaseScorer, result: AttackResult) -> Score:
    """Invoke *scorer* with error isolation.

    Returns a synthetic error ``Score`` if the scorer raises, so that
    sibling scorers are never affected and the result set is always
    complete and uniformly typed.
    """
    try:
        return await scorer.score(result)
    except Exception as exc:  # noqa: BLE001 — scorer-agnostic; can't predict exception types
        _logger.warning("Scorer %s failed for %s: %s", scorer.name, result.payload_instance.payload.id, exc)
        return Score(
            scorer_name=scorer.name,
            passed=False,
            value=0.0,
            rationale=f"Scorer error: {type(exc).__name__}: {exc}",
            details={"error": True, "exception_type": type(exc).__qualname__},
        )


async def run_scan(
    adapter: BaseAdapter,
    attacks: list[BaseAttack],
    scorers: list[BaseScorer],
    *,
    goal: str,
    evasion_chains: list[TransformChain] | None = None,
    delivery_vector: DeliveryVector = DeliveryVector.DIRECT,
    max_concurrent: int,
    max_retries: int = 3,
    retry_backoff_seconds: float = 2.0,
    parallel_scoring: bool = True,
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
        max_retries: Maximum retry attempts per payload on transient failure.
        retry_backoff_seconds: Base delay (seconds) between retries (exponential backoff).
        parallel_scoring: Run scorers in parallel per result (True) or sequentially (False).
        on_result: Optional callback invoked after each result is scored.

    Returns:
        ScanResult with all results and scores.

    """
    start = time.monotonic()

    # 1. Health check
    if not await adapter.health_check():
        _logger.warning("Adapter health check failed for %s", adapter.name)
        return ScanResult(
            results=(),
            scores=(),
            total_payloads=0,
            successful_attacks=0,
            duration_seconds=round(time.monotonic() - start, 2),
        )

    # 2. Generate payloads
    instances: list[PayloadInstance] = []
    for attack in attacks:
        instances.extend(attack.generate_payloads(goal, delivery_vector))
    _logger.info("Generated %d payloads from %d attacks", len(instances), len(attacks))

    # 3. Apply evasion transforms
    if evasion_chains:
        instances = apply_evasion_chains(instances, evasion_chains)
        _logger.info("After evasion fan-out: %d payloads", len(instances))

    # 3b. Assign stable indices for deterministic ordering after interleaving
    instances = [replace(inst, index=i) for i, inst in enumerate(instances)]

    # 4+5. Deliver and score interleaved — scoring starts as each delivery completes
    raw_results, scored, successful = await _deliver_and_score_all(
        adapter,
        instances,
        scorers,
        max_concurrent=max_concurrent,
        max_retries=max_retries,
        retry_backoff_seconds=retry_backoff_seconds,
        parallel_scoring=parallel_scoring,
        on_result=on_result,
    )

    duration = time.monotonic() - start
    _logger.info(
        "Scan complete: %d/%d successful in %.1fs",
        successful,
        len(raw_results),
        duration,
    )

    return ScanResult(
        results=tuple(raw_results),
        scores=tuple(scored),
        total_payloads=len(raw_results),
        successful_attacks=successful,
        duration_seconds=round(duration, 2),
    )


_RETRYABLE_STATUS_CODES: frozenset[int] = frozenset(
    {
        408,  # Request Timeout
        429,  # Too Many Requests
        500,  # Internal Server Error
        502,  # Bad Gateway
        503,  # Service Unavailable
        504,  # Gateway Timeout
        524,  # Cloudflare Timeout
        529,  # Anthropic Overloaded
    }
)

_MAX_RETRY_AFTER: float = 60.0
_MAX_BACKOFF: float = 60.0


def _is_retryable(exc: Exception) -> bool:
    """Classify whether *exc* is worth retrying.

    Uses duck-typing (``hasattr``) to stay adapter-agnostic — works
    with ``httpx.HTTPStatusError``, SDK-specific errors, or any
    exception that exposes ``.response.status_code``.
    """
    response = getattr(exc, "response", None)
    if response is not None:
        status = getattr(response, "status_code", None)
        if status is not None:
            return status in _RETRYABLE_STATUS_CODES
    # Transport / connection / OS-level errors — always retryable.
    if isinstance(exc, (ConnectionError, TimeoutError, OSError)):
        return True
    # Programming errors — never retryable.  Unknown errors default to
    # retryable as a fail-safe (prefer wasting retries over losing results).
    return not isinstance(exc, (ValueError, TypeError, KeyError, AttributeError))


def _parse_retry_after(exc: Exception) -> float | None:  # noqa: PLR0911 — parsing three distinct header formats
    """Extract ``Retry-After`` delay (seconds) from an HTTP error, if present.

    Follows the OpenAI/Anthropic SDK three-layer parsing pattern:
    ``retry-after-ms`` (non-standard, milliseconds) →
    ``retry-after`` (seconds) → ``retry-after`` (HTTP-date).
    """
    response = getattr(exc, "response", None)
    if response is None:
        return None
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    # Build a lowercased lookup so we handle arbitrary header casing
    # (httpx.Headers is already case-insensitive, but plain dicts are not).
    lower: dict[str, str] = {k.lower(): v for k, v in headers.items()}
    # 1. Non-standard millisecond header (used by OpenAI / Anthropic).
    raw_ms = lower.get("retry-after-ms")
    if raw_ms:
        try:
            return float(raw_ms) / 1000.0
        except (TypeError, ValueError):
            pass
    # 2. Standard: seconds (allows non-standard floats like "1.5").
    raw = lower.get("retry-after")
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        pass
    # 3. HTTP-date format (RFC 9110).
    parsed = email.utils.parsedate_tz(raw)
    if parsed is not None:
        return max(0.0, email.utils.mktime_tz(parsed) - time.time())
    return None


def _backoff_delay(attempt: int, base: float, exc: Exception) -> float:
    """Compute retry delay with Retry-After support and full jitter.

    If the exception carries a ``Retry-After`` header (HTTP 429), that
    value is used directly (capped at ``_MAX_RETRY_AFTER``).  Otherwise
    exponential backoff with full jitter is applied — the strategy
    recommended by the `AWS Architecture Blog`_ to minimise thundering
    herd effects in concurrent scanners.

    .. _AWS Architecture Blog:
       https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
    """
    retry_after = _parse_retry_after(exc)
    if retry_after is not None and 0 < retry_after <= _MAX_RETRY_AFTER:
        return retry_after
    exp = base * (2**attempt)
    return random.uniform(0, min(exp, _MAX_BACKOFF))  # noqa: S311 — jitter, not crypto


async def _send_one_with_retry(
    adapter: BaseAdapter,
    instance: PayloadInstance,
    max_retries: int,
    retry_backoff_seconds: float,
) -> AttackResult:
    """Send a single payload with classified retry and jittered backoff.

    Non-retryable errors (4xx client errors, programming errors) abort
    immediately.  Retryable errors (transport failures, 429, 5xx) are
    retried with exponential backoff and full jitter.  HTTP 429
    responses with a ``Retry-After`` header use the server-requested
    delay instead.
    """
    last_error: str = ""
    attempts_made = 0
    for attempt in range(max_retries + 1):
        attempts_made = attempt + 1
        try:
            return await adapter.send_payload(instance)
        except Exception as e:  # noqa: BLE001 — adapter-agnostic; can't predict exception types
            last_error = str(e)
            retryable = _is_retryable(e)
            if not retryable or attempt >= max_retries:
                if not retryable:
                    _logger.info("Non-retryable error for %s: %s", instance.payload.id, e)
                break
            delay = _backoff_delay(attempt, retry_backoff_seconds, e)
            _logger.info(
                "Retry %d/%d for %s after %.1fs: %s",
                attempt + 1,
                max_retries,
                instance.payload.id,
                delay,
                e,
            )
            await asyncio.sleep(delay)
    _logger.warning(
        "Send failed for %s after %d attempt(s): %s",
        instance.payload.id,
        attempts_made,
        last_error,
    )
    return AttackResult(payload_instance=instance, error=last_error)


async def _deliver_and_score_all(
    adapter: BaseAdapter,
    instances: list[PayloadInstance],
    scorers: list[BaseScorer],
    *,
    max_concurrent: int,
    max_retries: int,
    retry_backoff_seconds: float,
    parallel_scoring: bool,
    on_result: Callable[[AttackResult], Any] | None,
) -> tuple[list[AttackResult], list[tuple[AttackResult, tuple[Score, ...]]], int]:
    """Deliver payloads and score results in an interleaved pipeline.

    Each payload is delivered, then immediately scored before the next
    payload waits for its delivery slot.  The delivery semaphore is
    released *before* scoring begins so that new deliveries can proceed
    while scoring (potentially I/O-bound LLM judge calls) runs.

    Returns ``(raw_results, scored_pairs, successful_count)`` sorted by
    payload index for deterministic ordering.
    """
    delivery_sem = asyncio.Semaphore(max_concurrent)
    raw_results: list[AttackResult] = []
    scored: list[tuple[AttackResult, tuple[Score, ...]]] = []
    successful = 0

    async def _process_one(instance: PayloadInstance) -> None:
        nonlocal successful
        try:
            # --- Delivery phase (bounded by semaphore) ---
            async with delivery_sem:
                result = await _send_one_with_retry(adapter, instance, max_retries, retry_backoff_seconds)
            # Semaphore released — delivery slot freed for next payload.

            # --- Scoring phase (outside semaphore — doesn't block delivery) ---
            if parallel_scoring and len(scorers) > 1:
                result_scores = list(
                    await asyncio.gather(
                        *(_safe_score(scorer, result) for scorer in scorers),
                    )
                )
            else:
                result_scores = [await _safe_score(scorer, result) for scorer in scorers]

            if any(s.passed for s in result_scores):
                result = replace(result, attack_success=True)
                successful += 1

            # Atomic appends (no await between reads/writes of shared state).
            raw_results.append(result)
            scored.append((result, tuple(result_scores)))
        except Exception as exc:  # noqa: BLE001 — prevent TaskGroup cancellation cascade
            _logger.warning("Pipeline failed for %s: %s", instance.payload.id, exc)
            result = AttackResult(payload_instance=instance, error=str(exc))
            raw_results.append(result)
            scored.append((result, ()))

        if on_result:
            on_result(result)

    async with asyncio.TaskGroup() as tg:
        for inst in instances:
            tg.create_task(_process_one(inst))

    # Sort by payload index for deterministic ordering regardless of completion order.
    raw_results.sort(key=lambda r: r.payload_instance.index)
    scored.sort(key=lambda pair: pair[0].payload_instance.index)

    return raw_results, scored, successful
