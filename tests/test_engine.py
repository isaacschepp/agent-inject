# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Tests for scan engine."""

from __future__ import annotations

from typing import Any, ClassVar, override

from agent_inject.attacks.base import FixedJailbreakAttack
from agent_inject.engine import ScanResult, _safe_score, run_scan
from agent_inject.evasion.transforms import Base64Encode, compose
from agent_inject.harness.base import BaseAdapter
from agent_inject.models import AttackResult, DeliveryVector, PayloadInstance, Score
from agent_inject.scorers.base import BaseScorer


class StubAdapter(BaseAdapter):
    """Adapter that returns a fixed response."""

    name = "stub"

    def __init__(self, response: str = "ok") -> None:
        self._response = response

    @override
    async def send_payload(
        self,
        payload: PayloadInstance,
        context: dict[str, Any] | None = None,
    ) -> AttackResult:
        return AttackResult(payload_instance=payload, raw_output=self._response)


class AlwaysPassScorer(BaseScorer):
    """Scorer that always passes."""

    name = "always_pass"

    @override
    async def score(self, result: AttackResult) -> Score:
        return Score(scorer_name=self.name, passed=True, value=1.0)


class NeverPassScorer(BaseScorer):
    """Scorer that never passes."""

    name = "never_pass"

    @override
    async def score(self, result: AttackResult) -> Score:
        return Score(scorer_name=self.name, passed=False, value=0.0)


class SimpleAttack(FixedJailbreakAttack):
    name = "stub_attack"
    _templates: ClassVar[list[str]] = ["test: {goal}"]


class TestRunScan:
    async def test_basic(self) -> None:
        adapter = StubAdapter()
        result = await run_scan(
            adapter,
            attacks=[SimpleAttack()],
            scorers=[AlwaysPassScorer()],
            goal="test goal",
            max_concurrent=5,
        )
        assert isinstance(result, ScanResult)
        assert result.total_payloads == 1
        assert result.successful_attacks == 1
        assert result.duration_seconds >= 0

    async def test_with_evasion(self) -> None:
        adapter = StubAdapter()
        result = await run_scan(
            adapter,
            attacks=[SimpleAttack()],
            scorers=[NeverPassScorer()],
            goal="test",
            max_concurrent=5,
            evasion_chains=[compose(Base64Encode())],
        )
        # 1 original + 1 base64 variant = 2
        assert result.total_payloads == 2

    async def test_scoring(self) -> None:
        adapter = StubAdapter()
        result = await run_scan(
            adapter,
            attacks=[SimpleAttack()],
            scorers=[AlwaysPassScorer(), NeverPassScorer()],
            goal="test",
            max_concurrent=5,
        )
        assert result.total_payloads == 1
        # At least one scorer passed -> attack_success
        assert result.successful_attacks == 1
        # Two scores per result
        assert len(result.scores[0][1]) == 2

    async def test_no_scorers(self) -> None:
        adapter = StubAdapter()
        result = await run_scan(
            adapter,
            attacks=[SimpleAttack()],
            scorers=[],
            goal="test",
            max_concurrent=5,
        )
        assert result.total_payloads == 1
        assert result.successful_attacks == 0

    async def test_on_result_callback(self) -> None:
        callback_results: list[AttackResult] = []
        adapter = StubAdapter()
        await run_scan(
            adapter,
            attacks=[SimpleAttack()],
            scorers=[AlwaysPassScorer()],
            goal="test",
            max_concurrent=5,
            on_result=callback_results.append,
        )
        assert len(callback_results) == 1

    async def test_multiple_attacks(self) -> None:
        adapter = StubAdapter()

        class AnotherAttack(FixedJailbreakAttack):
            name = "another"
            _templates: ClassVar[list[str]] = ["a: {goal}", "b: {goal}"]

        result = await run_scan(
            adapter,
            attacks=[SimpleAttack(), AnotherAttack()],
            scorers=[NeverPassScorer()],
            goal="test",
            max_concurrent=5,
        )
        # 1 from SimpleAttack + 2 from AnotherAttack = 3
        assert result.total_payloads == 3

    async def test_custom_delivery_vector(self) -> None:
        adapter = StubAdapter()
        result = await run_scan(
            adapter,
            attacks=[SimpleAttack()],
            scorers=[],
            goal="test",
            max_concurrent=5,
            delivery_vector=DeliveryVector.TOOL_RETURN,
        )
        assert result.results[0].payload_instance.delivery_vector == DeliveryVector.TOOL_RETURN

    async def test_send_failure_preserved(self) -> None:
        class FailingAdapter(BaseAdapter):
            name = "failing"

            @override
            async def send_payload(
                self,
                payload: PayloadInstance,
                context: dict[str, Any] | None = None,
            ) -> AttackResult:
                msg = "target down"
                raise ConnectionError(msg)

        adapter = FailingAdapter()
        result = await run_scan(
            adapter,
            attacks=[SimpleAttack()],
            scorers=[],
            goal="test",
            max_concurrent=5,
            max_retries=0,
        )
        assert result.total_payloads == 1
        assert result.results[0].error is not None
        assert "target down" in result.results[0].error

    async def test_retry_on_transient_failure(self) -> None:
        call_count = 0

        class FlakeyAdapter(BaseAdapter):
            name = "flakey"

            @override
            async def send_payload(
                self,
                payload: PayloadInstance,
                context: dict[str, Any] | None = None,
            ) -> AttackResult:
                nonlocal call_count
                call_count += 1
                if call_count <= 2:
                    msg = "transient error"
                    raise ConnectionError(msg)
                return AttackResult(payload_instance=payload, raw_output="ok")

        adapter = FlakeyAdapter()
        result = await run_scan(
            adapter,
            attacks=[SimpleAttack()],
            scorers=[],
            goal="test",
            max_concurrent=5,
            max_retries=3,
            retry_backoff_seconds=0.01,
        )
        assert result.total_payloads == 1
        assert result.results[0].error is None
        assert result.results[0].raw_output == "ok"
        assert call_count == 3  # 2 failures + 1 success

    async def test_health_check_failure_aborts(self) -> None:
        class UnhealthyAdapter(BaseAdapter):
            name = "unhealthy"

            @override
            async def send_payload(
                self,
                payload: PayloadInstance,
                context: dict[str, Any] | None = None,
            ) -> AttackResult:
                return AttackResult(payload_instance=payload)

            @override
            async def health_check(self) -> bool:
                return False

        adapter = UnhealthyAdapter()
        result = await run_scan(
            adapter,
            attacks=[SimpleAttack()],
            scorers=[],
            goal="test",
            max_concurrent=5,
        )
        assert result.total_payloads == 0
        assert result.results == ()


class ExplodingScorer(BaseScorer):
    """Scorer that always raises."""

    name = "exploding"

    @override
    async def score(self, result: AttackResult) -> Score:
        msg = "scorer kaboom"
        raise RuntimeError(msg)


class TestParallelScoring:
    """Tests for parallel scorer execution (#509)."""

    async def test_parallel_produces_same_results_as_sequential(self) -> None:
        adapter = StubAdapter()
        scorers = [AlwaysPassScorer(), NeverPassScorer()]

        parallel = await run_scan(
            adapter,
            attacks=[SimpleAttack()],
            scorers=scorers,
            goal="test",
            max_concurrent=5,
            parallel_scoring=True,
        )
        sequential = await run_scan(
            adapter,
            attacks=[SimpleAttack()],
            scorers=scorers,
            goal="test",
            max_concurrent=5,
            parallel_scoring=False,
        )

        assert parallel.successful_attacks == sequential.successful_attacks
        assert len(parallel.scores) == len(sequential.scores)
        for (p_result, p_scores), (s_result, s_scores) in zip(parallel.scores, sequential.scores, strict=True):
            assert p_result.attack_success == s_result.attack_success
            assert len(p_scores) == len(s_scores)
            for p, s in zip(p_scores, s_scores, strict=True):
                assert p.scorer_name == s.scorer_name
                assert p.passed == s.passed

    async def test_parallel_scoring_preserves_scorer_order(self) -> None:
        adapter = StubAdapter()
        scorers = [AlwaysPassScorer(), NeverPassScorer()]
        result = await run_scan(
            adapter,
            attacks=[SimpleAttack()],
            scorers=scorers,
            goal="test",
            max_concurrent=5,
            parallel_scoring=True,
        )
        scores = result.scores[0][1]
        assert scores[0].scorer_name == "always_pass"
        assert scores[1].scorer_name == "never_pass"

    async def test_sequential_fallback(self) -> None:
        adapter = StubAdapter()
        result = await run_scan(
            adapter,
            attacks=[SimpleAttack()],
            scorers=[AlwaysPassScorer(), NeverPassScorer()],
            goal="test",
            max_concurrent=5,
            parallel_scoring=False,
        )
        assert result.successful_attacks == 1
        assert len(result.scores[0][1]) == 2

    async def test_single_scorer_uses_sequential_path(self) -> None:
        """With only 1 scorer, gather is not used (len(scorers) > 1 guard)."""
        adapter = StubAdapter()
        result = await run_scan(
            adapter,
            attacks=[SimpleAttack()],
            scorers=[AlwaysPassScorer()],
            goal="test",
            max_concurrent=5,
            parallel_scoring=True,
        )
        assert result.successful_attacks == 1
        assert len(result.scores[0][1]) == 1


class TestScorerErrorIsolation:
    """Tests for _safe_score error isolation (#514)."""

    async def test_safe_score_returns_error_score_on_failure(self, sample_attack_result: AttackResult) -> None:
        exploding = ExplodingScorer()
        score = await _safe_score(exploding, sample_attack_result)
        assert score.scorer_name == "exploding"
        assert score.passed is False
        assert score.value == 0.0
        assert "RuntimeError" in score.rationale
        assert score.details["error"] is True
        assert score.details["exception_type"] == "RuntimeError"

    async def test_exploding_scorer_does_not_kill_siblings(self) -> None:
        adapter = StubAdapter()
        result = await run_scan(
            adapter,
            attacks=[SimpleAttack()],
            scorers=[AlwaysPassScorer(), ExplodingScorer(), NeverPassScorer()],
            goal="test",
            max_concurrent=5,
            parallel_scoring=True,
        )
        scores = result.scores[0][1]
        assert len(scores) == 3
        # AlwaysPass still produced its score
        assert scores[0].scorer_name == "always_pass"
        assert scores[0].passed is True
        # ExplodingScorer produced an error score
        assert scores[1].scorer_name == "exploding"
        assert scores[1].passed is False
        assert scores[1].details.get("error") is True
        # NeverPass still produced its score
        assert scores[2].scorer_name == "never_pass"
        assert scores[2].passed is False
        # At least one scorer passed -> attack_success
        assert result.successful_attacks == 1

    async def test_exploding_scorer_isolated_in_sequential_mode(self) -> None:
        adapter = StubAdapter()
        result = await run_scan(
            adapter,
            attacks=[SimpleAttack()],
            scorers=[AlwaysPassScorer(), ExplodingScorer()],
            goal="test",
            max_concurrent=5,
            parallel_scoring=False,
        )
        scores = result.scores[0][1]
        assert len(scores) == 2
        assert scores[0].passed is True
        assert scores[1].details.get("error") is True
