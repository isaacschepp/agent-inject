"""Tests for scan engine."""

from __future__ import annotations

from typing import Any, ClassVar, override

from agent_inject.attacks.base import FixedJailbreakAttack
from agent_inject.engine import ScanResult, run_scan
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
        )
        assert result.total_payloads == 1
        assert result.results[0].error is not None
        assert "target down" in result.results[0].error

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
        )
        assert result.total_payloads == 0
        assert result.results == ()
