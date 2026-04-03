# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Tests for multi-turn strategy base classes."""

from __future__ import annotations

from agent_inject.strategies.base import ConversationState, ConversationTurn, MultiTurnResult, MultiTurnScanResult


class TestConversationTurn:
    def test_creation(self) -> None:
        turn = ConversationTurn(
            turn_number=1,
            sent_message="hello",
            received_response="hi there",
        )
        assert turn.turn_number == 1
        assert turn.sent_message == "hello"
        assert turn.received_response == "hi there"
        assert turn.is_refusal is False
        assert turn.score is None

    def test_frozen(self) -> None:
        turn = ConversationTurn(turn_number=1, sent_message="a", received_response="b")
        import pytest

        with pytest.raises(AttributeError):
            turn.sent_message = "changed"  # type: ignore[misc]


class TestConversationState:
    def test_empty_state(self) -> None:
        state = ConversationState(conversation_id="test-123", objective="test goal")
        assert state.turns == ()
        assert state.backtrack_count == 0
        assert state.success is False

    def test_add_turn(self) -> None:
        state = ConversationState(conversation_id="test-123", objective="test goal")
        turn = ConversationTurn(turn_number=1, sent_message="hi", received_response="hello")
        new_state = state.add_turn(turn)

        assert len(new_state.turns) == 1
        assert new_state.turns[0] is turn
        assert len(state.turns) == 0  # original unchanged

    def test_backtrack(self) -> None:
        state = ConversationState(conversation_id="test-123", objective="test goal")
        turn = ConversationTurn(turn_number=1, sent_message="hi", received_response="hello")
        state = state.add_turn(turn)
        state = state.backtrack()

        assert len(state.turns) == 0
        assert state.backtrack_count == 1

    def test_backtrack_empty(self) -> None:
        state = ConversationState(conversation_id="test-123", objective="test goal")
        state = state.backtrack()

        assert len(state.turns) == 0
        assert state.backtrack_count == 1

    def test_mark_success(self) -> None:
        state = ConversationState(conversation_id="test-123", objective="test goal")
        state = state.mark_success()

        assert state.success is True

    def test_immutability_chain(self) -> None:
        s0 = ConversationState(conversation_id="x", objective="y")
        t1 = ConversationTurn(turn_number=1, sent_message="a", received_response="b")
        t2 = ConversationTurn(turn_number=2, sent_message="c", received_response="d")
        s1 = s0.add_turn(t1)
        s2 = s1.add_turn(t2)
        s3 = s2.mark_success()

        assert len(s0.turns) == 0
        assert len(s1.turns) == 1
        assert len(s2.turns) == 2
        assert s2.success is False
        assert s3.success is True
        assert len(s3.turns) == 2


class TestMultiTurnResult:
    def test_creation(self) -> None:
        state = ConversationState(conversation_id="test", objective="goal")
        result = MultiTurnResult(
            strategy_name="crescendo",
            objective="goal",
            state=state,
            total_turns=5,
            success=True,
        )
        assert result.strategy_name == "crescendo"
        assert result.total_turns == 5
        assert result.success is True
        assert result.error is None


class TestMultiTurnScanResult:
    def test_asr_with_objectives(self) -> None:
        result = MultiTurnScanResult(
            total_objectives=4,
            successful_attacks=3,
        )
        assert result.asr == 0.75

    def test_asr_zero_objectives(self) -> None:
        result = MultiTurnScanResult(
            total_objectives=0,
            successful_attacks=0,
        )
        assert result.asr == 0.0
