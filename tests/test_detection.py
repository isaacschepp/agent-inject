# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Tests for shared detection utilities."""

from __future__ import annotations

from agent_inject.detection import (
    COMPLIANCE_INDICATORS,
    REFUSAL_PHRASES,
    detect_compliance,
    detect_refusal,
)


class TestRefusalPhrases:
    def test_canonical_list_has_18_phrases(self) -> None:
        assert len(REFUSAL_PHRASES) == 18

    def test_all_lowercase(self) -> None:
        for phrase in REFUSAL_PHRASES:
            assert phrase == phrase.lower()


class TestComplianceIndicators:
    def test_canonical_list_has_10_indicators(self) -> None:
        assert len(COMPLIANCE_INDICATORS) == 10


class TestDetectRefusal:
    def test_detects_known_phrases(self) -> None:
        assert detect_refusal("I can't help with that")
        assert detect_refusal("I'm not able to assist")
        assert detect_refusal("I'm not going to do that")
        assert detect_refusal("This violates my policy")

    def test_case_insensitive(self) -> None:
        assert detect_refusal("I CAN'T HELP")
        assert detect_refusal("I Won't Do That")

    def test_no_false_positive(self) -> None:
        assert not detect_refusal("Sure, here's the information")
        assert not detect_refusal("Let me help you with that")
        assert not detect_refusal("")


class TestDetectCompliance:
    def test_detects_known_indicators(self) -> None:
        assert detect_compliance("here's the code:\n```python\nimport socket")
        assert detect_compliance("```bash\n#!/bin/bash")
        assert detect_compliance("def exploit(target):")

    def test_case_insensitive(self) -> None:
        assert detect_compliance("HERE'S THE CODE")
        assert detect_compliance("Import Socket")

    def test_no_false_positive(self) -> None:
        assert not detect_compliance("I cannot help with that request.")
        assert not detect_compliance("")
