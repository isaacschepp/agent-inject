# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Tests for shared detection utilities."""

from __future__ import annotations

from agent_inject.detection import (
    COMPLIANCE_INDICATORS,
    REFUSAL_PHRASES,
    DetectionPhraseFile,
    DetectionResult,
    _load_phrases,
    detect_compliance,
    detect_refusal,
)


class TestYamlLoading:
    """YAML data files are loadable and valid."""

    def test_refusal_yaml_loads(self) -> None:
        phrases = _load_phrases("refusal")
        assert len(phrases) > 0

    def test_compliance_yaml_loads(self) -> None:
        phrases = _load_phrases("compliance")
        assert len(phrases) > 0

    def test_refusal_schema_valid(self) -> None:
        from importlib.resources import files

        import yaml

        resource = files("agent_inject").joinpath("data", "detection", "refusal.yaml")
        raw = yaml.safe_load(resource.read_text(encoding="utf-8"))
        validated = DetectionPhraseFile.model_validate(raw)
        assert validated.match_type == "word_boundary"
        assert validated.version == "1.0"

    def test_compliance_schema_valid(self) -> None:
        from importlib.resources import files

        import yaml

        resource = files("agent_inject").joinpath("data", "detection", "compliance.yaml")
        raw = yaml.safe_load(resource.read_text(encoding="utf-8"))
        validated = DetectionPhraseFile.model_validate(raw)
        assert validated.match_type == "substring"


class TestDetectionPhraseFileValidation:
    def test_empty_phrases_rejected(self) -> None:
        import pytest

        with pytest.raises(Exception, match="phrases must not be empty"):
            DetectionPhraseFile(version="1.0", phrases=[])


class TestDetectionResult:
    def test_bool_true_when_detected(self) -> None:
        r = DetectionResult(detected=True, confidence=0.5, matched_phrases=("i can't",))
        assert bool(r) is True
        assert r  # if r: works

    def test_bool_false_when_not_detected(self) -> None:
        r = DetectionResult(detected=False, confidence=0.0)
        assert bool(r) is False
        assert not r  # if not r: works

    def test_frozen(self) -> None:
        import pytest

        r = DetectionResult(detected=True, confidence=1.0)
        with pytest.raises(AttributeError):
            r.confidence = 0.5  # type: ignore[misc]


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

    def test_returns_detection_result(self) -> None:
        r = detect_refusal("I can't help with that")
        assert isinstance(r, DetectionResult)
        assert r.detected is True
        assert r.confidence > 0.0
        assert len(r.matched_phrases) >= 1

    def test_no_match_returns_zero_confidence(self) -> None:
        r = detect_refusal("Sure, here's the info")
        assert r.detected is False
        assert r.confidence == 0.0
        assert r.matched_phrases == ()


class TestRefusalConfidence:
    """Graduated confidence scoring."""

    def test_single_match_low_confidence(self) -> None:
        r = detect_refusal("I can't help")
        assert r.confidence < 0.5  # 1 match / 3 * position

    def test_multiple_matches_higher_confidence(self) -> None:
        r = detect_refusal("I can't help. I refuse to assist. I won't do that.")
        assert r.confidence > 0.5

    def test_three_matches_high_confidence(self) -> None:
        r = detect_refusal("I can't. I won't. I refuse to.")
        assert r.confidence >= 0.9

    def test_early_match_higher_than_late(self) -> None:
        early = detect_refusal("I can't help." + " " * 500)
        late = detect_refusal(" " * 500 + "I can't help.")
        assert early.confidence > late.confidence

    def test_matched_phrases_populated(self) -> None:
        r = detect_refusal("I can't help. I refuse to assist.")
        assert "i can't" in r.matched_phrases
        assert "i refuse to" in r.matched_phrases


class TestRefusalWordBoundary:
    """Word-boundary matching prevents phrases from matching inside longer words."""

    def test_not_appropriate_in_longer_word(self) -> None:
        assert not detect_refusal("this is not appropriately formatted")

    def test_as_an_ai_in_longer_word(self) -> None:
        assert not detect_refusal("as an aide, I can help you")

    def test_ethical_guidelines_in_longer_word(self) -> None:
        assert not detect_refusal("the ethical guidelinesbook is on the shelf")

    def test_phrase_at_start_of_text(self) -> None:
        assert detect_refusal("I can't help with that request.")

    def test_phrase_at_end_of_text(self) -> None:
        assert detect_refusal("Sorry, as an ai")

    def test_phrase_surrounded_by_punctuation(self) -> None:
        assert detect_refusal('"I refuse to" was the response.')

    def test_phrase_with_newline_boundary(self) -> None:
        assert detect_refusal("Here is context.\nI can't help with that.")


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

    def test_returns_detection_result(self) -> None:
        r = detect_compliance("here's the code:\n```python\nimport socket")
        assert isinstance(r, DetectionResult)
        assert r.detected is True
        assert r.confidence > 0.0
        assert len(r.matched_phrases) >= 1

    def test_multiple_indicators_higher_confidence(self) -> None:
        r = detect_compliance("here's the code:\n```python\nimport socket\nimport subprocess")
        assert r.confidence == 1.0  # 4 matches, saturates at 2
