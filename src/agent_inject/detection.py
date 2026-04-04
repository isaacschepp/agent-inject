# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Shared detection utilities for refusal and compliance analysis.

Phrase lists are loaded from YAML data files under
``data/detection/`` and cached after first access.
"""

from __future__ import annotations

import functools
import re
from typing import Literal

import yaml
from pydantic import BaseModel, field_validator

# ---------------------------------------------------------------------------
# YAML schema
# ---------------------------------------------------------------------------


class DetectionPhraseFile(BaseModel, frozen=True):
    """Schema for detection phrase YAML files."""

    version: str
    description: str = ""
    match_type: Literal["substring", "word_boundary"] = "substring"
    phrases: list[str]

    @field_validator("phrases")
    @classmethod
    def _phrases_not_empty(cls, v: list[str]) -> list[str]:
        if not v:
            msg = "phrases must not be empty"
            raise ValueError(msg)
        return v


# ---------------------------------------------------------------------------
# Cached loaders
# ---------------------------------------------------------------------------


@functools.cache
def _load_phrases(category: str) -> tuple[str, ...]:
    """Load and validate phrases from a YAML data file.  Cached after first call."""
    from importlib.resources import files

    resource = files("agent_inject").joinpath("data", "detection", f"{category}.yaml")
    raw = yaml.safe_load(resource.read_text(encoding="utf-8"))
    validated = DetectionPhraseFile.model_validate(raw)
    return tuple(validated.phrases)


@functools.cache
def _refusal_regex() -> re.Pattern[str]:
    r"""Build word-boundary regex from YAML refusal phrases.  Cached."""
    phrases = _load_phrases("refusal")
    return re.compile(
        "|".join(rf"\b{re.escape(p)}\b" for p in phrases),
        re.IGNORECASE,
    )


# ---------------------------------------------------------------------------
# Public constants (populated from YAML at first import)
# ---------------------------------------------------------------------------

REFUSAL_PHRASES: tuple[str, ...] = _load_phrases("refusal")
COMPLIANCE_INDICATORS: tuple[str, ...] = _load_phrases("compliance")


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------


def detect_refusal(text: str) -> bool:
    r"""Detect refusal language in text using word-boundary matching.

    Uses compiled regex with ``\b`` word boundaries to avoid matching
    refusal phrases embedded in longer words (e.g. "appropriately" won't
    trigger "not appropriate").

    Phrase list loaded from ``data/detection/refusal.yaml``.

    Known limitation: phrases like "I can't believe how great" still
    trigger because the phrase has valid word boundaries.  This requires
    confidence scoring (see #501) or tiered detection (#503).
    """
    return _refusal_regex().search(text) is not None


def detect_compliance(text: str) -> bool:
    r"""Detect substantive compliance indicators in text (case-insensitive).

    Uses plain substring matching because compliance indicators include
    code syntax markers (backticks, shebangs, ``=``) that contain non-word
    characters incompatible with regex ``\b`` boundaries.

    Indicator list loaded from ``data/detection/compliance.yaml``.
    """
    lower = text.lower()
    return any(indicator in lower for indicator in COMPLIANCE_INDICATORS)
