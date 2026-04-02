# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Fuzz evasion transforms with random input to find crashes and hangs."""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from agent_inject.evasion.transforms import (
        ROT13,
        Base64Encode,
        CharSpacing,
        FullwidthChars,
        Homoglyph,
        Leetspeak,
        TextReversal,
        ZeroWidthInsert,
        compose,
    )

TRANSFORMS = [
    Base64Encode(),
    ROT13(),
    Leetspeak(),
    CharSpacing(),
    Homoglyph(),
    FullwidthChars(),
    ZeroWidthInsert(),
    TextReversal(),
]


def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(512)

    if not text:
        return

    for transform in TRANSFORMS:
        try:
            result = transform.apply(text)
            assert isinstance(result, str)
        except (ValueError, UnicodeEncodeError, UnicodeDecodeError):
            pass

    idx_a = fdp.ConsumeIntInRange(0, len(TRANSFORMS) - 1)
    idx_b = fdp.ConsumeIntInRange(0, len(TRANSFORMS) - 1)
    try:
        chain = compose(TRANSFORMS[idx_a], TRANSFORMS[idx_b])
        result = chain.apply(text)
        assert isinstance(result, str)
    except (ValueError, UnicodeEncodeError, UnicodeDecodeError):
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
