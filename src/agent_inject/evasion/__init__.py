"""Evasion transforms for bypassing injection detectors."""

from agent_inject.evasion.transforms import (
    BUILTIN_TRANSFORMS,
    ROT13,
    Base64Encode,
    CharSpacing,
    EvasionTransform,
    FullwidthChars,
    Homoglyph,
    Leetspeak,
    TextReversal,
    TransformChain,
    ZeroWidthInsert,
    apply_evasion_chains,
    compose,
    compose_by_name,
)

__all__ = [
    "BUILTIN_TRANSFORMS",
    "ROT13",
    "Base64Encode",
    "CharSpacing",
    "EvasionTransform",
    "FullwidthChars",
    "Homoglyph",
    "Leetspeak",
    "TextReversal",
    "TransformChain",
    "ZeroWidthInsert",
    "apply_evasion_chains",
    "compose",
    "compose_by_name",
]
