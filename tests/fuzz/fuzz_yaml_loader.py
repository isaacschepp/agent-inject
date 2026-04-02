# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Fuzz the YAML payload loader with random input to find crashes."""

from __future__ import annotations

import contextlib
import sys

import atheris

with atheris.instrument_imports():
    import yaml
    from pydantic import ValidationError

    from agent_inject.attacks.loader import YamlPayloadFile


def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(1024)

    if not text:
        return

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError:
        return

    if not isinstance(raw, dict):
        return

    with contextlib.suppress(ValidationError, ValueError, TypeError):
        YamlPayloadFile.model_validate(raw)


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
