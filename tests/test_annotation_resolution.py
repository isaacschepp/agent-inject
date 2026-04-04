# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Verify that all *class* type annotations resolve at runtime (#528).

With ``from __future__ import annotations``, annotations are strings at
class-definition time.  However, ``typing.get_type_hints()`` — called by
documentation tools, serializers, and Pydantic — evaluates them via
``eval()`` in the module's global namespace.  If a name was imported
under ``if TYPE_CHECKING:`` but is used in a dataclass field annotation,
``get_type_hints()`` raises ``NameError``.

This test walks every class in ``agent_inject`` and calls
``get_type_hints()`` to catch this bug class before it reaches production.

Note: **function** annotations under ``TYPE_CHECKING`` are intentionally
NOT tested — no runtime consumer evaluates them.  This bug class only
affects classes (dataclasses, Pydantic models, attrs) where frameworks
introspect field annotations at runtime.
"""

from __future__ import annotations

import importlib
import pkgutil
import typing

import agent_inject

# Modules that have import-time side effects (e.g., Typer CLI entrypoint).
_SKIP_MODULES = frozenset({"agent_inject.__main__"})


def test_all_class_annotations_resolve() -> None:
    """typing.get_type_hints() must succeed for every class in the package."""
    errors: list[str] = []
    for _importer, modname, _ispkg in pkgutil.walk_packages(
        path=agent_inject.__path__,
        prefix="agent_inject.",
    ):
        if modname in _SKIP_MODULES:
            continue
        module = importlib.import_module(modname)
        for name in dir(module):
            obj = getattr(module, name)
            if not isinstance(obj, type):
                continue
            if obj.__module__ != modname:
                continue  # skip re-exports
            try:
                typing.get_type_hints(obj)
            except NameError as exc:
                errors.append(f"{modname}.{name}: {exc}")
    assert not errors, "Annotations that fail at runtime:\n" + "\n".join(errors)
