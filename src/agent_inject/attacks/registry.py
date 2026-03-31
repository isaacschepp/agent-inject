"""Attack registry with decorator-based registration and importlib discovery."""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from typing import TYPE_CHECKING

_logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from agent_inject.attacks.base import BaseAttack

_ATTACKS: dict[str, type[BaseAttack]] = {}
_discovered = False


def register_attack[T: "BaseAttack"](cls: type[T]) -> type[T]:
    """Register an attack class by name."""
    _ATTACKS[cls.name] = cls
    return cls


def get_attack(name: str) -> type[BaseAttack]:
    """Get a registered attack class by name."""
    _ensure_discovered()
    if name not in _ATTACKS:
        msg = f"Unknown attack: {name!r}. Available: {sorted(_ATTACKS)}"
        raise KeyError(msg)
    return _ATTACKS[name]


def get_all_attacks() -> dict[str, type[BaseAttack]]:
    """Get all registered attack classes."""
    _ensure_discovered()
    return dict(_ATTACKS)


def _ensure_discovered() -> None:
    """Auto-discover attack modules on first access."""
    global _discovered
    if _discovered:
        return
    _discover_builtin_attacks()
    _discovered = True


def _discover_builtin_attacks() -> None:
    """Scan agent_inject.attacks subpackages for BaseAttack subclasses."""
    import agent_inject.attacks as attacks_pkg
    from agent_inject.attacks.base import BaseAttack, FixedJailbreakAttack

    base_classes = {BaseAttack, FixedJailbreakAttack}

    for module_info in pkgutil.walk_packages(
        attacks_pkg.__path__,
        prefix="agent_inject.attacks.",
    ):
        if module_info.name in ("agent_inject.attacks.base", "agent_inject.attacks.registry"):
            continue
        try:
            module = importlib.import_module(module_info.name)
        except ImportError:
            _logger.warning("Failed to import attack module: %s", module_info.name, exc_info=True)
            continue
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseAttack)
                and not inspect.isabstract(obj)
                and obj not in base_classes
                and obj.name
                and obj.name not in _ATTACKS
            ):
                _ATTACKS[obj.name] = obj
