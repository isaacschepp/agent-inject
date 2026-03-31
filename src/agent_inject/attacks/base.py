"""Base classes for all attacks."""

from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any, ClassVar

from agent_inject.models import DeliveryVector, Payload, PayloadInstance, PayloadTier, TargetOutcome

_logger = logging.getLogger(__name__)


class BaseAttack(ABC):
    """Abstract base class for all attacks."""

    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    is_dos_attack: ClassVar[bool] = False

    @abstractmethod
    def generate_payloads(
        self,
        goal: str,
        delivery_vector: DeliveryVector = DeliveryVector.DIRECT,
        **kwargs: Any,
    ) -> list[PayloadInstance]:
        """Generate attack payload instances for the given goal."""

    def generate_canary(self) -> str:
        """Generate a unique canary string for detection."""
        return f"CANARY-{uuid.uuid4().hex[:12]}"


class FixedJailbreakAttack(BaseAttack):
    """Convenience class for template-based attacks."""

    _templates: ClassVar[list[str]] = []
    _tier: ClassVar[PayloadTier] = PayloadTier.CLASSIC
    _target_outcomes: ClassVar[tuple[TargetOutcome, ...]] = (TargetOutcome.GOAL_HIJACKING,)

    def generate_payloads(
        self,
        goal: str,
        delivery_vector: DeliveryVector = DeliveryVector.DIRECT,
        **kwargs: Any,
    ) -> list[PayloadInstance]:
        """Render all templates with the given goal and context."""
        format_vars: dict[str, Any] = {
            "user": "the user",
            "model": "the assistant",
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "pid": str(uuid.uuid4().int % 100000),
            **kwargs,
        }

        instances: list[PayloadInstance] = []
        for i, template in enumerate(self._templates):
            canary = self.generate_canary()
            format_vars["goal"] = goal
            format_vars["rogue_string"] = canary
            format_vars["canary"] = canary
            try:
                rendered = template.format(**format_vars)
            except KeyError as exc:
                _logger.warning(
                    "Skipping %s template %d: missing placeholder %s",
                    self.name,
                    i,
                    exc,
                )
                continue
            payload = Payload(
                id=f"{self.name}-{i}",
                template=template,
                tier=self._tier,
                delivery_vectors=(delivery_vector,),
                target_outcomes=self._target_outcomes,
                source=self.__class__.__module__,
                year=2026,
            )
            instances.append(
                PayloadInstance(
                    payload=payload,
                    rendered=rendered,
                    delivery_vector=delivery_vector,
                    goal=goal,
                    rogue_string=canary,
                )
            )
        return instances
