"""Base classes for all attacks."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from agent_inject.models import DeliveryVector, Payload, PayloadInstance, PayloadTier, TargetOutcome


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

    def generate_payloads(
        self,
        goal: str,
        delivery_vector: DeliveryVector = DeliveryVector.DIRECT,
        **kwargs: Any,
    ) -> list[PayloadInstance]:
        """Render all templates with the given goal and context."""
        canary = self.generate_canary()
        user = kwargs.get("user", "the user")
        model = kwargs.get("model", "the assistant")

        instances: list[PayloadInstance] = []
        for i, template in enumerate(self._templates):
            rendered = template.format(
                goal=goal,
                rogue_string=canary,
                user=user,
                model=model,
                canary=canary,
            )
            payload = Payload(
                id=f"{self.name}-{i}",
                template=template,
                tier=PayloadTier.CLASSIC,
                delivery_vectors=(delivery_vector,),
                target_outcomes=(TargetOutcome.GOAL_HIJACKING,),
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
