# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Base classes for all attacks."""

from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any, ClassVar, override

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
    _source: ClassVar[str] = ""
    _year: ClassVar[int] = 2026
    _mitre_atlas_ids: ClassVar[tuple[str, ...]] = ()
    _owasp_llm_ids: ClassVar[tuple[str, ...]] = ()
    _owasp_asi_ids: ClassVar[tuple[str, ...]] = ()

    @override
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
            except (KeyError, ValueError, IndexError) as exc:
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
                source=self._source or self.__class__.__module__,
                year=self._year,
                mitre_atlas_ids=self._mitre_atlas_ids,
                owasp_llm_ids=self._owasp_llm_ids,
                owasp_asi_ids=self._owasp_asi_ids,
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
