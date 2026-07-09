from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum


class EntityType(str, Enum):
    IBAN = "IBAN"
    CARD = "CARD"
    NIR = "NIR"
    SIRET = "SIRET"
    EMAIL = "EMAIL"
    PHONE_FR = "PHONE_FR"
    PERSON = "PERSON"
    LOCATION = "LOCATION"
    SECRET = "SECRET"
    IP_LEAK = "IP_LEAK"


class Action(str, Enum):
    ALLOW = "ALLOW"
    TOKENIZE = "TOKENIZE"
    BLOCK = "BLOCK"


@dataclass
class Finding:
    entity_type: EntityType
    start: int
    end: int
    value: str
    confidence: float
    layer: str
    meta: dict = field(default_factory=dict)


@dataclass
class DetectionResult:
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def max_confidence(self) -> float:
        return max((f.confidence for f in self.findings), default=0.0)