from __future__ import annotations
import asyncio
from ..config import get_settings
from .types import DetectionResult, Finding, EntityType, Action
from . import l1_deterministic

settings = get_settings()

# Types dont la presence rend un LOCATION potentiellement identifiant
IDENTIFYING_TYPES = {
    EntityType.PERSON, EntityType.EMAIL, EntityType.PHONE_FR,
    EntityType.IBAN, EntityType.CARD, EntityType.NIR,
}


class DetectionEngine:
    """Defense en profondeur : L1 deterministe, L2 NER, L3 semantique,
    L4 juge local. Chaque couche degrade proprement si indisponible."""

    async def analyze(self, text: str) -> DetectionResult:
        result = DetectionResult()

        # L1 — deterministe (< 1ms, confiance 1.0)
        for f in l1_deterministic.scan(text):
            result.add(f)

        # L2 — NER contextuel (Presidio, bloquant -> thread dedie)
        for f in await self._l2_ner(text):
            if not self._overlaps_existing(f, result):
                result.add(f)

        # L3 — empreinte semantique corpus IP
        # (IP_LEAK couvre tout le prompt : pas de deduplication)
        for f in await self._l3_semantic(text):
            result.add(f)

        # L4 — juge local sur cas ambigus
        if self._is_ambiguous(result):
            for f in await self._l4_judge(text, result):
                if not self._overlaps_existing(f, result):
                    result.add(f)

        # --- Regle contextuelle : un lieu seul n'identifie personne ---
        # 'France' dans une question generique reste intact ; le meme mot
        # dans un prompt contenant un nom/IBAN/email devient tokenisable.
        has_identifier = any(
            f.entity_type in IDENTIFYING_TYPES for f in result.findings
        )
        if not has_identifier:
            result.findings = [
                f for f in result.findings
                if f.entity_type != EntityType.LOCATION
            ]

        return result

    # --- Couches ---

    async def _l2_ner(self, text: str) -> list[Finding]:
        try:
            from . import l2_ner
        except ImportError:
            return []  # Presidio non installe : degradation propre
        try:
            return await asyncio.to_thread(l2_ner.scan_sync, text)
        except Exception:
            return []  # L2 ne doit jamais faire tomber la passerelle

    async def _l3_semantic(self, text: str) -> list[Finding]:
        try:
            from . import l3_semantic
        except ImportError:
            return []
        try:
            return await asyncio.to_thread(l3_semantic.scan_sync, text)
        except Exception:
            return []  # L3 ne doit jamais faire tomber la passerelle

    async def _l4_judge(self, text: str, partial: DetectionResult) -> list[Finding]:
        try:
            from . import l4_judge
        except ImportError:
            return []
        try:
            return await l4_judge.judge(text)
        except Exception:
            return []  # le juge ne doit jamais faire tomber la passerelle

    # --- Utilitaires ---

    @staticmethod
    def _overlaps_existing(f: Finding, result: DetectionResult) -> bool:
        """L1 (valide algorithmiquement) prime sur L2/L4 en recouvrement."""
        return any(f.start < e.end and f.end > e.start for e in result.findings)

    def _is_ambiguous(self, result: DetectionResult) -> bool:
        c = result.max_confidence()
        return settings.ambiguity_low <= c <= settings.ambiguity_high

    # --- Politique de decision ---

    def decide(self, finding: Finding) -> Action:
        if finding.entity_type == EntityType.SECRET:
            return Action.BLOCK
        if finding.entity_type == EntityType.IP_LEAK:
            return Action.BLOCK
        return Action.TOKENIZE