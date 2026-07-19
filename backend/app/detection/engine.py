from __future__ import annotations
import asyncio
from ..config import get_settings
from .types import DetectionResult, Finding, EntityType, Action
from . import l1_deterministic
from . import l0_normalize

settings = get_settings()

IDENTIFYING_TYPES = {
    EntityType.PERSON, EntityType.EMAIL, EntityType.PHONE_FR,
    EntityType.IBAN, EntityType.CARD, EntityType.NIR,
}


class DetectionEngine:
    """Défense en profondeur : L0 dé-obfuscation, L1 déterministe,
    L2 NER, L3 sémantique, L4 juge local. Chaque couche dégrade
    proprement si indisponible."""

    async def analyze(self, text: str,
                      client_id: str = "default") -> DetectionResult:
        """client_id cloisonne la couche L3 : chaque client n'est confronte
        qu'a SON corpus confidentiel (isolation multi-tenant)."""
        result = DetectionResult()

        # L0 — révèle les données dissimulées (base64, hex, espacement).
        # On scanne l'original ET chaque variante dé-obfusquée.
        views = l0_normalize.normalized_views(text)

        # Tentatives de contournement : drapeau d'audit (n'altère pas la détection)
        evasion = l0_normalize.detect_evasion(text)
        if evasion:
            result.evasion_attempts = evasion

        seen_values: set[tuple[str, int]] = set()

        for view in views:
            sub = await self._analyze_single(view.text, client_id)
            for f in sub.findings:
                key = (f.entity_type.value, hash(f.value))
                if key in seen_values:
                    continue
                seen_values.add(key)
                # Trace la technique d'obfuscation détectée
                if view.technique != "raw":
                    f.meta["obfuscation"] = view.technique
                result.add(f)

        # Règle contextuelle : un lieu seul n'identifie personne.
        has_identifier = any(
            f.entity_type in IDENTIFYING_TYPES for f in result.findings
        )
        if not has_identifier:
            result.findings = [
                f for f in result.findings
                if f.entity_type != EntityType.LOCATION
            ]

        return result

    async def _analyze_single(self, text: str, client_id: str) -> DetectionResult:
        """Pipeline L1-L4 sur un texte donné (une vue)."""
        result = DetectionResult()

        for f in l1_deterministic.scan(text):
            result.add(f)

        for f in await self._l2_ner(text):
            if not self._overlaps_existing(f, result):
                result.add(f)

        for f in await self._l3_semantic(text, client_id):
            result.add(f)

        if self._is_ambiguous(result):
            for f in await self._l4_judge(text, result):
                if not self._overlaps_existing(f, result):
                    result.add(f)

        return result

    # --- Couches ---

    async def _l2_ner(self, text: str) -> list[Finding]:
        try:
            from . import l2_ner
        except ImportError:
            return []
        try:
            return await asyncio.to_thread(l2_ner.scan_sync, text)
        except Exception:
            return []

    async def _l3_semantic(self, text: str, client_id: str) -> list[Finding]:
        try:
            from . import l3_semantic
        except ImportError:
            return []
        try:
            return await asyncio.to_thread(l3_semantic.scan_sync, text, client_id)
        except Exception:
            return []

    async def _l4_judge(self, text: str, partial: DetectionResult) -> list[Finding]:
        try:
            from . import l4_judge
        except ImportError:
            return []
        try:
            return await l4_judge.judge(text)
        except Exception:
            return []

    # --- Utilitaires ---

    @staticmethod
    def _overlaps_existing(f: Finding, result: DetectionResult) -> bool:
        return any(f.start < e.end and f.end > e.start for e in result.findings)

    def _is_ambiguous(self, result: DetectionResult) -> bool:
        c = result.max_confidence()
        return settings.ambiguity_low <= c <= settings.ambiguity_high

    # --- Politique de décision ---

    def decide(self, finding: Finding) -> Action:
        if finding.entity_type == EntityType.SECRET:
            return Action.BLOCK
        if finding.entity_type == EntityType.IP_LEAK:
            return Action.BLOCK
        return Action.TOKENIZE