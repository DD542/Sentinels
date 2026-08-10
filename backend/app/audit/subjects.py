"""
Index aveugle des personnes concernées (RGPD art. 15 et 17).

Problème : pour répondre à « effacez tout ce que vous avez sur Jean
Dupont », il faut pouvoir *retrouver* ses entrées d'audit. Mais stocker
« Jean Dupont » en clair reviendrait à constituer exactement le fichier
de données personnelles que SENTINEL est censé empêcher.

Solution : un **index aveugle**. On stocke `HMAC-SHA256(clé secrète,
valeur normalisée)` — une référence :

* **déterministe** : la même personne donne toujours la même référence,
  donc on peut la retrouver ;
* **non réversible** : la référence ne permet pas de remonter au nom ;
* **non énumérable** : sans la clé, impossible de tester « et si c'était
  Jean Dupont ? ». C'est ce qui distingue un HMAC d'un simple SHA-256 :
  un annuaire de noms ne suffit pas à casser l'index.

La référence sert aussi d'identifiant de clé de chiffrement : toutes les
entrées d'une même personne partagent une DEK, donc l'oublier détruit
ses données **et rien que les siennes**.
"""
from __future__ import annotations
import hashlib
import hmac
import re
import unicodedata

from ..config import get_settings

settings = get_settings()

_NON_ALNUM = re.compile(r"[^0-9a-z]+")


def _subject_key() -> bytes:
    """Clé de l'index, à domaine séparé : ni le scellement de la chaîne,
    ni l'enveloppe des clés de données ne réutilisent ce matériel."""
    return hashlib.sha256(
        bytes.fromhex(settings.audit_hmac_key) + b"subject-index").digest()


def normalize(value: str) -> str:
    """Rapproche les écritures d'une même personne ou d'une même donnée :
    casse, accents, espaces et séparateurs sont neutralisés.

    « Jean Dupont », « jean dupont » et « Jean  DUPONT » convergent ;
    « FR76 1010 7001 » et « FR7610107001 » aussi."""
    decomposed = unicodedata.normalize("NFKD", value)
    without_accents = "".join(c for c in decomposed
                              if not unicodedata.combining(c))
    return _NON_ALNUM.sub("", without_accents.casefold())


def subject_ref(value: str | None) -> str | None:
    """Référence aveugle d'une personne concernée. None si la valeur ne
    contient rien d'exploitable (on n'indexe pas du vide)."""
    if not value:
        return None
    normalized = normalize(value)
    if not normalized:
        return None
    digest = hmac.new(_subject_key(), normalized.encode(),
                      hashlib.sha256).hexdigest()
    return f"subj:{digest[:32]}"
