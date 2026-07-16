# ==============================================================================
# COMUNI - Decodifica DETERMINISTICA del comune di nascita dal codice fiscale.
# ==============================================================================
# Il codice catastale è ai caratteri 12–15 del CF: 1 lettera + 3 cifre
# (es. L353 → Trebisacce). La mappa codice→comune è una tabella di ~7900 voci
# (data/comuni.json, da comuni-json). Lookup O(1), offline, zero allucinazioni.
#
# Perché NON un LLM: mappare ~8000 codici catastali è un compito di *lookup*, non
# generativo; un LLM li confonde (es. dava Torino/L219 per L353/Trebisacce). Qui il
# risultato è esatto e riproducibile.
# ==============================================================================

import os
import json
import logging
from typing import Optional, List, Dict

logger = logging.getLogger("social-privacy-backend")

_TABLE: Optional[Dict[str, str]] = None

# Omocodia: quando due persone avrebbero lo stesso CF, alcune CIFRE sono sostituite
# da lettere secondo questa mappa. Va invertita sulle 3 cifre del codice catastale
# prima del lookup. (Stesso schema usato lato frontend.)
_OMO = {"L": "0", "M": "1", "N": "2", "P": "3", "Q": "4",
        "R": "5", "S": "6", "T": "7", "U": "8", "V": "9"}


def _load() -> Dict[str, str]:
    global _TABLE
    if _TABLE is None:
        path = os.path.join(os.path.dirname(__file__), "data", "comuni.json")
        try:
            with open(path, encoding="utf-8") as f:
                _TABLE = json.load(f)
        except Exception as e:
            logger.error(f"[Comuni] tabella non caricata ({e}); decodifica comune disattivata.")
            _TABLE = {}
    return _TABLE


def comune_from_cf(cf: str) -> Optional[str]:
    """Restituisce il comune di nascita dal CF (16 char) o None se il codice non è
    valido / non in tabella. Gestisce l'omocodia sulle cifre del codice catastale."""
    cf = (cf or "").strip().upper()
    if len(cf) != 16:
        return None
    code = cf[11:15]  # caratteri 12–15 (0-indexed 11..14)
    if not code or not code[0].isalpha():
        return None
    # De-omocodia le 3 posizioni numeriche (indici 1–3 del codice catastale).
    numeric = "".join(_OMO.get(ch, ch) for ch in code[1:])
    codice_catastale = code[0] + numeric
    return _load().get(codice_catastale)


def decode_fiscal_codes(cf_texts: List[str]) -> List[dict]:
    """Decodifica una lista di CF nel formato usato dalla UI: [{code, birthplace}].
    Solo le decodifiche riuscite sono incluse."""
    out = []
    for raw in cf_texts:
        code = (raw or "").strip().upper()
        comune = comune_from_cf(code)
        if code and comune:
            out.append({"code": code, "birthplace": comune})
    return out
