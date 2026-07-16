# ==============================================================================
# DOSSIER - Ricomposizione deterministica dell'identità dai frammenti PII.
# ==============================================================================
# Rende LETTERALE la tesi del prodotto: i dati sparsi, uniti, ricostruiscono una
# persona. Nessun LLM: assembla i campi presenti in una frase; elenca cosa manca
# ancora all'attaccante. Solo dati già estratti.
# ==============================================================================

from typing import List, Dict
from models.schemas import PIIEntity

# Etichette umane per i tipi PII assenti (lacune dell'attaccante).
_MISSING_LABEL = {
    "PHONE_NUMBER": "un telefono", "EMAIL": "un'email", "IBAN": "un IBAN",
    "FISCAL_CODE": "il codice fiscale", "DATE_OF_BIRTH": "la data di nascita",
    "ADDRESS": "un indirizzo",
}


def _first(piis, t):
    for p in piis:
        if p.type == t:
            return p.text
    return None


def build_dossier(piis: List[PIIEntity], fiscal_code_info: List[dict]) -> Dict:
    if not piis:
        return {"text": "", "missing": []}
    name = _first(piis, "NAME") or "Questa persona"
    parts = [f"{name}"]
    dob = _first(piis, "DATE_OF_BIRTH")
    place = None
    if fiscal_code_info:
        place = (fiscal_code_info[0] or {}).get("birthplace")
    if dob:
        parts.append(f"nata/o il {dob}" + (f" ({place})" if place else ""))
    age = _first(piis, "AGE")
    if age and not dob:
        parts.append(f"di {age}")
    loc = _first(piis, "LOCATION")
    if loc:
        parts.append(f"riconducibile a {loc}")
    org = _first(piis, "ORGANIZATION")
    if org:
        parts.append(f"legata/o a {org}")
    contacts = [c for c in (_first(piis, "EMAIL"), _first(piis, "PHONE_NUMBER")) if c]
    if contacts:
        parts.append("contattabile tramite " + " e ".join(contacts))
    text = "Agli occhi di un attaccante: " + ", ".join(parts) + "."

    present_types = {p.type for p in piis}
    missing = [lbl for t, lbl in _MISSING_LABEL.items() if t not in present_types]
    return {"text": text, "missing": missing}
