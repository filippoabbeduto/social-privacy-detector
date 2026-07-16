# ==============================================================================
# RISK EMPIRICAL - Modello di rischio empirico (SDCC)
# Percorso: backend/services/risk_empirical.py
#
# Rischio = Σ Pₐ·Iₐ sugli attacchi abilitati dai dati esposti (framework NIST SP 800-30).
#   - Impatto (I): dalle perdite medie per vittima dell'FBI IC3 2025 Annual Report,
#     mappate ordinalmente su scala 1–10.
#   - Probabilità (P): tassi di click/successo pubblicati dove disponibili — Verizon DBIR
#     2026 (phishing email ~1.4%, phone-centric ~2%) e Proofpoint 2024 (fallimento
#     simulazioni 9.3%). Le P non pubblicate (spear/ATO/SIM/furto identità) sono
#     verosimiglianze MODELLATE, non citazioni.
# Vedi design/2026-07-13-empirical-risk-model-design.md per fonti e onestà dei valori.
#
# Alternativa a services/risk_scorer.py (modello euristico). Selezione via RISK_MODEL.
# ==============================================================================

from collections import namedtuple
from typing import List

from models.schemas import PIIEntity
from services.risk_scorer import (
    _confidence_multiplier,
    CONFIDENCE_FLOOR,
    _compress,
    RISK_THRESHOLDS,
    extract_features,
)

# ──────────────────────────────────────────────────────────────────────────────
# CATALOGO ATTACCHI
# ──────────────────────────────────────────────────────────────────────────────

Attack = namedtuple("Attack", "id label required P I kind")

# required = frozenset di tipi CANONICI (vedi _ALIASES). kind="contextual" → riceve il
# moltiplicatore di credibilità dalla routine (spear/doxing sfruttano il contesto);
# "other" no. Ordine irrilevante (si ordina per P·I a runtime).
ATTACKS: List[Attack] = [
    Attack("spam",             "Spam / Telemarketing",            frozenset({"EMAIL"}),                                0.15,  1.5, "other"),
    Attack("phishing",         "Phishing generico",               frozenset({"EMAIL"}),                                0.014, 3.0, "other"),
    Attack("smishing",         "Smishing (SMS)",                  frozenset({"PHONE_NUMBER"}),                         0.02,  3.0, "other"),
    # Multicanale: avere ENTRAMBI i canali di contatto abilita attacchi combinati (mail
    # falsa + SMS di conferma), più efficaci del singolo canale — è l'effetto di correlazione
    # email+telefono (P modello, coerente coi tassi di interazione multicanale).
    Attack("multichannel",     "Attacco multicanale",             frozenset({"EMAIL", "PHONE_NUMBER"}),                0.09,  4.0, "other"),
    Attack("spear_bec",        "Spear phishing / BEC",            frozenset({"EMAIL", "NAME", "ORGANIZATION"}),        0.20,  9.5, "contextual"),
    Attack("ato",              "Account takeover",                frozenset({"EMAIL", "DATE_OF_BIRTH"}),               0.05,  8.0, "other"),
    Attack("sim_swap",         "SIM swapping",                    frozenset({"PHONE_NUMBER", "DATE_OF_BIRTH"}),        0.05,  7.5, "other"),
    Attack("id_theft_base",    "Furto d'identità (base)",         frozenset({"NAME", "DATE_OF_BIRTH", "ADDRESS"}),     0.06,  6.0, "other"),
    Attack("id_theft_cf",      "Furto d'identità (con CF)",       frozenset({"NAME", "DATE_OF_BIRTH", "FISCAL_CODE"}), 0.15,  9.5, "other"),
    Attack("financial_fraud",  "Frode di pagamento",              frozenset({"IBAN", "NAME"}),                         0.09,  7.0, "other"),
    Attack("financial_fraud2", "Frode di pagamento",              frozenset({"CREDIT_DEBIT_NUMBER", "NAME"}),          0.09,  7.0, "other"),
    # Identità finanziaria: codice fiscale + coordinate bancarie = kit per frodi
    # creditizie/apertura conti a nome della vittima, anche senza data di nascita.
    Attack("financial_identity","Identità finanziaria (CF+IBAN)",  frozenset({"FISCAL_CODE", "IBAN"}),                  0.10,  9.0, "other"),
    Attack("doxing",           "Doxing / stalking",               frozenset({"NAME", "ADDRESS"}),                      0.05,  6.0, "contextual"),
    Attack("impersonation_cf", "Impersonificazione servizi (CF)", frozenset({"FISCAL_CODE"}),                          0.04,  8.0, "other"),
    # Esposizione dell'IDENTITÀ (nome, username, link): non abilita frodi dirette ma
    # rende la persona impersonabile e correlabile fra piattaforme (OSINT). Prima questi
    # dati valevano 0 → un profilo con identità pubblica risultava "a rischio nullo".
    Attack("impersonation",    "Impersonificazione dell'identità", frozenset({"NAME"}),                                0.08,  5.0, "contextual"),
    Attack("osint_username",   "Correlazione cross-platform (OSINT)", frozenset({"USERNAME"}),                         0.10,  3.5, "other"),
    Attack("osint_url",        "Ricognizione OSINT (link personali)", frozenset({"URL"}),                              0.05,  3.0, "other"),
]

# Alias → tipo canonico usato nel catalogo. Comprehend e il motore regex usano nomi
# diversi per lo stesso concetto; qui li unifichiamo così il catalogo è indipendente
# dall'estrattore (Comprehend vs Presidio vs regex).
_ALIASES = {
    "PHONE": "PHONE_NUMBER",
    "AGE": "DATE_OF_BIRTH",
    "BANK_ACCOUNT_NUMBER": "IBAN",
    "INTERNATIONAL_BANK_ACCOUNT_NUMBER": "IBAN",
    "SSN": "FISCAL_CODE",
    "PASSPORT_NUMBER": "FISCAL_CODE",
}

# ──────────────────────────────────────────────────────────────────────────────
# TARATURA (verificata in audit — vedi audit/risk-score-empirical-2026-07-13.md)
# EMP_SCALE porta un profilo che abilita un attacco grave (spear/BEC, P·I≈1.9) verso la
# fascia HIGH; EMP_COMPRESSION_K spalma la fascia alta così solo il quasi-massimo → 100.
# ──────────────────────────────────────────────────────────────────────────────

# Valori tarati (vedi audit): S=41 porta gli attacchi gravi (spear/BEC ≈75, furto identità con
# CF ≈70, identità finanziaria CF+IBAN ≈72) in fascia HIGH e i singoli dati di contatto in LOW;
# K=100 (come il modello euristico) evita saturazione — nessun profilo realistico raggiunge 100.
EMP_SCALE = 41.0
EMP_COMPRESSION_K = 100.0


def _normalize_types(piis: List[PIIEntity]) -> set:
    """Insieme dei tipi canonici presenti (applica gli alias)."""
    return {_ALIASES.get(p.type, p.type) for p in piis}


def _fired_attacks(present: set) -> List[Attack]:
    """Attacchi abilitati (required ⊆ present), ordinati per rischio atteso Pₐ·Iₐ desc."""
    fired = [a for a in ATTACKS if a.required <= present]
    return sorted(fired, key=lambda a: a.P * a.I, reverse=True)


# ──────────────────────────────────────────────────────────────────────────────
# SCORING
# ──────────────────────────────────────────────────────────────────────────────

def _attack_points(a: Attack, pii_by_type: dict, credibility: float) -> float:
    """Contributo (non scalato) dell'attacco: Pₐ·Iₐ, modulato dalla confidenza MINIMA
    dei dati richiesti e, per gli attacchi contestuali, dal moltiplicatore di credibilità."""
    conf = min(_confidence_multiplier(pii_by_type.get(t, 0.0)) for t in a.required)
    mult = credibility if a.kind == "contextual" else 1.0
    return a.P * a.I * conf * mult


def _credibility(detected_piis: List[PIIEntity]) -> float:
    """Moltiplicatore di credibilità (routine): un luogo/organizzazione ripetuto rende gli
    attacchi contestuali (spear, doxing) più credibili. Cap prudente a 1.2."""
    feats = extract_features([p for p in detected_piis if p.score >= CONFIDENCE_FLOOR])
    reps = feats.get("raw_repetitions", {})
    max_rep = max((c for texts in reps.values() for c in texts.values()), default=0)
    return 1.0 + min(0.2, max(0, max_rep - 2) * 0.1)  # 3 rip → 1.1, 4+ → 1.2


def _distribute_points(contrib_values: List[float], raw: float, score: int) -> List[int]:
    """Ripartisce lo score FINALE (compresso) tra i contributi in interi che sommano
    ESATTAMENTE a score (metodo del resto più grande / Hamilton): evita il drift di
    arrotondamento quando ci sono molte combo (la somma mostrata coincide col verdetto).
    Ordine di input preservato. Sotto la soglia di compressione, score=EMP_SCALE·raw →
    le quote coincidono con round(EMP_SCALE·c)."""
    if raw <= 0 or score <= 0 or not contrib_values:
        return [0] * len(contrib_values)
    ideal = [c / raw * score for c in contrib_values]
    floors = [int(x) for x in ideal]
    remainder = score - sum(floors)
    # Assegna i `remainder` punti residui ai contributi col resto frazionario maggiore.
    order = sorted(range(len(ideal)), key=lambda i: ideal[i] - floors[i], reverse=True)
    for i in order[:remainder]:
        floors[i] += 1
    return floors


def _build(detected_piis: List[PIIEntity], apply_floor: bool, credibility: float):
    """Nucleo condiviso: restituisce (present, pii_by_type, contribs, raw, score)."""
    reliable = [p for p in detected_piis if (not apply_floor or p.score >= CONFIDENCE_FLOOR)]
    present = _normalize_types(reliable)
    pii_by_type: dict = {}
    for p in reliable:
        t = _ALIASES.get(p.type, p.type)
        pii_by_type[t] = max(pii_by_type.get(t, 0.0), p.score)
    fired = _fired_attacks(present)
    contribs = [(a, _attack_points(a, pii_by_type, credibility)) for a in fired]
    raw = sum(c for _, c in contribs)
    score = min(100, round(_compress(EMP_SCALE * raw)))
    return present, pii_by_type, contribs, raw, score


def build_empirical_assessment(detected_piis: List[PIIEntity], apply_floor: bool = True):
    """Entry point: restituisce (risk_level, explanation, score, motivations)."""
    cred = _credibility(detected_piis)
    _, _, contribs, raw, score = _build(detected_piis, apply_floor, cred)

    if score >= RISK_THRESHOLDS["HIGH"]:
        level = "HIGH"
    elif score >= RISK_THRESHOLDS["MEDIUM"]:
        level = "MEDIUM"
    else:
        level = "LOW"

    pts = _distribute_points([c for _, c in contribs], raw, score)
    motivations = [
        f"{a.label}: P {a.P:.0%} × impatto {a.I:g} → +{p}pt"
        for (a, _), p in zip(contribs, pts)
    ]
    if not contribs:
        explanation = (
            "Nessuna combinazione di dati esposti abilita un attacco noto: l'esposizione al "
            f"social engineering risulta minima. Score di rischio {score}/100."
        )
    else:
        top = contribs[0][0]
        explanation = (
            f"I dati esposti abilitano {len(contribs)} vettori d'attacco; il più grave è "
            f"«{top.label}» (impatto {top.I:g}/10). Il punteggio è il rischio atteso (probabilità × "
            f"impatto) aggregato su tutti i vettori. Score di rischio {score}/100."
        )
    return level, explanation, score, motivations


def build_empirical_extras(detected_piis: List[PIIEntity], apply_floor: bool = True) -> dict:
    """Dati strutturati per la UI: attacchi scattati (per la mappa) + routine.
    Stessa forma del modello euristico: {combos, repetitions}."""
    cred = _credibility(detected_piis)
    _, _, contribs, raw, score = _build(detected_piis, apply_floor, cred)
    pts = _distribute_points([c for _, c in contribs], raw, score)
    combos = [
        {"label": a.label, "types": sorted(a.required), "points": p, "impact": a.I}
        for (a, _), p in zip(contribs, pts)
    ]
    # Ordina per punti mostrati decrescenti: la mappa legge dall'alto (contributo maggiore).
    combos.sort(key=lambda c: c["points"], reverse=True)

    feats = extract_features(
        [p for p in detected_piis if (not apply_floor or p.score >= CONFIDENCE_FLOOR)]
    )
    repetitions = []
    for pii_type, text_counts in feats.get("raw_repetitions", {}).items():
        for text, c in text_counts.items():
            if c >= 3:
                lbl = "routine geografica" if pii_type == "LOCATION" else "affiliazione confermata"
                repetitions.append({"type": pii_type, "text": text, "count": c, "label": lbl})
    repetitions.sort(key=lambda r: r["count"], reverse=True)

    return {"combos": combos, "repetitions": repetitions}
