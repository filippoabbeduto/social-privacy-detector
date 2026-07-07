# ==============================================================================
# RISK SCORER - Feature Engineering per il calcolo del Risk Score (SDCC)
# Percorso: backend/services/risk_scorer.py
# ==============================================================================

from typing import List, Tuple
from models.schemas import PIIEntity


# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURAZIONE PESI E SOGLIE
# ──────────────────────────────────────────────────────────────────────────────

# Peso base per singola PII (indipendente dalle combinazioni)
# I pesi sono calibrati per evitare saturazione: un singolo tipo
# non deve mai superare da solo la soglia MEDIUM (35pt).
PII_BASE_WEIGHTS = {
    "EMAIL":         20,
    "PHONE_NUMBER":  20,
    # FISCAL_CODE e IBAN: codici identificativi altamente sensibili (aggiunti
    # insieme al rilevamento in pii_detector.py). Peso alto come EMAIL/PHONE ma,
    # per rispettare la regola "nessun singolo tipo supera da solo la soglia
    # MEDIUM (35pt)", restano a 22.
    "FISCAL_CODE":   22,
    "IBAN":          22,
    "DATE_OF_BIRTH": 15,
    "LOCATION":       8,
    "ORGANIZATION":   5,
    "URL":            5,
    "USERNAME":       4,
}

# Soglie per la classificazione finale
RISK_THRESHOLDS = {
    "HIGH":   70,
    "MEDIUM": 35,
}

# Bonus combinazioni pericolose (social engineering combos)
# Formato: (set di tipi richiesti, bonus punti, label descrittiva)
# NOTA: viene applicata SOLO la combo più specifica (con più tipi matchanti)
# per evitare accumulo artificiale dello score.
COMBO_BONUSES = [
    ({"EMAIL", "PHONE_NUMBER"},                                25, "contatto_diretto_multiplo"),
    ({"EMAIL", "DATE_OF_BIRTH"},                               20, "identita_phishing_combo"),
    ({"PHONE_NUMBER", "DATE_OF_BIRTH"},                        20, "identita_sim_swap_combo"),
    ({"LOCATION", "ORGANIZATION"},                             15, "profilazione_lavorativa"),
    ({"EMAIL", "LOCATION"},                                    15, "spear_phishing_geografico"),
    ({"DATE_OF_BIRTH", "LOCATION"},                            15, "identita_geografica"),
    ({"EMAIL", "PHONE_NUMBER", "DATE_OF_BIRTH"},               35, "identita_completa"),
    ({"EMAIL", "PHONE_NUMBER", "LOCATION"},                    35, "profilo_attacco_completo"),
    ({"EMAIL", "DATE_OF_BIRTH", "LOCATION"},                   30, "identita_completa_geo"),
    ({"EMAIL", "PHONE_NUMBER", "DATE_OF_BIRTH", "LOCATION"},   50, "massima_esposizione"),
]


def _confidence_multiplier(score: float) -> float:
    """
    Modula il peso di una PII in base alla confidence del rilevamento.
    Una PII rilevata con bassa confidenza contribuisce meno allo score finale.
    """
    if score >= 0.95: return 1.0
    if score >= 0.85: return 0.85
    if score >= 0.70: return 0.65
    return 0.40


# ──────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION
# ──────────────────────────────────────────────────────────────────────────────

# Tipi di PII per cui la ripetizione dello stesso testo rivela abitudini.
# LOCATION ripetuta = routine geografica, ORGANIZATION ripetuta = affiliazione confermata.
HABIT_TRACKABLE_TYPES = {"LOCATION", "ORGANIZATION"}


def extract_features(detected_piis: List[PIIEntity]) -> dict:
    """
    Trasforma la lista grezza di PIIEntity in un vettore di feature semantiche.
    Per ogni tipo tiene il massimo score di confidence tra le occorrenze rilevate,
    conta le occorrenze distinte per tipo, e traccia le ripetizioni dello stesso
    testo per LOCATION e ORGANIZATION (pattern di abitudine).
    """

    # Massimo score per tipo (per i pesi base)
    pii_by_type: dict[str, float] = {}
    for pii in detected_piis:
        current_best = pii_by_type.get(pii.type, 0.0)
        pii_by_type[pii.type] = max(current_best, pii.score)

    # Conteggio testi distinti per tipo (per il bonus diversità)
    unique_texts_per_type: dict[str, set] = {}
    for pii in detected_piis:
        unique_texts_per_type.setdefault(pii.type, set()).add(pii.text.lower())
    pii_counts: dict[str, int] = {t: len(texts) for t, texts in unique_texts_per_type.items()}

    # Conteggio ripetizioni grezze per (type, text) — rileva abitudini.
    # Es. "Roma" menzionata 5 volte = l'utente frequenta abitualmente Roma.
    # Tracciamo solo LOCATION e ORGANIZATION (gli unici tipi dove la
    # ripetizione dello stesso dato rivela un pattern comportamentale).
    raw_repetitions: dict[str, dict[str, int]] = {}
    for pii in detected_piis:
        if pii.type in HABIT_TRACKABLE_TYPES:
            type_reps = raw_repetitions.setdefault(pii.type, {})
            text_key = pii.text.lower()
            type_reps[text_key] = type_reps.get(text_key, 0) + 1

    present_types = set(pii_by_type.keys())

    # --- Feature booleane ---
    has_direct_contact  = bool({"EMAIL", "PHONE_NUMBER"} & present_types)
    has_identity_anchor = "DATE_OF_BIRTH" in present_types
    has_location        = "LOCATION" in present_types
    has_org             = "ORGANIZATION" in present_types
    has_url             = "URL" in present_types
    has_username        = "USERNAME" in present_types

    # --- Combinazioni critiche ---
    full_identity_combo   = {"EMAIL", "PHONE_NUMBER", "DATE_OF_BIRTH"}.issubset(present_types)
    spear_phishing_ready  = {"EMAIL", "LOCATION"}.issubset(present_types)
    social_graph_exposed  = has_location and has_org
    sim_swap_risk         = {"PHONE_NUMBER", "DATE_OF_BIRTH"}.issubset(present_types)
    max_exposure          = {"EMAIL", "PHONE_NUMBER", "DATE_OF_BIRTH", "LOCATION"}.issubset(present_types)

    # --- Conteggi aggregati ---
    total_pii_count   = len(detected_piis)
    unique_type_count = len(present_types)
    critical_count    = sum(1 for t in ["EMAIL", "PHONE_NUMBER", "DATE_OF_BIRTH"] if t in present_types)
    contextual_count  = sum(1 for t in ["LOCATION", "ORGANIZATION", "URL", "USERNAME"] if t in present_types)
    avg_confidence    = sum(pii_by_type.values()) / len(pii_by_type) if pii_by_type else 0.0

    return {
        "pii_by_type":          pii_by_type,
        "pii_counts":           pii_counts,
        "raw_repetitions":      raw_repetitions,
        "present_types":        present_types,
        "has_direct_contact":   has_direct_contact,
        "has_identity_anchor":  has_identity_anchor,
        "has_location":         has_location,
        "has_org":              has_org,
        "has_url":              has_url,
        "has_username":         has_username,
        "full_identity_combo":  full_identity_combo,
        "spear_phishing_ready": spear_phishing_ready,
        "social_graph_exposed": social_graph_exposed,
        "sim_swap_risk":        sim_swap_risk,
        "max_exposure":         max_exposure,
        "total_pii_count":      total_pii_count,
        "unique_type_count":    unique_type_count,
        "critical_count":       critical_count,
        "contextual_count":     contextual_count,
        "avg_confidence":       avg_confidence,
    }


# ──────────────────────────────────────────────────────────────────────────────
# SCORE CALCULATION
# ──────────────────────────────────────────────────────────────────────────────

def calculate_risk_score(features: dict) -> Tuple[int, List[str]]:
    """
    Calcola uno score numerico (0-100) a partire dalle feature estratte.
    La logica è a cinque livelli:
      1. Peso base per ogni tipo di PII, modulato dalla confidence
      2. Bonus diversità: testi distinti dello stesso tipo (es. 3 città diverse)
      3. Bonus abitudine: stesso testo ripetuto per LOCATION/ORGANIZATION
      4. Bonus della combo più specifica (mutuamente esclusivi)
      5. Bonus diversità dell'esposizione (tipi distinti)
    Restituisce (score, motivations) per trasparenza nel report.
    """
    score = 0.0
    motivations = []

    pii_by_type = features["pii_by_type"]
    pii_counts  = features["pii_counts"]

    # 1. Pesi base per singola PII, modulati dalla confidence
    for pii_type, confidence in pii_by_type.items():
        base = PII_BASE_WEIGHTS.get(pii_type, 5)
        weighted = base * _confidence_multiplier(confidence)
        score += weighted
        motivations.append(
            f"{pii_type} rilevato (confidence {confidence:.0%}, contributo +{weighted:.0f}pt)"
        )

    # 2. Bonus diversità: testi DISTINTI dello stesso tipo (es. Roma + Milano + Cosenza)
    for pii_type, count in pii_counts.items():
        if count >= 3:
            freq_bonus = min((count - 2) * 3, 15)  # cap a +15pt
            score += freq_bonus
            motivations.append(
                f"{pii_type}: {count} valori distinti rilevati, pattern ricorrente (+{freq_bonus}pt)"
            )

    # 3. Bonus abitudine: stesso testo ripetuto per LOCATION/ORGANIZATION.
    #    Se "Roma" appare 4 volte, l'utente sta rivelando una routine
    #    geografica sfruttabile per social engineering.
    raw_repetitions = features.get("raw_repetitions", {})
    for pii_type, text_counts in raw_repetitions.items():
        for text, reps in text_counts.items():
            if reps >= 3:
                habit_bonus = min((reps - 2) * 4, 12)  # cap a +12pt per singolo testo
                score += habit_bonus
                label = "routine geografica" if pii_type == "LOCATION" else "affiliazione confermata"
                motivations.append(
                    f"{pii_type} '{text}' menzionato {reps} volte: {label} rilevata (+{habit_bonus}pt)"
                )

    # 4. Bonus combo: si applica SOLO la combo più specifica (più tipi matchanti)
    #    per evitare accumulo artificiale dello score.
    #    Ordiniamo per numero di tipi richiesti (decrescente): la prima che
    #    matcha è quella più specifica.
    best_combo = None
    for required_types, bonus, label in sorted(
        COMBO_BONUSES, key=lambda x: len(x[0]), reverse=True
    ):
        if required_types.issubset(features["present_types"]):
            best_combo = (bonus, label)
            break

    if best_combo:
        score += best_combo[0]
        motivations.append(
            f"Combo '{best_combo[1]}': +{best_combo[0]}pt (combinazione ad alto rischio di social engineering)"
        )

    # 5. Bonus diversità dell'esposizione
    if features["unique_type_count"] >= 5:
        score += 15
        motivations.append("Esposizione multi-dimensionale (5+ tipi PII distinti): +15pt")
    elif features["unique_type_count"] >= 3:
        score += 7
        motivations.append("Esposizione diversificata (3+ tipi PII distinti): +7pt")

    return min(round(score), 100), motivations


# ──────────────────────────────────────────────────────────────────────────────
# RISK LEVEL + SPIEGAZIONE CONTESTUALE
# ──────────────────────────────────────────────────────────────────────────────

def build_risk_assessment(detected_piis: List[PIIEntity]) -> Tuple[str, str, int, List[str]]:
    """
    Entry point principale del modulo.
    Restituisce: (risk_level, explanation, numeric_score, motivations)
    """
    features = extract_features(detected_piis)
    score, motivations = calculate_risk_score(features)

    if score >= RISK_THRESHOLDS["HIGH"]:
        risk_level = "HIGH"
    elif score >= RISK_THRESHOLDS["MEDIUM"]:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    explanation = _build_explanation(risk_level, features, score)
    return risk_level, explanation, score, motivations


def _build_explanation(risk_level: str, features: dict, score: int) -> str:
    """
    Genera una spiegazione contestuale basata sulle feature reali del profilo,
    non su template generici indipendenti dai dati rilevati.
    """
    parts = []

    if features["max_exposure"]:
        parts.append(
            "Il profilo espone simultaneamente email, telefono, data di nascita e "
            "posizione geografica, fornendo a un attaccante tutti gli elementi per "
            "impersonificazione, SIM swapping e spear phishing mirato."
        )
    elif features["full_identity_combo"]:
        parts.append(
            "La combinazione di email, numero di telefono e data di nascita costituisce "
            "un profilo d'identità quasi completo, sufficiente per attacchi di account "
            "takeover e frodi d'identità."
        )
    elif features["spear_phishing_ready"]:
        parts.append(
            "La presenza combinata di email e informazioni geografiche consente la "
            "costruzione di messaggi di phishing altamente contestualizzati e credibili."
        )
    elif features["sim_swap_risk"]:
        parts.append(
            "Numero di telefono e data di nascita esposti congiuntamente aumentano il "
            "rischio di attacchi SIM swap per la compromissione di account protetti da 2FA."
        )
    elif features["social_graph_exposed"]:
        parts.append(
            "Luoghi frequentati e affiliazioni organizzative rendono ricostruibile la "
            "routine sociale e lavorativa del soggetto, utile per attacchi di ingegneria "
            "sociale indiretti."
        )
    elif features["has_direct_contact"]:
        parts.append(
            "I dati di contatto diretto (email e/o telefono) espongono il profilo a "
            "campagne di phishing e smishing anche senza ulteriori informazioni contestuali."
        )
    elif features["has_identity_anchor"]:
        parts.append(
            "La data di nascita, combinata con il nome utente pubblico, può essere "
            "sufficiente per il recupero di account su molte piattaforme tramite "
            "domande di sicurezza."
        )
    elif features["contextual_count"] > 0:
        parts.append(
            "I dati contestuali rilevati (location, organizzazioni) non consentono un "
            "attacco diretto ma contribuiscono alla profilazione dell'utente nel tempo."
        )
    else:
        parts.append(
            "Nessuna informazione personale identificabile rilevata. "
            "Il profilo mostra una buona igiene della privacy digitale."
        )

    parts.append(f"Score di rischio calcolato: {score}/100.")
    return " ".join(parts)
