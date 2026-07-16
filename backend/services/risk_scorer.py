# ==============================================================================
# RISK SCORER - Feature Engineering per il calcolo del Risk Score (SDCC)
# Percorso: backend/services/risk_scorer.py
# ==============================================================================

import math
import os
from typing import List, Tuple
from models.schemas import PIIEntity

# Modello di rischio selezionabile via env:
#   "empirical" (default): Rischio = Σ Pₐ·Iₐ con impatti/probabilità da studi (risk_empirical.py).
#   "heuristic": modello storico (pesi base + combo + compressione), disponibile come alternativa.
RISK_MODEL = os.getenv("RISK_MODEL", "empirical").lower()


# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURAZIONE PESI E SOGLIE
# ──────────────────────────────────────────────────────────────────────────────

# Peso base per singola PII (indipendente dalle combinazioni).
# I pesi sono calibrati per evitare saturazione: un singolo tipo non deve mai
# superare da solo la soglia MEDIUM (35pt).
#
# IMPORTANTE: la tabella copre DUE vocabolari, perché la stessa PII può arrivare
# da fonti diverse:
#   - Amazon Comprehend (in produzione) usa: NAME, ADDRESS, AGE, PHONE, EMAIL,
#     DATE_TIME, USERNAME, URL, SSN, ...;
#   - il motore a regole/mock usa: PHONE_NUMBER, DATE_OF_BIRTH, LOCATION,
#     ORGANIZATION, FISCAL_CODE, IBAN, ...
# Tenerli entrambi evita che una PII reale di Comprehend (es. ADDRESS di casa)
# ricada sul peso di default 5, sotto-stimando gravemente il rischio.
PII_BASE_WEIGHTS = {
    # Contatti diretti
    "EMAIL":         20,
    "PHONE_NUMBER":  20,
    "PHONE":         20,   # Comprehend
    # Codici/identificativi ad alta sensibilità
    "FISCAL_CODE":   22,
    "IBAN":          22,
    "SSN":           25,   # Comprehend
    "CREDIT_DEBIT_NUMBER":          25,  # Comprehend
    "BANK_ACCOUNT_NUMBER":          22,  # Comprehend
    "INTERNATIONAL_BANK_ACCOUNT_NUMBER": 22,  # Comprehend (IBAN)
    "PASSPORT_NUMBER":              22,  # Comprehend
    "DRIVER_ID":                    18,  # Comprehend
    # Localizzazione fisica: un INDIRIZZO di casa è esposizione fisica grave
    # (doxing/stalking), molto più di una generica LOCATION/città.
    "ADDRESS":       25,   # Comprehend
    "LOCATION":       8,
    # Anagrafica
    "NAME":          12,   # Comprehend (nome completo = ancora identificativa)
    "DATE_OF_BIRTH": 15,
    "AGE":           10,   # Comprehend (meno preciso di una data completa)
    "DATE_TIME":      4,   # Comprehend: spesso rumoroso (date di eventi), peso basso
    # Contestuali
    "ORGANIZATION":   5,
    "URL":            5,
    "USERNAME":       4,
}

# Soglie per la classificazione finale
RISK_THRESHOLDS = {
    "HIGH":   70,
    "MEDIUM": 35,
}

# Gerarchia di pericolosità dei tipi PII (dal più al meno pericoloso): guida la
# sanitizzazione mirata, che rimuove prima i dati ad alto impatto identitario/finanziario.
_DANGER_ORDER = [
    "FISCAL_CODE", "IBAN", "CREDIT_DEBIT_NUMBER", "PHONE_NUMBER", "DATE_OF_BIRTH",
    "AGE", "ADDRESS", "EMAIL", "USERNAME", "URL", "LOCATION", "ORGANIZATION", "NAME",
]


def plan_sanitization(detected_piis, target=None):
    """Pianifica la rimozione MINIMA per portare il rischio sotto la soglia BASSO.
    Rimuove i dati per pericolosità decrescente finché score < target (default MEDIUM=35).
    Deterministico: riusa build_risk_assessment. Ritorna {to_remove, to_keep, final_score, final_level}."""
    if target is None:
        target = RISK_THRESHOLDS["MEDIUM"]
    if not detected_piis:
        return {"to_remove": [], "to_keep": [], "final_score": 0, "final_level": "LOW"}

    def danger(p):
        # tipi non elencati → meno pericolosi (in coda)
        return _DANGER_ORDER.index(p.type) if p.type in _DANGER_ORDER else len(_DANGER_ORDER)

    _, _, base, _ = build_risk_assessment(detected_piis, apply_floor=False)
    if base < target:
        lvl, _, sc, _ = build_risk_assessment(detected_piis, apply_floor=False)
        return {"to_remove": [], "to_keep": list(detected_piis), "final_score": sc, "final_level": lvl}

    # Ordina i CANDIDATI alla rimozione dal più al meno pericoloso.
    ordered = sorted(detected_piis, key=danger)
    to_remove = []
    remaining = list(detected_piis)
    for p in ordered:
        _, _, score, _ = build_risk_assessment(remaining, apply_floor=False)
        if score < target:
            break
        to_remove.append(p)
        remaining = [q for q in remaining if q is not p]

    keep_ids = {id(q) for q in remaining}
    to_keep = [q for q in detected_piis if id(q) in keep_ids]
    lvl, _, sc, _ = build_risk_assessment(to_keep, apply_floor=False)
    return {"to_remove": to_remove, "to_keep": to_keep, "final_score": sc, "final_level": lvl}

# Compressione della scala oltre la soglia HIGH. La somma pesata (base + combo +
# diversità) è illimitata e, per profili molto esposti, sfonda facilmente il 100:
# la fascia alta satura e perde risoluzione (un profilo "grave" e uno "gravissimo"
# leggono entrambi 100). Sotto 70 la scala è ben tarata e resta INVARIATA; sopra 70
# si applica una curva concava che spalma [70, ∞) su [70, 100), avvicinandosi a 100
# senza raggiungerlo quasi mai. COMPRESSION_K governa la ripidità (più alto = più
# lenta la saturazione). Le soglie 35/70 restano valide: la trasformazione è
# monotòna e lascia fisso il punto 70.
# K=100: ritarato dopo il passaggio a "tutte le combo" (raw più grandi). Con questo
# valore solo la configurazione quasi-massima tocca 100; i profili realistici (fino a
# ~6 tipi distinti) restano sotto, ordinati per gravità.
COMPRESSION_START = 70
COMPRESSION_K = 100.0


def _compress(raw: float) -> float:
    """Compressione concava sopra COMPRESSION_START (identità sotto). Monotòna."""
    if raw <= COMPRESSION_START:
        return raw
    span = 100 - COMPRESSION_START
    return COMPRESSION_START + span * (1 - math.exp(-(raw - COMPRESSION_START) / COMPRESSION_K))

# Soglia minima di confidence per far contribuire una PII al PUNTEGGIO.
# I rilevamenti troppo incerti (es. Comprehend che tagga spazzatura OCR a 0.49)
# non devono pesare né innescare combo. NB: filtra solo il calcolo dello score,
# non la lista di PII mostrata all'utente. I codici IT (CF/IBAN) e i tipi solidi
# stanno ben sopra questa soglia, quindi non vengono toccati.
CONFIDENCE_FLOOR = 0.55

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
    # Combo su vocabolario Comprehend: nome + indirizzo fisico = doxing/stalking.
    # È il caso più insidioso: identifica la persona E la sua posizione reale.
    ({"NAME", "ADDRESS"},                                      25, "doxing_esposizione_fisica"),
    ({"NAME", "ADDRESS", "AGE"},                               35, "identificazione_completa"),
    ({"NAME", "ADDRESS", "PHONE"},                             40, "doxing_contattabile"),
    ({"ADDRESS", "PHONE"},                                     22, "localizzazione_contattabile"),
    ({"NAME", "PHONE"},                                        18, "identita_contattabile"),
    # ── Codici identificativi e finanziari ───────────────────────────────────
    # Il CODICE FISCALE non è un dato "isolato": codifica al suo interno data di
    # nascita, sesso e comune di nascita. Combinato con nome/contatti diventa una
    # chiave d'identità civile (INPS, Agenzia delle Entrate, SPID, recupero account).
    # L'IBAN e i dati di conto/carta aprono invece la frode finanziaria diretta
    # (BEC, false richieste di pagamento/rimborso, addebiti SEPA).
    ({"FISCAL_CODE", "NAME"},                                  25, "identita_anagrafica_cf"),
    ({"FISCAL_CODE", "EMAIL"},                                 20, "recupero_account_cf"),
    ({"FISCAL_CODE", "PHONE_NUMBER"},                          22, "identita_sim_cf"),
    ({"FISCAL_CODE", "PHONE"},                                 22, "identita_sim_cf"),
    ({"IBAN", "NAME"},                                         25, "frode_finanziaria"),
    ({"IBAN", "EMAIL"},                                        22, "frode_pagamento_bec"),
    ({"BANK_ACCOUNT_NUMBER", "NAME"},                          25, "frode_finanziaria"),
    ({"CREDIT_DEBIT_NUMBER", "NAME"},                          28, "frode_carta"),
    # Codice fiscale + coordinate bancarie = identità civile e finanziaria insieme.
    ({"FISCAL_CODE", "IBAN"},                                  30, "identita_finanziaria"),
    ({"FISCAL_CODE", "IBAN", "NAME"},                          40, "identita_finanziaria_totale"),
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


def _select_combos(present_types: set):
    """
    Restituisce TUTTE le combinazioni pericolose applicabili (i cui tipi sono un
    sottoinsieme di quelli presenti), ordinate per (num_tipi, bonus) decrescente.

    Razionale (ogni combo = un vettore d'attacco distinto):
      Una PII può abilitare più attacchi diversi. Es. con EMAIL+PHONE+DOB un attaccante
      può tentare sia il contatto multiplo (EMAIL+PHONE) sia il furto d'identità completo
      (EMAIL+PHONE+DOB): sono minacce DISTINTE e realizzabili, quindi entrambe pesano
      sull'esposizione al social engineering. Si contano perciò tutte le combo presenti,
      non solo una. La crescita dello score è tenuta a bada dalla compressione concava
      finale (_compress), non escludendo combo.
    Monotòna: aggiungere un dato può solo rendere applicabili PIÙ combo, mai meno.
    """
    return [
        (required_types, bonus, label)
        for required_types, bonus, label in sorted(
            COMBO_BONUSES, key=lambda x: (len(x[0]), x[1]), reverse=True
        )
        if required_types.issubset(present_types)
    ]


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
    # Nota: si considerano ENTRAMBI i vocabolari (Comprehend + regole/mock).
    has_direct_contact  = bool({"EMAIL", "PHONE_NUMBER", "PHONE"} & present_types)
    has_identity_anchor = bool({"DATE_OF_BIRTH", "AGE"} & present_types)
    has_location        = "LOCATION" in present_types
    has_org             = "ORGANIZATION" in present_types
    has_full_name       = "NAME" in present_types
    has_home_address    = "ADDRESS" in present_types
    # Doxing: nome completo + indirizzo fisico = identificazione + localizzazione.
    doxing_ready        = has_full_name and has_home_address
    # Codici identificativi/finanziari. Il CF codifica data di nascita, sesso e
    # comune di nascita: è aggregazione compressa in un solo codice.
    has_fiscal_code     = "FISCAL_CODE" in present_types
    has_financial       = bool(
        {"IBAN", "BANK_ACCOUNT_NUMBER", "INTERNATIONAL_BANK_ACCOUNT_NUMBER", "CREDIT_DEBIT_NUMBER"}
        & present_types
    )
    # CF + coordinate bancarie = identità civile e finanziaria insieme.
    financial_identity  = has_fiscal_code and has_financial

    # --- Combinazioni critiche ---
    full_identity_combo   = {"EMAIL", "PHONE_NUMBER", "DATE_OF_BIRTH"}.issubset(present_types)
    spear_phishing_ready  = {"EMAIL", "LOCATION"}.issubset(present_types)
    social_graph_exposed  = has_location and has_org
    sim_swap_risk         = {"PHONE_NUMBER", "DATE_OF_BIRTH"}.issubset(present_types)
    max_exposure          = {"EMAIL", "PHONE_NUMBER", "DATE_OF_BIRTH", "LOCATION"}.issubset(present_types)

    # --- Conteggi aggregati ---
    unique_type_count = len(present_types)
    contextual_count  = sum(1 for t in ["LOCATION", "ORGANIZATION", "URL", "USERNAME"] if t in present_types)

    return {
        "pii_by_type":          pii_by_type,
        "pii_counts":           pii_counts,
        "raw_repetitions":      raw_repetitions,
        "present_types":        present_types,
        "has_direct_contact":   has_direct_contact,
        "has_identity_anchor":  has_identity_anchor,
        "doxing_ready":         doxing_ready,
        "has_home_address":     has_home_address,
        "has_fiscal_code":      has_fiscal_code,
        "has_financial":        has_financial,
        "financial_identity":   financial_identity,
        "full_identity_combo":  full_identity_combo,
        "spear_phishing_ready": spear_phishing_ready,
        "social_graph_exposed": social_graph_exposed,
        "sim_swap_risk":        sim_swap_risk,
        "max_exposure":         max_exposure,
        "unique_type_count":    unique_type_count,
        "contextual_count":     contextual_count,
    }


# ──────────────────────────────────────────────────────────────────────────────
# SCORE CALCULATION
# ──────────────────────────────────────────────────────────────────────────────

def calculate_risk_score(features: dict) -> Tuple[int, List[str]]:
    """
    Calcola uno score numerico (0-100) a partire dalle feature estratte.
    La logica è a sei livelli:
      1. Peso base per ogni tipo di PII, modulato dalla confidence
      2. Bonus diversità: testi distinti dello stesso tipo (es. 3 città diverse)
      3. Bonus abitudine: stesso testo ripetuto per LOCATION/ORGANIZATION
      4. Bonus delle combo disgiunte selezionate (set-packing, vedi _select_combos)
      5. Bonus diversità dell'esposizione (tipi distinti)
      6. Compressione concava della fascia alta (vedi _compress) + clamp a 100
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

    # 4. Bonus combo: si sommano TUTTE le combo applicabili (ogni combo = un vettore
    #    d'attacco distinto realizzabile). L'accumulo è controllato a valle dalla
    #    compressione concava, non escludendo combo. Vedi _select_combos.
    for required_types, bonus, label in _select_combos(features["present_types"]):
        # #1: una combo vale quanto il suo anello più debole. Si scala il bonus per
        # il moltiplicatore di confidence MINIMO tra i tipi che la compongono, così
        # una combinazione basata su un rilevamento incerto non pesa a forza piena.
        conf_factor = min(_confidence_multiplier(pii_by_type[t]) for t in required_types)
        applied = round(bonus * conf_factor)
        score += applied
        motivations.append(
            f"Combo '{label}': +{applied}pt (combinazione ad alto rischio di social engineering)"
        )

    # 5. Bonus diversità dell'esposizione
    if features["unique_type_count"] >= 5:
        score += 15
        motivations.append("Esposizione multi-dimensionale (5+ tipi PII distinti): +15pt")
    elif features["unique_type_count"] >= 3:
        score += 7
        motivations.append("Esposizione diversificata (3+ tipi PII distinti): +7pt")

    # 6. Compressione concava della fascia alta (vedi _compress): la somma grezza,
    #    illimitata, viene mappata su [0,100] evitando la saturazione a 100. Quando la
    #    compressione cambia il valore, lo si dichiara (la somma dei contributi sopra
    #    NON coincide più col totale: onestà espositiva).
    raw = round(score)
    final = min(round(_compress(score)), 100)
    if raw != final:
        motivations.append(
            f"Scala compressa: contributi grezzi {raw}pt → {final}/100 "
            f"(curva concava anti-saturazione oltre {COMPRESSION_START})"
        )

    return final, motivations


# ──────────────────────────────────────────────────────────────────────────────
# RISK LEVEL + SPIEGAZIONE CONTESTUALE
# ──────────────────────────────────────────────────────────────────────────────

def _reliable(detected_piis: List[PIIEntity], apply_floor: bool) -> List[PIIEntity]:
    """
    Filtra i rilevamenti sotto la soglia di confidence, se richiesto.
    apply_floor=False è usato dall'endpoint /rescore: lì l'utente ha già scelto
    manualmente QUALI dati conteggiare (funzione "e se non l'avessi pubblicato?" e
    conferma di un rilevamento incerto), quindi la selezione del client è definitiva
    e non va rifiltrata dalla soglia automatica.
    """
    if not apply_floor:
        return list(detected_piis)
    return [p for p in detected_piis if p.score >= CONFIDENCE_FLOOR]


def build_risk_assessment(detected_piis: List[PIIEntity], apply_floor: bool = True) -> Tuple[str, str, int, List[str]]:
    """Dispatcher: instrada al modello selezionato da RISK_MODEL. Il modello empirico è
    importato lazy per evitare l'import circolare (risk_empirical importa da qui)."""
    if RISK_MODEL == "empirical":
        from services.risk_empirical import build_empirical_assessment
        return build_empirical_assessment(detected_piis, apply_floor)
    return _build_heuristic_assessment(detected_piis, apply_floor)


def _build_heuristic_assessment(detected_piis: List[PIIEntity], apply_floor: bool = True) -> Tuple[str, str, int, List[str]]:
    """
    Entry point principale del modulo.
    Restituisce: (risk_level, explanation, numeric_score, motivations)
    """
    # #2: si calcola il punteggio SOLO sui rilevamenti abbastanza affidabili.
    # Sotto la soglia il dato è troppo incerto per pesare (né base, né combo, né
    # diversità). La lista PII mostrata all'utente resta invariata a monte.
    reliable_piis = _reliable(detected_piis, apply_floor)
    features = extract_features(reliable_piis)
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

    if features["financial_identity"]:
        parts.append(
            "Il profilo espone il codice fiscale insieme a coordinate bancarie/di conto: "
            "identità civile e finanziaria sono compromesse insieme. Il codice fiscale "
            "consente impersonificazione presso servizi pubblici (SPID, INPS, Agenzia delle "
            "Entrate) e recupero di account; l'IBAN/conto abilita frodi di pagamento dirette "
            "(false richieste di rimborso, addebiti SEPA, business email compromise)."
        )
    elif features["doxing_ready"]:
        parts.append(
            "Il profilo espone il nome completo insieme a un indirizzo fisico preciso: "
            "questa combinazione permette l'identificazione diretta della persona e la sua "
            "localizzazione reale, esponendo a doxing, stalking e attacchi mirati sia "
            "online sia fisici (furti, molestie, impersonificazione presso servizi locali)."
        )
    elif features["max_exposure"]:
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
    elif features["has_home_address"]:
        parts.append(
            "È esposto un indirizzo fisico: anche senza contatti diretti, rende "
            "localizzabile la persona e utilizzabile per attacchi mirati o consegne/"
            "comunicazioni fraudolente che sfruttano la conoscenza del luogo."
        )
    elif features["has_financial"]:
        parts.append(
            "Sono esposte coordinate bancarie o dati di conto/carta: anche senza altri dati, "
            "abilitano frodi di pagamento (false richieste di rimborso, addebiti SEPA) e "
            "messaggi che imitano la banca facendo leva sui riferimenti reali del conto."
        )
    elif features["contextual_count"] > 0:
        parts.append(
            "I dati contestuali rilevati (location, organizzazioni) non consentono un "
            "attacco diretto ma contribuiscono alla profilazione dell'utente nel tempo."
        )
    elif features["unique_type_count"] > 0:
        # Sono state rilevate PII (es. solo nome, o solo età) che non formano una
        # combinazione critica: NON è "nessuna informazione", ma esposizione limitata.
        parts.append(
            "Sono stati rilevati dati personali identificativi: presi singolarmente non "
            "consentono un attacco diretto, ma aumentano la tracciabilità del soggetto e, "
            "se combinati con altre fonti, la sua profilabilità."
        )
    else:
        parts.append(
            "Nessuna informazione personale identificabile rilevata. "
            "Il profilo mostra una buona igiene della privacy digitale."
        )

    # Nota trasversale: se è presente il codice fiscale, evidenzia che NON è un dato
    # isolato ma ne racchiude altri (data di nascita, sesso, comune di nascita),
    # deducibili senza alcuna fonte esterna. Vale in qualunque scenario sopra.
    if features["has_fiscal_code"]:
        parts.append(
            "Nota: il codice fiscale non è un dato isolato — da esso si ricavano "
            "direttamente data di nascita, sesso e comune di nascita, ampliando l'esposizione "
            "oltre ai soli dati mostrati."
        )

    parts.append(f"Score di rischio calcolato: {score}/100.")
    return " ".join(parts)


# ──────────────────────────────────────────────────────────────────────────────
# DATI STRUTTURATI PER LA UI (mappa dell'aggregazione + segnale di routine)
# ──────────────────────────────────────────────────────────────────────────────

def build_risk_extras(detected_piis: List[PIIEntity], apply_floor: bool = True) -> dict:
    """Dispatcher: instrada al modello selezionato da RISK_MODEL (import lazy come sopra)."""
    if RISK_MODEL == "empirical":
        from services.risk_empirical import build_empirical_extras
        return build_empirical_extras(detected_piis, apply_floor)
    return _build_heuristic_extras(detected_piis, apply_floor)


def _build_heuristic_extras(detected_piis: List[PIIEntity], apply_floor: bool = True) -> dict:
    """
    Estrae, dagli stessi dati usati per il punteggio, due strutture che la UI
    disegna invece di descrivere a parole:
      - combos: le combinazioni pericolose disgiunte effettivamente scattate, ognuna
        {label, types, points} → "mappa dell'aggregazione": mostra QUALI dati,
        combinati, abilitano quale attacco (la tesi del prodotto resa visibile).
      - repetitions: i testi (LOCATION/ORGANIZATION) ripetuti ≥3 volte
        ({type, text, count, label}) → "segnale di routine": la frequenza è
        essa stessa un dato (un luogo citato più volte = abitudine sfruttabile).
    Le due informazioni sono GIÀ calcolate dallo scorer ma finivano appiattite in
    stringhe dentro `motivations`; qui vengono esposte in forma strutturata.
    """
    reliable_piis = _reliable(detected_piis, apply_floor)
    features = extract_features(reliable_piis)
    pii_by_type = features["pii_by_type"]

    # Tutte le combo applicabili (ogni combo = un vettore d'attacco): la mappa
    # dell'aggregazione le mostra come attacchi distinti.
    combos = []
    for required_types, bonus, label in _select_combos(features["present_types"]):
        # Stesso scaling per confidence usato nel punteggio (anello più debole),
        # così i punti mostrati nella mappa coincidono con quelli sommati allo score.
        conf_factor = min(_confidence_multiplier(pii_by_type[t]) for t in required_types)
        combos.append({
            "label": label,
            "types": sorted(required_types),
            "points": round(bonus * conf_factor),
        })

    repetitions = []
    for pii_type, text_counts in features.get("raw_repetitions", {}).items():
        for text, reps in text_counts.items():
            if reps >= 3:
                rep_label = "routine geografica" if pii_type == "LOCATION" else "affiliazione confermata"
                repetitions.append({"type": pii_type, "text": text, "count": reps, "label": rep_label})
    repetitions.sort(key=lambda r: r["count"], reverse=True)

    return {"combos": combos, "repetitions": repetitions}
