# ==============================================================================
# TEST - Dati strutturati per la UI: mappa dell'aggregazione + segnale di routine
# e ricalcolo interattivo (/rescore, apply_floor=False). (SDCC)
# ==============================================================================

from models.schemas import PIIEntity
# Test specifici del MODELLO EURISTICO (combo/compressione): puntano alle sue funzioni
# dirette, non al dispatcher (default ora "empirical"), così restano validi.
from services.risk_scorer import (
    _build_heuristic_extras as build_risk_extras,
    _build_heuristic_assessment as build_risk_assessment,
)
from services.pii_detector import PIIDetectorService


def _pii(t: str, text: str, score: float = 0.99) -> PIIEntity:
    return PIIEntity(type=t, text=text, score=score)


def test_combo_exposes_types_and_points():
    """La combo scattata deve elencare i tipi che la compongono e i punti,
    così la UI può disegnare la mappa dell'aggregazione."""
    piis = [_pii("EMAIL", "a@b.com"), _pii("PHONE_NUMBER", "+39 333 1234567")]
    combos = build_risk_extras(piis)["combos"]
    assert len(combos) == 1
    assert set(combos[0]["types"]) == {"EMAIL", "PHONE_NUMBER"}
    assert combos[0]["points"] > 0


def test_no_combo_when_single_pii():
    """Un solo dato non forma alcuna combinazione: nessun arco da disegnare."""
    assert build_risk_extras([_pii("EMAIL", "a@b.com")])["combos"] == []


def test_disjoint_combos_both_counted():
    """Due combo DISGIUNTE (nessun dato in comune) devono contare ENTRAMBE:
    EMAIL+PHONE (contatto) e NAME+ADDRESS (doxing) sono sinergie indipendenti."""
    piis = [_pii("EMAIL", "a@b.com"), _pii("PHONE_NUMBER", "+39 333 1234567"),
            _pii("NAME", "Mario Rossi"), _pii("ADDRESS", "via Roma 1, Milano")]
    labels = {c["label"] for c in build_risk_extras(piis)["combos"]}
    assert "contatto_diretto_multiplo" in labels
    assert "doxing_esposizione_fisica" in labels


def test_all_applicable_combos_counted():
    """Ogni combo applicabile è un vettore d'attacco distinto e viene contata: con
    EMAIL+PHONE+DOB scattano sia la 3-combo 'identita_completa' sia le sue 2-combo
    (contatto multiplo, phishing, SIM swap)."""
    piis = [_pii("EMAIL", "a@b.com"), _pii("PHONE_NUMBER", "+39 333 1234567"),
            _pii("DATE_OF_BIRTH", "10/05/1990")]
    labels = {c["label"] for c in build_risk_extras(piis)["combos"]}
    assert "identita_completa" in labels
    assert "contatto_diretto_multiplo" in labels
    assert {"identita_phishing_combo", "identita_sim_swap_combo"} <= labels


def test_repetitions_detect_routine():
    """Uno stesso luogo citato ≥3 volte è una routine geografica."""
    piis = [_pii("LOCATION", "Roma") for _ in range(4)]
    reps = build_risk_extras(piis)["repetitions"]
    assert len(reps) == 1
    assert reps[0]["text"] == "roma" and reps[0]["count"] == 4
    assert reps[0]["label"] == "routine geografica"


def test_fiscal_code_forms_combo_with_name():
    """CF + nome deve formare una combinazione (identità anagrafica), non restare
    un dato isolato senza archi sulla mappa."""
    combos = build_risk_extras([_pii("FISCAL_CODE", "RSSMRA90E10H501Z"), _pii("NAME", "Mario Rossi")])["combos"]
    assert len(combos) == 1
    assert set(combos[0]["types"]) == {"FISCAL_CODE", "NAME"}


def test_fiscal_code_plus_iban_is_financial_identity():
    """CF + IBAN = identità civile e finanziaria insieme: combo dedicata e la
    spiegazione deve citare il rischio finanziario."""
    piis = [_pii("FISCAL_CODE", "RSSMRA90E10H501Z"), _pii("IBAN", "IT60X0542811101000000123456")]
    combos = build_risk_extras(piis)["combos"]
    assert any(c["label"] == "identita_finanziaria" for c in combos)
    explanation = build_risk_assessment(piis)[1]
    assert "finanziaria" in explanation.lower()


def test_fiscal_code_explanation_mentions_derived_data():
    """La spiegazione deve chiarire che dal CF si ricavano altri dati personali."""
    explanation = build_risk_assessment([_pii("FISCAL_CODE", "RSSMRA90E10H501Z")])[1]
    assert "comune di nascita" in explanation.lower() or "data di nascita" in explanation.lower()


def test_combo_tie_break_prefers_higher_bonus():
    """A parità di dimensione (combo da 2), tra più combinazioni applicabili si
    sceglie la più grave. Con CF+IBAN+EMAIL deve vincere 'identita_finanziaria' (+30),
    non una combo da 2 con bonus minore che capita prima in lista."""
    piis = [
        _pii("FISCAL_CODE", "RSSMRA90E10H501Z"),
        _pii("IBAN", "IT60X0542811101000000123456"),
        _pii("EMAIL", "a@b.com"),
    ]
    combos = build_risk_extras(piis)["combos"]
    assert any(c["label"] == "identita_finanziaria" for c in combos)


def test_iban_not_detected_as_phone():
    """Regressione: le cifre dell'IBAN non devono essere lette come numero di telefono."""
    types = {e.type for e in PIIDetectorService().detect_pii("IBAN IT60X0542811101000000123456")}
    assert "IBAN" in types and "PHONE_NUMBER" not in types


def test_compression_below_threshold_is_identity():
    """Sotto la soglia HIGH (70) la scala NON è compressa: LOW/MED restano invariati."""
    from services.risk_scorer import _compress
    assert _compress(0) == 0 and _compress(35) == 35 and _compress(70) == 70


def test_compression_avoids_saturation():
    """Sopra 70 la compressione spalma la fascia alta: profili molto esposti NON
    si schiacciano tutti a 100 e restano distinguibili (monotona e < 100)."""
    from services.risk_scorer import _compress
    a, b = _compress(100), _compress(160)
    assert 70 < a < b < 100          # crescente e mai a 100
    assert round(a) != round(b)      # profili diversi → score diversi (risoluzione)


def test_rescore_no_floor_counts_low_confidence():
    """apply_floor=False: un rilevamento incerto CONFERMATO dall'utente deve
    incidere (a peso ridotto), a differenza del calcolo automatico che lo scarta."""
    low = [_pii("EMAIL", "a@b.com", 0.99), _pii("PHONE_NUMBER", "+39 333 1234567", 0.51)]
    auto = build_risk_assessment(low)[2]                       # soglia esclude il telefono
    confirmed = build_risk_assessment(low, apply_floor=False)[2]  # utente lo conferma
    assert confirmed > auto


def test_empirical_combo_points_sum_to_score():
    """I punti mostrati nelle combo devono sommare allo score FINALE (compresso),
    così la mappa dell'aggregazione è coerente col verdetto (nessun +pt pre-compressione)."""
    from models.schemas import PIIEntity
    from services.risk_empirical import build_empirical_assessment, build_empirical_extras
    # Profilo ricco → score in fascia alta (compressa).
    piis = [PIIEntity(type=t, text=v, score=0.9) for t, v in [
        ("EMAIL", "a@b.it"), ("NAME", "Mario Rossi"), ("ORGANIZATION", "Sapienza"),
        ("DATE_OF_BIRTH", "01/01/1990"), ("FISCAL_CODE", "RSSMRA90A01H501A"),
        ("IBAN", "IT60X0542811101000000123456"), ("PHONE_NUMBER", "333-1234567")]]
    _, _, score, _ = build_empirical_assessment(piis)
    pts = [c["points"] for c in build_empirical_extras(piis)["combos"]]
    # Somma esatta (a meno di arrotondamenti minimi) e ordine decrescente.
    assert sum(pts) == score  # somma esatta (Hamilton)
    assert pts == sorted(pts, reverse=True)
