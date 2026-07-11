# ==============================================================================
# TEST - Risk Scorer (feature engineering del punteggio di rischio) (SDCC)
# Verifica la classificazione LOW / MEDIUM / HIGH e le proprietà dello score.
# ==============================================================================

from models.schemas import PIIEntity
from services.risk_scorer import build_risk_assessment


def _pii(pii_type: str, text: str, score: float = 0.99) -> PIIEntity:
    """Helper per costruire una PIIEntity con confidence alta (mult = 1.0)."""
    return PIIEntity(type=pii_type, text=text, score=score)


def test_no_pii_is_low_risk_zero_score():
    """Nessuna PII → rischio LOW e score 0."""
    level, explanation, score, motivations = build_risk_assessment([])
    assert level == "LOW"
    assert score == 0
    assert isinstance(explanation, str) and explanation  # spiegazione non vuota


def test_single_email_is_low_risk():
    """
    Una sola PII non deve mai superare da sola la soglia MEDIUM (regola di
    calibrazione dei pesi). EMAIL pesa 20 → sotto 35 → LOW.
    """
    level, _, score, _ = build_risk_assessment([_pii("EMAIL", "a@b.com")])
    assert level == "LOW"
    assert score < 35


def test_email_plus_phone_is_medium_risk():
    """
    EMAIL + PHONE_NUMBER: 20 + 20 base + 25 di combo 'contatto_diretto_multiplo'
    = 65 → nella fascia MEDIUM (>=35 e <70).
    """
    piis = [_pii("EMAIL", "a@b.com"), _pii("PHONE_NUMBER", "+39 333 1234567")]
    level, _, score, _ = build_risk_assessment(piis)
    assert level == "MEDIUM"
    assert 35 <= score < 70


def test_full_exposure_is_high_risk():
    """
    Esposizione massima (email + telefono + data nascita + location) deve
    produrre rischio HIGH grazie al bonus combo 'massima_esposizione'.
    """
    piis = [
        _pii("EMAIL", "a@b.com"),
        _pii("PHONE_NUMBER", "+39 333 1234567"),
        _pii("DATE_OF_BIRTH", "10/05/1990"),
        _pii("LOCATION", "Roma"),
    ]
    level, _, score, _ = build_risk_assessment(piis)
    assert level == "HIGH"
    assert score >= 70


def test_score_is_capped_at_100():
    """Lo score non deve mai superare 100, anche con moltissime PII."""
    piis = [
        _pii("EMAIL", "a@b.com"),
        _pii("PHONE_NUMBER", "+39 333 1234567"),
        _pii("DATE_OF_BIRTH", "10/05/1990"),
        _pii("LOCATION", "Roma"),
        _pii("FISCAL_CODE", "RSSMRA90E10H501Z"),
        _pii("IBAN", "IT60X0542811101000000123456"),
        _pii("ORGANIZATION", "Sapienza"),
        _pii("URL", "https://x.dev"),
        _pii("USERNAME", "@mario_r"),
    ]
    _, _, score, _ = build_risk_assessment(piis)
    assert score <= 100


def test_fiscal_code_contributes_to_score():
    """Il nuovo tipo FISCAL_CODE deve incidere sullo score (peso registrato)."""
    _, _, score, motivations = build_risk_assessment([_pii("FISCAL_CODE", "RSSMRA90E10H501Z")])
    assert score > 0
    assert any("FISCAL_CODE" in m for m in motivations)


def test_comprehend_name_address_is_high_risk_doxing():
    """
    Regressione: il vocabolario di Amazon Comprehend (NAME, ADDRESS, AGE) deve
    essere pesato come quello del mock. Nome + indirizzo di casa = doxing → HIGH,
    e il verdetto NON deve dire "nessuna informazione rilevata" (bug corretto:
    prima questi tipi ricadevano sul peso di default 5 → score basso incongruente).
    """
    piis = [
        _pii("NAME", "Manuel Amodio", 1.0),
        _pii("ADDRESS", "Taverna di Montalto, via Monachelle", 1.0),
        _pii("AGE", "23 anni", 1.0),
    ]
    level, explanation, score, _ = build_risk_assessment(piis)
    assert level == "HIGH"
    assert score >= 70
    assert "nessuna informazione" not in explanation.lower()
    assert "doxing" in explanation.lower()


def test_single_address_not_reported_as_no_pii():
    """Un solo ADDRESS non deve produrre il verdetto 'nessuna informazione'."""
    _, explanation, score, _ = build_risk_assessment([_pii("ADDRESS", "via Roma 1, Milano")])
    assert score > 0
    assert "nessuna informazione" not in explanation.lower()


def test_low_confidence_detections_ignored_in_score():
    """#2: i rilevamenti sotto la soglia di confidence non incidono sul punteggio
    (né come peso, né innescando combo)."""
    piis = [
        _pii("EMAIL", "a@b.com", 0.99),   # affidabile
        _pii("ADDRESS", "cooo", 0.51),    # spazzatura, sotto soglia
        _pii("NAME", "x", 0.40),          # sotto soglia
    ]
    _, explanation, _, motivations = build_risk_assessment(piis)
    assert not any("ADDRESS" in m for m in motivations)
    assert not any("NAME" in m for m in motivations)
    assert "doxing" not in explanation.lower()  # la combo nome+indirizzo NON scatta


def test_combo_scaled_by_confidence():
    """#1: la stessa combo (nome + indirizzo) pesa meno se i rilevamenti hanno
    confidence più bassa: lo score cala."""
    high = build_risk_assessment([_pii("NAME", "x", 0.99), _pii("ADDRESS", "y", 0.99)])[2]
    mid = build_risk_assessment([_pii("NAME", "x", 0.70), _pii("ADDRESS", "y", 0.70)])[2]
    assert mid < high
