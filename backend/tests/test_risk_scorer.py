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
