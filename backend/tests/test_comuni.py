# ==============================================================================
# TEST - Decodifica deterministica del comune di nascita dal CF (comuni.py) (SDCC)
# Lookup su tabella dei codici catastali dei comuni, NON via LLM (che allucinava).
# ==============================================================================

from services.comuni import comune_from_cf


def test_trebisacce():
    # Caso reale che l'LLM sbagliava (dava Torino=L219 invece di L353).
    assert comune_from_cf("BBDFPP03A17L353G") == "Trebisacce"


def test_roma():
    assert comune_from_cf("RSSMRA90A01H501A") == "Roma"


def test_omocodia():
    # Omocodia: le cifre del codice catastale possono essere sostituite da lettere.
    # H501 con ultima cifra omocodica (1→M) resta Roma.
    assert comune_from_cf("RSSMRA90A01H50MA") == "Roma"


def test_unknown_code_returns_none():
    assert comune_from_cf("AAAAAA00A00Z999A") is None


def test_malformed_returns_none():
    assert comune_from_cf("troppo-corto") is None
    assert comune_from_cf("") is None
