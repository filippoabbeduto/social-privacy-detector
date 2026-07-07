# ==============================================================================
# TEST - PII Detector (motore regex mock) (SDCC)
# Verifica che _detect_pii_regex rilevi i tipi di PII attesi, inclusi i nuovi
# FISCAL_CODE e IBAN aggiunti per coprire i "codici identificativi" della traccia.
# ==============================================================================

from services.pii_detector import PIIDetectorService


# Testo "ricco" che contiene volutamente un'occorrenza di ogni tipo di PII.
SAMPLE_TEXT = (
    "Scrivimi a mario.rossi@example.com o al +39 333 1234567. "
    "Nato il 10/05/1990. CF: RSSMRA90E10H501Z. "
    "IBAN IT60X0542811101000000123456. "
    "Studio alla Sapienza di Roma. "
    "Sito: https://mario.dev seguimi @mario_r"
)


def _detected_types(text: str) -> set:
    """Helper: restituisce l'insieme dei tipi di PII rilevati nel testo."""
    service = PIIDetectorService()
    return {entity.type for entity in service.detect_pii(text)}


def test_detects_all_expected_pii_types():
    """
    Tutti i tipi attesi devono essere presenti. Usiamo subset (<=) e non
    uguaglianza: il motore regex può produrre match extra (es. una lunga
    sequenza di cifre dell'IBAN che assomiglia a un numero di telefono),
    e per questo test ci interessa la COPERTURA, non l'esattezza al singolo match.
    """
    detected = _detected_types(SAMPLE_TEXT)
    expected = {
        "EMAIL", "PHONE_NUMBER", "DATE_OF_BIRTH",
        "FISCAL_CODE", "IBAN",
        "ORGANIZATION", "LOCATION", "URL", "USERNAME",
    }
    missing = expected - detected
    assert not missing, f"Tipi PII non rilevati: {missing}"


def test_empty_text_returns_no_pii():
    """Un testo vuoto non deve produrre alcuna PII."""
    service = PIIDetectorService()
    assert service.detect_pii("") == []


def test_clean_text_has_no_pii():
    """Un testo senza dati personali non deve generare falsi positivi grossolani."""
    detected = _detected_types("Oggi è una bella giornata e sto studiando.")
    # Nessuno dei tipi 'forti' (contatto/identità) deve comparire.
    assert not ({"EMAIL", "PHONE_NUMBER", "FISCAL_CODE", "IBAN"} & detected)


def test_fiscal_code_is_normalized_uppercase():
    """Il codice fiscale rilevato deve essere normalizzato in maiuscolo."""
    service = PIIDetectorService()
    entities = service.detect_pii("il mio cf è rssmra90e10h501z grazie")
    fiscal = [e for e in entities if e.type == "FISCAL_CODE"]
    assert fiscal, "Codice fiscale in minuscolo non rilevato"
    assert fiscal[0].text == "RSSMRA90E10H501Z"


def test_email_not_misclassified_as_username():
    """Un'email non deve essere rilevata anche come USERNAME (il '@' è condiviso)."""
    service = PIIDetectorService()
    entities = service.detect_pii("contatto: only.email@test.com")
    usernames = [e for e in entities if e.type == "USERNAME"]
    assert usernames == []
