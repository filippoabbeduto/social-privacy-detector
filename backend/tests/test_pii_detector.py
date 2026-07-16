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
    """Helper: tipi rilevati dal MOTORE REGEX. Questi test verificano il motore a regole
    in modo specifico → chiamano _detect_pii_regex, non il dispatcher detect_pii (il cui
    default è ora 'presidio'), così restano validi e veloci a prescindere dal provider."""
    service = PIIDetectorService()
    return {entity.type for entity in service._detect_pii_regex(text)}


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


def test_comprehend_postprocessing_recovers_dob_and_keeps_names():
    """Post-processing: sul percorso Comprehend il regex italiano recupera la DATE_OF_BIRTH
    (che Comprehend darebbe come DATE_TIME) e i codici IT, mentre da Comprehend si tengono
    NAME/ADDRESS. Il DATE_TIME rumoroso viene scartato."""
    svc = PIIDetectorService()

    class FakeComprehend:
        def detect_pii_entities(self, Text, LanguageCode):
            def span(s):
                i = Text.index(s)
                return i, i + len(s)
            n0, n1 = span("Filippo Abbeduto")
            a0, a1 = span("via Roma 1")
            d0, d1 = span("22/06/2000")
            return {"Entities": [
                {"Type": "NAME", "BeginOffset": n0, "EndOffset": n1, "Score": 0.99},
                {"Type": "ADDRESS", "BeginOffset": a0, "EndOffset": a1, "Score": 0.95},
                {"Type": "DATE_TIME", "BeginOffset": d0, "EndOffset": d1, "Score": 0.90},
            ]}

    svc.comprehend_client = FakeComprehend()
    text = "Filippo Abbeduto, via Roma 1. Scrivimi a f@x.it, nato il 22/06/2000."
    types = {p.type for p in svc._detect_pii_comprehend(text)}
    assert "DATE_OF_BIRTH" in types      # recuperata dal regex
    assert "DATE_TIME" not in types      # rumore scartato
    assert "NAME" in types and "ADDRESS" in types  # da Comprehend
    assert "EMAIL" in types              # dal regex


def test_non_birth_dates_not_classified_as_dob():
    """Avversariale: una data di evento/scadenza NON deve diventare DATE_OF_BIRTH;
    una data con contesto di nascita sì."""
    svc = PIIDetectorService()
    def dob(t): return [p.text for p in svc._detect_pii_regex(t) if p.type == "DATE_OF_BIRTH"]
    assert dob("Il concerto è il 20/07/2025 a Milano.") == []
    assert dob("Scadenza pagamento: 31/12/2024.") == []
    assert dob("Nato il 10/05/1990 a Pisa.") == ["10/05/1990"]
    # data mista: solo la nascita
    assert dob("Nata il 22/06/1988, si sposa il 12/06/2025.") == ["22/06/1988"]


def test_order_number_not_classified_as_phone():
    """Avversariale: un numero d'ordine/fattura NON deve diventare PHONE_NUMBER;
    un telefono vero sì."""
    svc = PIIDetectorService()
    def ph(t): return [p.text for p in svc._detect_pii_regex(t) if p.type == "PHONE_NUMBER"]
    assert ph("Ordine numero 3391234567 spedito.") == []
    assert ph("Codice fattura 0442015567 da saldare.") == []
    assert ph("Il mio numero è 340 5567788.") == ["340 5567788"]


# ── Regressione: falsi positivi del NER su bio non discorsive ──────────────────
# Caso reale (profilo con calendario di date/eventi): spaCy produceva sigle di
# provincia come luoghi, parole urlate come organizzazioni e frammenti cuciti su
# più righe. Il filtro di casing di _looks_real deve scartarli tutti.

import pytest
from services.pii_presidio import _looks_real, _clean_ner


@pytest.mark.parametrize("text,strict", [
    ("CI", True), ("TO", True), ("PA", True), ("CB", True),        # sigle provincia
    ("bio", True), ("bigliettony", True),                          # parole comuni minuscole
    ("FUORI", False), ("STAT", False), ("GUE", False),             # acronimi nudi come org
    ("Piccolo Parco Urbano SOLD OUT", True),                       # frammenti cuciti
    ("SAN SIRO Bigliettony", True),
    ("Auditorium Snai Festival San NEW Siro Parco", False),
])
def test_ner_garbage_scartato(text, strict):
    assert not _looks_real(_clean_ner(text), strict=strict)


@pytest.mark.parametrize("text,strict", [
    ("Mario Rossi", True), ("Roma", True), ("Reggio Calabria", True),
    ("Reggia di Caserta", True), ("Villa Guidini", True),
    ("Sapienza", False), ("BancaX", False), ("Tech Startup", False),
])
def test_entita_legittime_conservate(text, strict):
    assert _looks_real(_clean_ner(text), strict=strict)


# ── Regressione: rilevamenti DEBOLI dentro un dato FORTE ──────────────────────
# Casi reali dal profilo demo: un IBAN scritto con gli spazi (come lo scrive una
# persona e come lo restituisce l'OCR di un documento fotografato) veniva PERSO come
# IBAN e i suoi gruppi di cifre diventavano numeri di telefono — che poi facevano
# scattare SIM swapping e smishing, gonfiando lo score con un canale inesistente.

def test_iban_con_spazi_rilevato_e_normalizzato():
    from services.pii_presidio import detect_pii_presidio
    out = detect_pii_presidio("IBAN IT60 X0542 811101 000000 123456 intestato a Marco Ferrante.")
    ibans = [p.text for p in out if p.type == "IBAN"]
    assert ibans == ["IT60X0542811101000000123456"]  # spazi normalizzati via
    assert not [p for p in out if p.type == "PHONE_NUMBER"]  # nessun telefono fantasma


def test_nome_della_via_non_e_una_persona():
    """'Via Garibaldi 12' è un indirizzo intero: il NER ne estraeva 'Garibaldi' come NOME."""
    from services.pii_presidio import detect_pii_presidio
    out = detect_pii_presidio("Nuova casa! Via Garibaldi 12, Roma. Passate a trovarmi.")
    assert "Via Garibaldi 12" in [p.text for p in out if p.type == "ADDRESS"]
    assert "Garibaldi" not in [p.text for p in out if p.type == "NAME"]


def test_durata_non_e_eta():
    """'Dopo 5 anni a Roma' è una durata. Ma un'età vera deve restare."""
    from services.pii_presidio import detect_pii_presidio
    assert not [p for p in detect_pii_presidio("Primo anno in Deloitte! Dopo 5 anni a Roma.")
                if p.type == "AGE"]
    assert [p.text for p in detect_pii_presidio("Ho 27 anni e vivo a Roma.") if p.type == "AGE"] == ["27 anni"]


def test_telefono_vero_sopravvive():
    """La protezione dai dati forti non deve mangiare i telefoni legittimi."""
    from services.pii_presidio import detect_pii_presidio
    out = detect_pii_presidio("Chiamami al +39 340 1234567.")
    assert [p.text for p in out if p.type == "PHONE_NUMBER"] == ["+39 340 1234567"]


# ── Regressione: campi IBAN letti dall'OCR come telefoni ──────────────────────
# Caso reale (report tony/ferrante): l'OCR di un documento legge i campi dell'IBAN
# (ABI 05428, CAB 11101, conto 000000 123456) come cifre nude quando il prefisso
# "IT60X" e' su un'altra riga. La regex del telefono spezzava la sequenza da 22 cifre
# in due falsi "telefoni". Un telefono vero e' un token isolato, non un gruppo dentro
# una sequenza piu' lunga di cifre.

def test_campi_iban_ocr_non_sono_telefoni():
    from services.pii_presidio import detect_pii_presidio
    out = detect_pii_presidio("05428 11101 000000 123456")
    assert not [p for p in out if p.type == "PHONE_NUMBER"]


import pytest
@pytest.mark.parametrize("testo,atteso", [
    ("Chiamami al +39 340 1234567.", "+39 340 1234567"),
    ("Tel 0542 811101", "0542 811101"),          # stesso prefisso dell'IBAN, ma isolato
    ("Cell: 333 1234567", "333 1234567"),
    ("il mio numero e 3401234567.", "3401234567"),
])
def test_telefoni_veri_sopravvivono(testo, atteso):
    from services.pii_presidio import detect_pii_presidio
    assert atteso in [p.text for p in detect_pii_presidio(testo) if p.type == "PHONE_NUMBER"]


# ── Regressione: email di contatto Instagram sotto nomi di campo variabili ────
# L'actor Apify espone l'email di contatto (account business/creator) con nomi
# diversi a seconda della versione. Invece di indovinarli, _instagram_extract
# raccoglie ogni email da qualunque campo testuale del profilo.

def test_email_contatto_qualunque_campo():
    from services.scraper import _instagram_extract
    from services.pii_presidio import detect_pii_presidio
    # email presente SOLO in un campo dal nome imprevisto
    item = {"username": "x", "fullName": "Marco Ferrante",
            "public_email": "marco.ferrante@gmail.com"}
    testo = _instagram_extract([item])
    assert "marco.ferrante@gmail.com" in [p.text for p in detect_pii_presidio(testo) if p.type == "EMAIL"]


def test_email_in_campo_non_previsto():
    from services.scraper import _instagram_extract
    item = {"username": "x", "contact_blob": "booking: agente@studio.it"}
    assert "agente@studio.it" in _instagram_extract([item])


# ── Regressione: org spazzatura multi-parola tutto-maiuscolo ──────────────────
# "OCC STATE" (OCR di un documento) passava come ORGANIZATION perché il filtro
# scartava solo le sigle SINGOLE brevi. Una org vera è Titlecase o camelCase.
import pytest

@pytest.mark.parametrize("testo", ["OCC STATE", "FISIOG CORPO SPIRTO"])
def test_org_multiparola_maiuscolo_scartata(testo):
    from services.pii_presidio import _looks_real, _clean_ner
    assert not _looks_real(_clean_ner(testo), strict=False)

@pytest.mark.parametrize("testo", ["Deloitte Italia", "BancaX", "Sapienza", "Studio Conti"])
def test_org_vere_conservate(testo):
    from services.pii_presidio import _looks_real, _clean_ner
    assert _looks_real(_clean_ner(testo), strict=False)
