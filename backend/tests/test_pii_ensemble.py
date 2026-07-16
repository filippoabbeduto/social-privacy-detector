# ==============================================================================
# TEST - Merge ensemble Presidio + LLM (pii_detector._merge_ensemble) (SDCC)
# Funzione pura: nessuna rete. Verifica confidenza-da-accordo, recall solo-LLM,
# conflitto di tipo, preservazione delle occorrenze e fallback a Presidio.
# ==============================================================================

from services.pii_detector import PIIDetectorService
from models.schemas import PIIEntity


def _svc():
    return PIIDetectorService()


def test_agreement_boosts_confidence():
    presidio = [PIIEntity(type="NAME", text="Mario Rossi", score=0.60)]
    llm = [PIIEntity(type="NAME", text="Mario Rossi", score=0.0)]
    out = _svc()._merge_ensemble(presidio, llm)
    m = [e for e in out if e.type == "NAME" and e.text == "Mario Rossi"]
    assert len(m) == 1 and m[0].score == 0.95


def test_llm_only_adds_recall_at_075():
    presidio = []
    llm = [PIIEntity(type="LOCATION", text="Rende", score=0.0)]
    out = _svc()._merge_ensemble(presidio, llm)
    m = [e for e in out if e.text == "Rende"]
    assert len(m) == 1 and m[0].type == "LOCATION" and m[0].score == 0.75


def test_fuzzy_non_confermato_scartato():
    """L'LLM ha risposto e non ha visto "Unical": è un falso positivo del NER."""
    presidio = [PIIEntity(type="ORGANIZATION", text="Unical", score=0.82)]
    out = _svc()._merge_ensemble(presidio, [])
    assert not [e for e in out if e.text == "Unical"]


def test_span_cucito_scartato_ma_citta_tenuta():
    """Caso reale (calendario eventi): spaCy cuce tre città in un unico span. L'LLM
    le restituisce separate, quindi lo span cucito non è contenuto in nessuna e cade;
    "Roma" invece è confermata."""
    presidio = [
        PIIEntity(type="LOCATION", text="Cortona Parma Roma", score=0.85),
        PIIEntity(type="LOCATION", text="Roma", score=0.85),
    ]
    llm = [PIIEntity(type="LOCATION", text="Roma", score=0.0),
           PIIEntity(type="LOCATION", text="Parma", score=0.0)]
    out = [e.text for e in _svc()._merge_ensemble(presidio, llm)]
    assert "Cortona Parma Roma" not in out
    assert "Roma" in out


def test_conferma_per_contenimento():
    """L'LLM restituisce lo span più largo: il candidato più stretto di Presidio è
    comunque confermato dal contesto e mantiene il proprio tipo."""
    presidio = [PIIEntity(type="LOCATION", text="Villa Guidini", score=0.85)]
    llm = [PIIEntity(type="LOCATION", text="Villa Guidini Reggia di Caserta", score=0.0)]
    out = _svc()._merge_ensemble(presidio, llm)
    assert ("LOCATION", "Villa Guidini", 0.85) in [(e.type, e.text, e.score) for e in out]


def test_type_conflict_presidio_wins():
    # Stesso testo, tipo diverso: Presidio dice LOCATION, LLM dice NAME -> vince Presidio,
    # la variante LLM viene scartata.
    presidio = [PIIEntity(type="LOCATION", text="Firenze", score=0.70)]
    llm = [PIIEntity(type="NAME", text="Firenze", score=0.0)]
    out = _svc()._merge_ensemble(presidio, llm)
    firenze = [e for e in out if e.text == "Firenze"]
    assert len(firenze) == 1
    assert firenze[0].type == "LOCATION"
    assert firenze[0].score == 0.70  # Presidio non degradato


def test_non_fuzzy_passes_through():
    presidio = [PIIEntity(type="EMAIL", text="a@b.it", score=0.99)]
    llm = []
    out = _svc()._merge_ensemble(presidio, llm)
    assert any(e.type == "EMAIL" and e.text == "a@b.it" and e.score == 0.99 for e in out)


def test_repeated_occurrences_preserved():
    # Due occorrenze di "Roma" (segnale di routine) NON vanno collassate.
    presidio = [
        PIIEntity(type="LOCATION", text="Roma", score=0.88),
        PIIEntity(type="LOCATION", text="Roma", score=0.88),
    ]
    llm = [PIIEntity(type="LOCATION", text="Roma", score=0.0)]
    out = _svc()._merge_ensemble(presidio, llm)
    roma = [e for e in out if e.text == "Roma"]
    assert len(roma) == 2
    assert all(e.score == 0.95 for e in roma)  # entrambe boostate dall'accordo


def test_llm_vuoto_scarta_i_fuzzy_ma_non_i_dati_strutturati():
    """LLM che risponde "nessuna entità": i fuzzy cadono, i dati strutturati (che non
    passano mai dall'LLM) restano intatti."""
    presidio = [
        PIIEntity(type="NAME", text="Mario Rossi", score=0.60),
        PIIEntity(type="EMAIL", text="a@b.it", score=0.99),
    ]
    out = _svc()._merge_ensemble(presidio, [])
    assert [(e.type, e.text, e.score) for e in out] == [("EMAIL", "a@b.it", 0.99)]


def test_llm_fallito_non_azzera_i_fuzzy(monkeypatch):
    """Guardia critica: se l'LLM fallisce (None) la verifica NON si applica: un
    timeout non deve cancellare tutti i nomi e i luoghi trovati da Presidio."""
    svc = _svc()
    monkeypatch.setattr("services.pii_presidio.detect_pii_presidio",
                        lambda t: [PIIEntity(type="NAME", text="Mario Rossi", score=0.85)])
    monkeypatch.setattr("services.pii_llm.detect_pii_llm", lambda t: None)
    out = svc._detect_pii_ensemble("Mario Rossi")
    assert [(e.type, e.text, e.score) for e in out] == [("NAME", "Mario Rossi", 0.85)]


def test_username_non_diventa_nome():
    """L'LLM legge gli username come nomi di persona ("@mario.rossi" → NAME). Sono già
    USERNAME per Presidio, che possiede i tipi strutturati: la variante fuzzy va scartata,
    altrimenti lo stesso dato compare due volte e con il tipo sbagliato."""
    presidio = [PIIEntity(type="USERNAME", text="@maspio_fresh", score=0.60)]
    llm = [PIIEntity(type="NAME", text="@maspio_fresh", score=0.0),
           PIIEntity(type="NAME", text="maspio_fresh", score=0.0)]  # anche senza @
    out = _svc()._merge_ensemble(presidio, llm)
    assert [(e.type, e.text) for e in out] == [("USERNAME", "@maspio_fresh")]


def test_email_non_diventa_nome():
    presidio = [PIIEntity(type="EMAIL", text="mario.rossi@x.it", score=1.0)]
    llm = [PIIEntity(type="NAME", text="mario.rossi@x.it", score=0.0)]
    out = _svc()._merge_ensemble(presidio, llm)
    assert [e.type for e in out] == ["EMAIL"]
