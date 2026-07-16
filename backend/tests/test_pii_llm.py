# ==============================================================================
# TEST - Estrattore PII via LLM (pii_llm.py) (SDCC)
# Client OpenAI finto (monkeypatch): nessuna rete. Verifica parsing, grounding,
# robustezza a JSON malformato e assenza di configurazione.
#
# Contratto: lista = l'LLM ha risposto (anche vuota); None = non configurato o
# fallito. A monte la distinzione decide se applicare la verifica dei candidati.
# ==============================================================================

import json
import services.pii_llm as pii_llm


class _FakeMessage:
    def __init__(self, content):
        self.content = content


class _FakeChoice:
    def __init__(self, content, finish_reason="stop"):
        self.message = _FakeMessage(content)
        self.finish_reason = finish_reason


class _FakeResponse:
    def __init__(self, content, finish_reason="stop"):
        self.choices = [_FakeChoice(content, finish_reason)]


def _install_fake_llm(monkeypatch, content, finish_reason="stop"):
    """Configura env + client OpenAI finto che restituisce `content` come risposta."""
    monkeypatch.setenv("PII_LLM_BASE_URL", "http://fake/v1")
    monkeypatch.setenv("PII_LLM_MODEL", "fake-model")
    monkeypatch.setenv("PII_LLM_API_KEY", "fake")

    class _FakeCompletions:
        def create(self, **kwargs):
            return _FakeResponse(content, finish_reason)

    class _FakeChat:
        def __init__(self):
            self.completions = _FakeCompletions()

    class _FakeClient:
        def __init__(self, **kwargs):
            self.chat = _FakeChat()

    monkeypatch.setattr(pii_llm, "_make_client", lambda base_url, api_key: _FakeClient())


def test_parses_valid_entities(monkeypatch):
    content = json.dumps({"entities": [
        {"type": "NAME", "text": "Mario Rossi"},
        {"type": "LOCATION", "text": "Cosenza"},
    ]})
    _install_fake_llm(monkeypatch, content)
    text = "Mi chiamo Mario Rossi e vivo a Cosenza."
    out = pii_llm.detect_pii_llm(text)
    types = {(e.type, e.text) for e in out}
    assert ("NAME", "Mario Rossi") in types
    assert ("LOCATION", "Cosenza") in types


def test_grounding_drops_hallucinated_span(monkeypatch):
    # "Napoli" NON compare nel testo -> va scartato dal grounding.
    content = json.dumps({"entities": [
        {"type": "LOCATION", "text": "Cosenza"},
        {"type": "LOCATION", "text": "Napoli"},
    ]})
    _install_fake_llm(monkeypatch, content)
    text = "Vivo a Cosenza."
    out = pii_llm.detect_pii_llm(text)
    texts = {e.text for e in out}
    assert "Cosenza" in texts
    assert "Napoli" not in texts


def test_drops_non_fuzzy_types(monkeypatch):
    # L'LLM non deve produrre codici: un EMAIL viene ignorato (lo possiede Presidio).
    content = json.dumps({"entities": [
        {"type": "EMAIL", "text": "a@b.it"},
        {"type": "NAME", "text": "Mario Rossi"},
    ]})
    _install_fake_llm(monkeypatch, content)
    text = "Mario Rossi a@b.it"
    out = pii_llm.detect_pii_llm(text)
    assert {e.type for e in out} == {"NAME"}


def test_malformed_json_returns_none(monkeypatch):
    _install_fake_llm(monkeypatch, "questo non e json {")
    assert pii_llm.detect_pii_llm("Mario Rossi") is None


def test_missing_config_returns_none(monkeypatch):
    monkeypatch.delenv("PII_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("PII_LLM_MODEL", raising=False)
    assert pii_llm.detect_pii_llm("Mario Rossi vive a Cosenza") is None


def test_truncated_response_returns_none(monkeypatch):
    """Modello reasoning: con max_tokens esaurito il contenuto torna vuoto e
    finish_reason='length'. Va trattato come fallimento, non come 'nessuna entità',
    altrimenti la verifica scarterebbe tutti i candidati di Presidio."""
    _install_fake_llm(monkeypatch, "", finish_reason="length")
    assert pii_llm.detect_pii_llm("Mario Rossi vive a Cosenza") is None


def test_no_entities_returns_empty_list(monkeypatch):
    """Risposta valida e vuota: è un'opinione dell'LLM ('non c'è nulla'), non un errore."""
    _install_fake_llm(monkeypatch, json.dumps({"entities": []}))
    assert pii_llm.detect_pii_llm("testo senza entita") == []
