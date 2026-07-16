# ==============================================================================
# TEST - Esempio didattico di messaggio d'attacco via Ollama (attack_example.py)
# Client finto (monkeypatch): nessuna rete.
# ==============================================================================

import services.attack_example as ax


def test_generates_example(monkeypatch):
    monkeypatch.setenv("PII_LLM_BASE_URL", "http://fake/v1")
    monkeypatch.setenv("PII_LLM_MODEL", "fake")

    class _Msg:
        content = "Gentile Filippo, la sua fattura Sapienza e pronta: clicchi qui."

    class _Choice:
        message = _Msg()

    class _Resp:
        choices = [_Choice()]

    class _Completions:
        def create(self, **k):
            return _Resp()

    class _Chat:
        completions = _Completions()

    class _Cli:
        chat = _Chat()

    monkeypatch.setattr(ax, "_make_client", lambda b, k: _Cli())
    msg, err = ax.generate_attack_example([{"type": "NAME", "text": "Filippo"}], "Spear phishing / BEC")
    assert "Filippo" in msg and err == ""


def test_recipient_is_most_reliable_name():
    """Il destinatario è il titolare dei dati: si passa esplicito al modello, altrimenti
    sui vettori tipo BEC inverte la direzione e firma il messaggio come la vittima."""
    pii = [{"type": "NAME", "text": "Tizio Incerto", "score": 0.60},
           {"type": "NAME", "text": "Tony Pitony", "score": 0.95},
           {"type": "EMAIL", "text": "a@b.it", "score": 1.0}]
    assert ax._recipient_name(pii) == "Tony Pitony"


def test_recipient_without_name_is_generic():
    assert "generica" in ax._recipient_name([{"type": "EMAIL", "text": "a@b.it", "score": 1.0}])


def test_brand_del_proprietario_non_e_ente_esterno():
    """Il mittente dev'essere ESTERNO alla vittima: le organizzazioni derivate dal suo
    nome/dominio sono sue, altrimenti sarebbe lei a scrivere a sé stessa."""
    pii = [{"type": "NAME", "text": "Tony Pitony", "score": 0.95},
           {"type": "URL", "text": "https://oggettony.com/", "score": 0.6},
           {"type": "ORGANIZATION", "text": "Bigliettony", "score": 0.75},
           {"type": "ORGANIZATION", "text": "OggettoTony", "score": 0.75}]
    assert ax._external_orgs(pii) == []
    assert "Poste Italiane" in ax._sender_hint(pii)  # ripiego su ente sensibile generico


def test_ente_esterno_riconosciuto_e_usato():
    pii = [{"type": "NAME", "text": "Mario Rossi", "score": 0.95},
           {"type": "ORGANIZATION", "text": "Sapienza", "score": 0.9}]
    assert ax._external_orgs(pii) == ["Sapienza"]
    assert "Sapienza" in ax._sender_hint(pii)


def test_strips_links_keeping_emails():
    """Il sito della vittima non deve mai diventare il link di phishing: ogni URL
    del messaggio è sostituito da [link], ma le email citate restano intatte."""
    msg = ax._strip_links(
        "Gentile Tony, da info@tonypitony.it: conferma su https://oggettony.com/confirm "
        "oppure www.esca.net o vai su oggettony.com/pay")
    assert "oggettony.com" not in msg
    assert "esca.net" not in msg
    assert msg.count("[link]") == 3
    assert "info@tonypitony.it" in msg


def test_no_config_returns_empty(monkeypatch):
    monkeypatch.delenv("PII_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("PII_LLM_MODEL", raising=False)
    msg, err = ax.generate_attack_example([{"type": "NAME", "text": "X"}], "Phishing")
    assert msg == "" and err == "not_configured"
