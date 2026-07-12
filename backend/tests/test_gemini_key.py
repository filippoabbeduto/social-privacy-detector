# Test risoluzione chiave LLM: env diretta vince; se manca tutto -> "" (no crash).
import services.report_generator as rg


def test_env_key_wins(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "sk-local")
    assert rg._resolve_gemini_key() == "sk-local"


def test_missing_returns_empty(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY_SSM", "")  # nessun parametro SSM configurato
    assert rg._resolve_gemini_key() == ""
