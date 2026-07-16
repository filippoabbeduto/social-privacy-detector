# ==============================================================================
# TEST - Pianificatore di sanitizzazione mirata a "rischio basso" (SDCC)
# Rimuove i dati più pericolosi finché lo score scende sotto 35, non azzera.
# ==============================================================================

from models.schemas import PIIEntity
from services.risk_scorer import plan_sanitization, RISK_THRESHOLDS


def _p(t, txt, s=0.9):
    return PIIEntity(type=t, text=txt, score=s)


def test_reduces_to_low_keeping_least_dangerous():
    piis = [_p("EMAIL", "a@b.it"), _p("PHONE_NUMBER", "333-1234567"),
            _p("FISCAL_CODE", "RSSMRA90A01H501A"), _p("IBAN", "IT60X0542811101000000123456"),
            _p("NAME", "Mario Rossi"), _p("ORGANIZATION", "Sapienza"),
            _p("DATE_OF_BIRTH", "01/01/1990")]
    plan = plan_sanitization(piis)
    assert plan["final_score"] < RISK_THRESHOLDS["MEDIUM"]           # sceso a BASSO
    kept_types = {p.type for p in plan["to_keep"]}
    removed_types = {p.type for p in plan["to_remove"]}
    # I codici più pericolosi vengono rimossi; i meno pericolosi (nome/org) restano se possibile.
    assert "FISCAL_CODE" in removed_types and "IBAN" in removed_types
    assert "NAME" in kept_types or "ORGANIZATION" in kept_types
    # to_remove + to_keep = insieme originale
    assert len(plan["to_remove"]) + len(plan["to_keep"]) == len(piis)


def test_already_low_removes_nothing():
    piis = [_p("NAME", "Mario Rossi"), _p("USERNAME", "@mario")]
    plan = plan_sanitization(piis)
    assert plan["to_remove"] == []
    assert plan["final_score"] < RISK_THRESHOLDS["MEDIUM"]


def test_most_dangerous_removed_first():
    piis = [_p("NAME", "Mario Rossi"), _p("FISCAL_CODE", "RSSMRA90A01H501A"),
            _p("IBAN", "IT60X0542811101000000123456"), _p("EMAIL", "a@b.it")]
    plan = plan_sanitization(piis)
    # Se qualcosa è rimosso, il primo rimosso è tra i più pericolosi (CF/IBAN), non il nome.
    if plan["to_remove"]:
        assert plan["to_remove"][0].type in {"FISCAL_CODE", "IBAN", "CREDIT_DEBIT_NUMBER", "PHONE_NUMBER"}


def test_empty_input():
    plan = plan_sanitization([])
    assert plan["to_remove"] == [] and plan["to_keep"] == [] and plan["final_score"] == 0


def test_sanitize_endpoint_targets_low(monkeypatch):
    # Senza LLM (mock) → masking deterministico dei soli to_remove.
    monkeypatch.setenv("AWS_MOCK", "true")
    from fastapi.testclient import TestClient
    from main import app
    c = TestClient(app)
    bio = ("Sono Mario Rossi, email mario@x.it, tel 333-1234567, "
           "CF RSSMRA90A01H501A, IBAN IT60X0542811101000000123456. Studio alla Sapienza.")
    r = c.post("/api/sanitize-bio", json={"text": bio})
    assert r.status_code == 200
    body = r.json()
    assert body["risk_level"] == "LOW"
    assert body["kept_types"]           # qualcosa è stato mantenuto (non azzerato)
    assert "FISCAL_CODE" in body["removed_types"]
