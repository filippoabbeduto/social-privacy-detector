# ==============================================================================
# TEST - Modello di rischio EMPIRICO (Σ Pₐ·Iₐ) (SDCC)
# ==============================================================================

from models.schemas import PIIEntity
from services.risk_empirical import (
    _normalize_types, _fired_attacks, ATTACKS,
    build_empirical_assessment, build_empirical_extras,
)


def _p(t, s=0.99):
    return PIIEntity(type=t, text=t, score=s)


# ── Catalogo / normalizzazione ────────────────────────────────────────────────

def test_alias_normalization():
    got = _normalize_types([_p("PHONE"), _p("AGE"), _p("BANK_ACCOUNT_NUMBER"), _p("SSN")])
    assert got == {"PHONE_NUMBER", "DATE_OF_BIRTH", "IBAN", "FISCAL_CODE"}


def test_fired_attacks_gate():
    fired = {a.id for a in _fired_attacks({"EMAIL"})}
    assert "phishing" in fired and "spam" in fired
    assert "spear_bec" not in fired


def test_fiscal_code_alone_fires_impersonation():
    assert "impersonation_cf" in {a.id for a in _fired_attacks({"FISCAL_CODE"})}


def test_catalog_values_present():
    ids = {a.id for a in ATTACKS}
    assert {"phishing", "smishing", "spear_bec", "ato", "sim_swap", "id_theft_base",
            "id_theft_cf", "financial_fraud", "doxing", "impersonation_cf", "spam"} <= ids


# ── Scoring ───────────────────────────────────────────────────────────────────

def test_empty_is_zero_low():
    lvl, expl, score, _ = build_empirical_assessment([])
    assert score == 0 and lvl == "LOW" and isinstance(expl, str)


def test_single_email_is_low():
    lvl, _, score, _ = build_empirical_assessment([_p("EMAIL")])
    assert lvl == "LOW" and score < 35


def test_bec_profile_is_high():
    lvl, _, score, _ = build_empirical_assessment([_p("EMAIL"), _p("NAME"), _p("ORGANIZATION")])
    assert lvl == "HIGH" and score >= 70


def test_bounded_and_monotone():
    base = build_empirical_assessment([_p("EMAIL"), _p("NAME")])[2]
    more = build_empirical_assessment([_p("EMAIL"), _p("NAME"), _p("ORGANIZATION")])[2]
    assert 0 <= base <= 100 and 0 <= more <= 100
    assert more >= base


def test_fiscal_code_alone_positive():
    assert build_empirical_assessment([_p("FISCAL_CODE")])[2] > 0


# ── Extras ────────────────────────────────────────────────────────────────────

def test_extras_combos_are_attacks():
    extras = build_empirical_extras([_p("EMAIL"), _p("NAME"), _p("ORGANIZATION")])
    labels = {c["label"] for c in extras["combos"]}
    assert "Spear phishing / BEC" in labels
    c0 = extras["combos"][0]
    assert {"label", "types", "points", "impact"} <= set(c0.keys()) and c0["points"] > 0


def test_extras_repetitions_detect_routine():
    reps = build_empirical_extras([_p("LOCATION") for _ in range(4)])["repetitions"]
    assert reps and reps[0]["count"] == 4


# ── Dispatch RISK_MODEL ───────────────────────────────────────────────────────

def test_dispatch_empirical(monkeypatch):
    import importlib
    import services.risk_scorer as RS
    monkeypatch.setenv("RISK_MODEL", "empirical")
    importlib.reload(RS)
    try:
        lvl, _, score, _ = RS.build_risk_assessment([_p("EMAIL"), _p("NAME"), _p("ORGANIZATION")])
        assert lvl == "HIGH"  # via modello empirico
        extras = RS.build_risk_extras([_p("EMAIL"), _p("NAME"), _p("ORGANIZATION")])
        assert any(c["label"] == "Spear phishing / BEC" for c in extras["combos"])
    finally:
        monkeypatch.setenv("RISK_MODEL", "heuristic")
        importlib.reload(RS)
