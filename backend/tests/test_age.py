# ==============================================================================
# TEST - Estrattore di ETÀ context-based (regex + Presidio) (SDCC)
# L'età si rileva SOLO con contesto ("27 anni", "27 years old", "classe 1998"):
# un numero nudo non deve mai diventare un'età (niente falsi positivi).
# ==============================================================================

from services.pii_detector import PIIDetectorService


def _regex_types(text):
    return [(e.type, e.text) for e in PIIDetectorService()._detect_pii_regex(text)]


def test_age_with_context_regex():
    out = _regex_types("Ciao, ho 27 anni. Classe 1998. I'm 30 years old.")
    ages = [txt for (t, txt) in out if t == "AGE"]
    assert any("27" in a for a in ages)
    assert any("1998" in a for a in ages)
    assert any("30" in a for a in ages)


def test_age_no_false_positive_regex():
    out = _regex_types("Ho pubblicato 27 post e speso 27€. Il 27 esco. Prima classe.")
    assert not any(t == "AGE" for (t, _txt) in out)


def test_age_presidio():
    from services.pii_presidio import detect_pii_presidio
    out = detect_pii_presidio("Mi chiamo Luca, ho 27 anni.")
    assert any(e.type == "AGE" for e in out)


def test_age_feeds_risk_as_dob_alias():
    # Nel modello empirico l'alias AGE→DATE_OF_BIRTH: un'età deve poter contribuire.
    from services.risk_empirical import _ALIASES
    assert _ALIASES.get("AGE") == "DATE_OF_BIRTH"


def test_age_no_false_positive_on_durations():
    # "N anni fa" (tempo trascorso) e "da/per N anni" (durata) NON sono età.
    out = _regex_types("Ci siamo conosciuti 3 anni fa. Studio da 5 anni. Vivo qui per 2 anni.")
    assert not any(t == "AGE" for (t, _txt) in out)


def test_age_still_detects_real_age():
    out = _regex_types("Ho 27 anni e sono contento.")
    assert any(t == "AGE" and "27" in txt for (t, txt) in out)
