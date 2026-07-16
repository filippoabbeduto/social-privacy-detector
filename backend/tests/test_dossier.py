# ==============================================================================
# TEST - Dossier deterministico (dossier.py): identità ricomposta dai frammenti (SDCC)
# ==============================================================================

from services.dossier import build_dossier
from models.schemas import PIIEntity


def _p(t, txt):
    return PIIEntity(type=t, text=txt, score=0.9)


def test_dossier_recomposes_identity():
    piis = [_p("NAME", "Filippo Abbeduto"), _p("EMAIL", "f@x.it"),
            _p("LOCATION", "Roma"), _p("ORGANIZATION", "Sapienza")]
    d = build_dossier(piis, [])
    assert "Filippo Abbeduto" in d["text"]
    assert "Roma" in d["text"] and "Sapienza" in d["text"]
    assert any("telefono" in m.lower() or "iban" in m.lower() for m in d["missing"])


def test_dossier_empty():
    d = build_dossier([], [])
    assert d["text"] == "" and d["missing"] == []
