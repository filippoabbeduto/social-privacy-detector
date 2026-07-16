# ==============================================================================
# TEST - Priorità di bonifica / leva (routers.analysis._compute_leverage) (SDCC)
# ==============================================================================

from models.schemas import PIIEntity
from routers.analysis import _compute_leverage


def _p(t, txt, s=0.99):
    return PIIEntity(type=t, text=txt, score=s)


def test_leverage_ranks_by_impact():
    piis = [_p("EMAIL", "a@b.it"), _p("FISCAL_CODE", "ABCDEF00A00A000A"),
            _p("IBAN", "IT60X0542811101000000123456"), _p("NAME", "Mario Rossi"),
            _p("DATE_OF_BIRTH", "01/01/1990")]
    base, items = _compute_leverage(piis)
    assert base > 0
    deltas = [it["delta"] for it in items]
    assert deltas == sorted(deltas, reverse=True)
    cf = next(it for it in items if it["type"] == "FISCAL_CODE")
    assert cf["delta"] >= min(deltas)


def test_leverage_empty():
    base, items = _compute_leverage([])
    assert base == 0 and items == []
