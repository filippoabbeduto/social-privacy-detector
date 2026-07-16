# ==============================================================================
# TEST - Risoluzione segreti env → SSM (secret_resolver.py) (SDCC)
# ==============================================================================

from services.secret_resolver import resolve_secret


def test_direct_value_wins():
    assert resolve_secret("abc", "some/param", aws_mock=True) == "abc"


def test_empty_direct_and_mock_returns_empty():
    # In mock non si contatta SSM: senza valore diretto → "".
    assert resolve_secret("", "some/param", aws_mock=True) == ""


def test_no_param_returns_empty():
    assert resolve_secret("", "", aws_mock=False) == ""
