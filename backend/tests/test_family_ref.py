# ==============================================================================
# TEST - Riferimenti familiari (FAMILY_REF)
# Requisito esplicito della traccia. Un nome permette di impersonare quella
# persona; un LEGAME permette di impersonare qualcuno vicino a lei, che inganna
# meglio ("sono la maestra di sua figlia Sofia..."). Rilevato e mostrato, NON
# pesato nello score: non c'è una fonte per stimarne P e I.
# ==============================================================================

import pytest
from services.pii_presidio import detect_pii_presidio
from services.risk_empirical import build_empirical_assessment


def _fam(text):
    return [p.text for p in detect_pii_presidio(text) if p.type == "FAMILY_REF"]


def test_legame_con_nome():
    """'mia figlia Sofia' espone piu' di 'mia figlia': il nome va catturato."""
    assert _fam("Al mare con mia figlia Sofia e mio marito Luca.") == \
        ["mia figlia Sofia", "mio marito Luca"]


def test_legame_senza_nome():
    assert _fam("Auguri a mia sorella! Oggi si laurea.") == ["mia sorella"]


def test_maiuscola_a_inizio_frase():
    assert _fam("Mia moglie Anna compie gli anni.") == ["Mia moglie Anna"]


def test_non_cattura_la_parola_seguente_se_non_e_un_nome():
    """Presidio compila i pattern con IGNORECASE di default: senza disattivarlo
    '[A-ZÀ-Ù]' matcherebbe le minuscole e qui catturava 'vivono' come nome."""
    assert _fam("I miei genitori vivono a Roma.") == ["miei genitori"]


@pytest.mark.parametrize("testo", [
    "Buona festa della mamma a tutte!",   # nessun possessivo: non e' un suo legame
    "Il nonno di Luca sta bene.",         # parentela di un terzo
])
def test_nessun_falso_positivo(testo):
    assert _fam(testo) == []


def test_non_altera_lo_score():
    """Vincolo di progetto: rilevato e mostrato, ma a costo ZERO sul punteggio.
    Nessun attacco lo richiede e non e' un tipo tracciato per le abitudini."""
    base = "Sono Marco Ferrante, marco@x.it, lavoro in Deloitte."
    con = base + " Al mare con mia figlia Sofia e mio marito Luca."
    _, _, score_base, _ = build_empirical_assessment(detect_pii_presidio(base))
    piis_con = detect_pii_presidio(con)
    _, _, score_con, _ = build_empirical_assessment(piis_con)
    assert score_con == score_base
    assert len([p for p in piis_con if p.type == "FAMILY_REF"]) == 2
