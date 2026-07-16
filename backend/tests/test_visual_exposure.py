# ==============================================================================
# TEST - Classificazione etichette visive sensibili (visual_exposure.py) (SDCC)
# Funzione pura: nessuna rete. Verifica categorie, match case-insensitive,
# assenza di collisioni e la nota deterministica per il report.
# ==============================================================================

from services.visual_exposure import classify_sensitive_labels, sensitive_note


def _lab(name, conf=90.0):
    return {"name": name, "confidence": conf}


def test_minori_category():
    out = classify_sensitive_labels([_lab("Child"), _lab("Baby")])
    cats = {(e["category"], e["label"]) for e in out}
    assert ("MINORI", "Child") in cats
    assert ("MINORI", "Baby") in cats


def test_documenti_and_geo_categories():
    out = classify_sensitive_labels([_lab("Passport"), _lab("License Plate")])
    by_label = {e["label"]: e["category"] for e in out}
    assert by_label["Passport"] == "DOCUMENTI"
    assert by_label["License Plate"] == "GEO"


def test_no_collision_license_plate_vs_driving_license():
    out = classify_sensitive_labels([_lab("License Plate"), _lab("Driving License")])
    by_label = {e["label"]: e["category"] for e in out}
    assert by_label["License Plate"] == "GEO"
    assert by_label["Driving License"] == "DOCUMENTI"


def test_generic_labels_ignored():
    out = classify_sensitive_labels([_lab("Text"), _lab("Person"), _lab("Beach")])
    assert out == []


def test_case_insensitive():
    out = classify_sensitive_labels([_lab("CHILD")])
    assert len(out) == 1 and out[0]["category"] == "MINORI"


def test_confidence_preserved():
    out = classify_sensitive_labels([_lab("Passport", 81.3)])
    assert out[0]["confidence"] == 81.3


def test_empty_input():
    assert classify_sensitive_labels([]) == []


def test_note_empty_when_no_sensitive():
    assert sensitive_note([]) == ""


def test_note_mentions_categories():
    sensitive = [
        {"category": "MINORI", "label": "Child", "confidence": 90.0},
        {"category": "DOCUMENTI", "label": "Passport", "confidence": 88.0},
    ]
    note = sensitive_note(sensitive)
    assert "minore" in note.lower()
    assert "documento" in note.lower()


def test_sensitive_label_schema_roundtrip():
    from models.schemas import SensitiveLabel, AnalysisReportResponse
    sl = SensitiveLabel(category="MINORI", label="Child", confidence=92.0)
    resp = AnalysisReportResponse(analysis_id="x", social_url="x", status="COMPLETED",
                                  sensitive_visual=[sl])
    assert resp.sensitive_visual[0].category == "MINORI"
    assert resp.sensitive_visual[0].label == "Child"


def test_no_substring_false_positives():
    # Keyword corte non devono matchare dentro parole più lunghe.
    out = classify_sensitive_labels([_lab("Cowboy"), _lab("Documentary"), _lab("Roadmap"), _lab("Keyboard")])
    assert out == []


def test_whole_word_still_matches():
    out = classify_sensitive_labels([_lab("Boy"), _lab("Document"), _lab("Street Sign")])
    cats = {e["category"] for e in out}
    assert cats == {"MINORI", "DOCUMENTI", "GEO"}


# ── Regressione: le due soglie dell'analisi visiva ────────────────────────────
# Caso reale: su una foto con un minore, Rekognition non ha mai emesso "Child".
# Causa: MaxLabels=15 (i 15 posti erano esauriti da etichette di scena) e
# MinConfidence=75 (un minore inquadrato male esce sotto soglia). Quei numeri
# erano tarati per le etichette di scena, dove conta la precisione; per le
# categorie sensibili la priorità è opposta.

def test_categoria_sensibile_rilevata_anche_a_bassa_confidenza():
    """Un minore a confidenza bassa DEVE comunque far scattare la categoria:
    la classificazione non filtra per confidenza, lo fa solo la visualizzazione."""
    from services.visual_exposure import classify_sensitive_labels
    labels = [{"name": "Person", "confidence": 99.0},
              {"name": "Child", "confidence": 58.0}]  # sotto la vecchia soglia di 75
    out = classify_sensitive_labels(labels)
    assert [s["category"] for s in out] == ["MINORI"]


def test_soglie_visive_coerenti():
    """La soglia di interrogazione dev'essere piu' bassa di quella di visualizzazione,
    altrimenti il filtro largo non serve a niente."""
    from services.pii_detector import (REKOGNITION_MIN_CONFIDENCE,
                                       VISUAL_DISPLAY_MIN_CONFIDENCE,
                                       REKOGNITION_MAX_LABELS)
    assert REKOGNITION_MIN_CONFIDENCE < VISUAL_DISPLAY_MIN_CONFIDENCE
    assert REKOGNITION_MAX_LABELS >= 50


# ── Minori dalla stima d'età (DetectFaces) ────────────────────────────────────
# DetectLabels non vede i minori: su una foto reale con un minore restituisce
# "Adult" al 98.9% e mai "Child". DetectFaces stima 9-15 anni e lo prende.

def test_minore_certo_dalla_stima_eta():
    """Caso reale: la foto aveva due volti, 9-15 anni e 55-61. Solo il primo va segnalato."""
    from services.visual_exposure import minors_from_faces
    out = minors_from_faces([{"low": 9, "high": 15, "confidence": 99.9},
                             {"low": 55, "high": 61, "confidence": 99.8}])
    assert len(out) == 1
    assert out[0]["category"] == "MINORI"
    assert "9-15" in out[0]["label"]
    assert "possibile" not in out[0]["label"]  # intervallo tutto sotto i 18: certo


def test_intervallo_a_cavallo_segnalato_come_possibile():
    """Recall: appena la stima ammette un minore si segnala, ma l'incertezza si dichiara."""
    from services.visual_exposure import minors_from_faces
    out = minors_from_faces([{"low": 15, "high": 23, "confidence": 99.0}])
    assert len(out) == 1 and "possibile minore" in out[0]["label"]


def test_adulti_non_segnalati():
    from services.visual_exposure import minors_from_faces
    assert minors_from_faces([{"low": 25, "high": 33, "confidence": 99.9}]) == []
    assert minors_from_faces([]) == []


def test_nota_report_dai_soli_volti():
    """Un minore trovato SOLO dalla stima d'età deve comunque produrre la nota."""
    from services.visual_exposure import minors_from_faces, sensitive_note
    note = sensitive_note(minors_from_faces([{"low": 9, "high": 15, "confidence": 99.9}]))
    assert "minore" in note.lower()


# ── Collasso: una voce per categoria ──────────────────────────────────────────
# Caso reale: sei avvisi per tre categorie, con "Minore" ripetuto tre volte.

def test_una_voce_per_categoria_eta_vince_sui_minori():
    """Con la stima dell'età disponibile, per i minori si mostra SOLO quella:
    è più precisa di 'Child' e più affidabile."""
    from services.visual_exposure import collapse_sensitive
    etichette = [
        {"category": "MINORI", "label": "Child", "confidence": 99.0},
        {"category": "MINORI", "label": "Girl", "confidence": 99.0},
        {"category": "DOCUMENTI", "label": "Document", "confidence": 97.0},
        {"category": "DOCUMENTI", "label": "Driving License", "confidence": 92.0},
        {"category": "GEO", "label": "Landmark", "confidence": 96.0},
    ]
    volti = [{"category": "MINORI", "label": "Volto con età stimata 4-8 anni", "confidence": 100.0}]
    out = collapse_sensitive(etichette, volti)
    assert [e["category"] for e in out] == ["MINORI", "DOCUMENTI", "GEO"]  # 6 -> 3
    assert out[0]["label"] == "Volto con età stimata 4-8 anni"  # non "Child"
    # la prova più specifica non si perde: confluisce nella stessa voce
    assert out[1]["label"] == "Document, Driving License"


def test_senza_volti_le_etichette_restano_la_rete_di_sicurezza():
    """Minore di spalle o disegnato: nessun volto da stimare, ma l'etichetta c'è."""
    from services.visual_exposure import collapse_sensitive
    out = collapse_sensitive([{"category": "MINORI", "label": "Child", "confidence": 99.0}], [])
    assert len(out) == 1 and out[0]["label"] == "Child"


def test_piu_minori_una_sola_voce_col_conteggio():
    from services.visual_exposure import collapse_sensitive
    volti = [{"category": "MINORI", "label": "Volto con età stimata 4-8 anni", "confidence": 99.0},
             {"category": "MINORI", "label": "Volto con età stimata 9-15 anni", "confidence": 99.0}]
    out = collapse_sensitive([], volti)
    assert len(out) == 1 and "+1 altri volti di minore" in out[0]["label"]
