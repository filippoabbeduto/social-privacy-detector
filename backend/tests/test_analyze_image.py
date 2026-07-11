# ==============================================================================
# Test dell'endpoint OCR /api/analyze-image (Amazon Textract + pipeline PII).
# In modalità mock, extract_text_from_image restituisce un testo simulato, quindi
# la pipeline completa gira senza AWS reale.
# ==============================================================================

import time

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)

# 1x1 PNG minimale (basta come "file immagine": in mock l'OCR è simulato).
_PNG_1x1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c4890000000d4944415478da6360000002000154a24f9f0000000049454e44ae426082"
)


def test_analyze_image_accoda_e_completa():
    """Upload immagine -> 202 con analysis_id -> polling fino a COMPLETED, con
    etichette visive (Rekognition) presenti nel risultato."""
    r = client.post("/api/analyze-image", files={"file": ("test.png", _PNG_1x1, "image/png")})
    assert r.status_code == 202
    jid = r.json()["analysis_id"]

    result = None
    for _ in range(15):
        time.sleep(1)
        result = client.get(f"/api/analysis/{jid}").json()
        if result["status"] in ("COMPLETED", "FAILED"):
            break
    assert result["status"] == "COMPLETED"
    # In mock, detect_image_labels restituisce etichette di esempio: devono
    # comparire nel risultato (esposizione visiva via Rekognition).
    assert result["image_labels"], "attese etichette visive dall'immagine"
    assert result["image_labels"][0]["name"]


def test_analyze_image_rifiuta_non_immagine():
    """Un file non-immagine viene respinto con 415."""
    r = client.post("/api/analyze-image", files={"file": ("note.txt", b"solo testo", "text/plain")})
    assert r.status_code == 415
