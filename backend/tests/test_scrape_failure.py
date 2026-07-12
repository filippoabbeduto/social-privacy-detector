# ==============================================================================
# Test: uno scraping senza dati (profilo privato/inesistente/irraggiungibile)
# NON deve produrre un'analisi su dati inventati, ma marcare il job come FAILED.
# Regressione per il bug: in reale lo scraper faceva fallback su bio mock.
# ==============================================================================

# La pipeline e i suoi singleton sono stati estratti in services/pipeline.py
# (riuso tra worker in-process e Lambda): i test ora puntano lì.
from services import pipeline
from services.storage import JOB_STATUS_FAILED, JOB_STATUS_COMPLETED


def test_scrape_vuoto_marca_job_failed(monkeypatch):
    """Scrape che ritorna None -> job FAILED con messaggio 'non accessibile'."""
    aid = "test-scrape-none"
    pipeline.storage_service.create_job(aid, "https://instagram.com/inesistente")

    # Simula profilo non accessibile: lo scraper non trova né testo né immagini.
    monkeypatch.setattr(
        pipeline.scraper_service, "scrape_profile_with_images", lambda url: (None, [])
    )

    pipeline.run_analysis(aid, "https://instagram.com/inesistente", scraped_content=None)

    rec = pipeline.storage_service.get_analysis(aid)
    assert rec["status"] == JOB_STATUS_FAILED
    assert "non accessibile" in (rec.get("error") or "").lower()


def test_scraped_content_fornito_dal_client_procede(monkeypatch):
    """Se il client fornisce già il testo, l'analisi procede anche senza scraping."""
    aid = "test-scrape-provided"
    pipeline.storage_service.create_job(aid, "https://instagram.com/tizio")

    # Lo scraper NON deve nemmeno essere chiamato: il testo è già fornito.
    def _boom(url):
        raise AssertionError("lo scraper non doveva essere invocato")
    monkeypatch.setattr(pipeline.scraper_service, "scrape_profile_with_images", _boom)

    pipeline.run_analysis(
        aid,
        "https://instagram.com/tizio",
        scraped_content="Mario Rossi, email mario.rossi@gmail.com, cell 333-1234567",
    )

    rec = pipeline.storage_service.get_analysis(aid)
    assert rec["status"] == JOB_STATUS_COMPLETED
    assert rec["pii_count"] >= 1
