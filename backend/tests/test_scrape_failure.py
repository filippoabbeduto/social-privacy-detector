# ==============================================================================
# Test: uno scraping senza dati (profilo privato/inesistente/irraggiungibile)
# NON deve produrre un'analisi su dati inventati, ma marcare il job come FAILED.
# Regressione per il bug: in reale lo scraper faceva fallback su bio mock.
# ==============================================================================

from routers import analysis
from services.storage import JOB_STATUS_FAILED, JOB_STATUS_COMPLETED


def test_scrape_vuoto_marca_job_failed(monkeypatch):
    """Scrape che ritorna None -> job FAILED con messaggio 'non accessibile'."""
    aid = "test-scrape-none"
    analysis.storage_service.create_job(aid, "https://instagram.com/inesistente")

    # Simula profilo non accessibile: lo scraper non trova dati.
    monkeypatch.setattr(analysis.scraper_service, "scrape_profile", lambda url: None)

    analysis._run_analysis_pipeline(aid, "https://instagram.com/inesistente", scraped_content=None)

    rec = analysis.storage_service.get_analysis(aid)
    assert rec["status"] == JOB_STATUS_FAILED
    assert "non accessibile" in (rec.get("error") or "").lower()


def test_scraped_content_fornito_dal_client_procede(monkeypatch):
    """Se il client fornisce già il testo, l'analisi procede anche senza scraping."""
    aid = "test-scrape-provided"
    analysis.storage_service.create_job(aid, "https://instagram.com/tizio")

    # Lo scraper NON deve nemmeno essere chiamato: il testo è già fornito.
    def _boom(url):
        raise AssertionError("scrape_profile non doveva essere invocato")
    monkeypatch.setattr(analysis.scraper_service, "scrape_profile", _boom)

    analysis._run_analysis_pipeline(
        aid,
        "https://instagram.com/tizio",
        scraped_content="Mario Rossi, email mario.rossi@gmail.com, cell 333-1234567",
    )

    rec = analysis.storage_service.get_analysis(aid)
    assert rec["status"] == JOB_STATUS_COMPLETED
    assert rec["pii_count"] >= 1
