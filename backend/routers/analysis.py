# ==============================================================================
# ANALYSIS ROUTER - Endpoints per l'analisi asincrona dei profili social (SDCC)
# Percorso: backend/routers/analysis.py
#
# Architettura asincrona:
#   POST /api/analyze     → Crea job PENDING, accoda lavoro, risponde 202
#   GET  /api/analysis/id → Polling dello stato (PENDING → PROCESSING → COMPLETED)
#   GET  /api/analyses    → Lista storico analisi
#
# Il worker gira SEMPRE in-process come thread daemon (sia in mock sia in
# produzione): il backend FastAPI è un server persistente su EC2, quindi non
# serve SQS + Lambda. Vedi la docstring di _enqueue_job per il razionale.
# ==============================================================================

import os
import json
import uuid
import time
import logging
import threading
from typing import Optional
# NOTA: rimosso "import json" — era usato solo dal vecchio percorso SQS (ora
# eliminato per coerenza architetturale, vedi _enqueue_job).

from fastapi import APIRouter, status, HTTPException

from models.schemas import (
    ProfileAnalysisRequest,
    AnalysisJobResponse,
    AnalysisReportResponse,
    RiskAssessment,
)
from services.pii_detector import PIIDetectorService
from services.report_generator import ReportGeneratorService
from services.scraper import ScraperService
from services.storage import StorageService
from services.risk_scorer import build_risk_assessment

logger = logging.getLogger("social-privacy-backend")

AWS_MOCK = os.getenv("AWS_MOCK", "true").lower() == "true"

router = APIRouter(prefix="/api", tags=["Analysis"])

pii_service     = PIIDetectorService()
report_service  = ReportGeneratorService()
scraper_service = ScraperService()
storage_service = StorageService()


# ──────────────────────────────────────────────────────────────────────────────
# BACKGROUND WORKER: esegue la pipeline di analisi in un thread separato.
# Gira in-process sul backend FastAPI persistente (stesso comportamento in
# mock e in produzione) — nessuna Lambda coinvolta.
# ──────────────────────────────────────────────────────────────────────────────

def _run_analysis_pipeline(analysis_id: str, social_url: str, scraped_content: Optional[str]):
    """
    Worker che esegue l'intera pipeline di analisi in un thread daemon.
    Stesso codice in mock e in produzione: cambia solo la sorgente dati
    (mock regex/bio simulate vs servizi AWS reali via Boto3), non l'orchestrazione.

    Pipeline:
      1. Aggiorna stato → PROCESSING
      2. Scraping del profilo (Apify / mock)
      3. Estrazione PII (Comprehend / Regex)
      4. Deduplicazione PII per il report
      5. Generazione report minacce (Bedrock / mock)
      6. Calcolo risk score (feature engineering)
      7. Salvataggio risultati → COMPLETED
    """
    try:
        # Aggiorna stato a PROCESSING
        storage_service.update_status(analysis_id, "PROCESSING")
        logger.info(f"[Worker] Pipeline avviata per job {analysis_id}")

        # Simula latenza di elaborazione in mock mode per testare il polling
        if AWS_MOCK:
            time.sleep(3)

        # Step 1: Scraping del profilo
        target_text = scraped_content
        if not target_text:
            target_text = scraper_service.scrape_profile(social_url)

        # Step 2: Estrazione PII (raw, con duplicati — servono allo scorer)
        raw_piis = pii_service.detect_pii(target_text or "")

        # Step 3: Deduplicazione per la risposta frontend e il report minacce
        seen = set()
        detected_piis = []
        for entity in raw_piis:
            key = (entity.type, entity.text.lower())
            if key not in seen:
                seen.add(key)
                detected_piis.append(entity)

        # Step 4: Generazione report minacce (su dati deduplicati)
        social_threats = report_service.generate_threats(detected_piis)

        # Step 5: Calcolo livello di rischio tramite feature engineering (su dati RAW)
        risk_level, risk_explanation, risk_score, risk_motivations = build_risk_assessment(raw_piis)

        # Step 6: Salvataggio risultati → COMPLETED
        results = {
            "detected_pii": [p.model_dump() for p in detected_piis],
            "social_engineering_report": [t.model_dump() for t in social_threats],
            "risk_assessment": {
                "risk_level": risk_level,
                "explanation": risk_explanation,
                "score": risk_score,
                "motivations": risk_motivations,
            },
            "risk_level": risk_level,
            "risk_score": risk_score,
            "pii_count": len(detected_piis),
            "pii_types": list({p.type for p in detected_piis}),
        }

        # Step 6b: persistenza del report completo su S3. L'architettura del
        # progetto prevede S3 come storage dei report; DynamoDB conserva metadati
        # + risultati per la lettura diretta. Qui carichiamo il report JSON su S3 e
        # salviamo la sua chiave nel record (prima era codice morto: upload_report
        # esisteva ma non veniva mai invocato, quindi il bucket restava vuoto).
        report_json = json.dumps(results, ensure_ascii=False, default=str)
        s3_key = storage_service.upload_report(analysis_id, report_json)
        if s3_key:
            results["s3_report_key"] = s3_key

        storage_service.complete_job(analysis_id, results)
        logger.info(f"[Worker] Pipeline completata per job {analysis_id}. Rischio: {risk_level} ({risk_score}/100)")

    except Exception as e:
        logger.error(f"[Worker] Errore nella pipeline per job {analysis_id}: {e}")
        storage_service.fail_job(analysis_id, str(e))


def _enqueue_job(analysis_id: str, social_url: str, scraped_content: Optional[str]):
    """
    Accoda il job per l'elaborazione asincrona.

    SCELTA ARCHITETTURALE (coerente con il piano di progetto "no Lambda"):
    l'elaborazione avviene SEMPRE in-process in un thread daemon, sia in mock
    sia in produzione. Il backend FastAPI è un server PERSISTENTE che gira su
    EC2, quindi può eseguire la pipeline in background da solo — senza bisogno
    di una coda SQS + Lambda consumer.

    In precedenza, in produzione, questo metodo inviava il job a SQS: ma nel
    progetto non esiste alcun consumer/Lambda che lo legga, quindi i messaggi
    sarebbero rimasti inevasi (percorso rotto). Rimosso per coerenza.

    [Estensione futura opzionale] Per mostrare un pattern distribuito
    "producer/consumer" (tema SDCC), si potrebbe reintrodurre SQS AGGIUNGENDO
    un worker consumer dedicato (container separato o Lambda). Sarebbe una
    feature deliberata, non il default.

    Il thread è daemon=True: non blocca lo shutdown del processo.
    """
    worker_thread = threading.Thread(
        target=_run_analysis_pipeline,
        args=(analysis_id, social_url, scraped_content),
        daemon=True,
    )
    worker_thread.start()
    queue_label = "MOCK Queue" if AWS_MOCK else "Background Worker"
    logger.info(f"[{queue_label}] Job {analysis_id} accodato via thread in-process")


# ──────────────────────────────────────────────────────────────────────────────
# POST /api/analyze - Accoda una nuova analisi (risponde 202 Accepted)
# ──────────────────────────────────────────────────────────────────────────────

@router.post("/analyze", response_model=AnalysisJobResponse, status_code=status.HTTP_202_ACCEPTED)
def analyze_profile(payload: ProfileAnalysisRequest):
    """
    Accoda una nuova analisi di un profilo social.

    NON esegue la pipeline in linea — la delega a un worker asincrono
    (thread locale in mock, Lambda in produzione).

    Il client riceve un analysis_id e fa polling su GET /api/analysis/{id}
    per ottenere i risultati quando lo stato diventa COMPLETED.
    """
    logger.info(f"Ricevuta richiesta di analisi per URL: {payload.social_url}")

    # 1. Genera ID univoco per il job
    analysis_id = str(uuid.uuid4())

    # 2. Crea il job con stato PENDING nel database
    storage_service.create_job(
        analysis_id=analysis_id,
        social_url=payload.social_url,
        scraped_content=payload.scraped_content,
    )

    # 3. Accoda il lavoro (thread mock o SQS)
    _enqueue_job(analysis_id, payload.social_url, payload.scraped_content)

    # 4. Risponde immediatamente con 202 Accepted
    logger.info(f"Job {analysis_id} accodato. Il client può fare polling su GET /api/analysis/{analysis_id}")
    return AnalysisJobResponse(
        analysis_id=analysis_id,
        status="PENDING",
        message="Analisi accodata. Usa GET /api/analysis/{analysis_id} per controllare lo stato.",
    )


# ──────────────────────────────────────────────────────────────────────────────
# GET /api/analysis/{id} - Polling dello stato di un'analisi
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/analysis/{analysis_id}", response_model=AnalysisReportResponse, status_code=status.HTTP_200_OK)
def get_analysis(analysis_id: str):
    """
    Recupera lo stato corrente di un'analisi.

    Il frontend chiama questo endpoint in polling (ogni 3 secondi) finché
    lo status non diventa COMPLETED o FAILED.

    Restituisce:
      - status=PENDING    → analisi in coda, risultati non ancora disponibili
      - status=PROCESSING → analisi in corso
      - status=COMPLETED  → risultati disponibili in detected_pii, risk_assessment, etc.
      - status=FAILED     → errore, messaggio in campo 'error'
    """
    record = storage_service.get_analysis(analysis_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analisi {analysis_id} non trovata"
        )

    # Costruisci la risposta in base allo stato
    return AnalysisReportResponse(
        analysis_id=record["analysis_id"],
        social_url=record["social_url"],
        status=record["status"],
        detected_pii=record.get("detected_pii"),
        social_engineering_report=record.get("social_engineering_report"),
        risk_assessment=record.get("risk_assessment"),
        error=record.get("error"),
    )


# ──────────────────────────────────────────────────────────────────────────────
# GET /api/analyses - Lista storico analisi
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/analyses", status_code=status.HTTP_200_OK)
def list_analyses():
    """
    Restituisce la lista di tutte le analisi effettuate (storico).
    """
    analyses = storage_service.list_analyses()
    return {
        "total": len(analyses),
        "analyses": analyses
    }
