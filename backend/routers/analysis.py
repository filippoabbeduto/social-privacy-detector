# ==============================================================================
# ANALYSIS ROUTER - Endpoints per l'analisi asincrona dei profili social (SDCC)
# Percorso: backend/routers/analysis.py
#
# Architettura asincrona:
#   POST /api/analyze     → Crea job PENDING, accoda lavoro, risponde 202
#   GET  /api/analysis/id → Polling dello stato (PENDING → PROCESSING → COMPLETED)
#
# Il worker gira SEMPRE in-process come thread daemon (sia in mock sia in
# produzione): il backend FastAPI è un server persistente su EC2, quindi non
# serve SQS + Lambda. Vedi la docstring di _enqueue_job per il razionale.
# ==============================================================================

import os
import uuid
import logging
import threading
from typing import Optional, List

from fastapi import APIRouter, status, HTTPException, UploadFile, File

from models.schemas import (
    ProfileAnalysisRequest,
    AnalysisJobResponse,
    AnalysisReportResponse,
)
# La pipeline e i singleton dei servizi vivono ora in services/pipeline.py, così
# da essere riusati identici sia dal thread in-process sia dalla Lambda (SQS).
# Qui importiamo solo ciò che serve al router: la funzione di analisi, i due
# servizi usati direttamente dagli endpoint e il limite dimensione immagine.
from services.pipeline import (
    run_analysis, storage_service, pii_service, MAX_IMAGE_BYTES,
)
from services import queue

logger = logging.getLogger("social-privacy-backend")

AWS_MOCK = os.getenv("AWS_MOCK", "true").lower() == "true"

# Modalità del worker che esegue la pipeline:
#   inprocess (default): thread daemon nello stesso processo FastAPI (locale/mock)
#   sqs: l'API fa da produttore, invia il job a una coda SQS e una Lambda lo consuma
# Selezione via env: nessuna modifica al client (fa sempre polling sul risultato).
WORKER_MODE = os.getenv("WORKER_MODE", "inprocess").lower()

router = APIRouter(prefix="/api", tags=["Analysis"])


# ──────────────────────────────────────────────────────────────────────────────
# ACCODAMENTO DEL LAVORO: produttore della pipeline asincrona.
# Due modalità selezionabili via WORKER_MODE (vedi _enqueue_job): thread
# in-process (locale/mock) oppure coda SQS + Lambda (produzione distribuita).
# La pipeline vera e propria vive in services/pipeline.run_analysis.
# ──────────────────────────────────────────────────────────────────────────────


def _enqueue_job(analysis_id: str, social_url: str, scraped_content: Optional[str],
                 image_labels: Optional[List[dict]] = None):
    """
    Accoda il job per l'elaborazione asincrona (pattern produttore/consumatore).

    Due modalità, scelte da WORKER_MODE:
      - sqs (produzione): l'API è il PRODUTTORE; invia il job a una coda SQS e
        una Lambda event-driven lo CONSUMA (disaccoppiamento, at-least-once +
        idempotenza, DLQ, auto-scaling serverless). Ritorna subito.
      - inprocess (default, locale/mock): la pipeline gira in un thread daemon
        nello stesso processo FastAPI. Il backend su EC2 è persistente, quindi
        può eseguirla in background senza infrastruttura aggiuntiva.

    In entrambi i casi il client fa polling su GET /api/analysis/{id}: nessuna
    differenza lato client. Il thread è daemon=True: non blocca lo shutdown.
    """
    # Modalità distribuita: delega alla coda SQS (la consuma la Lambda).
    if WORKER_MODE == "sqs":
        queue.send_job({
            "analysis_id": analysis_id,
            "social_url": social_url,
            "scraped_content": scraped_content,
            "image_labels": image_labels,
        })
        logger.info(f"[SQS] Job {analysis_id} delegato alla Lambda via coda")
        return

    # Modalità in-process (default): esegue run_analysis in un thread daemon.
    worker_thread = threading.Thread(
        target=run_analysis,
        args=(analysis_id, social_url, scraped_content, image_labels),
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
    (thread in-process, sia in mock sia in produzione).

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

    # 3. Accoda il lavoro (thread in-process)
    _enqueue_job(analysis_id, payload.social_url, payload.scraped_content)

    # 4. Risponde immediatamente con 202 Accepted
    logger.info(f"Job {analysis_id} accodato. Il client può fare polling su GET /api/analysis/{analysis_id}")
    return AnalysisJobResponse(
        analysis_id=analysis_id,
        status="PENDING",
        message="Analisi accodata. Usa GET /api/analysis/{analysis_id} per controllare lo stato.",
    )


# ──────────────────────────────────────────────────────────────────────────────
# POST /api/analyze-image - OCR (Amazon Textract) + analisi PII su un'immagine
# ──────────────────────────────────────────────────────────────────────────────


@router.post("/analyze-image", response_model=AnalysisJobResponse, status_code=status.HTTP_202_ACCEPTED)
async def analyze_image(file: UploadFile = File(...)):
    """
    Analizza un'IMMAGINE (screenshot, foto di un documento/cartello, ...) invece
    di un profilo testuale. Amazon Textract estrae il testo visibile (OCR), poi
    si riusa la STESSA pipeline asincrona (PII detection + rischio + report). Copre
    le PII esposte dentro le immagini, non solo nella biografia testuale.
    """
    # Accetta solo immagini.
    if not (file.content_type or "").startswith("image/"):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Carica un file immagine (PNG, JPEG, ...).",
        )

    image_bytes = await file.read()
    if not image_bytes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File immagine vuoto.")
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Immagine troppo grande (max 5 MB).",
        )

    # Due segnali complementari sull'immagine: testo visibile (Textract/OCR) ed
    # etichette visive (Rekognition/DetectLabels). La foto viene analizzata se
    # espone ALMENO uno dei due: una foto senza testo ma con contesto visivo
    # (spiaggia, monumento, veicolo) è comunque rilevante per la privacy.
    extracted_text = pii_service.extract_text_from_image(image_bytes)
    image_labels = pii_service.detect_image_labels(image_bytes)
    if (not extracted_text or not extracted_text.strip()) and not image_labels:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Nessun testo né contenuto visivo rilevato nell'immagine.",
        )

    # Riusa la pipeline asincrona: il testo OCR come 'scraped_content' e le
    # etichette visive passate a parte (marcano il job come 'da immagine').
    analysis_id = str(uuid.uuid4())
    source = f"immagine: {file.filename}" if file.filename else "immagine caricata"
    storage_service.create_job(analysis_id=analysis_id, social_url=source, scraped_content=extracted_text)
    _enqueue_job(analysis_id, source, extracted_text, image_labels=image_labels)

    logger.info(f"[Analisi immagine] Job {analysis_id} da '{file.filename}' accodato "
                f"({len(extracted_text)} char OCR, {len(image_labels)} etichette).")
    return AnalysisJobResponse(
        analysis_id=analysis_id,
        status="PENDING",
        message="Immagine in analisi. Usa GET /api/analysis/{analysis_id} per lo stato.",
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
        image_labels=record.get("image_labels"),
        narrative_summary=record.get("narrative_summary"),
        social_engineering_report=record.get("social_engineering_report"),
        risk_assessment=record.get("risk_assessment"),
        error=record.get("error"),
    )

# NOTA sicurezza: RIMOSSO l'endpoint GET /api/analyses. Restituiva l'elenco di
# TUTTE le analisi con le relative PII e, non essendoci autenticazione, chiunque
# avrebbe potuto leggere i dati personali di tutti gli utenti (information
# disclosure). Il singolo risultato resta accessibile solo a chi conosce il
# proprio analysis_id (UUID non indovinabile), coerentemente con la
# minimizzazione dei dati. L'endpoint non era usato dal frontend.
