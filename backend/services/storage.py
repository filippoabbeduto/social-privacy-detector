# ==============================================================================
# STORAGE SERVICE - Persistenza Dati su AWS (SDCC)
# Percorso: backend/services/storage.py
#
# Gestisce il ciclo di vita completo dei job di analisi:
#   PENDING → PROCESSING → COMPLETED / FAILED
#
# In mock mode salva in un dizionario in-memory.
# In produzione usa DynamoDB per i record e S3 per i report.
# ==============================================================================

import os
import json
import logging
import threading
from decimal import Decimal
from datetime import datetime, timezone
from typing import Dict, Any, Optional

logger = logging.getLogger("social-privacy-backend")

AWS_MOCK = os.getenv("AWS_MOCK", "true").lower() == "true"

# GDPR / storage limitation: i record (che contengono PII estratte dallo scraping)
# NON sono conservati in modo permanente. A ogni analisi si imposta 'expires_at'
# (epoch secondi): il TTL nativo di DynamoDB cancella automaticamente il record
# scaduto. Finestra di conservazione configurabile via env (default 24 ore).
DATA_RETENTION_HOURS = int(os.getenv("DATA_RETENTION_HOURS", "24"))


def _floats_to_decimal(obj: Any) -> Any:
    """
    Converte ricorsivamente i float in Decimal. DynamoDB (via boto3) NON accetta
    il tipo float e solleva "Float types are not supported": gli score PII e di
    rischio sono float, quindi vanno convertiti prima del put_item. Si usa
    Decimal(str(x)) per evitare le imprecisioni binarie del float (es. 0.97 esatto).
    Dict/list sono attraversati in profondita'; gli altri tipi restano invariati.
    """
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _floats_to_decimal(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_floats_to_decimal(v) for v in obj]
    return obj

# Stati validi per il lifecycle di un job
JOB_STATUS_PENDING    = "PENDING"
JOB_STATUS_PROCESSING = "PROCESSING"
JOB_STATUS_COMPLETED  = "COMPLETED"
JOB_STATUS_FAILED     = "FAILED"


class StorageService:
    """
    Servizio di persistenza dati con supporto al lifecycle asincrono dei job.

    Modalità MOCK: dizionario in-memory (i dati si perdono al riavvio del container).
    Modalità PRODUZIONE: DynamoDB per i record delle analisi, S3 per file/report.

    Lifecycle di un job:
      1. create_job()      → stato PENDING
      2. update_status()   → stato PROCESSING
      3. complete_job()    → stato COMPLETED (con risultati)
         oppure fail_job() → stato FAILED (con errore)
    """

    def __init__(self):
        self.dynamodb_table = None
        self.s3_client = None
        self.table_name = os.getenv("DYNAMODB_TABLE", "SocialPrivacyAnalyses")
        self.bucket_name = os.getenv("S3_BUCKET", "social-privacy-reports")

        # In-memory store per mock mode. Il worker gira in un thread separato
        # mentre le richieste HTTP leggono/scrivono: un lock serializza gli accessi
        # al dizionario condiviso (evita race read-modify-write). In produzione lo
        # store è DynamoDB e il lock non entra in gioco.
        self._mock_store: Dict[str, Dict[str, Any]] = {}
        self._mock_lock = threading.Lock()

        if not AWS_MOCK:
            try:
                import boto3
                region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
                dynamodb = boto3.resource("dynamodb", region_name=region)
                self.dynamodb_table = dynamodb.Table(self.table_name)
                self.s3_client = boto3.client("s3", region_name=region)
                logger.info(f"StorageService: DynamoDB table '{self.table_name}' e S3 bucket '{self.bucket_name}' collegati.")
            except Exception as e:
                logger.error(f"StorageService: Impossibile inizializzare DynamoDB/S3. Errore: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # JOB LIFECYCLE
    # ──────────────────────────────────────────────────────────────────────────

    def create_job(self, analysis_id: str, social_url: str, scraped_content: Optional[str] = None) -> bool:
        """
        Crea un nuovo job di analisi con stato PENDING.
        Chiamato dall'endpoint POST /api/analyze prima di accodare il lavoro.
        """
        now = datetime.now(timezone.utc)
        record = {
            "analysis_id": analysis_id,
            "social_url": social_url,
            "scraped_content": scraped_content,
            "status": JOB_STATUS_PENDING,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            # Scadenza per il TTL di DynamoDB (auto-cancellazione — GDPR). Impostata
            # alla creazione e mantenuta per tutta la vita del record.
            "expires_at": int(now.timestamp()) + DATA_RETENTION_HOURS * 3600,
            # Risultati (popolati al completamento)
            "detected_pii": None,
            "social_engineering_report": None,
            "risk_assessment": None,
            "error": None,
        }
        return self._put_record(analysis_id, record)

    def update_status(self, analysis_id: str, new_status: str) -> bool:
        """
        Aggiorna solo lo stato di un job esistente (es. PENDING → PROCESSING).
        """
        record = self._get_record(analysis_id)
        if not record:
            logger.warning(f"update_status: Job {analysis_id} non trovato")
            return False
        record["status"] = new_status
        record["updated_at"] = datetime.now(timezone.utc).isoformat()
        return self._put_record(analysis_id, record)

    def claim_job(self, analysis_id: str) -> bool:
        """
        Reclama un job per l'elaborazione portandolo PENDING -> PROCESSING in modo
        ATOMICO. Ritorna True solo se lo stato era PENDING (claim riuscito), False
        altrimenti (job inesistente, gia' in elaborazione o completato).
        Serve all'idempotenza: SQS e' at-least-once e puo' consegnare lo stesso
        messaggio piu' volte, ma solo il PRIMO claim procede; gli altri escono.
        In mock l'atomicita' e' garantita dal lock; su DynamoDB da una update
        condizionale (ConditionExpression) = concorrenza ottimistica lato DB.
        """
        now = datetime.now(timezone.utc).isoformat()
        if AWS_MOCK or not self.dynamodb_table:
            with self._mock_lock:
                rec = self._mock_store.get(analysis_id)
                if not rec or rec.get("status") != JOB_STATUS_PENDING:
                    return False
                rec["status"] = JOB_STATUS_PROCESSING
                rec["updated_at"] = now
                return True
        try:
            self.dynamodb_table.update_item(
                Key={"analysis_id": analysis_id},
                UpdateExpression="SET #s = :proc, updated_at = :now",
                ConditionExpression="#s = :pending",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":proc": JOB_STATUS_PROCESSING,
                    ":pending": JOB_STATUS_PENDING,
                    ":now": now,
                },
            )
            return True
        except self.dynamodb_table.meta.client.exceptions.ConditionalCheckFailedException:
            # Un altro consumatore ha gia' reclamato il job (stato != PENDING).
            return False
        except Exception as e:
            logger.error(f"[DynamoDB] claim_job fallito per {analysis_id}: {e}")
            return False

    def complete_job(self, analysis_id: str, results: Dict[str, Any]) -> bool:
        """
        Segna un job come COMPLETED e salva i risultati dell'analisi.
        Chiamato dal worker (thread locale o Lambda) al termine della pipeline.

        Args:
            results: dizionario con chiavi:
                - detected_pii: lista di PII serializzate
                - social_engineering_report: lista di threat serializzate
                - risk_assessment: dict con risk_level, explanation, score, motivations
                - pii_count: numero PII univoche
                - pii_types: lista tipi PII
        """
        record = self._get_record(analysis_id)
        if not record:
            logger.warning(f"complete_job: Job {analysis_id} non trovato")
            return False

        record["status"] = JOB_STATUS_COMPLETED
        record["updated_at"] = datetime.now(timezone.utc).isoformat()
        record.update(results)
        return self._put_record(analysis_id, record)

    def fail_job(self, analysis_id: str, error_message: str) -> bool:
        """
        Segna un job come FAILED e salva il messaggio di errore.
        """
        record = self._get_record(analysis_id)
        if not record:
            logger.warning(f"fail_job: Job {analysis_id} non trovato")
            return False

        record["status"] = JOB_STATUS_FAILED
        record["updated_at"] = datetime.now(timezone.utc).isoformat()
        record["error"] = error_message
        return self._put_record(analysis_id, record)

    # ──────────────────────────────────────────────────────────────────────────
    # LETTURA DATI
    # ──────────────────────────────────────────────────────────────────────────

    def get_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """
        Recupera un'analisi per ID (incluso il suo stato corrente).
        Usato dal frontend per il polling.
        """
        return self._get_record(analysis_id)

    # ──────────────────────────────────────────────────────────────────────────
    # S3: Upload Report / File
    # ──────────────────────────────────────────────────────────────────────────

    def upload_report(self, analysis_id: str, report_content: str) -> Optional[str]:
        """
        Carica il report testuale su S3 e restituisce la key.
        In mock mode, salva nel dizionario locale.
        """
        s3_key = f"reports/{analysis_id}/report.json"

        if AWS_MOCK or not self.s3_client:
            logger.info(f"[MOCK S3] Simulazione upload report per {analysis_id}")
            self._mock_store.setdefault(analysis_id, {})["s3_report_key"] = s3_key
            return s3_key

        try:
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=s3_key,
                Body=report_content,
                ContentType="application/json"
            )
            logger.info(f"[AWS S3] Report caricato: s3://{self.bucket_name}/{s3_key}")
            return s3_key
        except Exception as e:
            logger.error(f"Errore S3 put_object: {e}")
            return None

    # ──────────────────────────────────────────────────────────────────────────
    # METODI INTERNI DI ACCESSO (mock / DynamoDB)
    # ──────────────────────────────────────────────────────────────────────────

    def _put_record(self, analysis_id: str, record: Dict[str, Any]) -> bool:
        """Scrive un record nello storage (mock dict o DynamoDB)."""
        if AWS_MOCK or not self.dynamodb_table:
            logger.info(f"[MOCK DynamoDB] Scrittura job {analysis_id} (status: {record.get('status')})")
            with self._mock_lock:
                self._mock_store[analysis_id] = record
            return True

        try:
            # DynamoDB non supporta None come valore — rimuoviamo le chiavi nulle.
            clean_record = {k: v for k, v in record.items() if v is not None}
            # DynamoDB non supporta float: convertiamo ogni float (anche annidato) in Decimal.
            clean_record = _floats_to_decimal(clean_record)
            self.dynamodb_table.put_item(Item=clean_record)
            logger.info(f"[AWS DynamoDB] Job {analysis_id} salvato (status: {record.get('status')})")
            return True
        except Exception as e:
            # In produzione lo store è DynamoDB. NON ricadiamo sul dizionario
            # in-memory: darebbe una falsa durabilità (il dato si perderebbe al
            # riavvio e non sarebbe condiviso tra eventuali repliche), mascherando
            # un guasto reale dietro un apparente successo. Segnaliamo l'errore e
            # ritorniamo False, così il fallimento resta visibile.
            logger.error(f"[AWS DynamoDB] put_item FALLITO per {analysis_id}: {e}. Risultato NON persistito.")
            return False

    def _get_record(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Legge un record dallo storage (mock dict o DynamoDB)."""
        if AWS_MOCK or not self.dynamodb_table:
            with self._mock_lock:
                return self._mock_store.get(analysis_id)

        try:
            response = self.dynamodb_table.get_item(Key={"analysis_id": analysis_id})
            return response.get("Item")
        except Exception as e:
            # Come sopra: in produzione non si consulta il mock (sarebbe vuoto/stantìo).
            # Si segnala l'errore e si ritorna None, senza fingere un dato che non c'è.
            logger.error(f"[AWS DynamoDB] get_item FALLITO per {analysis_id}: {e}.")
            return None
