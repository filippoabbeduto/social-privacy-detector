# ==============================================================================
# QUEUE SERVICE - Produttore SQS (accodamento asincrono dei job di analisi)
# In WORKER_MODE=sqs l'API invia qui il job; una Lambda lo consuma dalla coda.
# Disaccoppia produttore (API) e consumatore (Lambda): tema produttore/consumatore
# dei sistemi distribuiti. No-op in mock o se la coda non è configurata.
# ==============================================================================
import os
import json
import logging

logger = logging.getLogger("social-privacy-backend")

AWS_MOCK = os.getenv("AWS_MOCK", "true").lower() == "true"
_QUEUE_URL = os.getenv("SQS_QUEUE_URL", "").strip()


def _client():
    # Import boto3 solo quando serve (in mock non viene mai chiamato).
    import boto3
    region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    return boto3.client("sqs", region_name=region)


def send_job(payload: dict) -> bool:
    """Invia il job alla coda SQS. No-op (ritorna False) se in mock o coda assente."""
    if AWS_MOCK or not _QUEUE_URL:
        logger.info("[SQS] send_job saltato (mock o SQS_QUEUE_URL assente)")
        return False
    try:
        _client().send_message(QueueUrl=_QUEUE_URL, MessageBody=json.dumps(payload))
        logger.info(f"[SQS] Job {payload.get('analysis_id')} accodato")
        return True
    except Exception as e:
        logger.error(f"[SQS] send_job fallito: {e}")
        return False
