# ==============================================================================
# LAMBDA HANDLER - Consumatore SQS della pipeline (WORKER_MODE=sqs).
# Triggerata dalla coda SQS: per ogni messaggio esegue la stessa pipeline del
# worker in-process (services.pipeline.run_analysis). run_analysis reclama il job
# (idempotenza) e cattura gli errori APPLICATIVI (fail_job, nessun retry inutile).
# Qui gestiamo solo gli errori INFRASTRUTTURALI: il messaggio torna in coda
# (visibility timeout) e dopo N tentativi finisce in DLQ (poison message).
#
# Usa la "partial batch response" (batchItemFailures): se un batch contiene piu'
# record, solo quelli falliti vengono riconsegnati, non l'intero batch.
# ==============================================================================
import json
import logging

from services.pipeline import run_analysis

logger = logging.getLogger("social-privacy-backend")


def handler(event, context):
    failures = []
    for record in event.get("Records", []):
        mid = record.get("messageId")
        try:
            job = json.loads(record["body"])
            run_analysis(
                analysis_id=job["analysis_id"],
                social_url=job["social_url"],
                scraped_content=job.get("scraped_content"),
                image_labels=job.get("image_labels"),
                face_ages=job.get("face_ages"),
            )
        except Exception as e:
            # Errore infrastrutturale (parsing del messaggio o eccezione risollevata
            # da run_analysis): il messaggio va rimesso in coda per un nuovo tentativo.
            logger.error(f"[Lambda] messaggio {mid} fallito: {e}")
            failures.append({"itemIdentifier": mid})
    return {"batchItemFailures": failures}
