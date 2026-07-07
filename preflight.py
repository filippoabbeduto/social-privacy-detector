#!/usr/bin/env python3
# ==============================================================================
# preflight.py - Verifica connettivita AWS prima del test end-to-end reale.
# Controlla: credenziali IAM, tabella DynamoDB, bucket S3, e supporto lingua
# di Comprehend DetectPiiEntities (inglese vs italiano).
# NON invoca Bedrock (evita costi token). Comprehend costa ~pochi centesimi.
# Uso: .venv/bin/python preflight.py
# ==============================================================================

import os
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def load_env(path=".env"):
    """Carica le variabili da .env in os.environ (parser minimale, no dipendenze)."""
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        os.environ.setdefault(key.strip(), val.strip())


def check(label, fn):
    """Esegue un controllo e stampa esito, senza interrompere gli altri."""
    try:
        result = fn()
        print(f"  OK   {label}: {result}")
        return True
    except Exception as e:  # noqa: BLE001 - vogliamo vedere ogni errore in chiaro
        print(f"  FAIL {label}: {type(e).__name__}: {e}")
        return False


def main():
    load_env()
    region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    table_name = os.environ.get("DYNAMODB_TABLE", "SocialPrivacyAnalyses")
    bucket = os.environ.get("S3_BUCKET", "social-privacy-reports")
    print(f"Regione: {region} | Tabella: {table_name} | Bucket: {bucket}\n")

    ok = True

    # 1. Credenziali IAM valide
    ok &= check(
        "Credenziali (STS)",
        lambda: boto3.client("sts", region_name=region)
        .get_caller_identity()["Arn"],
    )

    # 2. Tabella DynamoDB esiste ed e attiva
    ok &= check(
        "Tabella DynamoDB",
        lambda: boto3.client("dynamodb", region_name=region)
        .describe_table(TableName=table_name)["Table"]["TableStatus"],
    )

    # 3. Bucket S3 accessibile
    def _head_bucket():
        boto3.client("s3", region_name=region).head_bucket(Bucket=bucket)
        return "accessibile"

    ok &= check("Bucket S3", _head_bucket)

    # 4. Comprehend PII: confronto inglese vs italiano (la traccia usa profili IT)
    comp = boto3.client("comprehend", region_name=region)
    sample_en = "Hi, I'm Mario Rossi, email mario.rossi@gmail.com, phone +39 333 1234567."
    sample_it = "Ciao, sono Mario Rossi, la mia email e mario.rossi@gmail.com, cell +39 333 1234567."

    def _pii(text, lang):
        r = comp.detect_pii_entities(Text=text, LanguageCode=lang)
        types = [e["Type"] for e in r["Entities"]]
        return f"{len(types)} entita: {types}"

    print("\nComprehend DetectPiiEntities:")
    check("  inglese (en)", lambda: _pii(sample_en, "en"))
    # Comprehend PII accetta solo alcune lingue; 'it' potrebbe dare errore.
    # Proviamo comunque, e in fallback analizziamo il testo IT come 'en'.
    if not check("  italiano (it)", lambda: _pii(sample_it, "it")):
        print("  -> 'it' non supportato. Fallback: testo IT analizzato come 'en':")
        check("  IT-come-en", lambda: _pii(sample_it, "en"))

    print("\nRisultato:", "TUTTO OK" if ok else "CI SONO ERRORI (vedi sopra)")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
