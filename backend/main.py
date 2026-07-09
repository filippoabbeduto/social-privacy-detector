# ==============================================================================
# SOCIAL PRIVACY DETECTOR - MAIN BACKEND (FastAPI + Boto3 / AWS Mock)
# Corso di Laurea Magistrale in Ingegneria Informatica - a.a. 2025/26
# Progetto di Sistemi Distribuiti e Cloud Computing (SDCC)
# ==============================================================================

import os
import logging
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware

from routers.analysis import router as analysis_router

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("social-privacy-backend")

# ------------------------------------------------------------------------------
# FASTAPI APP INITIALIZATION
# ------------------------------------------------------------------------------
# docs_url e openapi_url con il prefisso /api
# affinche il reverse proxy Nginx possa mappare correttamente la documentazione.

app = FastAPI(
    title="Social Privacy Detector API",
    description="Sistemi Distribuiti e Cloud Computing (SDCC) - Progetto d'Esame",
    version="1.0.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json"
)

# ------------------------------------------------------------------------------
# CORS middleware
# ------------------------------------------------------------------------------
# Fix sicurezza: in precedenza allow_origins=["*"] insieme a allow_credentials=True.
# Questa combinazione è (1) insicura — qualunque sito poteva chiamare l'API — e
# (2) di fatto invalida: i browser RIFIUTANO "*" quando le credenziali sono attive.
#
# In produzione frontend e backend sono serviti dalla STESSA origine tramite il
# reverse proxy Nginx, quindi il CORS non entra nemmeno in gioco. Serve solo in
# sviluppo locale quando si chiama il backend direttamente (es. Vite su :5173).
# Le origini consentite sono ora configurabili via variabile d'ambiente
# CORS_ALLOWED_ORIGINS (lista separata da virgole), con default sui soli host locali.
_default_cors_origins = "http://localhost,http://localhost:3000,http://localhost:5173"
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CORS_ALLOWED_ORIGINS", _default_cors_origins).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,   # lista esplicita invece di "*"
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------------------
# INCLUDE ROUTERS
# ------------------------------------------------------------------------------
app.include_router(analysis_router)


# ------------------------------------------------------------------------------
# HEALTHCHECK ENDPOINT
# ------------------------------------------------------------------------------
AWS_MOCK = os.getenv("AWS_MOCK", "true").lower() == "true"


@app.get("/api/health", status_code=status.HTTP_200_OK)
def health_check():
    """
    Rileva lo stato di salute del microservizio FastAPI,
    segnalando la configurazione attiva (Local-First Mock o AWS reale).
    """
    return {
        "status": "healthy",
        "mock_mode_active": AWS_MOCK,
        "region_configured": os.getenv("AWS_DEFAULT_REGION", "eu-west-1"),
        "environment_mode": os.getenv("ENV", "development"),
        "services": {
            "pii_detection": "Amazon Comprehend (Mock)" if AWS_MOCK else "Amazon Comprehend (Boto3)",
            "ocr": "Amazon Textract (Mock)" if AWS_MOCK else "Amazon Textract (Boto3)",
            "ai_report": "Amazon Bedrock Claude (Mock)" if AWS_MOCK else "Amazon Bedrock Claude (Boto3)",
            "database": "In-Memory (Mock)" if AWS_MOCK else "Amazon DynamoDB (Boto3)",
            "storage": "In-Memory (Mock)" if AWS_MOCK else "Amazon S3 (Boto3)",
        }
    }