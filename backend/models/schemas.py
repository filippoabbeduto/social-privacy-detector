# ==============================================================================
# PYDANTIC MODELS - Schema di Validazione Input/Output (SDCC)
# ==============================================================================

from typing import List, Optional
from pydantic import BaseModel, Field


# ──────────────────────────────────────────────────────────────────────────────
# REQUEST MODELS
# ──────────────────────────────────────────────────────────────────────────────

class ProfileAnalysisRequest(BaseModel):
    # NOTA (fix deprecazione Pydantic v2): si usa "examples=[...]" invece di
    # "example=..." . In Pydantic v2 il vecchio argomento "example" è deprecato
    # (verrà rimosso in v3) e generava un DeprecationWarning; "examples" è la
    # forma corretta e compare comunque nella documentazione Swagger /api/docs.
    social_url: str = Field(
        ...,
        description="URL del profilo social da analizzare (es. Instagram o LinkedIn)",
        examples=["https://instagram.com/filippo_abbeduto_99"]
    )
    scraped_content: Optional[str] = Field(
        None,
        description="Contenuto testuale o biografia opzionale da analizzare direttamente tramite regex/NLP",
        examples=["Frequentando l'aula studio alla Sapienza! Chiamami al 333-1234567 o scrivimi a filippo.abb@sapienza.it"]
    )


# ──────────────────────────────────────────────────────────────────────────────
# PII ENTITY MODEL (Output di Amazon Comprehend / Regex Engine)
# ──────────────────────────────────────────────────────────────────────────────

class PIIEntity(BaseModel):
    type: str = Field(..., description="Tipo di dato personale trovato (es. EMAIL, PHONE_NUMBER, LOCATION, DATE_OF_BIRTH, PERSON_NAME, URL, ORGANIZATION)")
    text: str = Field(..., description="Il frammento di testo contenente il dato sensibile")
    score: float = Field(..., description="Indice di accuratezza/confidenza del rilevamento (0.0 a 1.0)")


# ──────────────────────────────────────────────────────────────────────────────
# SOCIAL ENGINEERING THREAT MODEL (Output di Bedrock Claude)
# ──────────────────────────────────────────────────────────────────────────────

class SocialEngineeringThreat(BaseModel):
    threat_vector: str = Field(..., description="Nome della tipologia di attacco (es. Spear-Phishing, Impersonificazione)")
    severity: str = Field(..., description="Livello di gravità della minaccia (LOW, MEDIUM, HIGH)")
    explanation: str = Field(..., description="Spiegazione dettagliata di come l'attaccante userà il dato")


# ──────────────────────────────────────────────────────────────────────────────
# RISK ASSESSMENT MODEL
# ──────────────────────────────────────────────────────────────────────────────

class RiskAssessment(BaseModel):
    risk_level: str = Field(..., description="Livello complessivo di esposizione (LOW, MEDIUM, HIGH)")
    explanation: str = Field(..., description="Valutazione qualitativa in linguaggio naturale sul livello di rischio")
    score: int = Field(..., description="Score numerico di rischio (0-100)")
    motivations: List[str] = Field(..., description="Lista dei contributi al punteggio di rischio")


# ──────────────────────────────────────────────────────────────────────────────
# RESPONSE MODEL ASINCRONO (202 Accepted)
# ──────────────────────────────────────────────────────────────────────────────

class AnalysisJobResponse(BaseModel):
    analysis_id: str = Field(..., description="UUID univoco del job di analisi accodato")
    status: str = Field(..., description="Stato del job (PENDING, PROCESSING, COMPLETED, FAILED)")
    message: str = Field(..., description="Messaggio informativo sullo stato del job")


# ──────────────────────────────────────────────────────────────────────────────
# RESPONSE MODEL COMPLETO (quando status == COMPLETED)
# ──────────────────────────────────────────────────────────────────────────────

class AnalysisReportResponse(BaseModel):
    analysis_id: str = Field(..., description="UUID univoco associato all'analisi corrente")
    social_url: str = Field(..., description="URL originale inoltrato per l'analisi")
    status: str = Field(..., description="Stato dell'elaborazione (PENDING, PROCESSING, COMPLETED, FAILED)")
    detected_pii: Optional[List[PIIEntity]] = Field(None, description="Elenco delle PII estratte (disponibile solo quando status=COMPLETED)")
    narrative_summary: Optional[str] = Field(None, description="Sintesi in linguaggio naturale dell'esposizione: quali dati sono più esposti, pattern ricorrenti e perché aumentano il rischio (disponibile quando status=COMPLETED)")
    social_engineering_report: Optional[List[SocialEngineeringThreat]] = Field(None, description="Report dei vettori di minaccia (disponibile solo quando status=COMPLETED)")
    risk_assessment: Optional[RiskAssessment] = Field(None, description="Valutazione complessiva del rischio (disponibile solo quando status=COMPLETED)")
    error: Optional[str] = Field(None, description="Messaggio di errore (disponibile solo quando status=FAILED)")

