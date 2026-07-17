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
        description="URL del profilo social da analizzare (es. Instagram, TikTok o Facebook)",
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
# IMAGE LABEL MODEL (Output di Amazon Rekognition DetectLabels)
# ──────────────────────────────────────────────────────────────────────────────

class ImageLabel(BaseModel):
    name: str = Field(..., description="Etichetta visiva rilevata nell'immagine (es. Beach, Car, Person)")
    confidence: float = Field(..., description="Confidenza del rilevamento (0-100)")


class SensitiveLabel(BaseModel):
    category: str = Field(..., description="Categoria sensibile: MINORI | DOCUMENTI | GEO")
    label: str = Field(..., description="Etichetta Rekognition che ha attivato la categoria")
    confidence: float = Field(..., description="Confidenza del rilevamento (0-100)")


class RescoreRequest(BaseModel):
    """Ricalcolo del rischio su un sottoinsieme di PII scelto dall'utente
    (funzione "e se non l'avessi pubblicato?" e conferma dei rilevamenti incerti).
    Il client invia esattamente i dati che vuole conteggiare; il punteggio viene
    ricalcolato senza rifiltrare per confidenza (la scelta del client è definitiva)."""
    detected_pii: List[PIIEntity] = Field(default_factory=list, description="PII da conteggiare nel ricalcolo")


class SanitizeRequest(BaseModel):
    """Richiesta di riscrittura sicura di una biografia.

    Il client passa le PII gia' rilevate dall'analisi (come /rescore e /leverage):
    cosi' il backend NON ri-esegue il NER locale. Il modello spaCy pesa ~600 MB e la
    detection non deve girare nel web tier (t3.micro condivisa con frontend e nginx),
    dove satura la RAM e blocca il worker — le analisi girano apposta nella Lambda.
    Se la lista e' assente, si ricade sul rilevamento locale (path lento, solo per
    uso standalone dell'API)."""
    text: str = Field(..., description="Testo della bio da ripulire dalle PII")
    detected_pii: List[PIIEntity] = Field(
        default_factory=list,
        description="PII gia' rilevate dall'analisi; se vuota il backend le rileva da se'")


class SanitizeResponse(BaseModel):
    """Versione ripulita della bio + rischio ricalcolato su di essa."""
    cleaned_text: str = Field(..., description="Bio riscritta senza dati personali")
    score: int = Field(..., description="Score di rischio della versione ripulita (0-100)")
    risk_level: str = Field(..., description="Livello di rischio della versione ripulita")
    removed_types: List[str] = Field(default_factory=list, description="Tipi di PII rimossi rispetto all'originale")
    kept_types: List[str] = Field(default_factory=list, description="Tipi di PII mantenuti (a basso rischio) nella versione sicura")


# ──────────────────────────────────────────────────────────────────────────────
# SOCIAL ENGINEERING THREAT MODEL (Output del report LLM — Gemini/mock)
# ──────────────────────────────────────────────────────────────────────────────

class SocialEngineeringThreat(BaseModel):
    threat_vector: str = Field(..., description="Nome della tipologia di attacco (es. Spear-Phishing, Impersonificazione)")
    severity: str = Field(..., description="Livello di gravità della minaccia (LOW, MEDIUM, HIGH)")
    explanation: str = Field(..., description="Spiegazione dettagliata di come l'attaccante userà il dato")


# ──────────────────────────────────────────────────────────────────────────────
# RISK ASSESSMENT MODEL
# ──────────────────────────────────────────────────────────────────────────────

class FiscalCodeInfo(BaseModel):
    """Comune di nascita decodificato dal codice catastale (Belfiore) di un CF, via LLM."""
    code: str = Field(..., description="Il codice fiscale")
    birthplace: str = Field(..., description="Comune (o stato estero) di nascita")


class RiskCombo(BaseModel):
    """Combinazione pericolosa scattata: quali tipi di PII, combinati, abilitano
    quale attacco (alimenta la 'mappa dell'aggregazione' nella UI)."""
    label: str = Field(..., description="Nome interno della combinazione (es. identita_completa)")
    types: List[str] = Field(..., description="Tipi di PII che compongono la combinazione")
    points: int = Field(..., description="Punti aggiunti allo score da questa combinazione")
    impact: Optional[float] = Field(None, description="Impatto assoluto dell'attacco (1-10), per la severità")


class RiskRepetition(BaseModel):
    """Testo (luogo/organizzazione) ripetuto più volte: la frequenza rivela
    un'abitudine sfruttabile ('segnale di routine' nella UI)."""
    type: str = Field(..., description="Tipo di PII ripetuta (LOCATION o ORGANIZATION)")
    text: str = Field(..., description="Il testo ripetuto")
    count: int = Field(..., description="Numero di occorrenze")
    label: str = Field(..., description="Interpretazione (routine geografica / affiliazione confermata)")


class RiskAssessment(BaseModel):
    risk_level: str = Field(..., description="Livello complessivo di esposizione (LOW, MEDIUM, HIGH)")
    explanation: str = Field(..., description="Valutazione qualitativa in linguaggio naturale sul livello di rischio")
    score: int = Field(..., description="Score numerico di rischio (0-100)")
    motivations: List[str] = Field(..., description="Lista dei contributi al punteggio di rischio")
    combos: List[RiskCombo] = Field(default_factory=list, description="Combinazioni pericolose disgiunte scattate (per la mappa dell'aggregazione)")
    repetitions: List[RiskRepetition] = Field(default_factory=list, description="Testi ripetuti che rivelano una routine")


class LeverageItem(BaseModel):
    type: str
    text: str
    delta: int = Field(..., description="Punti di cui scenderebbe lo score rimuovendo questa PII")


class LeverageResponse(BaseModel):
    base_score: int
    items: List[LeverageItem] = Field(default_factory=list)


class AttackerDossier(BaseModel):
    text: str = ""
    missing: List[str] = Field(default_factory=list)


class AttackExampleRequest(BaseModel):
    pii: List[PIIEntity] = Field(default_factory=list)
    vector_label: str = ""


class AttackExampleResponse(BaseModel):
    message: str = ""
    reason: str = Field("", description="'' se ok | 'not_configured' | 'no_response' (per diagnosi lato UI)")


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
    image_labels: Optional[List[ImageLabel]] = Field(None, description="Etichette visive rilevate nelle immagini da Amazon Rekognition (esposizione visiva; disponibile quando status=COMPLETED)")
    sensitive_visual: Optional[List[SensitiveLabel]] = Field(None, description="Etichette visive sensibili categorizzate (minori, documenti, geolocalizzazione); disponibile quando status=COMPLETED")
    attacker_dossier: Optional[AttackerDossier] = Field(None, description="Identità ricomposta dai frammenti PII (deterministica) e lacune dell'attaccante")
    fiscal_code_info: Optional[List[FiscalCodeInfo]] = Field(None, description="Comune di nascita decodificato dai codici fiscali presenti (tabella deterministica dei codici catastali)")
    narrative_summary: Optional[str] = Field(None, description="Sintesi in linguaggio naturale dell'esposizione: quali dati sono più esposti, pattern ricorrenti e perché aumentano il rischio (disponibile quando status=COMPLETED)")
    social_engineering_report: Optional[List[SocialEngineeringThreat]] = Field(None, description="Report dei vettori di minaccia (disponibile solo quando status=COMPLETED)")
    risk_assessment: Optional[RiskAssessment] = Field(None, description="Valutazione complessiva del rischio (disponibile solo quando status=COMPLETED)")
    error: Optional[str] = Field(None, description="Messaggio di errore (disponibile solo quando status=FAILED)")

