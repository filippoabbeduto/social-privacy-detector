# ==============================================================================
# PIPELINE SERVICE - Pipeline di analisi CONDIVISA (SDCC)
# Percorso: backend/services/pipeline.py
#
# Estratta da routers/analysis.py per essere RIUSATA da entrambi i consumatori:
#   - worker in-process (thread daemon) in modalità locale/mock (WORKER_MODE=inprocess)
#   - AWS Lambda triggerata da SQS in produzione (WORKER_MODE=sqs)
# Stesso codice, stessa orchestrazione: cambia solo CHI la invoca. I singoli
# servizi (Comprehend/Textract/Rekognition/DynamoDB/S3) restano dietro i loro
# wrapper con fallback mock.
#
# I 4 singleton dei servizi vivono QUI (non più nel router): in mock ogni
# istanza ha il proprio store in-memory, quindi due istanze = due store = bug.
# Un unico punto di creazione garantisce che router, thread e Lambda usino gli
# stessi oggetti.
# ==============================================================================

import os
import json
import time
import socket
import logging
import ipaddress
from typing import Optional, List, Tuple
from urllib.parse import urlparse

import requests

from services.pii_detector import PIIDetectorService
from services.report_generator import ReportGeneratorService
from services.scraper import ScraperService
from services.storage import StorageService
from services.risk_scorer import build_risk_assessment, build_risk_extras

logger = logging.getLogger("social-privacy-backend")

AWS_MOCK = os.getenv("AWS_MOCK", "true").lower() == "true"

# Singleton dei servizi condivisi (vedi nota in testa al modulo).
pii_service     = PIIDetectorService()
report_service  = ReportGeneratorService()
scraper_service = ScraperService()
storage_service = StorageService()


# Numero massimo di immagini dei post su cui fare OCR (Textract) durante l'analisi
# di un profilo. LIMITE ESSENZIALE PER I COSTI: senza, un profilo con migliaia di
# post scaricherebbe e analizzerebbe ogni foto, esaurendo credito Apify/Textract.
# Configurabile via env; default prudente.
MAX_POST_IMAGES_OCR = int(os.getenv("MAX_POST_IMAGES_OCR", "6"))

# Tetto di dimensione per le immagini analizzate (upload utente e download dai post).
# Sia Textract (DetectDocumentText) sia Rekognition (DetectLabels), quando l'immagine
# è inviata come byte grezzi (non via S3), accettano al massimo 5 MB: superarli fa
# fallire ENTRAMBI i servizi. Blocchiamo quindi a 5 MB — così un file troppo grande
# viene respinto subito con un messaggio corretto, invece di fallire dopo con un 422
# fuorviante. Vale anche come difesa anti-DoS (non si carica in memoria un file enorme).
MAX_IMAGE_BYTES = 5 * 1024 * 1024  # 5 MB (limite dei byte grezzi per Textract/Rekognition)


def _is_public_https_url(url: str) -> bool:
    """
    Difesa anti-SSRF: accetta solo URL https il cui host NON risolve a un
    indirizzo interno (privato, loopback, link-local — incluso l'endpoint di
    metadata EC2 169.254.169.254 — riservato o multicast). Gli URL delle immagini
    provengono dallo scraping e sono quindi input non fidato: senza questo filtro
    il backend potrebbe essere indotto a interrogare servizi della rete interna.
    ponytail: la risoluzione DNS avviene qui e la connessione dopo (piccola
    finestra TOCTOU/DNS-rebinding); per il contesto del progetto è accettabile,
    l'irrobustimento sarebbe pinnare l'IP validato sulla connessione.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    try:
        addrinfos = socket.getaddrinfo(parsed.hostname, None)
    except Exception:
        return False
    for info in addrinfos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast):
            return False
    return True


def _fetch_image_safely(url: str) -> Optional[bytes]:
    """
    Scarica un'immagine da un URL scrapato con difese anti-SSRF e anti-DoS:
    solo https verso host pubblici (vedi _is_public_https_url), NESSUN redirect
    (un redirect potrebbe puntare a un IP interno aggirando il primo controllo) e
    tetto di dimensione MAX_IMAGE_BYTES applicato in streaming (evita di caricare
    in memoria un file arbitrariamente grande). Ritorna i byte o None.
    """
    if not _is_public_https_url(url):
        logger.warning(f"[Textract] URL immagine rifiutato (guardia SSRF): {url[:60]}")
        return None
    try:
        with requests.get(url, timeout=15, stream=True, allow_redirects=False) as resp:
            if not resp.ok:
                return None
            data = bytearray()
            for chunk in resp.iter_content(64 * 1024):
                data.extend(chunk)
                if len(data) > MAX_IMAGE_BYTES:
                    logger.warning(f"[Textract] Immagine oltre il limite, scartata: {url[:60]}")
                    return None
            return bytes(data) or None
    except Exception as e:
        logger.warning(f"[Textract] Download immagine fallito ({url[:60]}...): {e}")
        return None


def _process_post_images(image_urls: List[str]) -> Tuple[List[str], List[dict], List[dict]]:
    """
    Scarica le prime MAX_POST_IMAGES_OCR immagini dei post (in modo sicuro, vedi
    _fetch_image_safely) e ne ricava TRE segnali: il testo visibile via Amazon
    Textract (OCR retrospettivo), le etichette visive via Amazon Rekognition
    (oggetti/scene/luoghi) e la stima dell'età dei volti (solo AGE_RANGE, per
    segnalare i minori: le etichette da sole non li vedono — vedi visual_exposure).
    Cattura così le PII testuali dentro le foto, l'esposizione visiva (dove/cosa
    mostra la foto) e la presenza di minori. Ogni immagine è indipendente: un errore
    o uno scarto su una non blocca le altre.
    """
    texts: List[str] = []
    labels: List[dict] = []
    faces: List[dict] = []
    for url in image_urls[:MAX_POST_IMAGES_OCR]:
        content = _fetch_image_safely(url)
        if not content:
            continue
        extracted = pii_service.extract_text_from_image(content)
        if extracted and extracted.strip():
            texts.append(extracted.strip())
        labels.extend(pii_service.detect_image_labels(content))
        faces.extend(pii_service.detect_face_age_ranges(content))
    if texts:
        logger.info(f"[Textract] OCR post: testo estratto da {len(texts)} immagini.")
    if labels:
        logger.info(f"[Rekognition] Etichette visive dai post: {len(labels)} totali.")
    if faces:
        logger.info(f"[Rekognition] Volti con età stimata: {len(faces)}.")
    return texts, _dedupe_labels(labels), faces


def _dedupe_labels(labels: List[dict]) -> List[dict]:
    """
    Deduplica le etichette visive per nome (tenendo la confidenza più alta) e le
    ordina per confidenza decrescente: più immagini possono produrre la stessa
    etichetta (es. 'Beach') e non ha senso ripeterla nel report.
    """
    best: dict = {}
    for lbl in labels:
        name = lbl["name"]
        if name not in best or lbl["confidence"] > best[name]["confidence"]:
            best[name] = lbl
    return sorted(best.values(), key=lambda l: l["confidence"], reverse=True)


def run_analysis(analysis_id: str, social_url: str, scraped_content: Optional[str],
                 image_labels: Optional[List[dict]] = None,
                 face_ages: Optional[List[dict]] = None):
    """
    Esegue l'intera pipeline di analisi. Invocata sia dal thread in-process sia
    dalla Lambda (consumatore SQS). Stesso codice in mock e in produzione: cambia
    solo la sorgente dati (mock regex/bio simulate vs servizi AWS reali via Boto3),
    non l'orchestrazione.

    Pipeline:
      1. Idempotenza: reclama il job PENDING→PROCESSING (claim atomico)
      2. Scraping del profilo (Apify / mock)
      3. Estrazione PII (Comprehend / Regex)
      4. Deduplicazione PII per il report
      5. Generazione report minacce (Gemini / mock)
      6. Calcolo risk score (feature engineering)
      7. Salvataggio risultati → COMPLETED
    Emette metriche custom su CloudWatch lungo il percorso (no-op in mock).
    """
    from services import metrics
    _t0 = time.monotonic()
    try:
        # Idempotenza (SQS è at-least-once → possibile doppia consegna): reclama il
        # job portandolo PENDING→PROCESSING in modo atomico. Se è già stato preso
        # (riconsegna SQS o doppio worker), esci senza rielaborarlo.
        if not storage_service.claim_job(analysis_id):
            logger.info(f"[Worker] Job {analysis_id} già reclamato: skip (idempotenza)")
            return
        metrics.emit("AnalysisStarted", 1)
        logger.info(f"[Worker] Pipeline avviata per job {analysis_id}")

        # Simula latenza di elaborazione in mock mode per testare il polling
        if AWS_MOCK:
            time.sleep(3)

        # Step 1: Scraping del profilo. Se il client non fornisce già il testo,
        # lo recuperiamo via scraper. In modalità reale uno scrape fallito
        # (profilo privato/inesistente/irraggiungibile, piattaforma non supportata)
        # restituisce None: in quel caso NON proseguiamo l'analisi su dati inventati
        # — segnaliamo il job come FAILED con un messaggio chiaro. Analizzare una
        # bio mock riporterebbe PII false come reali (problema di integrità dati).
        # image_labels valorizzato (anche lista vuota) ⇒ è un job da IMMAGINE
        # caricata: le etichette visive arrivano già dall'endpoint e NON si fa
        # scraping anche se il testo OCR è vuoto (una foto può non avere testo).
        is_image_job = image_labels is not None
        target_text = scraped_content
        if not target_text and not is_image_job:
            target_text, image_urls = scraper_service.scrape_profile_with_images(social_url)
            if not target_text or not target_text.strip():
                logger.warning(
                    f"[Worker] Scraping senza dati per {social_url}: profilo non accessibile."
                )
                storage_service.fail_job(
                    analysis_id,
                    "Profilo non accessibile: potrebbe essere privato, inesistente o "
                    "irraggiungibile, oppure la piattaforma non è supportata. "
                    "Nessun dato da analizzare."
                )
                return

            # Analisi delle immagini dei post (fino al limite configurato): il testo
            # OCR viene aggiunto a quello analizzato (PII dentro le foto), le
            # etichette visive Rekognition alimentano l'esposizione visiva e la stima
            # d'età dei volti serve a segnalare i minori.
            ocr_texts, image_labels, face_ages = _process_post_images(image_urls)
            if ocr_texts:
                target_text += (
                    "\n\n[Testo rilevato nelle immagini dei post]\n" + "\n".join(ocr_texts)
                )

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

        # Cross-tipo: la stessa stringa non deve comparire sotto due tipi FUZZY. spaCy,
        # su occorrenze diverse dello stesso testo, a volte lo tagga NOME in un punto e
        # ORGANIZZAZIONE in un altro ("Cosenza" come LOCATION 0.95 E ORGANIZATION 0.85):
        # nel report esce due volte con tipi in conflitto. Si tiene il tipo a confidenza
        # più alta. Solo per il display: lo score usa raw_piis, e un'org senza email non
        # abilita comunque nulla, quindi il punteggio non cambia.
        _FUZZY = {"NAME", "LOCATION", "ORGANIZATION"}
        best_type = {}  # testo → (score, tipo) del tipo fuzzy più confidente
        for e in detected_piis:
            if e.type in _FUZZY:
                cur = best_type.get(e.text.lower())
                if cur is None or e.score > cur[0]:
                    best_type[e.text.lower()] = (e.score, e.type)
        detected_piis = [e for e in detected_piis
                         if e.type not in _FUZZY or best_type[e.text.lower()][1] == e.type]

        # Step 4: Calcolo livello di rischio tramite feature engineering (su dati RAW).
        # Fatto PRIMA del report così i vettori d'attacco che l'LLM spiega COINCIDONO con
        # gli attacchi/combinazioni che lo score ha effettivamente calcolato (coerenza).
        risk_level, risk_explanation, risk_score, risk_motivations = build_risk_assessment(raw_piis)
        # Dati strutturati per la UI: attacchi/combinazioni scattati (mappa dell'aggregazione)
        # e testi ripetuti (segnale di routine).
        risk_extras = build_risk_extras(raw_piis)

        # Le etichette visive si usano con DUE soglie: Rekognition viene interrogato in
        # modo largo (recall), ma report e UI vedono solo quelle affidabili, altrimenti
        # l'elenco si riempie di rumore. La classificazione delle categorie sensibili
        # (Step 5c) usa invece la lista COMPLETA.
        from services.pii_detector import VISUAL_DISPLAY_MIN_CONFIDENCE
        display_labels = [l for l in (image_labels or [])
                          if l.get("confidence", 0) >= VISUAL_DISPLAY_MIN_CONFIDENCE]

        # Step 5: Generazione report — l'LLM SPIEGA gli attacchi calcolati dallo score
        # (non ne inventa altri). Le etichette visive (Rekognition) restano contesto.
        narrative_summary, social_threats = report_service.generate_report(
            detected_piis, display_labels, attacks=risk_extras["combos"]
        )

        # Step 5b: se ci sono codici fiscali, decodifica il comune di nascita in modo
        # DETERMINISTICO (tabella dei codici catastali dei comuni, non LLM: quest'ultimo
        # allucinava i comuni). Data e sesso restano deterministici lato UI.
        from services.comuni import decode_fiscal_codes as decode_cf_comune
        fiscal_codes = [p.text for p in detected_piis if p.type == "FISCAL_CODE"]
        fiscal_code_info = decode_cf_comune(fiscal_codes) if fiscal_codes else []

        # Step 5d: dossier dell'attaccante — ricompone i frammenti PII in un'identità
        # (deterministico, nessun LLM), con le lacune ancora da colmare.
        from services.dossier import build_dossier
        attacker_dossier = build_dossier(detected_piis, fiscal_code_info)

        # Step 5c: esposizione visiva SENSIBILE — classifica le etichette Rekognition
        # (minori, documenti, geolocalizzazione) e, se presenti, aggiunge una nota alla
        # sintesi (così finisce anche nel report/PDF). Nessun impatto sullo score.
        # Due sorgenti per le categorie sensibili: le ETICHETTE (oggetti/scene) e la
        # stima dell'ETÀ dei volti. Serve la seconda perché DetectLabels non vede i
        # minori: su una foto reale con un minore di 9-15 anni restituisce "Adult" al
        # 98.9% e mai "Child" (verificato interrogandolo senza filtri).
        # La classificazione per etichette vede TUTTE le etichette, comprese quelle poco
        # confidenti: per un minore un falso allarme è un fastidio, un mancato
        # rilevamento è il fallimento della funzione. L'elenco mostrato all'utente resta
        # invece filtrato (display_labels): recall qui, precisione lì.
        # collapse_sensitive tiene UNA voce per categoria: le due sorgenti insieme
        # producevano fino a sei avvisi per tre categorie, ripetendo lo stesso messaggio.
        from services.visual_exposure import (classify_sensitive_labels, sensitive_note,
                                              minors_from_faces, collapse_sensitive)
        sensitive_visual = collapse_sensitive(classify_sensitive_labels(image_labels or []),
                                              minors_from_faces(face_ages or []))
        if sensitive_visual:
            note = sensitive_note(sensitive_visual)
            narrative_summary = (f"{narrative_summary} {note}".strip()
                                 if narrative_summary else note)

        # Step 6: Salvataggio risultati → COMPLETED
        results = {
            "detected_pii": [p.model_dump() for p in detected_piis],
            "image_labels": display_labels,
            "sensitive_visual": sensitive_visual,
            "attacker_dossier": attacker_dossier,
            "fiscal_code_info": fiscal_code_info,
            "narrative_summary": narrative_summary,
            "social_engineering_report": [t.model_dump() for t in social_threats],
            "risk_assessment": {
                "risk_level": risk_level,
                "explanation": risk_explanation,
                "score": risk_score,
                "motivations": risk_motivations,
                "combos": risk_extras["combos"],
                "repetitions": risk_extras["repetitions"],
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

        # Metriche di successo (CloudWatch): completamento, latenza pipeline, e i
        # due indicatori di dominio (score di rischio e numero di PII trovate).
        metrics.emit("AnalysisCompleted", 1)
        metrics.emit("PipelineLatencyMs", (time.monotonic() - _t0) * 1000.0, "Milliseconds")
        metrics.emit("RiskScore", float(risk_score), "None")
        metrics.emit("PIICount", float(len(detected_piis)), "Count")

        storage_service.complete_job(analysis_id, results)
        logger.info(f"[Worker] Pipeline completata per job {analysis_id}. Rischio: {risk_level} ({risk_score}/100)")

    except Exception as e:
        logger.error(f"[Worker] Errore nella pipeline per job {analysis_id}: {e}")
        metrics.emit("AnalysisFailed", 1)
        storage_service.fail_job(analysis_id, str(e))
