# ==============================================================================
# PII DETECTOR SERVICE - Rilevamento Dati Personali (SDCC)
# Simula Amazon Comprehend (DetectPiiEntities) + Textract (OCR) in locale
# tramite espressioni regolari avanzate. In produzione, chiama Boto3 reale.
# ==============================================================================

import os
import re
import logging
from typing import List

from models.schemas import PIIEntity

logger = logging.getLogger("social-privacy-backend")

AWS_MOCK = os.getenv("AWS_MOCK", "true").lower() == "true"

# Interruttore per l'analisi visiva (Amazon Rekognition DetectLabels). Permette di
# disattivarla senza toccare il codice (es. contenimento costi) mettendo la
# variabile a "false". Attiva di default; ininfluente in AWS_MOCK (labels simulate).
ENABLE_REKOGNITION = os.getenv("ENABLE_REKOGNITION", "true").lower() == "true"


class PIIDetectorService:
    """
    Servizio di rilevamento PII (Personally Identifiable Information).

    Modalità MOCK (locale):
        Usa espressioni regolari ottimizzate per individuare email, telefoni,
        date di nascita, URL, nomi di organizzazioni e luoghi.

    Modalità PRODUZIONE (AWS):
        Invoca Amazon Comprehend via Boto3 per NER + PII Detection,
        e Amazon Textract per OCR su immagini allegate ai post.
    """

    def __init__(self):
        self.comprehend_client = None
        self.textract_client = None
        self.rekognition_client = None

        if not AWS_MOCK:
            try:
                import boto3
                region = os.getenv("AWS_DEFAULT_REGION", "eu-west-1")
                self.comprehend_client = boto3.client("comprehend", region_name=region)
                self.textract_client = boto3.client("textract", region_name=region)
                # Rekognition: analisi visiva (oggetti/scene/luoghi) delle immagini,
                # complementare all'OCR di Textract. Inizializzato solo se abilitato.
                if ENABLE_REKOGNITION:
                    self.rekognition_client = boto3.client("rekognition", region_name=region)
                logger.info("⚡ PIIDetectorService: Client AWS Comprehend, Textract e Rekognition inizializzati.")
            except Exception as e:
                logger.error(f"PIIDetectorService: Impossibile inizializzare Boto3. Errore: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # METODO PRINCIPALE: Estrazione PII
    # ──────────────────────────────────────────────────────────────────────────

    def detect_pii(self, text: str) -> List[PIIEntity]:
        """
        Punto di ingresso unico. Sceglie automaticamente tra Comprehend reale o regex mock.
        """
        if self.comprehend_client and not AWS_MOCK:
            return self._detect_pii_comprehend(text)
        return self._detect_pii_regex(text)

    # ──────────────────────────────────────────────────────────────────────────
    # IMPLEMENTAZIONE MOCK: Regex Engine (Local-First)
    # ──────────────────────────────────────────────────────────────────────────

    def _detect_pii_regex(self, text: str) -> List[PIIEntity]:
        """
        Estrae PII usando espressioni regolari. Copre i tipi richiesti dalla traccia.
        Usa finditer su tutti i pattern per catturare occorrenze multiple dello
        stesso tipo con testo diverso (utile per rilevare pattern comportamentali
        ricorrenti, es. stessa location menzionata più volte).
        """
        logger.info("[MOCK Comprehend] Esecuzione PII Detection via Regex Engine")
        pii_found: List[PIIEntity] = []

        # 1. EMAIL
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        for match in email_pattern.finditer(text):
            pii_found.append(PIIEntity(type="EMAIL", text=match.group(), score=0.99))

        # 2. PHONE_NUMBER (formati internazionali: es. +1 555-123-4567, +44 20 7946, 3331234567)
        phone_pattern = re.compile(r'\+?(?:[0-9][\s.-]?){7,14}[0-9]')
        for match in phone_pattern.finditer(text):
            phone_str = match.group().strip()
            digits_only = re.sub(r'\D', '', phone_str)
            # Filtro base: i numeri telefonici validi (inclusi prefissi) hanno tra 7 e 15 cifre
            if 7 <= len(digits_only) <= 15:
                pii_found.append(PIIEntity(type="PHONE_NUMBER", text=phone_str, score=0.95))

        # 3. DATE_OF_BIRTH (formati: 01/01/1999, 01-01-1999, 1 gennaio 1999)
        date_numeric = re.compile(r'\b(?:0?[1-9]|[12][0-9]|3[01])[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:19|20)\d{2}\b')
        for match in date_numeric.finditer(text):
            pii_found.append(PIIEntity(type="DATE_OF_BIRTH", text=match.group(), score=0.90))

        mesi = r'(?:gennaio|febbraio|marzo|aprile|maggio|giugno|luglio|agosto|settembre|ottobre|novembre|dicembre|january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|oct|nov|dec)'
        date_text = re.compile(rf'\b(?:0?[1-9]|[12][0-9]|3[01])\s+{mesi}\s+(?:19|20)\d{{2}}\b', re.IGNORECASE)
        for match in date_text.finditer(text):
            pii_found.append(PIIEntity(type="DATE_OF_BIRTH", text=match.group(), score=0.88))

        # 4. URL_PERSONAL (link personali, siti web)
        url_pattern = re.compile(r'https?://(?:www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z]{2,6}\b[-a-zA-Z0-9()@:%_+.~#?&/=]*')
        for match in url_pattern.finditer(text):
            pii_found.append(PIIEntity(type="URL", text=match.group(), score=0.92))

        # 5. ORGANIZATION (università, aziende note internazionali e locali)
        org_keywords = [
            "sapienza", "unical", "università", "university", "college", "politecnico", "bocconi", "luiss", "harvard", "stanford", "mit", "oxford",
            "reply", "accenture", "deloitte", "kpmg", "eni", "enel", "poste italiane", "fiat", "ferrari",
            "amazon", "google", "microsoft", "meta", "apple", "ibm", "netflix", "tesla", "spacex"
        ]
        # finditer per catturare occorrenze multiple
        for org in org_keywords:
            org_pattern = re.compile(rf'\b{re.escape(org)}\b', re.IGNORECASE)
            for match in org_pattern.finditer(text):
                pii_found.append(PIIEntity(type="ORGANIZATION", text=match.group(), score=0.85))

        # 6. LOCATION (città e nazioni globali e italiane)
        location_keywords = [
            "roma", "milano", "napoli", "torino", "firenze", "bologna", "palermo", "genova", "bari", "catania", "venezia", "padova", "cosenza", "rende",
            "calabria", "lazio", "lombardia", "campania", "piemonte", "toscana", "sicilia", "puglia", "emilia", "veneto",
            "london", "new york", "paris", "tokyo", "berlin", "madrid", "sydney", "dubai", "san francisco", "los angeles",
            "italy", "italia", "usa", "united states", "uk", "united kingdom", "france", "germany", "spain", "japan"
        ]
        # finditer per catturare occorrenze multiple (rileva routine geografiche)
        for loc in location_keywords:
            loc_pattern = re.compile(rf'\b{re.escape(loc)}\b', re.IGNORECASE)
            for match in loc_pattern.finditer(text):
                pii_found.append(PIIEntity(type="LOCATION", text=match.group(), score=0.88))

        # 7. USERNAME (pattern @username nei social)
        username_pattern = re.compile(r'@[a-zA-Z0-9_.]{3,30}')
        for match in username_pattern.finditer(text):
            # Escludiamo le email (che contengono @)
            if '@' in match.group() and '.' not in match.group():
                pii_found.append(PIIEntity(type="USERNAME", text=match.group(), score=0.80))

        # 8. FISCAL_CODE — Codice Fiscale italiano (16 caratteri).
        #    Aggiunto per coprire i "codici identificativi" richiesti dalla traccia.
        #    Struttura: 6 lettere (cognome+nome) · 2 cifre (anno) · 1 lettera (mese)
        #    · 2 cifre (giorno+sesso) · 1 lettera (comune) · 3 cifre · 1 lettera (controllo).
        #    IGNORECASE perché l'utente potrebbe scriverlo in minuscolo.
        fiscal_code_pattern = re.compile(
            r'\b[A-Za-z]{6}\d{2}[A-Za-z]\d{2}[A-Za-z]\d{3}[A-Za-z]\b'
        )
        for match in fiscal_code_pattern.finditer(text):
            # Confidence alta: è un formato molto strutturato, raro come falso positivo.
            pii_found.append(PIIEntity(type="FISCAL_CODE", text=match.group().upper(), score=0.97))

        # 9. IBAN — coordinate bancarie (altro "codice identificativo" sensibile).
        #    Formato generico: 2 lettere (paese) · 2 cifre (controllo) · 11-30 alfanumerici.
        #    L'IBAN italiano è lungo 27 caratteri, ma il pattern copre anche altri paesi.
        iban_pattern = re.compile(r'\b[A-Za-z]{2}\d{2}[A-Za-z0-9]{11,30}\b')
        for match in iban_pattern.finditer(text):
            pii_found.append(PIIEntity(type="IBAN", text=match.group().upper(), score=0.97))

        # NOTA: NON deduplicare qui. Il risk_scorer ha bisogno delle
        # occorrenze grezze per rilevare pattern di abitudine (es. stessa
        # location menzionata più volte = routine). La deduplicazione per
        # la risposta al frontend avviene in analysis.py.
        return pii_found

    # ──────────────────────────────────────────────────────────────────────────
    # IMPLEMENTAZIONE REALE: Amazon Comprehend (Boto3)
    # ──────────────────────────────────────────────────────────────────────────

    def _detect_pii_comprehend(self, text: str) -> List[PIIEntity]:
        """
        Invoca Amazon Comprehend DetectPiiEntities via Boto3.
        Richiede credenziali AWS valide (IAM Instance Profile su EC2).
        """
        logger.info("[AWS Comprehend] Invocazione reale DetectPiiEntities")
        pii_found: List[PIIEntity] = []

        try:
            # Comprehend DetectPiiEntities supporta SOLO le lingue en/es: passando
            # "it" darebbe ValidationException. Analizziamo il testo italiano come
            # "en": le PII strutturate (EMAIL, PHONE, ecc.) sono language-agnostic e
            # anche NAME/ADDRESS vengono comunque riconosciuti.
            response = self.comprehend_client.detect_pii_entities(
                Text=text,
                LanguageCode="en"
            )

            # Codici identificativi italiani rilevati dal motore regex con il tipo
            # corretto. Comprehend li individua ma li tipizza male (l'IBAN come
            # INTERNATIONAL_BANK_ACCOUNT_NUMBER, il codice fiscale come DRIVER_ID):
            # li sostituiamo con la nostra classificazione, evitando i doppioni.
            it_codes = [p for p in self._detect_pii_regex(text)
                        if p.type in ("FISCAL_CODE", "IBAN")]
            it_code_texts = {p.text.upper() for p in it_codes}

            for entity in response.get("Entities", []):
                start = entity.get("BeginOffset", 0)
                end = entity.get("EndOffset", 0)
                entity_text = text[start:end]

                # Salta l'entita Comprehend che ricade su un codice IT gia
                # tipizzato da noi: sarebbe lo stesso testo con un tipo sbagliato.
                if entity_text.upper() in it_code_texts:
                    continue

                pii_found.append(PIIEntity(
                    type=entity.get("Type", "UNKNOWN"),
                    text=entity_text,
                    score=round(entity.get("Score", 0.0), 2)
                ))

            # Aggiunge i codici IT con la classificazione corretta.
            pii_found.extend(it_codes)

        except Exception as e:
            logger.error(f"Errore Comprehend: {e}. Fallback su regex.")
            return self._detect_pii_regex(text)

        return pii_found

    # ──────────────────────────────────────────────────────────────────────────
    # OCR: Amazon Textract (per immagini)
    # ──────────────────────────────────────────────────────────────────────────

    def extract_text_from_image(self, image_bytes: bytes) -> str:
        """
        Estrae testo da un'immagine tramite Amazon Textract.
        In mock mode, restituisce un testo di esempio.
        """
        if AWS_MOCK or not self.textract_client:
            logger.info("[MOCK Textract] Simulazione estrazione OCR da immagine")
            return "Testo estratto da immagine simulata: 'Diploma di Laurea - Università della Calabria - Classe 2024'"

        try:
            response = self.textract_client.detect_document_text(
                Document={'Bytes': image_bytes}
            )
            extracted = ""
            for block in response.get("Blocks", []):
                if block["BlockType"] == "LINE":
                    extracted += block["Text"] + " "
            return extracted.strip()

        except Exception as e:
            logger.error(f"Errore Textract: {e}")
            return ""

    # ──────────────────────────────────────────────────────────────────────────
    # VISIONE: Amazon Rekognition DetectLabels (analisi semantica delle immagini)
    # ──────────────────────────────────────────────────────────────────────────

    def detect_image_labels(self, image_bytes: bytes) -> List[dict]:
        """
        Rileva oggetti, scene e luoghi in un'immagine tramite Amazon Rekognition
        (DetectLabels). Complementare all'OCR: cattura ciò che una foto espone
        ANCHE senza testo (spiaggia, monumento, veicolo, contesto, ecc.), utile a
        stimare l'esposizione visiva (routine, geografia). Restituisce una lista di
        {"name", "confidence"}. In mock mode restituisce etichette di esempio.
        """
        if AWS_MOCK or not self.rekognition_client:
            logger.info("[MOCK Rekognition] Simulazione DetectLabels")
            # Un'immagine vuota o minima (es. 1x1 px, ~poche decine di byte) non deve
            # produrre etichette inventate: sotto una soglia di dimensione si
            # restituisce lista vuota, così il ramo "nessun contenuto visivo" resta
            # raggiungibile anche in mock e la demo non mostra un'esposizione fittizia.
            if len(image_bytes) < 2048:
                return []
            return [
                {"name": "Beach", "confidence": 98.4},
                {"name": "Person", "confidence": 96.1},
                {"name": "Car", "confidence": 88.7},
                {"name": "License Plate", "confidence": 81.2},
            ]

        try:
            response = self.rekognition_client.detect_labels(
                Image={"Bytes": image_bytes},
                MaxLabels=15,
                MinConfidence=75,   # scarta le etichette poco affidabili
            )
            return [
                {"name": lbl["Name"], "confidence": round(lbl.get("Confidence", 0.0), 1)}
                for lbl in response.get("Labels", [])
            ]
        except Exception as e:
            logger.error(f"Errore Rekognition: {e}")
            return []
