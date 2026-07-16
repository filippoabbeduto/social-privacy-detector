# ==============================================================================
# PII DETECTOR SERVICE - Rilevamento Dati Personali (SDCC)
# Dispatcher dell'estrazione PII via PII_PROVIDER: "presidio" (default, locale),
# "ensemble" (Presidio ∪ LLM con grounding), "comprehend" (Amazon Comprehend),
# "regex" (solo regole). Gestisce anche OCR (Textract) e visione (Rekognition).
# ==============================================================================

import os
import re
import logging
from datetime import datetime
from typing import List

# ── Euristiche per ridurre i falsi positivi su date e telefoni (test avversariali) ──
_CURRENT_YEAR = datetime.now().year
# Una data è DI NASCITA se ha contesto di nascita vicino oppure un anno plausibile.
_BIRTH_CONTEXT = re.compile(r'(nat[oaie]\b|nascit|class[ei]\b)', re.IGNORECASE)
# Contesto che indica che una sequenza di cifre NON è un telefono (ordine/fattura/…).
_NON_PHONE_CONTEXT = re.compile(r'(ordine|fattura|codice|rif\.?|p\.?\s?iva|partita\s+iva|bolletta|preventivo)', re.IGNORECASE)
# Un "telefono" che è in realtà un orario/fascia oraria (es. "09.00 15.30").
_TIME_LIKE = re.compile(r"^\d{1,2}[.:]\d{2}(?:\s*[-–a]?\s*\d{1,2}[.:]\d{2})*$")

from models.schemas import PIIEntity

logger = logging.getLogger("social-privacy-backend")

AWS_MOCK = os.getenv("AWS_MOCK", "true").lower() == "true"

# Motore di estrazione PII: "presidio" (default), "ensemble" (Presidio ∪ LLM con grounding),
# "comprehend" (Amazon Comprehend + post-processing), "regex" (solo regole). Vedi detect_pii.
PII_PROVIDER = os.getenv("PII_PROVIDER", "presidio").lower()

# ── Analisi visiva: due soglie, perché i due usi hanno priorità OPPOSTE ────────
# Si INTERROGA Rekognition in modo largo (recall) e si FILTRA in modo stretto solo
# per ciò che si mostra all'utente (precisione).
#   - la classificazione delle categorie SENSIBILI (minori/documenti/geo) vede tutto:
#     meglio un falso allarme che un minore non segnalato;
#   - l'elenco "Esposizione visiva" del report mostra solo le etichette affidabili,
#     altrimenti si riempie di rumore.
REKOGNITION_MAX_LABELS = 50          # DetectLabels si paga a immagine: alzarlo è gratis
REKOGNITION_MIN_CONFIDENCE = 55      # default di AWS: soglia di INTERROGAZIONE
VISUAL_DISPLAY_MIN_CONFIDENCE = 75.0  # soglia di VISUALIZZAZIONE (era l'unica esistente)

# Interruttore per l'analisi visiva (Amazon Rekognition DetectLabels). Permette di
# disattivarla senza toccare il codice (es. contenimento costi) mettendo la
# variabile a "false". Attiva di default; ininfluente in AWS_MOCK (labels simulate).
ENABLE_REKOGNITION = os.getenv("ENABLE_REKOGNITION", "true").lower() == "true"


class PIIDetectorService:
    """
    Servizio di rilevamento PII (Personally Identifiable Information).

    Estrazione testo selezionabile via PII_PROVIDER:
        - "presidio" (default): NER italiano locale (spaCy) + recognizer custom;
        - "ensemble": Presidio ∪ LLM (solo tipi fuzzy, con grounding);
        - "comprehend": Amazon Comprehend + post-processing (solo con AWS reale);
        - "regex": solo motore a regole (offline, base).
    OCR (Textract) e visione (Rekognition) sono invocati sulle immagini; in
    AWS_MOCK sono simulati, con Presidio/regex che girano comunque in locale.
    """

    def __init__(self):
        self.comprehend_client = None
        self.textract_client = None
        self.rekognition_client = None

        if not AWS_MOCK:
            try:
                import boto3
                region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
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
        Punto di ingresso unico. Il motore è selezionabile via PII_PROVIDER:
          - "presidio" (default): NER italiano locale + recognizer custom (deterministico,
            ispezionabile, funziona anche senza AWS). Se Presidio non è installato → regex.
          - "ensemble": Presidio ∪ LLM (solo tipi fuzzy, con grounding). Se l'LLM non è
            configurato/raggiungibile → Presidio-solo.
          - "comprehend": Amazon Comprehend + post-processing (solo con AWS_MOCK=false).
          - "regex": solo motore a regole (offline, base).
        """
        if PII_PROVIDER == "ensemble":
            return self._detect_pii_ensemble(text)
        if PII_PROVIDER == "presidio":
            try:
                from services.pii_presidio import detect_pii_presidio
                return detect_pii_presidio(text)
            except Exception as e:
                logger.warning(f"Presidio non disponibile ({e}); fallback su motore regex.")
                return self._detect_pii_regex(text)
        if PII_PROVIDER == "comprehend" and self.comprehend_client and not AWS_MOCK:
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
        logger.info("[Regex] Esecuzione PII Detection via motore a espressioni regolari")
        pii_found: List[PIIEntity] = []

        # 1. EMAIL
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        for match in email_pattern.finditer(text):
            pii_found.append(PIIEntity(type="EMAIL", text=match.group(), score=0.99))

        # 2. PHONE_NUMBER (formati internazionali: es. +1 555-123-4567, +44 20 7946, 3331234567)
        # I lookaround (?<![A-Za-z0-9]) ... (?![A-Za-z0-9]) impediscono di catturare
        # una sequenza di cifre INCASTONATA in un token alfanumerico più lungo — tipico
        # dell'IBAN (coda di ~22 cifre dopo il prefisso paese) o di un codice: senza,
        # l'IBAN veniva erroneamente rilevato anche come numero di telefono.
        phone_pattern = re.compile(r'(?<![A-Za-z0-9])\+?(?:[0-9][\s.-]?){7,14}[0-9](?![A-Za-z0-9])')
        for match in phone_pattern.finditer(text):
            phone_str = match.group().strip()
            digits_only = re.sub(r'\D', '', phone_str)
            # Filtro base: i numeri telefonici validi (inclusi prefissi) hanno tra 7 e 15 cifre
            if not (7 <= len(digits_only) <= 15):
                continue
            # Scarta se il contesto precedente indica un numero NON telefonico
            # (ordine, fattura, codice…) o se è un orario/fascia oraria (09.00 15.30).
            if _NON_PHONE_CONTEXT.search(text[max(0, match.start() - 18):match.start()]):
                continue
            if _TIME_LIKE.match(phone_str):
                continue
            pii_found.append(PIIEntity(type="PHONE_NUMBER", text=phone_str, score=0.95))

        # 3. DATE_OF_BIRTH — solo date PLAUSIBILMENTE di nascita, non ogni data.
        #    Una data conta come nascita se ha contesto di nascita vicino ("nato/a il",
        #    "nascita", "classe") OPPURE un anno plausibile (adulto: dal 1900 ad almeno
        #    13 anni fa). Così eventi/scadenze ("concerto il 20/07/2025", "scadenza
        #    31/12/2024") NON vengono classificati come data di nascita.
        def _is_birth_date(m) -> bool:
            ym = re.search(r'(?:19|20)\d{2}', m.group())
            year = int(ym.group()) if ym else 0
            near = text[max(0, m.start() - 30):m.start()]
            return bool(_BIRTH_CONTEXT.search(near)) or (1900 <= year <= _CURRENT_YEAR - 13)

        date_numeric = re.compile(r'\b(?:0?[1-9]|[12][0-9]|3[01])[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:19|20)\d{2}\b')
        for match in date_numeric.finditer(text):
            if _is_birth_date(match):
                pii_found.append(PIIEntity(type="DATE_OF_BIRTH", text=match.group(), score=0.90))

        mesi = r'(?:gennaio|febbraio|marzo|aprile|maggio|giugno|luglio|agosto|settembre|ottobre|novembre|dicembre|january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|oct|nov|dec)'
        date_text = re.compile(rf'\b(?:0?[1-9]|[12][0-9]|3[01])\s+{mesi}\s+(?:19|20)\d{{2}}\b', re.IGNORECASE)
        for match in date_text.finditer(text):
            if _is_birth_date(match):
                pii_found.append(PIIEntity(type="DATE_OF_BIRTH", text=match.group(), score=0.88))

        # 3b. AGE — età, SOLO con contesto nel match ("27 anni", "27 years old",
        #     "classe 1998"), così un numero nudo ("27 post", "27€") non è mai un'età.
        #     Esclude le DURATE/tempo trascorso: "N anni fa" (lookahead), "da/per N anni"
        #     (lookbehind) NON sono età.
        age_pattern = re.compile(
            # Le durate NON sono età: "N anni fa", "da|per|dopo|in N anni".
            r'(?<!da )(?<!per )(?<!dopo )(?<!in )\b\d{1,3}\s*anni\b(?!\s+fa)|\b\d{1,2}\s*years?\s*old\b|\bclasse\s+(?:19|20)\d{2}\b',
            re.IGNORECASE)
        for match in age_pattern.finditer(text):
            pii_found.append(PIIEntity(type="AGE", text=match.group().strip(), score=0.80))

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

    # Tipi che il motore regex italiano gestisce meglio di Comprehend-come-inglese
    # (dati strutturati e specifici IT). Su questi il regex "vince": Comprehend li
    # perde o li tipizza male (es. la data di nascita come DATE_TIME, il codice
    # fiscale come DRIVER_ID, l'IBAN come INTERNATIONAL_BANK_ACCOUNT_NUMBER).
    _REGEX_OWNED_TYPES = {
        "EMAIL", "PHONE_NUMBER", "DATE_OF_BIRTH", "URL",
        "ORGANIZATION", "LOCATION", "USERNAME", "FISCAL_CODE", "IBAN",
    }

    # Tipi "fuzzy" gestiti dall'ensemble Presidio+LLM (NER a testo libero).
    _FUZZY_TYPES = {"NAME", "LOCATION", "ORGANIZATION"}

    # Token spesso scambiati da Comprehend per LOCATION/ORGANIZATION (rumore da scartare).
    _NER_NOISE = {"iban", "cf", "p.iva", "piva", "email", "tel", "cell", "srl", "spa"}

    def _detect_pii_comprehend(self, text: str) -> List[PIIEntity]:
        """
        Amazon Comprehend + POST-PROCESSING italiano.

        Tre fonti fuse:
          1. motore regex italiano → dati strutturati/IT coi tipi giusti (email, telefono,
             data di nascita, URL, username, codice fiscale, IBAN, + gazetteer luoghi/org);
          2. Comprehend DetectPiiEntities ("en") → NAME e ADDRESS (che il regex non fa);
          3. Comprehend DetectEntities ("en") → LOCATION e ORGANIZATION di QUALSIASI città/
             azienda (NER generale) — non solo il gazetteer.
        Comprehend sul testo italiano tipizza male i dati strutturati (la data di nascita
        diventa DATE_TIME, il codice fiscale DRIVER_ID, l'IBAN un bank account): per questo
        il regex "possiede" quei tipi (_REGEX_OWNED_TYPES) e i doppioni/DATE_TIME di
        Comprehend vengono scartati. Così 'nata il 22/06/2000' resta DATE_OF_BIRTH anche in
        AWS reale, e 'Lecce'/'TechStartup Srl' vengono riconosciuti pur non essendo in lista.
        Costo: due chiamate Comprehend per testo (PII + entità generali).
        """
        logger.info("[AWS Comprehend] DetectPiiEntities + DetectEntities + post-processing italiano")

        # 1) Base: motore regex italiano (email, telefono, DOB, URL, org, luoghi,
        #    username, codice fiscale, IBAN) con i tipi corretti.
        merged: List[PIIEntity] = list(self._detect_pii_regex(text))
        regex_texts = {p.text.lower() for p in merged}

        # 2) Arricchimento con Comprehend per ciò che il regex non copre (NAME, ADDRESS…).
        try:
            response = self.comprehend_client.detect_pii_entities(Text=text, LanguageCode="en")
        except Exception as e:
            logger.error(f"Errore Comprehend: {e}. Uso solo il motore regex.")
            return merged

        for entity in response.get("Entities", []):
            etype = entity.get("Type", "UNKNOWN")
            etext = text[entity.get("BeginOffset", 0):entity.get("EndOffset", 0)]

            # Scarta i tipi che il regex gestisce meglio (li abbiamo già, tipizzati bene).
            if etype in self._REGEX_OWNED_TYPES:
                continue
            # DATE_TIME di Comprehend: rumoroso (date di eventi) e le date di nascita le
            # prende già il regex come DATE_OF_BIRTH → scarta.
            if etype == "DATE_TIME":
                continue
            # Evita doppioni sullo stesso testo già rilevato dal regex.
            if etext.lower() in regex_texts:
                continue

            merged.append(PIIEntity(
                type=etype,
                text=etext,
                score=round(entity.get("Score", 0.0), 2),
            ))

        # 3) NER GENERALE (DetectEntities) per LOCATION/ORGANIZATION di QUALSIASI città o
        #    azienda — non solo il gazetteer. DetectPiiEntities NON restituisce questi tipi
        #    (sono in DetectEntities). Così riconosciamo luoghi/organizzazioni arbitrari
        #    (es. Lecce, Como, Verona, TechStartup Srl) invece della sola lista fissa.
        try:
            ner = self.comprehend_client.detect_entities(Text=text, LanguageCode="en")
        except Exception as e:
            logger.warning(f"[Comprehend DetectEntities] non disponibile: {e}")
            return merged

        for entity in ner.get("Entities", []):
            etype = entity.get("Type")
            if etype not in ("LOCATION", "ORGANIZATION"):
                continue
            etext = text[entity.get("BeginOffset", 0):entity.get("EndOffset", 0)].strip(" ,.;:")
            # Scarta rumore tipico (parole-chiave scambiate per entità) e i doppioni.
            if len(etext) < 2 or etext.lower() in self._NER_NOISE:
                continue
            if etext.lower() in regex_texts:
                continue
            merged.append(PIIEntity(type=etype, text=etext, score=round(entity.get("Score", 0.0), 2)))

        return merged

    # ──────────────────────────────────────────────────────────────────────────
    # ENSEMBLE: Presidio ∪ LLM (solo tipi fuzzy, con grounding)
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _canon_type(t: str) -> str:
        """PERSON → NAME; il resto invariato (label canoniche del progetto)."""
        return "NAME" if t.upper() == "PERSON" else t.upper()

    def _detect_pii_ensemble(self, text: str) -> List[PIIEntity]:
        """Ensemble: Presidio + LLM (solo tipi fuzzy, con grounding).

        L'LLM ha due ruoli, serviti dalla STESSA chiamata:
          - recall: aggiunge i fuzzy che Presidio non ha visto;
          - precisione: VERIFICA i fuzzy di Presidio. Il NER di spaCy, su bio non
            discorsive (cataloghi di eventi, gag), produce nomi e luoghi inesistenti
            che il filtro di casing non può riconoscere — span cuciti su più righe
            ("Cortona Parma Roma") o personaggi inventati. L'LLM legge il testo con il
            contesto e non li restituisce: i candidati non confermati si scartano.
        Se l'LLM non è configurato o fallisce (detect_pii_llm → None) la verifica NON
        si applica e l'ensemble degrada a Presidio puro: un timeout non deve azzerare
        tutti i nomi e i luoghi.
        """
        try:
            from services.pii_presidio import detect_pii_presidio
            presidio_piis = detect_pii_presidio(text)
        except Exception as e:
            logger.warning(f"Presidio non disponibile ({e}); ensemble su solo regex.")
            presidio_piis = self._detect_pii_regex(text)
        try:
            from services.pii_llm import detect_pii_llm
            llm_piis = detect_pii_llm(text)
        except Exception as e:
            logger.warning(f"[ensemble] LLM non disponibile ({e}); uso solo Presidio.")
            llm_piis = None
        if llm_piis is None:
            logger.warning("[ensemble] LLM non ha risposto: niente verifica, solo Presidio.")
            return presidio_piis
        return self._merge_ensemble(presidio_piis, llm_piis)

    def _merge_ensemble(self, presidio_piis: List[PIIEntity],
                        llm_piis: List[PIIEntity]) -> List[PIIEntity]:
        """Unisce Presidio e LLM sui tipi fuzzy, usando l'LLM anche come verifica:
          - accordo (stesso tipo+testo) → score 0.95
          - fuzzy di Presidio NON confermato dall'LLM → SCARTATO (falso positivo del NER)
          - conflitto di tipo (stesso testo, tipo fuzzy diverso) → vince Presidio, LLM scartata
          - testo già rilevato da Presidio come dato STRUTTURATO (username, email, URL, CF...)
            → la variante fuzzy dell'LLM è scartata: i tipi strutturati sono di Presidio
          - solo-LLM (grounded, testo non già presente) → nuova entità a 0.75
          - entità non-fuzzy (email, CF, IBAN, ...) → invariate: non passano dall'LLM

        "Confermato" = il testo di Presidio compare dentro uno span restituito dall'LLM.
        Il contenimento (non l'uguaglianza) tiene i casi in cui l'LLM restituisce lo span
        più largo ("Villa Guidini" dentro "Villa Guidini Reggia di Caserta"), ma scarta
        comunque gli span cuciti di Presidio ("Cortona Parma Roma", quando l'LLM
        restituisce le tre città separate).
        """
        def key(e: PIIEntity):
            return (self._canon_type(e.type), e.text.strip().lower())

        # Chiavi (tipo,testo) e testi fuzzy lato Presidio.
        presidio_fuzzy_keys = {
            key(e) for e in presidio_piis if self._canon_type(e.type) in self._FUZZY_TYPES
        }
        presidio_fuzzy_texts = {
            e.text.strip().lower()
            for e in presidio_piis if self._canon_type(e.type) in self._FUZZY_TYPES
        }
        llm_fuzzy_keys = {
            key(e) for e in llm_piis if self._canon_type(e.type) in self._FUZZY_TYPES
        }
        # Testi che Presidio ha già rilevato come dati STRUTTURATI. L'LLM tende a leggere
        # gli username come nomi di persona ("@mario.rossi" → NAME): sono già USERNAME e
        # la variante fuzzy va scartata. È la stessa difesa che pii_presidio applica agli
        # span di spaCy sovrapposti a un dato strutturato, qui estesa all'output dell'LLM.
        presidio_structured_texts = [
            e.text.strip().lower()
            for e in presidio_piis if self._canon_type(e.type) not in self._FUZZY_TYPES
        ]

        # Span fuzzy restituiti dall'LLM, per la verifica per contenimento.
        llm_fuzzy_spans = [
            e.text.strip().lower()
            for e in llm_piis if self._canon_type(e.type) in self._FUZZY_TYPES
        ]

        merged: List[PIIEntity] = []
        # 1) Presidio: i fuzzy passano solo se l'LLM li conferma (preserva le occorrenze).
        for e in presidio_piis:
            ct = self._canon_type(e.type)
            if ct not in self._FUZZY_TYPES:
                merged.append(e)  # dato strutturato: l'LLM non ha voce in capitolo
                continue
            if key(e) in llm_fuzzy_keys:
                merged.append(PIIEntity(type=e.type, text=e.text, score=max(e.score, 0.95)))
                continue
            etext = e.text.strip().lower()
            if any(etext in span for span in llm_fuzzy_spans):
                merged.append(e)  # confermato dal contesto, tipo di Presidio
                continue
            logger.debug(f"[ensemble] scartato (non confermato dall'LLM): {ct} {e.text!r}")

        # 2) Recall solo-LLM: chiavi LLM assenti da Presidio e senza conflitto di testo.
        seen_llm_keys = set()
        for e in llm_piis:
            ct = self._canon_type(e.type)
            if ct not in self._FUZZY_TYPES:
                continue
            k = key(e)
            if k in presidio_fuzzy_keys:
                continue  # accordo: già gestito al punto 1
            etext = e.text.strip().lower()
            if etext in presidio_fuzzy_texts:
                continue  # conflitto di tipo: vince Presidio
            # Già rilevato come dato strutturato: "@mario.rossi" è USERNAME, non NAME.
            # Contenimento nei due versi: l'LLM può restituire "mario.rossi" senza la @.
            if any(etext in s or s in etext for s in presidio_structured_texts):
                continue
            if k in seen_llm_keys:
                continue  # dedup interno LLM
            seen_llm_keys.add(k)
            merged.append(PIIEntity(type=ct, text=e.text, score=0.75))

        return merged

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
                # Si chiede a Rekognition il MASSIMO che sa dire, e si filtra dopo.
                # Prima erano MaxLabels=15 / MinConfidence=75: numeri tarati per le
                # etichette di SCENA (dove conta la precisione) applicati però anche alle
                # categorie sensibili, dove la priorità è opposta — un falso allarme è un
                # fastidio, un mancato rilevamento è il fallimento della funzione.
                # DetectLabels si paga A IMMAGINE, non a etichetta: alzare MaxLabels è gratis.
                # NB: questo NON risolve il rilevamento dei minori. Verificato su un caso
                # reale interrogando Rekognition senza alcun filtro: su una foto con un
                # minore restituisce "Adult" al 98.9% e non emette "Child" a NESSUNA
                # confidenza. DetectLabels classifica oggetti e scene, non stima l'età:
                # per quella serve DetectFaces (vedi detect_face_age_ranges).
                MaxLabels=REKOGNITION_MAX_LABELS,
                MinConfidence=REKOGNITION_MIN_CONFIDENCE,
            )
            return [
                {"name": lbl["Name"], "confidence": round(lbl.get("Confidence", 0.0), 1)}
                for lbl in response.get("Labels", [])
            ]
        except Exception as e:
            logger.error(f"Errore Rekognition: {e}")
            return []

    def detect_face_age_ranges(self, image_bytes: bytes) -> List[dict]:
        """Stima l'età dei volti presenti (Amazon Rekognition DetectFaces → AgeRange).

        SERVE SOLO a segnalare la presenza di MINORI nelle foto pubblicate, che
        DetectLabels non sa fare: interrogato senza filtri su una foto reale con un
        minore restituisce "Adult" al 98.9% e mai "Child". DetectLabels classifica
        oggetti e scene; l'unica API AWS che stima l'età è DetectFaces.

        SCELTA GDPR (deliberata e argomentata in relazione). Non è trattamento di dati
        BIOMETRICI ai sensi dell'art. 4(14) GDPR, che qualifica come tali i soli dati
        che permettono «l'identificazione univoca» di una persona:
          - si richiede ESCLUSIVAMENTE l'attributo AGE_RANGE (non emozioni, non genere,
            non landmark facciali): minimizzazione, art. 5(1)(c);
          - non si crea alcun template facciale, non si indicizza e non si confronta:
            le API di RICONOSCIMENTO (IndexFaces, CompareFaces, SearchFacesByImage)
            restano escluse, e con esse le Face Collection;
          - non si conserva nulla: si tiene solo l'intervallo d'età, mai l'immagine né
            un descrittore del volto;
          - la finalità è di TUTELA del minore (cfr. considerando 38 GDPR), non di
            identificazione.
        Restituisce [{"low": int, "high": int, "confidence": float}] per ogni volto
        (confidence = quanto Rekognition è certo che sia un volto, non una stima
        sull'età). Mai solleva: un errore di stima non deve far fallire l'analisi.
        """
        if not ENABLE_REKOGNITION:
            return []
        if AWS_MOCK or not self.rekognition_client:
            logger.info("[MOCK Rekognition] Simulazione DetectFaces (AGE_RANGE)")
            if len(image_bytes) < 2048:
                return []
            return [{"low": 25, "high": 33, "confidence": 99.9}]

        try:
            response = self.rekognition_client.detect_faces(
                Image={"Bytes": image_bytes},
                Attributes=["AGE_RANGE"],  # SOLO l'età: nessun altro attributo del volto
            )
            out = []
            for face in response.get("FaceDetails", []):
                age = face.get("AgeRange") or {}
                if "Low" in age and "High" in age:
                    out.append({"low": int(age["Low"]), "high": int(age["High"]),
                                "confidence": round(float(face.get("Confidence", 0.0)), 1)})
            return out
        except Exception as e:
            logger.error(f"Errore Rekognition DetectFaces: {e}")
            return []
