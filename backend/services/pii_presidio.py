# ==============================================================================
# PII PRESIDIO - Estrazione PII con Microsoft Presidio + spaCy italiano (SDCC)
# Percorso: backend/services/pii_presidio.py
#
# Alternativa deterministica e LOCALE ad Amazon Comprehend: NER italiano (spaCy
# it_core_news_lg) per NAME/LOCATION/ORGANIZATION + recognizer PATTERN custom per i
# dati strutturati/IT (email, telefono, data di nascita, codice fiscale, IBAN, URL,
# username, indirizzo). Ogni regola è NOSTRA e ispezionabile: i falsi positivi si
# correggono qui (a differenza del NER opaco di Comprehend). Output: List[PIIEntity]
# coi tipi canonici del progetto, con la confidenza di Presidio.
#
# L'AnalyzerEngine è costoso da creare (carica il modello spaCy): singleton lazy.
# ==============================================================================

import re
import logging
from datetime import datetime
from typing import List

from models.schemas import PIIEntity

logger = logging.getLogger("social-privacy-backend")

_CURRENT_YEAR = datetime.now().year
_BIRTH_CONTEXT = re.compile(r'(nat[oaie]\b|nascit|class[ei]\b)', re.IGNORECASE)
_NON_PHONE_CONTEXT = re.compile(r'(ordine|fattura|codice|rif\.?|p\.?\s?iva|partita\s+iva|bolletta|preventivo)', re.IGNORECASE)

# Tipo entità Presidio → tipo canonico del progetto.
_PMAP = {
    "EMAIL_ADDRESS": "EMAIL", "IBAN_CODE": "IBAN", "IBAN": "IBAN", "PHONE_NUMBER": "PHONE_NUMBER",
    "URL": "URL", "PERSON": "NAME", "LOCATION": "LOCATION", "ORGANIZATION": "ORGANIZATION",
    "FISCAL_CODE": "FISCAL_CODE", "DATE_OF_BIRTH": "DATE_OF_BIRTH",
    "USERNAME": "USERNAME", "ADDRESS": "ADDRESS", "AGE": "AGE",
    "FAMILY_REF": "FAMILY_REF",
}

_MESI = r"(?:gennaio|febbraio|marzo|aprile|maggio|giugno|luglio|agosto|settembre|ottobre|novembre|dicembre)"

# Termini di parentela per il riconoscimento dei RIFERIMENTI FAMILIARI (richiesti
# esplicitamente dalla traccia). Il pattern richiede il POSSESSIVO di prima persona:
# è ciò che distingue "mia figlia Sofia" (un legame del titolare del profilo) da
# "festa della mamma" o da una parentela altrui. Senza il possessivo si prenderebbe
# ogni occorrenza della parola "mamma".
_PARENTELA = (r"(?i:moglie|marito|compagn[oa]|fidanzat[oa]|figli[oa]|figli|madre|mamma|"
              r"padre|pap[àa]|babbo|sorella|fratello|nonn[oa]|zi[oa]|cugin[oa]|"
              r"nipote|suocer[oa]|cognat[oa]|genero|nuora|genitori)")

# Tipi FORTI: identificatori con struttura verificabile (formato rigido, non ambigui).
# Ciò che si sovrappone a uno di essi è un falso positivo di un motore più debole —
# es. spaCy tagga un'email come nome, o il regex del telefono aggancia i gruppi di
# cifre dentro un IBAN. ADDRESS è qui perché "Via Garibaldi 12" è un indirizzo intero:
# il NER, senza questa protezione, ne estraeva "Garibaldi" come NOME di persona.
_STRUCTURED = {"EMAIL", "IBAN", "FISCAL_CODE", "PHONE_NUMBER", "URL", "DATE_OF_BIRTH",
               "USERNAME", "ADDRESS"}

# Tipi DEBOLI: si scartano se si sovrappongono a un tipo forte. Oltre ai fuzzy del NER
# ci sono PHONE_NUMBER e AGE, che nascono da regex su cifre nude e quindi agganciano
# volentieri pezzi di IBAN, codici fiscali e date.
_WEAK_VS_STRUCTURED = {"NAME", "LOCATION", "ORGANIZATION", "PHONE_NUMBER", "AGE"}
# Parole comuni che spaCy scambia per nome/organizzazione.
_NER_STOPWORDS = {"contatto", "contatti", "it", "email", "mail", "tel", "cell", "iban", "cf", "p.iva", "piva"}

# Un "telefono" che è in realtà un orario/fascia oraria (es. "09.00 15.30", "9:00-13:00").
_TIME_LIKE = re.compile(r"^\d{1,2}[.:]\d{2}(?:\s*[-–a]?\s*\d{1,2}[.:]\d{2})*$")

# Parole con casing "normale" per nomi/luoghi: Titlecase ("Roma", "Verdi").
_W_TITLE = re.compile(r"[A-ZÀ-Ù][a-zà-ù'’]*\.?$")
# Particelle: le uniche parole minuscole ammesse dentro un nome/luogo ("Reggia di Caserta").
_PARTICLES = {"di", "de", "del", "della", "dei", "degli", "da", "dal", "dalla",
              "van", "von", "der", "la", "le", "lo", "du", "of", "and", "e"}


def _clean_ner(s: str) -> str:
    """Ripulisce il testo di un'entità NER: taglia dopo separatori di bio (| • –),
    rimuove emoji/simboli, normalizza gli spazi."""
    s = re.split(r"[|•]", s)[0]
    s = re.sub(r"[^\wÀ-ù\s'’.&-]", " ", s)
    return " ".join(s.split()).strip(" .-'’")


def _looks_real(s: str, strict: bool) -> bool:
    """True se il testo sembra un nome/luogo/organizzazione reale.

    Il NER di spaCy, su bio social non discorsive (cataloghi di date/eventi, testo
    urlato, gag), produce tre classi di spazzatura che qui si scartano per casing:
      1. sigle nude ("CI", "TO", "PA") — province/abbreviazioni, non luoghi;
      2. frammenti concatenati che mescolano MAIUSCOLE e Titlecase, sintomo di uno
         span cucito su più righe ("Piccolo Parco Urbano SOLD OUT", "SAN SIRO X");
      3. parole comuni minuscole prese per nome ("bio").
    strict (NAME/LOCATION): solo Titlecase + particelle ("Reggia di Caserta").
    Non-strict (ORGANIZATION): tollera camelCase e sigle puntate (BancaX, S.p.A.),
    scarta l'acronimo nudo breve ("FUORI", "GUE") e le sigle MULTI-parola tutto
    maiuscolo ("OCC STATE"), tipiche dell'OCR di un documento o del testo urlato.
    """
    words = s.split()
    if not words or len(s) < 3:
        return False
    caps = [w for w in words if len(w) > 1 and w.isupper()]
    if caps and len(caps) != len(words):
        return False  # (2) mix MAIUSCOLE/Titlecase = frammento cucito
    all_caps = bool(caps) and len(caps) == len(words)
    if not strict:
        # multi-parola tutto maiuscolo = spazzatura OCR ("OCC STATE", "FISIOG CORPO
        # SPIRTO"): una org vera è Titlecase (Deloitte Italia) o camelCase (BancaX).
        if all_caps and len(words) >= 2:
            return False
        # acronimo nudo breve, ambiguo in una bio ("FUORI", "GUE")
        if len(words) == 1 and words[0].isupper() and len(words[0]) <= 6:
            return False
        return True
    if all_caps:
        return False  # (1) nome/luogo tutto maiuscolo: sigla o testo urlato
    return all(w.isdigit() or _W_TITLE.match(w) or w.lower() in _PARTICLES for w in words)

_analyzer = None  # singleton


def _build_analyzer():
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    cfg = {"nlp_engine_name": "spacy", "models": [{"lang_code": "it", "model_name": "it_core_news_lg"}]}
    nlp = NlpEngineProvider(nlp_configuration=cfg).create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp, supported_languages=["it"])

    # Recognizer PATTERN custom per i dati strutturati/IT (Presidio ne ha alcuni di
    # default — email/IBAN/URL — ma il telefono di default manca i formati italiani).
    custom = [
        PatternRecognizer(supported_entity="FISCAL_CODE", supported_language="it",
            patterns=[Pattern("cf", r"\b[A-Za-z]{6}\d{2}[A-Za-z]\d{2}[A-Za-z]\d{3}[A-Za-z]\b", 0.9)]),
        # IBAN nostro (l'IbanRecognizer di default scarta alcuni IBAN per checksum;
        # noi li riconosciamo comunque, coerenti col motore regex).
        # Ammette gli SPAZI fra i gruppi, come si scrive un IBAN nella vita reale e come
        # lo restituisce l'OCR di un documento fotografato. Senza, un IBAN spaziato non
        # veniva rilevato E i suoi gruppi di cifre venivano scambiati per numeri di
        # telefono (che poi facevano scattare SIM swapping e smishing): si perdeva il
        # dato più pericoloso e se ne inventava uno inesistente.
        PatternRecognizer(supported_entity="IBAN", supported_language="it",
            patterns=[Pattern("iban_it", r"\b[A-Za-z]{2}\d{2}(?:\s?[A-Za-z0-9]){11,30}\b", 0.85)]),
        PatternRecognizer(supported_entity="DATE_OF_BIRTH", supported_language="it", patterns=[
            Pattern("dob_num", r"\b(?:0?[1-9]|[12][0-9]|3[01])[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:19|20)\d{2}\b", 0.85),
            Pattern("dob_txt", r"\b(?:0?[1-9]|[12][0-9]|3[01])\s+" + _MESI + r"\s+(?:19|20)\d{2}\b", 0.85)]),
        PatternRecognizer(supported_entity="USERNAME", supported_language="it",
            patterns=[Pattern("user", r"@[a-zA-Z0-9_.]{3,30}", 0.6)]),
        # RIFERIMENTI FAMILIARI — richiesti dalla traccia fra le PII da individuare.
        # Non è il nome in sé (già coperto da NAME): è il LEGAME dichiarato in pubblico.
        # Un nome permette di impersonare quella persona; un legame permette di
        # impersonare qualcuno di vicino a lei, che è l'inganno più efficace ("sono la
        # maestra di sua figlia Sofia..."). Il nome che segue è catturato quando c'è,
        # perché "mia figlia Sofia" espone più di "mia figlia".
        #
        # global_regex_flags SENZA IGNORECASE: Presidio lo attiva di default, e con
        # quello attivo "[A-ZÀ-Ù]" matcherebbe anche le minuscole — "I miei genitori
        # vivono a Roma" catturava "vivono" come se fosse un nome. Qui il caso è
        # informazione: solo una parola con l'iniziale maiuscola è un nome proprio.
        # Il possessivo e i termini di parentela riprendono le due varianti a mano.
        PatternRecognizer(supported_entity="FAMILY_REF", supported_language="it",
            global_regex_flags=re.DOTALL | re.MULTILINE,
            patterns=[
                Pattern("fam_poss", r"\b[Mm](?:i[ao]|iei|ie)\s+" + _PARENTELA
                                    + r"\b(?:\s+[A-ZÀ-Ù][a-zà-ù'’]+)?", 0.8),
            ]),
        PatternRecognizer(supported_entity="ADDRESS", supported_language="it",
            patterns=[Pattern("addr", r"\b(?:Via|Viale|Corso|Piazza|Piazzale|Vicolo|Largo)\s+(?:[A-ZÀ-Ù][\wÀ-ù']+\s*){1,4}\d+", 0.75)]),
        PatternRecognizer(supported_entity="PHONE_NUMBER", supported_language="it",
            patterns=[Pattern("tel_it", r"(?<![A-Za-z0-9])\+?(?:[0-9][\s.\-]?){7,14}[0-9](?![A-Za-z0-9])", 0.7)]),
        # ETÀ — solo con CONTESTO nel match (numero+"anni", "years old", "classe AAAA"),
        # così un numero nudo ("27 post", "27€", "il 27") NON viene mai preso per età.
        PatternRecognizer(supported_entity="AGE", supported_language="it", patterns=[
            # Esclude le DURATE, che non sono età: "N anni fa", "da|per|dopo N anni",
            # "in N anni". Osservato su dati reali: "Dopo 5 anni a Roma" → età 5 anni.
            Pattern("age_it", r"(?<!da )(?<!per )(?<!dopo )(?<!in )\b\d{1,3}\s*anni\b(?!\s+fa)", 0.75),
            Pattern("age_en", r"\b\d{1,2}\s*years?\s*old\b", 0.75),
            Pattern("age_classe", r"\bclasse\s+(?:19|20)\d{2}\b", 0.7)]),
    ]
    for r in custom:
        analyzer.registry.add_recognizer(r)
    logger.info("⚡ Presidio AnalyzerEngine (spaCy it_core_news_lg + recognizer custom) inizializzato.")
    return analyzer


def _get_analyzer():
    global _analyzer
    if _analyzer is None:
        _analyzer = _build_analyzer()
    return _analyzer


def detect_pii_presidio(text: str) -> List[PIIEntity]:
    """Estrae le PII con Presidio, restituendo i tipi canonici del progetto.
    Applica gli stessi filtri anti-falso-positivo della strategia regex — ma qui sono
    NOSTRI e deterministici: data di nascita solo con contesto/anno plausibile, telefono
    escluso se contesto ordine/fattura, username solo se non incastonato (es. in un'email)."""
    analyzer = _get_analyzer()
    results = analyzer.analyze(text=text, language="it")

    # ── 1ª passata: candidati con filtri specifici (DOB, telefono, username) ──────
    raw = []  # (canonical, val, start, end, score)
    for r in results:
        if r.score < 0.6:
            continue
        canonical = _PMAP.get(r.entity_type)
        if not canonical:
            continue
        val = text[r.start:r.end]

        if canonical == "DATE_OF_BIRTH":
            ym = re.search(r'(?:19|20)\d{2}', val)
            year = int(ym.group()) if ym else 0
            near = text[max(0, r.start - 30):r.start]
            if not (_BIRTH_CONTEXT.search(near) or 1900 <= year <= _CURRENT_YEAR - 13):
                continue
        if canonical == "PHONE_NUMBER":
            if _NON_PHONE_CONTEXT.search(text[max(0, r.start - 18):r.start]):
                continue
            if _TIME_LIKE.match(val.strip()):
                continue  # è un orario/fascia oraria, non un telefono
            # Un telefono è un token ISOLATO, non un gruppo dentro una sequenza più lunga
            # di cifre. L'OCR di un documento legge i campi di un IBAN (ABI CAB conto) come
            # cifre nude quando il prefisso "IT60X" è su un'altra riga: la regex del
            # telefono spezza allora la sequenza da 22 cifre in due falsi "telefoni"
            # (05428 11101, 000000 123456). Se subito prima o subito dopo — saltando gli
            # spazi — ci sono altre cifre, il match è parte di un numero più lungo.
            if re.search(r"\d[\s]*$", text[max(0, r.start - 3):r.start]) or \
               re.match(r"[\s]*\d", text[r.end:r.end + 3]):
                continue
        if canonical == "USERNAME" and r.start > 0 and text[r.start - 1] not in " \t\n(":
            continue
        raw.append((canonical, val, r.start, r.end, r.score))

    # ── 2ª passata: scarta i rilevamenti DEBOLI dentro un dato FORTE ─────────────
    # Un tipo forte ha struttura verificabile; ciò che gli si sovrappone è un errore di
    # un motore più debole. Due famiglie di errori, entrambe osservate su dati reali:
    #   - spaCy tagga come NOME/ORG/LUOGO un'email, un IBAN o il nome di una via
    #     ("Via Garibaldi 12" → NOME "Garibaldi");
    #   - il regex di telefono/età aggancia cifre dentro un IBAN o un codice fiscale
    #     ("IT60 X0542 811101 000000..." → TELEFONO "811101 000000").
    # Il confronto è per span sul testo, quindi indipendente da quale motore ha prodotto
    # cosa. Un tipo forte non si autoesclude: si confronta solo con gli ALTRI span.
    def _overlaps(s, e, canonical):
        return any(not (e <= ss or s >= ee)
                   for (c, v, ss, ee, sc) in raw
                   if c in _STRUCTURED and not (ss == s and ee == e and c == canonical))

    out: List[PIIEntity] = []
    for (canonical, val, s, e, score) in raw:
        if canonical in _WEAK_VS_STRUCTURED and _overlaps(s, e, canonical):
            continue
        if canonical in ("NAME", "LOCATION", "ORGANIZATION"):
            if val.strip().lower() in _NER_STOPWORDS:
                continue
            # Ripulisce la spazzatura del NER su bio social (frammenti, versi, casing
            # artistico): taglia dopo i separatori e scarta se non "sembra reale".
            cleaned = _clean_ner(val)
            if not _looks_real(cleaned, strict=(canonical in ("NAME", "LOCATION"))):
                continue
            val = cleaned
        if canonical in ("FISCAL_CODE", "IBAN"):
            val = val.upper()
        if canonical == "IBAN":
            # Normalizza la forma canonica: un IBAN è lo stesso dato scritto con o senza
            # spazi, e senza questo la deduplicazione a valle lo conterebbe due volte.
            val = re.sub(r"\s+", "", val)
        out.append(PIIEntity(type=canonical, text=val, score=round(float(score), 2)))
    return out
