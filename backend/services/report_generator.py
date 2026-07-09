# ==============================================================================
# REPORT GENERATOR SERVICE - Generazione Report AI (SDCC)
# Simula Amazon Bedrock Runtime (Claude) in locale.
# In produzione, invoca bedrock_runtime.invoke_model() via Boto3.
# ==============================================================================

import os
import json
import logging
from typing import List

from models.schemas import PIIEntity, SocialEngineeringThreat

logger = logging.getLogger("social-privacy-backend")

AWS_MOCK = os.getenv("AWS_MOCK", "true").lower() == "true"


class ReportGeneratorService:
    """
    Genera report di social engineering basati sulle PII rilevate.

    Modalita MOCK: logica deterministica basata sui tipi di PII trovati.
    Modalita PRODUZIONE: invoca Claude su Amazon Bedrock per report in linguaggio naturale.
    """

    def __init__(self):
        self.bedrock_client = None

        # Provider del report generativo, selezionabile via env (architettura
        # "switchable"): "gemini" (default, API esterna gratuita), "bedrock" (AWS,
        # quando la quota è disponibile) oppure "mock" (deterministico).
        # I provider LLM esterni (Gemini/DeepSeek/OpenAI) espongono tutti un
        # endpoint OpenAI-compatible, quindi condividono UN SOLO code path: cambia
        # solo base_url + modello + chiave.
        self.report_provider = os.getenv("REPORT_PROVIDER", "gemini").lower()

        if self.report_provider == "gemini":
            self.llm_base_url = os.getenv("LLM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai/")
            self.llm_model = os.getenv("LLM_MODEL", "gemini-2.5-flash")
            self.llm_api_key = (os.getenv("GEMINI_API_KEY") or os.getenv("LLM_API_KEY", "")).strip()
        else:
            # Generico OpenAI-compatible (es. DeepSeek, OpenAI): tutto da env.
            self.llm_base_url = os.getenv("LLM_BASE_URL", "").strip()
            self.llm_model = os.getenv("LLM_MODEL", "").strip()
            self.llm_api_key = os.getenv("LLM_API_KEY", "").strip()

        # Il client Bedrock si inizializza solo se il provider scelto è "bedrock".
        if not AWS_MOCK and self.report_provider == "bedrock":
            try:
                import boto3
                region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
                self.bedrock_client = boto3.client("bedrock-runtime", region_name=region)
                logger.info("ReportGeneratorService: Client AWS Bedrock Runtime inizializzato.")
            except Exception as e:
                logger.error(f"ReportGeneratorService: Impossibile inizializzare Bedrock. Errore: {e}")

    # --------------------------------------------------------------------------
    # METODO PRINCIPALE
    # --------------------------------------------------------------------------

    def generate_threats(self, pii_list: List[PIIEntity]) -> List[SocialEngineeringThreat]:
        """
        Genera l'analisi dei vettori di attacco secondo il provider configurato.
        In modalità mock (sviluppo offline) usa sempre la logica deterministica.
        In caso di errore di qualsiasi provider si ricade sempre sul mock, così la
        pipeline non si interrompe mai.
        """
        if AWS_MOCK:
            return self._generate_mock(pii_list)
        if self.report_provider == "bedrock":
            return self._generate_with_bedrock(pii_list) if self.bedrock_client else self._generate_mock(pii_list)
        if self.report_provider == "mock":
            return self._generate_mock(pii_list)
        # Provider LLM esterno OpenAI-compatible (gemini / deepseek / openai / ...)
        return self._generate_with_llm(pii_list)

    # --------------------------------------------------------------------------
    # HELPER CONDIVISI (prompt e parsing), riusati da tutti i provider
    # --------------------------------------------------------------------------

    def _build_prompt(self, pii_list: List[PIIEntity]) -> str:
        """Costruisce il prompt in linguaggio naturale a partire dalle PII."""
        pii_summary = "\n".join(
            [f"- {p.type}: {p.text} (confidence: {p.score})" for p in pii_list]
        )
        return (
            "Sei un esperto di cybersecurity e social engineering. Analizza le seguenti "
            "informazioni personali (PII) trovate su un profilo social pubblico e genera un report "
            "strutturato sui possibili vettori di attacco di ingegneria sociale.\n\n"
            f"PII rilevate:\n{pii_summary}\n\n"
            "Per ogni vettore di attacco, fornisci:\n"
            "1. Nome del vettore (threat_vector)\n"
            "2. Gravità: LOW, MEDIUM o HIGH (severity)\n"
            "3. Spiegazione dettagliata in italiano (explanation)\n\n"
            "Rispondi SOLO con un JSON array valido, senza markdown o testo aggiuntivo."
        )

    def _parse_threats(self, raw_text: str, pii_list: List[PIIEntity]) -> List[SocialEngineeringThreat]:
        """
        Converte la risposta JSON del modello in oggetti SocialEngineeringThreat.
        Rimuove eventuali recinti markdown (```json ... ```) che alcuni modelli
        aggiungono nonostante la richiesta. In caso di parsing fallito → mock.
        """
        text = (raw_text or "").strip()
        if text.startswith("```"):
            text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        try:
            data = json.loads(text)
            threats = [
                SocialEngineeringThreat(
                    threat_vector=item.get("threat_vector", "Minaccia Sconosciuta"),
                    severity=item.get("severity", "MEDIUM"),
                    explanation=item.get("explanation", "Spiegazione non disponibile."),
                )
                for item in data
            ]
            return threats if threats else self._generate_mock(pii_list)
        except Exception as e:
            logger.error(f"[Report] Parsing risposta LLM fallito: {e}. Fallback su mock.")
            return self._generate_mock(pii_list)

    def _generate_with_llm(self, pii_list: List[PIIEntity]) -> List[SocialEngineeringThreat]:
        """
        Genera il report tramite un'API LLM esterna OpenAI-compatible (default
        Google Gemini). Usato al posto di Bedrock quando la quota AWS non è
        disponibile; il codice Bedrock resta come alternativa via REPORT_PROVIDER.
        """
        if not self.llm_api_key:
            logger.warning("[LLM Report] Chiave API mancante (GEMINI_API_KEY/LLM_API_KEY). Fallback su mock.")
            return self._generate_mock(pii_list)

        logger.info(f"[LLM Report] Provider={self.report_provider} modello={self.llm_model}")
        try:
            from openai import OpenAI  # SDK OpenAI usato contro l'endpoint compatibile del provider
            client = OpenAI(api_key=self.llm_api_key, base_url=self.llm_base_url)
            resp = client.chat.completions.create(
                model=self.llm_model,
                messages=[{"role": "user", "content": self._build_prompt(pii_list)}],
                # 4096: i modelli "thinking" (es. Gemini 2.5 Flash) consumano parte del
                # budget in ragionamento; con 2000 il report dettagliato in italiano si
                # troncava (JSON incompleto). 4096 dà margine sufficiente.
                max_tokens=4096,
            )
            return self._parse_threats(resp.choices[0].message.content, pii_list)
        except Exception as e:
            logger.error(f"[LLM Report] Errore provider {self.report_provider}: {e}. Fallback su mock.")
            return self._generate_mock(pii_list)

    # --------------------------------------------------------------------------
    # IMPLEMENTAZIONE MOCK: Generazione Deterministica
    # --------------------------------------------------------------------------

    def _generate_mock(self, pii_list: List[PIIEntity]) -> List[SocialEngineeringThreat]:
        """
        Genera scenari di minaccia deterministici basati sui tipi di PII trovati.
        Simula l'output che Claude produrrebbe su Bedrock.
        """
        logger.info("[MOCK Bedrock] Generazione report minacce deterministico")
        threats: List[SocialEngineeringThreat] = []

        pii_types = {p.type for p in pii_list}

        if "EMAIL" in pii_types:
            threats.append(SocialEngineeringThreat(
                threat_vector="Spear-Phishing Mirato",
                severity="HIGH",
                explanation=(
                    "La presenza di un indirizzo email esposto consente ad un attaccante di inviare "
                    "messaggi di phishing altamente personalizzati. In un contesto accademico, l'attaccante "
                    "potrebbe impersonare la segreteria studenti o un docente per sottrarre credenziali. "
                    "In ambito aziendale, potrebbe imitare il dipartimento HR o IT per installare malware "
                    "tramite allegati infetti."
                )
            ))

        if "PHONE_NUMBER" in pii_types:
            threats.append(SocialEngineeringThreat(
                threat_vector="SMiShing e Vishing (Voice Phishing)",
                severity="HIGH",
                explanation=(
                    "Un numero di telefono esposto apre la porta ad attacchi di SMiShing (phishing via SMS) "
                    "e Vishing (phishing telefonico). L'attaccante puo inviare SMS fraudolenti imitando "
                    "banche, corrieri o servizi di autenticazione. Un attacco Vishing particolarmente "
                    "sofisticato potrebbe sfruttare tecniche di AI voice cloning per replicare la voce "
                    "di un collega o familiare."
                )
            ))

        if "DATE_OF_BIRTH" in pii_types:
            threats.append(SocialEngineeringThreat(
                threat_vector="Furto d'Identità e Account Takeover",
                severity="HIGH",
                explanation=(
                    "La data di nascita è uno dei dati più utilizzati per il recupero password e la verifica "
                    "dell'identità. Combinata con il nome completo, consente il furto d'identità digitale, "
                    "l'apertura fraudolenta di account bancari e l'accesso a servizi che usano domande "
                    "di sicurezza basate su dati anagrafici."
                )
            ))

        if "LOCATION" in pii_types:
            threats.append(SocialEngineeringThreat(
                threat_vector="Profilazione Geografica e Stalking Digitale",
                severity="MEDIUM",
                explanation=(
                    "I riferimenti a luoghi frequentati abitualmente permettono di costruire una mappa delle "
                    "routine quotidiane dell'utente. Queste informazioni possono facilitare attacchi di "
                    "social engineering basati sul contesto geografico, come la consegna di pacchi fraudolenti "
                    "o tentativi di impersonificazione che fanno leva sulla conoscenza del territorio."
                )
            ))

        if "ORGANIZATION" in pii_types:
            threats.append(SocialEngineeringThreat(
                threat_vector="Impersonificazione Istituzionale",
                severity="MEDIUM",
                explanation=(
                    "Il nome dell'organizzazione di appartenenza consente attacchi di impersonificazione "
                    "estremamente credibili. L'attaccante può fingersi un membro dello stesso ente (collega, "
                    "docente, responsabile HR) per instaurare fiducia ed estorcere informazioni riservate "
                    "o credenziali di accesso a sistemi interni."
                )
            ))

        if "URL" in pii_types:
            threats.append(SocialEngineeringThreat(
                threat_vector="Ricognizione OSINT Ampliata",
                severity="LOW",
                explanation=(
                    "I link personali esposti (blog, portfolio, altri profili social) ampliano la superficie "
                    "di attacco consentendo all'avversario di raccogliere ulteriori informazioni tramite "
                    "tecniche OSINT (Open Source Intelligence), correlando dati tra piattaforme diverse "
                    "per costruire un profilo completo della vittima."
                )
            ))

        if "USERNAME" in pii_types:
            threats.append(SocialEngineeringThreat(
                threat_vector="Correlazione Cross-Platform",
                severity="LOW",
                explanation=(
                    "Gli username pubblici consentono di cercare la stessa persona su altre piattaforme "
                    "tramite strumenti OSINT automatizzati (es. Sherlock, Maigret). Questo permette "
                    "di aggregare informazioni disperse su piu profili e costruire un dossier completo."
                )
            ))

        # Default sicuro se nessuna PII trovata
        if not threats:
            threats.append(SocialEngineeringThreat(
                threat_vector="Valutazione Sicurezza Profilo",
                severity="LOW",
                explanation=(
                    "Il testo analizzato non ha rivelato dati personali identificabili in chiaro. "
                    "L'esposizione pubblica è considerata minima. Si raccomanda comunque di effettuare "
                    "verifiche periodiche sulla propria digital footprint."
                )
            ))

        return threats

    # --------------------------------------------------------------------------
    # IMPLEMENTAZIONE REALE: Amazon Bedrock (Claude)
    # --------------------------------------------------------------------------

    def _generate_with_bedrock(self, pii_list: List[PIIEntity]) -> List[SocialEngineeringThreat]:
        """
        Invoca Claude su Amazon Bedrock per generare l'analisi delle minacce.
        """
        logger.info("[AWS Bedrock] Invocazione Claude per report minacce")

        # NOTA: NIENTE "temperature" qui. I modelli Claude recenti (Opus 4.8/4.7,
        # Sonnet 5) accettano solo adaptive thinking e rifiutano temperature/top_p/
        # budget_tokens con un errore 400 ValidationException. Su Haiku 3 era
        # ammesso, ma toglierlo funziona su entrambi.
        prompt_body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 2000,
            "messages": [{"role": "user", "content": self._build_prompt(pii_list)}],
        }

        try:
            # Model id configurabile via .env. Default: Sonnet 4.5 tramite inference
            # profile cross-region "us." — i modelli Claude recenti su Bedrock
            # richiedono l'inference profile (non l'id "anthropic.*" grezzo) per
            # l'invocazione on-demand in us-east-1. Per usare Haiku metti
            # BEDROCK_MODEL_ID=anthropic.claude-3-haiku-20240307-v1:0 nel .env.
            model_id = os.getenv("BEDROCK_MODEL_ID", "us.anthropic.claude-sonnet-4-5-20250929-v1:0")
            response = self.bedrock_client.invoke_model(
                modelId=model_id,
                contentType="application/json",
                accept="application/json",
                body=json.dumps(prompt_body)
            )

            response_body = json.loads(response["body"].read())
            content_text = response_body.get("content", [{}])[0].get("text", "[]")
            return self._parse_threats(content_text, pii_list)

        except Exception as e:
            logger.error(f"Errore Bedrock Claude: {e}. Fallback su mock.")
            return self._generate_mock(pii_list)
