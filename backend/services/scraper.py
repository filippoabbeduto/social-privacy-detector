# ==============================================================================
# SCRAPER SERVICE - Raccolta Dati da Profili Social (SDCC)
# Percorso: backend/services/scraper.py
#
# Integra Apify Scraping-as-a-Service per l'estrazione dati da profili
# social pubblici. Apify gestisce internamente la rotazione degli IP,
# i proxy residenziali e la simulazione browser (Playwright/Puppeteer).
#
# Piattaforme supportate:
#   - Instagram (bio, post, fullName, externalUrl)
#   - TikTok    (bio, nickname, post descriptions)
#   - Twitter/X (bio, tweets, displayName, location)
#   - Facebook  (bio, about, name)
#   - LinkedIn  (headline, summary, skills, location)
#
# In mock mode restituisce biografie simulate per la demo offline.
# ==============================================================================

import os
import re
import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger("social-privacy-backend")

AWS_MOCK = os.getenv("AWS_MOCK", "true").lower() == "true"


# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURAZIONE ACTOR APIFY PER PIATTAFORMA
# ──────────────────────────────────────────────────────────────────────────────

# Ogni piattaforma è mappata a:
#   - actor_id:      identificativo dell'Actor nel marketplace Apify
#   - build_input:   funzione che costruisce il payload JSON per l'Actor
#   - extract_text:  funzione che estrae il testo dai risultati dell'Actor

PLATFORM_CONFIGS: Dict[str, Dict[str, Any]] = {}


def _register_platform(
    name: str,
    url_patterns: List[str],
    actor_id: str,
    build_input,
    extract_text,
):
    """Registra la configurazione di una piattaforma social."""
    PLATFORM_CONFIGS[name] = {
        "url_patterns": url_patterns,
        "actor_id": actor_id,
        "build_input": build_input,
        "extract_text": extract_text,
    }


# ── INSTAGRAM ────────────────────────────────────────────────────────────────

def _instagram_input(url: str) -> dict:
    # L'Actor apify~instagram-profile-scraper richiede la lista di "usernames",
    # NON gli URL diretti (con directUrls dava 400 "Field input.usernames is
    # required"). Estraiamo lo username dall'URL del profilo.
    match = re.search(r'instagram\.com/([a-zA-Z0-9_.]+)', url)
    username = match.group(1) if match else url
    return {"usernames": [username]}


def _instagram_extract(items: list) -> str:
    texts = []
    for item in items:
        if item.get("biography"):
            texts.append(item["biography"])
        if item.get("fullName"):
            texts.append(f"Nome completo: {item['fullName']}")
        if item.get("username"):
            texts.append(f"@{item['username']}")
        if item.get("externalUrl"):
            texts.append(item["externalUrl"])
        if item.get("businessEmail"):
            texts.append(item["businessEmail"])
        if item.get("businessPhoneNumber"):
            texts.append(item["businessPhoneNumber"])
        if item.get("businessCategoryName"):
            texts.append(f"Categoria: {item['businessCategoryName']}")
        # Post recenti (caption)
        if item.get("caption"):
            texts.append(item["caption"])
        if item.get("latestPosts"):
            for post in item["latestPosts"][:5]:
                if post.get("caption"):
                    texts.append(post["caption"])
    return " | ".join(texts)


_register_platform(
    name="instagram",
    url_patterns=["instagram.com"],
    actor_id="apify~instagram-profile-scraper",
    build_input=_instagram_input,
    extract_text=_instagram_extract,
)


# ── TIKTOK ───────────────────────────────────────────────────────────────────

def _tiktok_input(url: str) -> dict:
    # Estrae lo username dall'URL per l'Actor TikTok
    match = re.search(r'tiktok\.com/@([a-zA-Z0-9_.]+)', url)
    username = match.group(1) if match else url
    return {"profiles": [username], "resultsPerPage": 10}


def _tiktok_extract(items: list) -> str:
    texts = []
    for item in items:
        if item.get("authorMeta"):
            meta = item["authorMeta"]
            if meta.get("name"):
                texts.append(f"Nome: {meta['name']}")
            if meta.get("nickName"):
                texts.append(f"Nickname: {meta['nickName']}")
            if meta.get("signature"):
                texts.append(meta["signature"])
        # Campi top-level (profili senza authorMeta)
        if item.get("signature"):
            texts.append(item["signature"])
        if item.get("nickname"):
            texts.append(f"Nickname: {item['nickname']}")
        # Descrizioni dei video
        if item.get("text"):
            texts.append(item["text"])
        if item.get("desc"):
            texts.append(item["desc"])
    return " | ".join(texts)


_register_platform(
    name="tiktok",
    url_patterns=["tiktok.com"],
    actor_id="clockworks~tiktok-scraper",
    build_input=_tiktok_input,
    extract_text=_tiktok_extract,
)


# ── TWITTER / X ──────────────────────────────────────────────────────────────

def _twitter_input(url: str) -> dict:
    # Estrae lo username dall'URL
    match = re.search(r'(?:twitter|x)\.com/([a-zA-Z0-9_]+)', url)
    username = match.group(1) if match else url
    return {
        "twitterHandles": [username],
        "maxTweets": 10,
        "addUserInfo": True,
    }


def _twitter_extract(items: list) -> str:
    texts = []
    for item in items:
        # Info profilo utente
        if item.get("author") and isinstance(item["author"], dict):
            author = item["author"]
            if author.get("name"):
                texts.append(f"Nome: {author['name']}")
            if author.get("description"):
                texts.append(author["description"])
            if author.get("location"):
                texts.append(f"Location: {author['location']}")
            if author.get("url"):
                texts.append(author["url"])
        # Campi top-level (formato alternativo)
        if item.get("description"):
            texts.append(item["description"])
        if item.get("displayName"):
            texts.append(f"Nome: {item['displayName']}")
        if item.get("location"):
            texts.append(f"Location: {item['location']}")
        # Testi dei tweet
        if item.get("full_text"):
            texts.append(item["full_text"])
        if item.get("text"):
            texts.append(item["text"])
    return " | ".join(texts)


_register_platform(
    name="twitter",
    url_patterns=["twitter.com", "x.com"],
    actor_id="apidojo~tweet-scraper",
    build_input=_twitter_input,
    extract_text=_twitter_extract,
)


# ── FACEBOOK ─────────────────────────────────────────────────────────────────

def _facebook_input(url: str) -> dict:
    return {"profileUrls": [url], "maxResults": 5}


def _facebook_extract(items: list) -> str:
    texts = []
    for item in items:
        if item.get("name"):
            texts.append(f"Nome: {item['name']}")
        if item.get("bio"):
            texts.append(item["bio"])
        if item.get("about"):
            texts.append(item["about"])
        if item.get("intro"):
            texts.append(item["intro"])
        if item.get("work"):
            texts.append(f"Lavoro: {item['work']}")
        if item.get("education"):
            texts.append(f"Studi: {item['education']}")
        if item.get("currentCity"):
            texts.append(f"Città: {item['currentCity']}")
        if item.get("hometown"):
            texts.append(f"Città natale: {item['hometown']}")
        if item.get("relationship"):
            texts.append(f"Relazione: {item['relationship']}")
        if item.get("email"):
            texts.append(item["email"])
        if item.get("phone"):
            texts.append(item["phone"])
        if item.get("website"):
            texts.append(item["website"])
    return " | ".join(texts)


_register_platform(
    name="facebook",
    url_patterns=["facebook.com", "fb.com"],
    actor_id="apivault_labs~facebook-profile-scraper",
    build_input=_facebook_input,
    extract_text=_facebook_extract,
)


# ── LINKEDIN ─────────────────────────────────────────────────────────────────

def _linkedin_input(url: str) -> dict:
    return {"profileUrls": [url]}


def _linkedin_extract(items: list) -> str:
    texts = []
    for item in items:
        if item.get("fullName"):
            texts.append(f"Nome: {item['fullName']}")
        if item.get("headline"):
            texts.append(item["headline"])
        if item.get("summary"):
            texts.append(item["summary"])
        if item.get("location"):
            texts.append(f"Location: {item['location']}")
        if item.get("email"):
            texts.append(item["email"])
        # Esperienze lavorative
        if item.get("experience"):
            for exp in item["experience"][:3]:
                parts = []
                if exp.get("title"):
                    parts.append(exp["title"])
                if exp.get("companyName"):
                    parts.append(f"presso {exp['companyName']}")
                if exp.get("location"):
                    parts.append(f"a {exp['location']}")
                if parts:
                    texts.append("Esperienza: " + " ".join(parts))
        # Istruzione
        if item.get("education"):
            for edu in item["education"][:2]:
                parts = []
                if edu.get("schoolName"):
                    parts.append(edu["schoolName"])
                if edu.get("degreeName"):
                    parts.append(edu["degreeName"])
                if parts:
                    texts.append("Studi: " + " - ".join(parts))
        # Skills
        if item.get("skills"):
            skill_names = [s.get("name", s) if isinstance(s, dict) else str(s)
                           for s in item["skills"][:5]]
            texts.append(f"Competenze: {', '.join(skill_names)}")
    return " | ".join(texts)


_register_platform(
    name="linkedin",
    url_patterns=["linkedin.com"],
    actor_id="curious_coder~linkedin-profile-scraper",
    build_input=_linkedin_input,
    extract_text=_linkedin_extract,
)


# ──────────────────────────────────────────────────────────────────────────────
# SERVIZIO SCRAPER
# ──────────────────────────────────────────────────────────────────────────────

class ScraperService:
    """
    Servizio di raccolta dati dai profili social pubblici.

    Modalità MOCK: restituisce biografie pre-confezionate per diversi scenari di test.
    Modalità PRODUZIONE: invoca Apify REST API per scraping reale multi-piattaforma.

    Piattaforme supportate: Instagram, TikTok, Twitter/X, Facebook, LinkedIn.
    """

    SUPPORTED_PLATFORMS = list(PLATFORM_CONFIGS.keys())

    def __init__(self):
        self.apify_token = os.getenv("APIFY_API_TOKEN", "")
        self.apify_base_url = "https://api.apify.com/v2"

    # ──────────────────────────────────────────────────────────────────────────
    # METODO PRINCIPALE
    # ──────────────────────────────────────────────────────────────────────────

    def scrape_profile(self, social_url: str) -> Optional[str]:
        """
        Recupera il contenuto testuale pubblico di un profilo social.
        Restituisce il testo combinato della bio + post recenti.
        """
        if AWS_MOCK or not self.apify_token or self.apify_token == "mock_apify_token":
            return self._scrape_mock(social_url)
        return self._scrape_apify(social_url)

    # ──────────────────────────────────────────────────────────────────────────
    # RILEVAMENTO PIATTAFORMA
    # ──────────────────────────────────────────────────────────────────────────

    def _detect_platform(self, social_url: str) -> Optional[str]:
        """
        Identifica la piattaforma social dall'URL fornito.
        Restituisce il nome della piattaforma o None se non riconosciuta.
        """
        url_lower = social_url.lower()
        for platform_name, config in PLATFORM_CONFIGS.items():
            for pattern in config["url_patterns"]:
                if pattern in url_lower:
                    return platform_name
        return None

    # ──────────────────────────────────────────────────────────────────────────
    # IMPLEMENTAZIONE MOCK: Biografie Simulate
    # ──────────────────────────────────────────────────────────────────────────

    def _scrape_mock(self, social_url: str) -> str:
        """
        Restituisce biografie pre-confezionate per diversi scenari di test.
        I dati simulano il tipo di contenuto che Apify estraerebbe da un profilo reale.
        """
        logger.info(f"[MOCK Scraper] Simulazione scraping per: {social_url}")
        url_lower = social_url.lower()

        if "filippo" in url_lower or "student" in url_lower:
            # Bio con codice fiscale aggiunto per dimostrare il nuovo rilevamento
            # FISCAL_CODE (codice identificativo) introdotto in pii_detector.py.
            return (
                "Studente di Ingegneria Informatica alla Sapienza di Roma. "
                "Nato il 15 marzo 1999 a Cosenza, Calabria. "
                "Contattami a filippo.abb@sapienza.it o cellulare: +39 345-6789123. "
                "Codice fiscale per la segreteria: ABBFPP99C15D086X. "
                "Frequento l'aula studio al Dipartimento DIMES dell'Unical. "
                "Visita il mio portfolio: https://filippo-dev.github.io "
                "Follow me @filippo_dev su tutti i social!"
            )
        elif "rossi" in url_lower or "work" in url_lower:
            return (
                "Cloud Architect presso Reply a Milano. "
                "Gestisco infrastrutture AWS e progetto soluzioni serverless. "
                "Contatto professionale: mario.rossi@reply.it. "
                "LinkedIn: https://linkedin.com/in/mario-rossi-cloud "
                "Certificato AWS Solutions Architect Professional."
            )
        elif "cyber" in url_lower or "secure" in url_lower:
            return (
                "Appassionato di OSINT e sicurezza informatica. "
                "Ricorda di limitare l'esposizione di informazioni identificabili "
                "sui tuoi canali pubblici! Privacy-first mindset."
            )
        elif "tiktok" in url_lower:
            return (
                "Nickname: Marco_Vibes99 | Studente UniCal a Cosenza. "
                "Nato il 22/06/2000. Seguitemi anche su IG: @marco_vibes "
                "Balletto in piazza Duomo a Milano con gli amici! "
                "Giornata al mare a Tropea, sempre Tropea, amo Tropea! "
                "Contatto per collab: marco.vibes@gmail.com"
            )
        elif "linkedin" in url_lower:
            return (
                "Nome: Andrea Bianchi | Senior Cloud Engineer presso Accenture. "
                "Location: Roma, Italia. Esperienza: Cloud Architect presso Deloitte a Milano. "
                "Studi: Università della Calabria - Laurea Magistrale in Ingegneria Informatica. "
                "Competenze: AWS, Terraform, Kubernetes, Docker, Python. "
                "Contatto: andrea.bianchi@accenture.com | +39 347-9876543"
            )
        elif "facebook" in url_lower or "fb.com" in url_lower:
            return (
                "Nome: Giulia Ferretti | Città: Napoli, Italia. "
                "Città natale: Cosenza. Studi: Università Federico II. "
                "Lavoro: Marketing Manager presso Enel. "
                "Compleanno: 10 agosto 1995. "
                "giulia.ferretti@enel.com | https://giuliaferretti.it"
            )
        elif "twitter" in url_lower or "x.com" in url_lower:
            return (
                "Nome: Luca Dev | Bio: Full-stack developer @Reply Milano. "
                "Location: Milano, Italia. "
                "Oggi workshop su Kubernetes al Politecnico di Milano! "
                "Per collaborazioni: luca.dev@reply.it "
                "Il mio blog: https://lucadev.tech"
            )
        else:
            return (
                "Profilo generico. Nessun contatto evidente mostrato nella biografia "
                "o nei post pubblici di questo utente."
            )

    # ──────────────────────────────────────────────────────────────────────────
    # IMPLEMENTAZIONE REALE: Apify REST API (Multi-Piattaforma)
    # ──────────────────────────────────────────────────────────────────────────

    def _scrape_apify(self, social_url: str) -> Optional[str]:
        """
        Invoca un Actor Apify per estrarre dati da un profilo social reale.
        L'Actor è selezionato automaticamente in base alla piattaforma rilevata dall'URL.
        Usa l'endpoint sincrono run-sync-get-dataset-items con timeout di 180s.
        In caso di errore o piattaforma non supportata, fallback su mock.
        """
        platform = self._detect_platform(social_url)

        if not platform:
            logger.warning(
                f"[Apify] Piattaforma non riconosciuta per URL: {social_url}. "
                f"Piattaforme supportate: {', '.join(self.SUPPORTED_PLATFORMS)}"
            )
            return self._scrape_mock(social_url)

        config = PLATFORM_CONFIGS[platform]
        actor_id = config["actor_id"]
        logger.info(f"[Apify] Piattaforma rilevata: {platform}. Actor: {actor_id}")

        try:
            import requests

            # Esegui l'Actor in modo sincrono e ottieni direttamente i risultati
            run_url = f"{self.apify_base_url}/acts/{actor_id}/run-sync-get-dataset-items"
            payload = config["build_input"](social_url)
            headers = {"Content-Type": "application/json"}
            params = {"token": self.apify_token}

            logger.info(f"[Apify] Invocazione sincrona: {run_url}")
            logger.info(f"[Apify] Payload: {payload}")

            response = requests.post(
                run_url,
                json=payload,
                headers=headers,
                params=params,
                timeout=180,  # l'API sincrona di Apify ha un limite di 300s
            )
            response.raise_for_status()

            items = response.json()
            if not items:
                logger.warning(f"[Apify] Nessun risultato per {social_url}. Fallback su mock.")
                return self._scrape_mock(social_url)

            # Estrai il testo con il parser specifico della piattaforma
            combined = config["extract_text"](items)

            if not combined.strip():
                logger.warning(f"[Apify] Testo estratto vuoto per {social_url}. Fallback su mock.")
                return self._scrape_mock(social_url)

            logger.info(
                f"[Apify] Scraping completato per {platform}. "
                f"Items: {len(items)}, Lunghezza testo: {len(combined)} caratteri"
            )
            return combined

        except Exception as e:
            logger.error(f"[Apify] Errore scraping {platform}: {e}. Fallback su mock.")
            return self._scrape_mock(social_url)
