# ==============================================================================
# VISUAL EXPOSURE - Classificazione deterministica delle etichette Rekognition
# in categorie sensibili (MINORI, DOCUMENTI, GEO).
# ==============================================================================
# Dà un ruolo di dominio alle etichette DetectLabels (già ottenute): individua le
# esposizioni visive sensibili e produce (1) un elenco categorizzato per la UI/response
# e (2) una nota deterministica per il report.
#
# Due sorgenti, perché una sola non basta:
#   - le ETICHETTE di DetectLabels (classificazione di oggetti/scene) per DOCUMENTI e GEO,
#     e per i MINORI quando l'infanzia è un tratto visivo evidente della scena;
#   - la stima dell'ETÀ di DetectFaces (minors_from_faces) per i MINORI che le etichette
#     non vedono. Misurato su un caso reale: su una foto con un minore di 9-15 anni,
#     DetectLabels restituisce "Adult" al 98.9% e non emette "Child" a NESSUNA confidenza
#     — classifica oggetti e scene, non stima l'età. DetectFaces la stima e lo prende.
#     Sull'ammissibilità (analisi ≠ riconoscimento) vedi detect_face_age_ranges.
# ==============================================================================

import re
from typing import List, Dict

# Keyword per categoria (frasi, lowercase). L'ordine delle categorie è la priorità di
# assegnazione: MINORI batte DOCUMENTI batte GEO se un nome combaciasse con più set.
SENSITIVE_CATEGORIES: Dict[str, List[str]] = {
    "MINORI": ["child", "children", "baby", "kid", "toddler", "boy", "girl", "infant", "newborn"],
    "DOCUMENTI": ["passport", "document", "id card", "identity", "driving license",
                  "driver license", "credit card", "debit card", "boarding pass",
                  "diploma", "certificate"],
    # GEO tenuto stretto: solo etichette che rivelano DOVE. "beach"/"mountain" generici
    # restano contesto (non sensibili).
    "GEO": ["license plate", "targa", "street sign", "road sign", "landmark", "monument", "map"],
}

# Nome leggibile della categoria per la nota del report.
_CATEGORY_NOUN = {"MINORI": "un minore", "DOCUMENTI": "un documento", "GEO": "la posizione"}

# Maggiore età: sotto questa soglia il volto è di un minore.
MINOR_AGE = 18


def minors_from_faces(age_ranges: List[dict]) -> List[dict]:
    """Segnala i volti di minori dalla stima d'età di DetectFaces.

    age_ranges: [{"low": int, "high": int, "confidence": float}] (vedi
    PIIDetectorService.detect_face_age_ranges). Restituisce voci nella stessa forma
    delle etichette sensibili, così si fondono con quelle di DetectLabels.

    Rekognition restituisce un INTERVALLO, non un'età puntuale. Si segnala se il
    limite INFERIORE è sotto i 18 — cioè appena la stima ammette che possa essere un
    minore — perché qui la priorità è il recall: un falso allarme costa un'occhiata,
    un minore non segnalato è il fallimento della funzione. L'etichetta riporta
    sempre l'intervallo stimato, così l'utente giudica da sé, e distingue il caso
    certo (tutto l'intervallo sotto i 18, es. 9-15) da quello incerto (a cavallo
    della soglia, es. 15-23).
    """
    out: List[dict] = []
    for face in age_ranges or []:
        low, high = face.get("low"), face.get("high")
        if low is None or high is None or low >= MINOR_AGE:
            continue
        certo = high < MINOR_AGE
        out.append({
            "category": "MINORI",
            "label": (f"Volto con età stimata {low}-{high} anni"
                      if certo else
                      f"Volto con età stimata {low}-{high} anni (possibile minore)"),
            "confidence": face.get("confidence", 0.0),
        })
    return out


def collapse_sensitive(from_labels: List[dict], from_faces: List[dict]) -> List[dict]:
    """Una sola voce per categoria: le prove multiple sono ridondanza per chi legge.

    Su una foto reale uscivano SEI avvisi per TRE categorie — «Minore: Child»,
    «Minore: Girl», «Minore: volto 4-8 anni», «Documento: Document», «Documento:
    Driving License», «Geolocalizzazione: Landmark» — che dicono la stessa cosa più
    volte. All'utente interessa *che* c'è un minore, non con quali etichette il
    servizio di visione ci sia arrivato.

    Per i MINORI vince la stima dell'ETÀ quando c'è: è più precisa («4-8 anni» invece
    di «Child») e più affidabile — su un'altra foto reale con un minore le etichette
    dicevano «Adult» al 98.9% e mai «Child». Le etichette restano però la rete di
    sicurezza per i casi senza volto stimabile (minore di spalle, disegno), quindi NON
    si eliminano: si preferisce solo la stima quando è disponibile.

    Per le altre categorie si tiene la prova più confidente e le altre etichette
    confluiscono nella stessa voce, così non si perde informazione (es. «Driving
    License» è più specifico di «Document» e non va buttato).
    """
    out: List[dict] = []
    for cat in SENSITIVE_CATEGORIES:  # ordine = priorità dichiarata
        if cat == "MINORI" and from_faces:
            best = dict(from_faces[0])
            if len(from_faces) > 1:
                best["label"] += f" (+{len(from_faces) - 1} altri volti di minore)"
            out.append(best)
            continue
        group = sorted((e for e in from_labels if e["category"] == cat),
                       key=lambda e: -float(e.get("confidence") or 0))
        if not group:
            continue
        primary = dict(group[0])
        others = [e["label"] for e in group[1:]]
        if others:
            primary["label"] = primary["label"] + ", " + ", ".join(others)
        out.append(primary)
    return out


def _matches(low: str, kw: str) -> bool:
    """Match per PAROLA/FRASE intera (con confini di parola), non sottostringa: evita
    che 'boy' matchi 'cowboy', 'map' matchi 'roadmap', 'document' matchi 'documentary'."""
    return re.search(r"\b" + re.escape(kw) + r"\b", low) is not None


def _category_of(name: str) -> str:
    low = name.lower()
    for category, keywords in SENSITIVE_CATEGORIES.items():
        if any(_matches(low, kw) for kw in keywords):
            return category
    return ""


def classify_sensitive_labels(labels: List[dict]) -> List[dict]:
    """Restituisce le sole etichette sensibili, con la loro categoria. Ordine di input
    preservato. Etichette non sensibili → ignorate."""
    out: List[dict] = []
    for lab in labels or []:
        name = str(lab.get("name", "")).strip()
        if not name:
            continue
        category = _category_of(name)
        if category:
            out.append({
                "category": category,
                "label": name,
                "confidence": lab.get("confidence", 0.0),
            })
    return out


def sensitive_note(sensitive: List[dict]) -> str:
    """Frase italiana deterministica dalle categorie presenti. '' se vuoto."""
    if not sensitive:
        return ""
    # Categorie presenti, nell'ordine di priorità di SENSITIVE_CATEGORIES.
    present = [c for c in SENSITIVE_CATEGORIES if any(s["category"] == c for s in sensitive)]
    nouns = [_CATEGORY_NOUN[c] for c in present]
    if len(nouns) == 1:
        soggetto = nouns[0]
    else:
        soggetto = ", ".join(nouns[:-1]) + " e " + nouns[-1]
    return f"Attenzione: le immagini espongono {soggetto}."
