# ==============================================================================
# CONFTEST - Configurazione condivisa per i test pytest (SDCC)
# ==============================================================================
# Scopo di questo file:
#   1. Aggiungere la root del backend a sys.path, così i test importano
#      "services/" e "models/" sia lanciando pytest da backend/ sia da repo root.
#   2. Forzare AWS_MOCK=true PRIMA che i servizi vengano importati, così i test
#      girano interamente in locale senza inizializzare alcun client boto3 reale.
# ==============================================================================

import os
import sys

# 1. Rendi importabile la root del backend (la cartella che contiene services/ e models/)
_BACKEND_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BACKEND_ROOT not in sys.path:
    sys.path.insert(0, _BACKEND_ROOT)

# 2. Modalità mock garantita per i test (setdefault: non sovrascrive se già impostata)
os.environ.setdefault("AWS_MOCK", "true")
