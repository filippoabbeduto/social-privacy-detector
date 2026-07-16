#!/usr/bin/env bash
# ==============================================================================
# Rigenera i grafici CloudWatch inclusi nella relazione (img/cw-*.png).
#
# DA ESEGUIRE PRIMA DELLA CONSEGNA: i PNG sono istantanee di dati reali e
# invecchiano a ogni nuova analisi.
#
#   ./genera-grafici-cloudwatch.sh
#
# Richiede: AWS CLI configurata (aws sts get-caller-identity deve rispondere).
#
# NOTE DI FORMA (imparate a caccia di bug, non ripetere gli errori):
#   - "view":"bar" in CloudWatch NON e' un istogramma temporale: aggrega tutta la
#     finestra in UNA barra. Per i conteggi radi serve "timeSeries" con period=86400.
#   - period piccolo (300) su dati radi produce zigzag illeggibili: quasi ogni
#     bucket e' vuoto e CloudWatch collega punti lontanissimi.
#   - PipelineLatencyMs va diviso per 1000 con un'espressione: nessuno legge "121.79K ms".
#   - AnalysisFailed non pubblica quando non ci sono errori: senza FILL(m,0) il
#     widget mostra "--" invece di una riga a zero.
#   - Nelle annotazioni CloudWatch appende gia' il valore: label "Soglia ALTO",
#     non "Soglia ALTO (70)", altrimenti esce "Soglia ALTO (70) (70)".
# ==============================================================================
set -euo pipefail

REGION="us-east-1"
NS="SocialPrivacyDetector"
DIR="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Finestra mostrata nei grafici. Allargare se le analisi sono piu' diradate.
RANGE="-P5D"

render() {  # render <file-json> <png-di-destinazione>
  aws cloudwatch get-metric-widget-image \
    --metric-widget "file://$1" --region "$REGION" \
    --query 'MetricWidgetImage' --output text | base64 -d > "$2"
  echo "  $(basename "$2") -> $(stat -c%s "$2") byte"
}

cat > "$TMP/analisi.json" <<EOF
{"metrics":[
 [{"expression":"FILL(m3,0)","label":"Fallite","id":"e3","color":"#d62728","region":"$REGION"}],
 ["$NS","AnalysisStarted",{"stat":"Sum","label":"Avviate","color":"#7f7f7f"}],
 ["$NS","AnalysisCompleted",{"stat":"Sum","label":"Completate","color":"#2ca02c"}],
 ["$NS","AnalysisFailed",{"id":"m3","stat":"Sum","visible":false}]],
 "view":"timeSeries","stacked":false,"region":"$REGION","period":86400,
 "width":1100,"height":360,"start":"$RANGE","end":"P0D","timezone":"+0200",
 "title":"Analisi al giorno: avviate, completate, fallite",
 "yAxis":{"left":{"min":0,"label":"Analisi","showUnits":false}}}
EOF

cat > "$TMP/latenza.json" <<EOF
{"metrics":[
 [{"expression":"m1/1000","label":"Latenza media","id":"e1","color":"#1f77b4","region":"$REGION"}],
 [{"expression":"m2/1000","label":"p95","id":"e2","color":"#ff7f0e","region":"$REGION"}],
 ["$NS","PipelineLatencyMs",{"id":"m1","stat":"Average","visible":false}],
 ["...",{"id":"m2","stat":"p95","visible":false}]],
 "view":"timeSeries","region":"$REGION","period":21600,
 "width":1100,"height":360,"start":"$RANGE","end":"P0D","timezone":"+0200",
 "title":"Latenza della pipeline (secondi): scraping + estrazione PII + rischio + report",
 "yAxis":{"left":{"min":0,"label":"secondi","showUnits":false}}}
EOF

cat > "$TMP/score.json" <<EOF
{"metrics":[
 ["$NS","RiskScore",{"stat":"Average","label":"Score medio","color":"#1f77b4"}],
 ["...",{"stat":"Maximum","label":"Profilo piu esposto","color":"#d62728"}],
 ["...",{"stat":"Minimum","label":"Profilo meno esposto","color":"#2ca02c"}]],
 "view":"timeSeries","region":"$REGION","period":86400,
 "width":1100,"height":360,"start":"$RANGE","end":"P0D","timezone":"+0200",
 "title":"Score di rischio dei profili analizzati (media, max e min giornalieri)",
 "yAxis":{"left":{"min":0,"max":100,"label":"Score","showUnits":false}},
 "annotations":{"horizontal":[
   {"label":"Soglia ALTO","value":70,"color":"#d62728","fill":"above"},
   {"label":"Soglia MEDIO","value":35,"color":"#ff7f0e"}]}}
EOF

echo "Rigenerazione grafici CloudWatch (finestra $RANGE):"
render "$TMP/analisi.json" "$DIR/cw-analisi.png"
render "$TMP/latenza.json" "$DIR/cw-latenza.png"
render "$TMP/score.json"   "$DIR/cw-score.png"
echo
echo "Fatto. Ricompilare la relazione e RILEGGERE i commenti nella sottosezione"
echo "'La dashboard di osservabilita' in esercizio': citano numeri e fenomeni"
echo "specifici (l'analisi persa del 14/07, la latenza che cresce) che potrebbero"
echo "non valere piu' sui dati nuovi."
