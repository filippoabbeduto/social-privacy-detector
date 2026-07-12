#!/usr/bin/env bash
# ==============================================================================
# cleanup.sh — Pulizia di fine progetto (Social Privacy Detector, SDCC)
#
# QUANDO: DOPO L'ESAME (fine luglio 2026), NON alla consegna del 18 luglio.
# L'app (EC2 + Elastic IP + stack SQS/Lambda) deve restare LIVE e raggiungibile
# fino all'esame per la demo. Questo script smonta/spegne tutto: lanciarlo solo
# quando l'infrastruttura non serve più.
#
# Ogni passo chiede conferma (y/N); i passi IRREVERSIBILI (rilascio Elastic IP,
# cancellazione stack) sono segnalati.
# Richiede: aws CLI v2 configurata (region us-east-1, utente con permessi).
#
# Uso:  bash infra/cleanup.sh
# ==============================================================================
set -uo pipefail   # NO -e: un passo che fallisce non deve bloccare i successivi

REGION="us-east-1"
ACCOUNT="569103037849"
IAM_USER="filippo-dev"
EC2_ID="i-0e539aa835d3e1935"
EIP="174.129.183.58"
STACK="spd-distributed"

confirm() { read -r -p "$1 [y/N] " r; [[ "$r" == "y" || "$r" == "Y" ]]; }
hr() { printf '\n=== %s ===\n' "$1"; }

# ------------------------------------------------------------------------------
# 1. Togli i permessi admin temporanei da filippo-dev (least privilege)
#    Erano stati aggiunti solo per creare ruolo OIDC + stack CloudFormation.
# ------------------------------------------------------------------------------
hr "1. Permessi admin temporanei su $IAM_USER"
echo "Policy managed attualmente attaccate a $IAM_USER:"
aws iam list-attached-user-policies --user-name "$IAM_USER" \
  --query 'AttachedPolicies[].PolicyName' --output table 2>&1
if confirm "Staccare AdministratorAccess da $IAM_USER?"; then
  aws iam detach-user-policy --user-name "$IAM_USER" \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>&1 \
    && echo "AdministratorAccess staccata." \
    || echo "Non attaccata o già rimossa (controlla la lista sopra per eventuali policy custom da togliere a mano)."
fi

# ------------------------------------------------------------------------------
# 2. Spegni l'istanza EC2 (REVERSIBILE: si riaccende con start-instances)
# ------------------------------------------------------------------------------
hr "2. Spegnimento EC2 $EC2_ID"
if confirm "Spegnere l'istanza EC2? (reversibile)"; then
  aws ec2 stop-instances --instance-ids "$EC2_ID" --region "$REGION" \
    --query 'StoppingInstances[].CurrentState.Name' --output text 2>&1
fi

# ------------------------------------------------------------------------------
# 3. Rilascio Elastic IP (IRREVERSIBILE: perdi l'indirizzo 174.129.183.58)
#    Farlo solo se NON ti serve più l'IP stabile.
# ------------------------------------------------------------------------------
hr "3. Rilascio Elastic IP $EIP  [IRREVERSIBILE]"
if confirm "Rilasciare l'Elastic IP $EIP? Perderai l'indirizzo per sempre."; then
  ALLOC=$(aws ec2 describe-addresses --public-ips "$EIP" --region "$REGION" \
            --query 'Addresses[0].AllocationId' --output text 2>/dev/null)
  if [[ -n "$ALLOC" && "$ALLOC" != "None" ]]; then
    ASSOC=$(aws ec2 describe-addresses --allocation-ids "$ALLOC" --region "$REGION" \
              --query 'Addresses[0].AssociationId' --output text 2>/dev/null)
    [[ -n "$ASSOC" && "$ASSOC" != "None" ]] && \
      aws ec2 disassociate-address --association-id "$ASSOC" --region "$REGION" 2>&1
    aws ec2 release-address --allocation-id "$ALLOC" --region "$REGION" 2>&1 \
      && echo "Elastic IP rilasciato."
  else
    echo "Elastic IP $EIP non trovato (forse già rilasciato)."
  fi
fi

# ------------------------------------------------------------------------------
# 4. Cancellazione stack CloudFormation (IRREVERSIBILE: elimina SQS/DLQ/Lambda/
#    ruolo/dashboard/allarme/SNS). Farlo solo se smonti l'infra distribuita.
# ------------------------------------------------------------------------------
hr "4. Cancellazione stack $STACK  [IRREVERSIBILE]"
if confirm "Cancellare lo stack $STACK (coda, Lambda, dashboard, allarme)?"; then
  aws cloudformation delete-stack --stack-name "$STACK" --region "$REGION" 2>&1
  echo "Richiesta di delete inviata. Stato:"
  aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" \
    --query 'Stacks[0].StackStatus' --output text 2>&1 || echo "(stack in eliminazione o già rimosso)"
fi

# ------------------------------------------------------------------------------
# 5. Rotazione segreti — MANUALE (non automatizzabile: sistemi esterni)
# ------------------------------------------------------------------------------
hr "5. Rotazione segreti (DA FARE A MANO)"
cat <<'NOTE'
Ruota/revoca questi segreti (comparsi in chat/config durante lo sviluppo):
  - GEMINI_API_KEY   -> aistudio.google.com/apikey (revoca la vecchia, genera nuova)
  - APIFY token      -> Apify Console > Settings > Integrations (revoca/rigenera)
  - GitHub PAT       -> GitHub > Settings > Developer settings > Tokens (revoca)
  - Key pair EC2 .pem -> crea nuova key pair, sostituiscila sull'istanza, elimina la vecchia
  - Utente IAM filippo-dev -> se non serve più, rigenera/elimina le access key
Dopo la rotazione, aggiorna:
  - .env / .env.production (nuova GEMINI_API_KEY, APIFY_API_TOKEN)
  - GitHub Secrets (se cambi la key pair EC2: EC2_SSH_KEY)
NOTE

echo
echo "Cleanup terminato."
