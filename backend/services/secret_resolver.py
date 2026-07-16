# ==============================================================================
# SECRET RESOLVER - Risoluzione di un segreto: env diretta → SSM SecureString.
# ==============================================================================
# In produzione l'ambiente contiene solo il NOME del parametro SSM; il valore è
# cifrato (KMS) e letto a runtime via IAM. Mai solleva: ritorna "" se non trova nulla.
# ==============================================================================

import os
import logging

logger = logging.getLogger("social-privacy-backend")


def resolve_secret(direct: str, ssm_param: str, aws_mock: bool) -> str:
    """direct: valore già in chiaro (env). ssm_param: nome del parametro SSM.
    Ordine: valore diretto → SSM SecureString. In aws_mock non contatta SSM."""
    direct = (direct or "").strip()
    if direct:
        return direct
    ssm_param = (ssm_param or "").strip()
    if not ssm_param or aws_mock:
        return ""
    try:
        import boto3
        region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        ssm = boto3.client("ssm", region_name=region)
        return ssm.get_parameter(Name=ssm_param, WithDecryption=True)["Parameter"]["Value"].strip()
    except Exception as e:
        logger.error(f"[SSM] lettura chiave '{ssm_param}' fallita: {e}")
        return ""
