# ==============================================================================
# METRICS SERVICE - Metriche custom su Amazon CloudWatch (osservabilita').
# No-op in mock; NON solleva mai: il monitoraggio non deve rompere la pipeline
# (un CloudWatch degradato non deve far fallire un'analisi).
# ==============================================================================
import os
import logging

logger = logging.getLogger("social-privacy-backend")

AWS_MOCK = os.getenv("AWS_MOCK", "true").lower() == "true"
_NAMESPACE = "SocialPrivacyDetector"


def _client():
    # Import boto3 solo quando serve (in mock non viene mai chiamato).
    import boto3
    region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    return boto3.client("cloudwatch", region_name=region)


def emit(name: str, value: float = 1.0, unit: str = "Count") -> None:
    """Pubblica una metrica custom. No-op in mock, silenzioso in caso d'errore."""
    if AWS_MOCK:
        return
    try:
        _client().put_metric_data(
            Namespace=_NAMESPACE,
            MetricData=[{"MetricName": name, "Value": value, "Unit": unit}],
        )
    except Exception as e:
        logger.warning(f"[CloudWatch] emit '{name}' fallito: {e}")
