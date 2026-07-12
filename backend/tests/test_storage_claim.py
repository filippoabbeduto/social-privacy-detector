# Test idempotenza: claim_job porta PENDING->PROCESSING una sola volta.
from services.storage import StorageService, JOB_STATUS_PROCESSING


def test_claim_job_only_once():
    s = StorageService()  # AWS_MOCK=true nei test -> store in memoria
    s.create_job("id1", "http://x")
    assert s.claim_job("id1") is True          # primo claim riesce
    assert s.claim_job("id1") is False         # secondo claim (gia' PROCESSING) fallisce
    rec = s.get_analysis("id1")
    assert rec["status"] == JOB_STATUS_PROCESSING


def test_claim_missing_job_is_false():
    s = StorageService()
    assert s.claim_job("nope") is False
