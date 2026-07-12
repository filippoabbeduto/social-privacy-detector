# Test selezione modalita': in WORKER_MODE=sqs _enqueue_job invia a SQS.
import routers.analysis as a


def test_enqueue_sqs_mode_sends_message(monkeypatch):
    sent = {}
    monkeypatch.setattr(a, "WORKER_MODE", "sqs")
    monkeypatch.setattr(a.queue, "send_job", lambda p: sent.update(p) or True)
    a._enqueue_job("id9", "http://x", "bio", [{"name": "Beach", "confidence": 90}])
    assert sent["analysis_id"] == "id9"
    assert sent["scraped_content"] == "bio"
