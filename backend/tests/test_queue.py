# Test produttore SQS: no-op in mock, invio reale quando configurato.
import services.queue as q


def test_send_job_noop_in_mock(monkeypatch):
    # In AWS_MOCK (default nei test) send_job non chiama SQS e ritorna False.
    assert q.send_job({"analysis_id": "x"}) is False


def test_send_job_calls_sqs(monkeypatch):
    sent = {}

    class FakeClient:
        def send_message(self, QueueUrl, MessageBody):
            sent["url"] = QueueUrl
            sent["body"] = MessageBody
            return {"MessageId": "m1"}

    monkeypatch.setattr(q, "AWS_MOCK", False)
    monkeypatch.setattr(q, "_QUEUE_URL", "https://sqs/q")
    monkeypatch.setattr(q, "_client", lambda: FakeClient())
    assert q.send_job({"analysis_id": "x"}) is True
    assert sent["url"] == "https://sqs/q"
    assert '"analysis_id": "x"' in sent["body"]
