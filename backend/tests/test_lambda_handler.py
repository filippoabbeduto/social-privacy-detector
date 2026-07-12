# Test consumatore Lambda: chiama run_analysis e segnala solo gli errori infra.
import json
import lambda_handler


def _sqs_event(body: dict, mid="m1"):
    return {"Records": [{"messageId": mid, "body": json.dumps(body)}]}


def test_handler_calls_run_analysis(monkeypatch):
    calls = []
    monkeypatch.setattr(lambda_handler, "run_analysis",
                        lambda **kw: calls.append(kw))
    ev = _sqs_event({"analysis_id": "a1", "social_url": "http://x",
                     "scraped_content": "bio", "image_labels": None})
    out = lambda_handler.handler(ev, None)
    assert calls[0]["analysis_id"] == "a1"
    assert out == {"batchItemFailures": []}


def test_handler_reports_infra_failure(monkeypatch):
    def boom(**kw):
        raise RuntimeError("dynamo throttled")

    monkeypatch.setattr(lambda_handler, "run_analysis", boom)
    ev = _sqs_event({"analysis_id": "a2", "social_url": "http://x",
                     "scraped_content": None, "image_labels": None}, mid="m2")
    out = lambda_handler.handler(ev, None)
    assert out["batchItemFailures"] == [{"itemIdentifier": "m2"}]
