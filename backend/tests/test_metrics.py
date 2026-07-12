# Test osservabilita': emit e' no-op in mock e non solleva mai (nemmeno su errore).
import services.metrics as m


def test_emit_noop_in_mock_does_not_raise():
    # In mock non chiama CloudWatch e non solleva.
    m.emit("AnalysisCompleted", 1)


def test_emit_swallows_errors(monkeypatch):
    class Boom:
        def put_metric_data(self, **kw):
            raise RuntimeError("cloudwatch down")

    monkeypatch.setattr(m, "AWS_MOCK", False)
    monkeypatch.setattr(m, "_client", lambda: Boom())
    m.emit("AnalysisFailed", 1)  # non deve sollevare
