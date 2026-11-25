from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient

from app.main import app

TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("VULNTRACK_TOKEN", TOKEN)
    monkeypatch.setenv("VULNTRACK_DB", str(tmp_path / "test.db"))
    return TestClient(app)


def report(client, **overrides):
    body = {"title": "Unauthenticated file deletion", "product": "example-plugin 1.2.3", "cvss_vector": CRITICAL}
    body.update(overrides)
    return client.post("/api/findings", json=body, headers=AUTH)


def test_probes_need_no_token(client):
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/ready").json() == {"status": "ready"}


def test_api_rejects_missing_or_wrong_token(client):
    assert client.get("/api/findings").status_code == 401
    assert client.get("/api/findings", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.get("/api/findings", headers={"Authorization": TOKEN}).status_code == 401


def test_api_fails_closed_without_configured_token(client, monkeypatch):
    monkeypatch.delenv("VULNTRACK_TOKEN")
    assert client.get("/api/findings", headers=AUTH).status_code == 503


def test_openapi_schema_is_not_exposed(client):
    assert client.get("/openapi.json").status_code == 404


def test_create_scores_and_sets_deadline(client):
    response = report(client, reported_on="2026-11-01", cve="CVE-2026-12345")
    assert response.status_code == 201
    finding = response.json()
    assert finding["score"] == 9.8
    assert finding["severity"] == "critical"
    assert finding["status"] == "reported"
    assert finding["due_on"] == "2026-11-08"


def test_invalid_input_is_rejected(client):
    assert report(client, cvss_vector="CVSS:3.1/AV:N").status_code == 422
    assert report(client, cve="CVE-26-1").status_code == 422
    assert report(client, title="").status_code == 422


def test_status_workflow(client):
    finding_id = report(client).json()["id"]
    url = f"/api/findings/{finding_id}"
    assert client.patch(url, json={"status": "disclosed"}, headers=AUTH).status_code == 409
    assert client.patch(url, json={"status": "triaged"}, headers=AUTH).json()["status"] == "triaged"
    assert client.patch(url, json={"status": "patched"}, headers=AUTH).json()["status"] == "patched"
    assert client.patch(url, json={"status": "reported"}, headers=AUTH).status_code == 409
    assert client.patch(url, json={"status": "unknown"}, headers=AUTH).status_code == 422


def test_unknown_finding_returns_404(client):
    assert client.get("/api/findings/999", headers=AUTH).status_code == 404
    assert client.patch("/api/findings/999", json={"status": "triaged"}, headers=AUTH).status_code == 404


def test_overdue_lists_only_open_findings_past_deadline(client):
    old = (date.today() - timedelta(days=30)).isoformat()
    late_id = report(client, reported_on=old).json()["id"]
    fixed_id = report(client, reported_on=old).json()["id"]
    report(client)
    client.patch(f"/api/findings/{fixed_id}", json={"status": "triaged"}, headers=AUTH)
    client.patch(f"/api/findings/{fixed_id}", json={"status": "patched"}, headers=AUTH)

    overdue = client.get("/api/findings", params={"overdue": "true"}, headers=AUTH).json()
    assert [f["id"] for f in overdue] == [late_id]
    assert len(client.get("/api/findings", headers=AUTH).json()) == 3
    assert len(client.get("/api/findings", params={"status": "patched"}, headers=AUTH).json()) == 1
