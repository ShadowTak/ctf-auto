"""Regression tests for the web UI's cooperative stop endpoint."""
import web_app


def test_stop_running_job_becomes_cancelled():
    jid = web_app._new_job()
    client = web_app.app.test_client()

    response = client.post(f"/api/stop/{jid}")
    payload = response.get_json()
    assert response.status_code == 200
    assert payload["accepted"] is True
    assert payload["status"] == "stopping"

    status = client.get(f"/api/status/{jid}").get_json()
    assert status["status"] == "stopping"
    assert status["stop_requested"] is True

    web_app._finish_job(jid, [{"type": "partial"}])
    status = client.get(f"/api/status/{jid}").get_json()
    assert status["status"] == "cancelled"
    assert status["results"] == [{"type": "partial"}]


def test_stop_completed_job_is_not_accepted():
    jid = web_app._new_job()
    web_app._finish_job(jid, [])
    response = web_app.app.test_client().post(f"/api/stop/{jid}")
    assert response.status_code == 200
    assert response.get_json() == {"status": "done", "accepted": False}

