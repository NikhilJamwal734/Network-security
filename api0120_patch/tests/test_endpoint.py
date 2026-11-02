from pathlib import Path


def test_minimal_release_status_no_private_fields():
    from api0120_patch.app.api.release_status import release_status
    body=release_status()
    assert body['release']=='12.0'
    assert body['production_ready'] is False
    assert not ({'host','path','token','secret','debug','dependencies'} & set(body))


def test_fastapi_testclient_import_is_singular():
    # Explicitly guard against the common `fastapi.testclients` typo.
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from api0120_patch.app.api.release_status import router
    app=FastAPI()
    app.include_router(router)
    response=TestClient(app).get('/api/v1/release/status')
    assert response.status_code==200
    assert response.json()['production_ready'] is False
