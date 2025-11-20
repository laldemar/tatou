# server/test/test_api.py

import io
import uuid
import pytest
import time
import watermarking_utils as WMUtils 

from server import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def user_credentials():
    """
    Generate a unique user each test run to avoid UNIQUE(email/login) collisions
    in the DB.
    """
    suffix = str(int(time.time() * 1000000))
    email = f"test_{suffix}@example.com"
    login = f"user_{suffix}"
    password = "Secr3tP@ss!"
    return {"email": email, "login": login, "password": password}


@pytest.fixture
def auth_header(client, user_credentials):
    """
    Create a user + log in, returns {"Authorization": "Bearer <token>"} header.
    """
    # create-user
    resp = client.post("/api/create-user", json={
        "email": user_credentials["email"],
        "login": user_credentials["login"],
        "password": user_credentials["password"],
    })
    assert resp.status_code in (201, 409)  # 409 if you re-run with same email

    # login
    resp = client.post("/api/login", json={
        "email": user_credentials["email"],
        "password": user_credentials["password"],
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert "token" in data

    token = data["token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def uploaded_document_id(client, auth_header):
    """
    Uploads a tiny PDF-like file and returns its document id.
    """
    fake_pdf = b"%PDF-1.4\n%test\n"
    data = {
        "file": (io.BytesIO(fake_pdf), "test.pdf"),
        "name": "test.pdf",
    }
    resp = client.post(
        "/api/upload-document",
        data=data,
        headers=auth_header,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 201
    body = resp.get_json()
    assert "id" in body
    return body["id"]


# ---------------------------------------------------------------------
# Basic health / public endpoints
# ---------------------------------------------------------------------

def test_healthz_route(client):
    # This is the one you already had
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.is_json
    assert "message" in resp.get_json()


def test_get_watermarking_methods(client):
    resp = client.get("/api/get-watermarking-methods")
    assert resp.status_code == 200
    assert resp.is_json
    data = resp.get_json()
    assert "methods" in data
    assert "count" in data
    # It’s ok if count == 0, but usually you’ll have some methods registered.


# ---------------------------------------------------------------------
# Auth / user lifecycle
# ---------------------------------------------------------------------

def test_create_user_and_login_flow(client, user_credentials):
    # create-user
    resp = client.post("/api/create-user", json={
        "email": user_credentials["email"],
        "login": user_credentials["login"],
        "password": user_credentials["password"],
    })
    assert resp.status_code in (201, 409)
    if resp.status_code == 201:
        body = resp.get_json()
        assert "id" in body
        assert body["email"] == user_credentials["email"]
        assert body["login"] == user_credentials["login"]

    # login
    resp = client.post("/api/login", json={
        "email": user_credentials["email"],
        "password": user_credentials["password"],
    })
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["token_type"] == "bearer"
    assert isinstance(body["expires_in"], int)


def test_login_missing_fields(client):
    # No password
    resp = client.post("/api/login", json={"email": "x@example.com"})
    assert resp.status_code == 400
    assert resp.is_json


# ---------------------------------------------------------------------
# Documents: upload / list / get / delete
# ---------------------------------------------------------------------

def test_upload_and_list_documents(client, auth_header):
    fake_pdf = b"%PDF-1.4\nHello"
    data = {
        "file": (io.BytesIO(fake_pdf), "hello.pdf"),
        "name": "hello.pdf",
    }

    # upload-document
    resp = client.post(
        "/api/upload-document",
        data=data,
        headers=auth_header,
        content_type="multipart/form-data",
    )
    assert resp.status_code == 201
    created = resp.get_json()
    assert created["name"] == "hello.pdf"
    doc_id = created["id"]

    # list-documents
    resp = client.get("/api/list-documents", headers=auth_header)
    assert resp.status_code == 200
    docs = resp.get_json()["documents"]
    assert any(d["id"] == doc_id for d in docs)


def test_get_document_by_id(client, auth_header, uploaded_document_id):
    # GET /api/get-document/<id>
    resp = client.get(f"/api/get-document/{uploaded_document_id}",
                      headers=auth_header)
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("application/pdf")


def test_delete_document_flow(client, auth_header, uploaded_document_id):
    # DELETE /api/delete-document/<id>
    resp = client.delete(f"/api/delete-document/{uploaded_document_id}",
                         headers=auth_header)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["deleted"] is True

    # Subsequent get should 404
    resp = client.get(f"/api/get-document/{uploaded_document_id}",
                      headers=auth_header)
    assert resp.status_code in (404, 410)


# ---------------------------------------------------------------------
# Versions & watermarking
# ---------------------------------------------------------------------

def test_list_versions_empty(client, auth_header, uploaded_document_id):
    # No versions created yet, should return empty list
    resp = client.get(f"/api/list-versions/{uploaded_document_id}",
                      headers=auth_header)
    assert resp.status_code == 200
    body = resp.get_json()
    assert "versions" in body
    # It’s fine if zero – this just exercises the route.
    assert isinstance(body["versions"], list)


def test_list_all_versions(client, auth_header):
    resp = client.get("/api/list-all-versions", headers=auth_header)
    assert resp.status_code == 200
    body = resp.get_json()
    assert "versions" in body
    assert isinstance(body["versions"], list)

def _pick_method_name() -> str:
    # Reuse whatever is registered, skip the unsafe one
    for name in WMUtils.METHODS.keys():
        if name != "UnsafeBashBridgeAppendEOF":
            return name
    pytest.skip("No suitable watermarking method registered")


def test_create_and_read_watermark_happy_path(
    client, auth_header, uploaded_document_id
):
    method_name = _pick_method_name()
    secret = "api-secret"
    key = "api-key"

    # 1) create-watermark
    resp = client.post(
        f"/api/create-watermark/{uploaded_document_id}",
        json={
            "method": method_name,
            "position": None,
            "key": key,
            "secret": secret,
            "intended_for": "UnitTest",
        },
        headers=auth_header,
    )
    assert resp.status_code in (200, 201)
    data = resp.get_json()
    assert data["documentid"] == uploaded_document_id

    # 2) read-watermark
    resp = client.post(
        f"/api/read-watermark/{uploaded_document_id}",
        json={
            "method": method_name,
            "position": None,
            "key": key,
        },
        headers=auth_header,
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["secret"] == secret



# NOTE: Fully testing create-watermark / read-watermark “happy path” would
# require knowing exactly how your watermarking methods behave.
# The tests above at least hit the listing endpoints and your separate
# watermarking unit tests cover the actual algorithms.


# ---------------------------------------------------------------------
# RMAP endpoints – just basic coverage
# ---------------------------------------------------------------------

def test_rmap_initiate_missing_payload(client):
    resp = client.post("/api/rmap-initiate", json={})
    # In dev env RMAP may not be initialized, so 400 or 503 is OK
    assert resp.status_code in (400, 503)
    assert resp.is_json


def test_rmap_get_link_missing_payload(client):
    resp = client.post("/api/rmap-get-link", json={})
    assert resp.status_code in (400, 503)
    assert resp.is_json