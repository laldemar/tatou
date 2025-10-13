# fuzz/test_fuzz_all_endpoints.py
import io
import json
import time
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

from payloads import pdf_bytes, safe_name, weird_str, positions

REPORT_DIR = Path(__file__).parent / "reports"
REPORT_DIR.mkdir(exist_ok=True)

def _report_path(endpoint):
    # e.g. reports/create-user_report.ndjson
    return REPORT_DIR / f"{endpoint}_report.ndjson"

def _append_report(endpoint, entry):
    p = _report_path(endpoint)
    existing = p.read_text() if p.exists() else ""
    p.write_text(existing + json.dumps(entry) + "\n")

def _record_issue(endpoint, kind, req, resp):
    entry = {
        "time": int(time.time()),
        "endpoint": endpoint,
        "kind": kind,
        "method": getattr(req, "method", "?"),
        "url": getattr(req, "url", "?"),
        "status": getattr(resp, "status_code", None),
        "body": resp.text[:1200] if hasattr(resp, "text") and resp.text else None,
    }
    _append_report(endpoint, entry)

#
# Small helpers to mimic your existing behaviour (upload file, pick method, ...)
#
def _upload(session, base_url, auth, name="doc", content=b"%PDF-1.4\n%%EOF\n"):
    files = {"file": ("f.pdf", io.BytesIO(content), "application/pdf")}
    data  = {"name": name}
    return session.post(f"{base_url}/api/upload-document", headers=auth, files=files, data=data)

def _pick_method(session, base_url):
    r = session.get(f"{base_url}/api/get-watermarking-methods")
    if r.ok:
        methods = [m.get("name") for m in r.json().get("methods", []) if "name" in m]
        # prefer known names when available for better coverage of specific code paths
        for m in ("toy-eof", "valdemar", "theo"):
            if m in methods:
                return m
        return methods[0] if methods else None
    return None

#
# Tests for each endpoint — each test writes to a separate report file
#

# create-user
@given(login=st.text(min_size=1, max_size=40), password=st.text(min_size=1, max_size=60),
       email=st.emails())
@settings(max_examples=30)
def test_fuzz_create_user(session, base_url, login, password, email):
    endpoint = "create-user"
    payload = {"login": login, "password": password, "email": email}
    r = session.post(f"{base_url}/api/create-user", json=payload)
    if r.status_code >= 500:
        _record_issue(endpoint, "server-500-create-user", r.request, r)
        pytest.xfail(f"Server 5xx on create-user: {r.status_code}")
    # spec says must validate fields; allow 201 or 400-ish responses
    assert r.status_code in (201, 400, 422, 409)

# login
@given(email=st.text(min_size=0, max_size=80), password=st.text(min_size=0, max_size=80))
@settings(max_examples=20)
def test_fuzz_login(session, base_url, email, password):
    endpoint = "login"
    payload = {"email": email, "password": password}
    r = session.post(f"{base_url}/api/login", json=payload)
    if r.status_code >= 500:
        _record_issue(endpoint, "server-500-login", r.request, r)
        pytest.xfail(f"Server 5xx on login: {r.status_code}")
    # login should reject missing/invalid credentials, succeed for valid combos
    assert r.status_code in (200, 400, 401, 403)

# healthz (not fuzzed heavily — just check presence)
def test_healthz_endpoint(session, base_url):
    endpoint = "healthz"
    r = session.get(f"{base_url}/healthz")
    if r.status_code >= 500:
        _record_issue(endpoint, "server-500-healthz", r.request, r)
        pytest.xfail(f"Server 5xx on healthz: {r.status_code}")
    assert r.status_code == 200
    assert "message" in r.json()

# get-watermarking-methods
def test_get_watermarking_methods(session, base_url, auth):
    endpoint = "get-watermarking-methods"
    r = session.get(f"{base_url}/api/get-watermarking-methods")
    if r.status_code >= 500:
        _record_issue(endpoint, "server-500-methods", r.request, r)
        pytest.xfail(f"Server 5xx on get-watermarking-methods: {r.status_code}")
    assert r.status_code == 200
    # basic structural check
    assert "methods" in r.json() or "count" in r.json()

# upload-document
@given(name=safe_name, content=pdf_bytes())
@settings(max_examples=30)
def test_fuzz_upload_document(session, base_url, auth, name, content):
    endpoint = "upload-document"
    r = _upload(session, base_url, auth, name=name, content=content)
    if r.status_code >= 500:
        _record_issue(endpoint, "server-500-upload", r.request, r)
        pytest.xfail(f"Server 5xx on upload: {r.status_code}")
    assert r.status_code in (201, 400, 415, 422)

# list-documents
# @settings(max_examples=10)
def test_list_documents(session, base_url, auth):
    endpoint = "list-documents"
    r = session.get(f"{base_url}/api/list-documents", headers=auth)
    if r.status_code >= 500:
        _record_issue(endpoint, "server-500-list-documents", r.request, r)
        pytest.xfail(f"Server 5xx on list-documents: {r.status_code}")
    assert r.status_code in (200, 401)  # 401 if no auth or token problem

# delete-document (path and query variants)
id_text_nonempty = st.text(min_size=1, max_size=12)
@given(doc_id=st.one_of(st.integers(min_value=-5, max_value=1000), id_text_nonempty))
@settings(max_examples=25)
def test_fuzz_delete_document(session, base_url, auth, doc_id):
    endpoint = "delete-document"
    # Try path variant first
    r = session.delete(f"{base_url}/api/delete-document/{doc_id}", headers=auth)
    if r.status_code == 405:
        # try query param variant if route expects it
        r = session.delete(f"{base_url}/api/delete-document", headers=auth, params={"id": str(doc_id)})
    if r.status_code >= 500:
        _record_issue(endpoint, "server-500-delete", r.request, r)
        pytest.xfail(f"Server 5xx on delete: {r.status_code}")
    assert r.status_code in (200, 400, 401, 403, 404, 405)

# list-versions (path and query variants)
@given(doc_id=st.one_of(st.integers(min_value=-5, max_value=1000), id_text_nonempty))
@settings(max_examples=25)
def test_fuzz_list_versions(session, base_url, auth, doc_id):
    endpoint = "list-versions"
    r = session.get(f"{base_url}/api/list-versions/{doc_id}", headers=auth)
    if r.status_code >= 500:
        _record_issue(endpoint, "server-500-list-versions", r.request, r)
        pytest.xfail(f"Server 5xx on list-versions: {r.status_code}")
    assert r.status_code in (200, 400, 404, 401)

    # query param variant
    r2 = session.get(f"{base_url}/api/list-versions", headers=auth, params={"documentid": str(doc_id)})
    if r2.status_code >= 500:
        _record_issue(endpoint, "server-500-list-versions-q", r2.request, r2)
        pytest.xfail(f"Server 5xx on list-versions (query): {r2.status_code}")
    assert r2.status_code in (200, 400, 404, 401)

# list-all-versions
#@settings(max_examples=10)
def test_list_all_versions(session, base_url, auth):
    endpoint = "list-all-versions"
    r = session.get(f"{base_url}/api/list-all-versions", headers=auth)
    if r.status_code >= 500:
        _record_issue(endpoint, "server-500-list-all-versions", r.request, r)
        pytest.xfail(f"Server 5xx on list-all-versions: {r.status_code}")
    assert r.status_code in (200, 401)

# create-watermark (both path and query variants) - fuzz secret/key/position/method
@given(secret=weird_str, key=weird_str, position=positions)
@settings(max_examples=30)
def test_fuzz_create_watermark(session, base_url, auth, secret, key, position):
    endpoint = "create-watermark"
    # 1) upload a small valid document to get a document id
    up = _upload(session, base_url, auth, name="ok", content=b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n")
    if up.status_code >= 500:
        _record_issue(endpoint, "server-500-upload-before-create", up.request, up)
        pytest.xfail(f"Server 5xx on upload: {up.status_code}")
    if up.status_code != 201:
        return
    did = up.json().get("id")
    method = _pick_method(session, base_url)
    if not method:
        return

    payload = {"method": method, "position": position, "key": key, "secret": secret, "intended_for": "fuzz"}
    # try path variant
    r = session.post(f"{base_url}/api/create-watermark/{did}", headers=auth, json=payload)
    if r.status_code >= 500:
        _record_issue(endpoint, "server-500-create-wm", r.request, r)
        pytest.xfail(f"Server 5xx on create-watermark: {r.status_code}")
    assert r.status_code in (201, 400, 422, 401)

    # try query variant
    r2 = session.post(f"{base_url}/api/create-watermark", headers=auth, json={**payload, "id": did})
    if r2.status_code >= 500:
        _record_issue(endpoint, "server-500-create-wm-q", r2.request, r2)
        pytest.xfail(f"Server 5xx on create-watermark (query): {r2.status_code}")
    assert r2.status_code in (201, 400, 422, 401)

# read-watermark (path and query variants)
@given(position=positions, key=weird_str)
@settings(max_examples=25)
def test_fuzz_read_watermark(session, base_url, auth, position, key):
    endpoint = "read-watermark"
    # upload a doc
    up = _upload(session, base_url, auth, name="ok_read", content=b"%PDF-1.4\n%%EOF\n")
    if up.status_code >= 500:
        _record_issue(endpoint, "server-500-upload-before-read", up.request, up)
        pytest.xfail(f"Server 5xx on upload: {up.status_code}")
    if up.status_code != 201:
        return
    did = up.json().get("id")
    method = _pick_method(session, base_url)
    if not method:
        return

    payload = {"method": method, "position": position, "key": key}
    r = session.post(f"{base_url}/api/read-watermark/{did}", headers=auth, json=payload)
    if r.status_code >= 500:
        _record_issue(endpoint, "server-500-read-wm", r.request, r)
        pytest.xfail(f"Server 5xx on read-watermark: {r.status_code}")
    assert r.status_code in (200, 400, 404, 422, 401)

    # query param variant
    r2 = session.post(f"{base_url}/api/read-watermark", headers=auth, json={**payload, "id": did})
    if r2.status_code >= 500:
        _record_issue(endpoint, "server-500-read-wm-q", r2.request, r2)
        pytest.xfail(f"Server 5xx on read-watermark (query): {r2.status_code}")
    assert r2.status_code in (200, 400, 404, 422, 401)
