import io
from hypothesis import given, settings, strategies as st
from payloads import pdf_bytes, safe_name, weird_str, positions

def no_5xx(r):
    assert r.status_code < 500, f"{r.request.method} {r.request.url} -> {r.status_code}\n{r.text[:400]}"

def _upload(session, base_url, auth, name="doc", content=b"%PDF-1.4\n%%EOF\n"):
    files = {"file": ("f.pdf", io.BytesIO(content), "application/pdf")}
    data  = {"name": name}
    return session.post(f"{base_url}/api/upload-document", headers=auth, files=files, data=data)

def _pick_method(session, base_url):
    r = session.get(f"{base_url}/api/get-watermarking-methods")
    if r.ok:
        methods = [m["name"] for m in r.json().get("methods", [])]
        # prefer a known baseline if present
        for m in ("toy-eof", "valdemar", "theo"):
            if m in methods: 
                return m
        return methods[0] if methods else None
    return None

def test_healthz(session, base_url):
    r = session.get(f"{base_url}/healthz")
    assert r.status_code == 200
    assert "message" in r.json()

@given(name=safe_name, content=pdf_bytes())
@settings(max_examples=25)
def test_fuzz_upload_document(session, base_url, auth, name, content):
    r = _upload(session, base_url, auth, name=name, content=content)
    no_5xx(r)
    assert r.status_code in (201, 400, 415, 422)

@given(secret=weird_str, key=weird_str, position=positions)
@settings(max_examples=15)
def test_fuzz_watermark_flow(session, base_url, auth, secret, key, position):
    # 1) upload a minimal, valid-ish PDF
    up = _upload(session, base_url, auth, name="ok", content=b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n")
    no_5xx(up)
    if up.status_code != 201:
        return  # server rejected; fine for fuzzing
    did = up.json()["id"]

    # 2) pick any available method
    method = _pick_method(session, base_url)
    if not method:
        return  # nothing to try

    # 3) try to create watermark
    payload = {"method": method, "position": position, "key": key, "secret": secret, "intended_for": "fuzz"}
    r = session.post(f"{base_url}/api/create-watermark/{did}", headers=auth, json=payload)
    no_5xx(r)
    assert r.status_code in (201, 400, 422)

@given(doc_id=st.one_of(st.integers(min_value=-5, max_value=5), weird_str))
@settings(max_examples=25)
def test_fuzz_list_versions_and_delete(session, base_url, auth, doc_id):
    r1 = session.get(f"{base_url}/api/list-versions/{doc_id}", headers=auth)
    assert r1.status_code in (200, 400, 404)  # may be bad id, but never 5xx

    r2 = session.delete(f"{base_url}/api/delete-document/{doc_id}", headers=auth)
    # After you patch the endpoint (parametrized SQL + auth), these pass.
    assert r2.status_code in (200, 400, 404)
