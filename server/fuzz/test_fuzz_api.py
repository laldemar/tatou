import io, random, json, requests
from hypothesis import given, settings, HealthCheck, strategies as st
from payloads import weird_str, email_str, pdf_bytes, b64ish

settings.register_profile("dev", settings(
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    max_examples=50,
    deadline=None,
))
settings.load_profile("dev")

def no_5xx(r):
    assert r.status_code < 500, f"{r.request.method} {r.request.url} -> {r.status_code}\n{r.text[:400]}"

# ---------- Public endpoints ----------
def test_healthz(base_url):
    r = requests.get(f"{base_url}/healthz")
    no_5xx(r)
    assert r.json().get("message")

@given(email=email_str, login=weird_str, password=weird_str)
def test_fuzz_create_user(base_url, email, login, password):
    r = requests.post(f"{base_url}/api/create-user", json={
        "email": email, "login": login[:60], "password": password[:80]
    })
    no_5xx(r)

@given(email=email_str, password=weird_str)
def test_fuzz_login(base_url, email, password):
    r = requests.post(f"{base_url}/api/login", json={"email": email, "password": password})
    no_5xx(r)

# ---------- Auth endpoints ----------
@given(name=weird_str, content=pdf_bytes())
def test_fuzz_upload_document(base_url, auth, name, content):
    files = {"file": ("fuzz.pdf", io.BytesIO(content), "application/pdf")}
    data  = {"name": name[:100] or "x.pdf"}
    r = requests.post(f"{base_url}/api/upload-document", headers=auth, files=files, data=data)
    no_5xx(r)
    assert r.status_code in {201, 400, 403, 415}

def _methods(base_url):
    r = requests.get(f"{base_url}/api/get-watermarking-methods")
    if r.status_code >= 500: return []
    return [m["name"] for m in r.json().get("methods", [])]

@given(secret=weird_str, key=weird_str,
       position=st.sampled_from(["", "topleft", "topright", "bottomleft", "bottomright", "center",
                                 "../../../../etc", "\x00"]))
def test_fuzz_watermark_flow(base_url, auth, secret, key, position):
    # Upload seed doc
    pdf = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n"
    up = requests.post(f"{base_url}/api/upload-document", headers=auth,
                       files={"file": ("seed.pdf", io.BytesIO(pdf), "application/pdf")},
                       data={"name": "seed"})
    no_5xx(up)
    if up.status_code != 201:
        return
    doc_id = up.json()["id"]

    methods = _methods(base_url)
    if not methods:
        return
    method = random.choice(methods)

    # Create watermark
    cw = requests.post(f"{base_url}/api/create-watermark/{doc_id}", headers=auth, json={
        "method": method, "position": position,
        "key": key[:120], "secret": (secret or "x")[:200],
        "intended_for": "fuzzer"
    })
    no_5xx(cw)
    assert cw.status_code in {201, 400}

    # Read watermark (only if created)
    if cw.status_code == 201:
        rw = requests.post(f"{base_url}/api/read-watermark/{doc_id}", headers=auth, json={
            "method": method, "position": position, "key": key[:120]
        })
        no_5xx(rw)
        assert rw.status_code in {200, 201, 400}

@given(payload=b64ish)
def test_fuzz_rmap_endpoints(base_url, auth, payload):
    r1 = requests.post(f"{base_url}/api/rmap-initiate", headers=auth, json={"payload": payload})
    no_5xx(r1)
    r2 = requests.post(f"{base_url}/api/rmap-get-link", headers=auth, json={"payload": payload})
    no_5xx(r2)

@given(doc_id=st.one_of(st.integers(min_value=-10, max_value=10), weird_str))
def test_fuzz_list_versions_and_delete(base_url, auth, doc_id):
    r = requests.get(f"{base_url}/api/list-versions", headers=auth, params={"id": str(doc_id)})
    no_5xx(r)
    r = requests.delete(f"{base_url}/api/delete-document/{doc_id}", headers=auth)
    no_5xx(r)
