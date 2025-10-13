# server/fuzz/test_regression_api.py
import io
import pytest

PDF_MIN = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n"

@pytest.mark.regression
def test_upload_document_returns_201_no_500(session, base_url, auth):
    files = {"file": ("regress.pdf", io.BytesIO(PDF_MIN), "application/pdf")}
    data = {"name": "regress-case"}
    r = session.post(f"{base_url}/api/upload-document", headers=auth, files=files, data=data)
    assert r.status_code != 500, f"upload returned 500: {r.status_code} {r.text}"
    assert r.status_code == 201, f"expected 201 on upload, got {r.status_code}: {r.text}"
    payload = r.json()
    assert "id" in payload and isinstance(payload["id"], int)

@pytest.mark.regression
def test_delete_document_invalid_id_is_not_5xx(session, base_url, auth):
    # Path variant with non-int won't match route -> usually 404 from Flask/router
    r_path = session.delete(f"{base_url}/api/delete-document/:", headers=auth)
    assert r_path.status_code not in (500, 503), f"path variant produced server error: {r_path.status_code} {r_path.text}"
    assert r_path.status_code in (404, 405)  # 404 is typical (no route match)

    # Query variant with non-int should now return 400 (our validation), not 5xx
    r_q = session.delete(f"{base_url}/api/delete-document", headers=auth, params={"id": ":"})
    assert r_q.status_code == 400, f"expected 400 for non-int id, got {r_q.status_code}: {r_q.text}"

@pytest.mark.regression
def test_delete_document_valid_id_works_then_404_on_second_delete(session, base_url, auth):
    # 1) Upload a doc
    files = {"file": ("deleteme.pdf", io.BytesIO(PDF_MIN), "application/pdf")}
    up = session.post(f"{base_url}/api/upload-document", headers=auth, files=files, data={"name": "deleteme"})
    assert up.status_code == 201, f"upload failed: {up.status_code} {up.text}"
    doc_id = up.json()["id"]

    # 2) Delete it
    d = session.delete(f"{base_url}/api/delete-document/{doc_id}", headers=auth)
    assert d.status_code == 200, f"delete failed: {d.status_code} {d.text}"
    body = d.json()
    assert body.get("deleted") is True
    assert str(body.get("id")) in (str(doc_id), doc_id)  # int or str, either is fine

    # 3) Delete again -> should be not found (proves we deleted)
    d2 = session.delete(f"{base_url}/api/delete-document/{doc_id}", headers=auth)
    assert d2.status_code == 404, f"expected 404 on second delete, got {d2.status_code}: {d2.text}"
