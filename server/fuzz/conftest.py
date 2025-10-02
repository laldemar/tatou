import os, time, requests, random, string
import pytest

BASE_URL = os.getenv("TATOU_BASE_URL", "http://localhost:5000")

@pytest.fixture(scope="session")
def base_url():
    return BASE_URL

@pytest.fixture(scope="session")
def test_user():
    s = str(int(time.time()))
    return {"email": f"fuzzer{s}@example.com", "login": f"fuzz{s}", "password": "P@ssw0rd!"+s}

@pytest.fixture(scope="session")
def token(base_url, test_user):
    # Create user (ignore 409)
    requests.post(f"{base_url}/api/create-user", json=test_user)
    r = requests.post(f"{base_url}/api/login", json={
        "email": test_user["email"], "password": test_user["password"]
    })
    assert r.status_code < 500, r.text
    data = r.json()
    assert "token" in data, data
    return data["token"]

@pytest.fixture
def auth(token):
    return {"Authorization": f"Bearer {token}"}
