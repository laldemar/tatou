# pytest fixtures used by all fuzz tests
import os, random, string
import requests
import pytest

BASE = os.environ.get("TATOU_BASE_URL", "http://localhost:5000")

def _rand(n=6):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))

@pytest.fixture(scope="session")
def base_url():
    return BASE

@pytest.fixture(scope="session")
def session():
    s = requests.Session()
    s.headers.update({"Accept": "application/json"})
    return s

@pytest.fixture(scope="session")
def auth(session, base_url):
    # create-or-get a user; then login to get a token
    email = f"fuzz_{_rand()}@example.com"
    login = f"fuzz_{_rand()}"
    password = "fuzzpass123"

    # create user (idempotent-ish)
    session.post(f"{base_url}/api/create-user",
                 json={"email": email, "login": login, "password": password})

    # login
    r = session.post(f"{base_url}/api/login", json={"email": email, "password": password})
    r.raise_for_status()
    token = r.json()["token"]
    return {"Authorization": f"Bearer {token}"}
