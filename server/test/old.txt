#!/usr/bin/env python3
# Smoke-test for the RMAP HTTP server: completes the handshake and downloads the PDF once.

from __future__ import annotations
import os
import sys
import json
import base64
import requests
from pathlib import Path
from urllib.parse import urljoin
from pgpy import PGPKey, PGPMessage

# ---- Import IdentityManager from installed rmap (or local src fallback) ----
try:
    from rmap.identity_manager import IdentityManager
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent / "server" / "src"))
    from rmap.identity_manager import IdentityManager  # type: ignore

# ---- Config (env-overridable) ----
BASE = os.environ.get("BASE", "http://localhost:5000")
if not BASE.startswith(("http://", "https://")):
    BASE = "http://" + BASE  # make requests happy if scheme omitted

IDENTITY = os.environ.get("IDENTITY", "Alice")
ALICE_PASSPHRASE = os.environ.get("ALICE_PASSPHRASE")  # only if Alice key is protected

# point to the /server directory (one level above /server/test)
repo = Path(__file__).resolve().parents[1]  # .../server
keys_dir = repo / "keys"
clients_dir = keys_dir / "clients"
server_pub = keys_dir / "server_public.asc"
server_priv = keys_dir / "server_private.asc"
alice_priv = clients_dir / f"{IDENTITY}_private.asc"

# ---- Sanity checks ----
for p in [clients_dir, server_pub, server_priv, alice_priv]:
    if not p.exists():
        print(f"Missing: {p}")
        sys.exit(2)

# ---- Build helper (uses server pub/priv + clients dir) ----
im = IdentityManager(
    client_keys_dir=clients_dir,
    server_public_key_path=server_pub,
    server_private_key_path=server_priv,
    server_private_key_passphrase=os.environ.get("RMAP_SERVER_PRIV_PASSPHRASE"),
)

# ---------------- Message 1 ----------------
nonce_client = 54891657
msg1_plain = {"nonceClient": nonce_client, "identity": IDENTITY}
msg1 = {"payload": im.encrypt_for_server(msg1_plain)}

r1 = requests.post(urljoin(BASE, "/rmap-initiate"), json=msg1, timeout=10)
print("rmap-initiate:", r1.status_code, r1.text)
r1.raise_for_status()

# Decrypt Response 1 with Alice's private key (client side) — handle binary payloads
payload_b64 = r1.json()["payload"]
payload_bytes = base64.b64decode(payload_b64)
pgp_msg = PGPMessage.from_blob(payload_bytes)

alice_key, _ = PGPKey.from_file(str(alice_priv))
if alice_key.is_protected and ALICE_PASSPHRASE:
    alice_key.unlock(ALICE_PASSPHRASE)

resp1_plain = json.loads(alice_key.decrypt(pgp_msg).message)
print("Decrypted Response1:", resp1_plain)
nonce_server = int(resp1_plain["nonceServer"])

# ---------------- Message 2 ----------------
msg2 = {"payload": im.encrypt_for_server({"nonceServer": nonce_server})}
r2 = requests.post(urljoin(BASE, "/rmap-get-link"), json=msg2, timeout=10)
print("rmap-get-link:", r2.status_code, r2.text)
r2.raise_for_status()

data = r2.json()
if "link" not in data:
    print("Unexpected response from /rmap-get-link:", data)
    sys.exit(1)

link = data["link"]
print("One-time download link:", link, "\nExpires at:", data.get("expires"))

# ---- Download the PDF once (token is single-use and time-limited) ----
out_path = repo / "got.pdf"
r3 = requests.get(link, timeout=15)
ct = (r3.headers.get("content-type") or "").lower()
if r3.status_code != 200 or not ct.startswith("application/pdf"):
    print("Download failed:", r3.status_code, r3.text[:200])
    sys.exit(1)

out_path.write_bytes(r3.content)
print(f"Downloaded PDF → {out_path} ({len(r3.content)} bytes)")
