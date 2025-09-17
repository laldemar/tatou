# This is a test to make sure the rmap http server is working

#!/usr/bin/env python3
from __future__ import annotations
import os, sys, json, base64, requests
from pathlib import Path
from pgpy import PGPKey, PGPMessage

# Import IdentityManager from the installed rmap package
try:
    from rmap.identity_manager import IdentityManager
except ModuleNotFoundError:
    # (only if you’ve vendored rmap somewhere else)
    sys.path.insert(0, str(Path(__file__).resolve().parent / "server" / "src"))
    from rmap.identity_manager import IdentityManager  # type: ignore

BASE = os.environ.get("BASE", "http://localhost:5000")  # your running server
IDENTITY = os.environ.get("IDENTITY", "Alice")          # must match clients/Alice.asc
ALICE_PASSPHRASE = os.environ.get("ALICE_PASSPHRASE")   # optional, if Alice key protected

repo = Path(__file__).resolve().parent
keys_dir = repo / "server" / "keys"
clients_dir = keys_dir / "clients"
server_pub  = keys_dir / "server_public.asc"
server_priv = keys_dir / "server_private.asc"
alice_priv  = clients_dir / f"{IDENTITY}_private.asc"

# Sanity
for p in [clients_dir, server_pub, server_priv, alice_priv]:
    if not p.exists():
        print(f"Missing: {p}")
        sys.exit(2)

# Build helper (uses server pub/priv + clients dir)
im = IdentityManager(
    client_keys_dir=clients_dir,
    server_public_key_path=server_pub,
    server_private_key_path=server_priv,
    server_private_key_passphrase=os.environ.get("RMAP_SERVER_PRIV_PASSPHRASE"),
)

# --- Message 1: client -> server ---
nonce_client = 54891657
msg1_plain = {"nonceClient": nonce_client, "identity": IDENTITY}
msg1 = {"payload": im.encrypt_for_server(msg1_plain)}
r1 = requests.post(f"{BASE}/rmap-initiate", json=msg1, timeout=10)
print("rmap-initiate:", r1.status_code, r1.text)
r1.raise_for_status()

# Decrypt Response 1 with Alice's private key (client side)
armored = base64.b64decode(r1.json()["payload"]).decode("utf-8")
pgp_msg = PGPMessage.from_blob(armored)
alice_key, _ = PGPKey.from_file(str(alice_priv))
if alice_key.is_protected and ALICE_PASSPHRASE:
    alice_key.unlock(ALICE_PASSPHRASE)
resp1_plain = json.loads(alice_key.decrypt(pgp_msg).message)
nonce_server = int(resp1_plain["nonceServer"])
print("Decrypted Response1:", resp1_plain)

# --- Message 2: client -> server ---
msg2 = {"payload": im.encrypt_for_server({"nonceServer": nonce_server})}
r2 = requests.post(f"{BASE}/rmap-get-link", json=msg2, timeout=10)
print("rmap-get-link:", r2.status_code, r2.text)
r2.raise_for_status()

# Verify final 32-hex
result_hex = r2.json()["result"]
combined = (int(nonce_client) << 64) | int(nonce_server)
expected = f"{combined:032x}"
print("Verification:", "OK ✅" if result_hex == expected else "MISMATCH ❌")
