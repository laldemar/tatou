#!/usr/bin/env python3
"""
Tiny RMAP client for the SOFTSEC project.

Usage example (against your own server):
    python server/get_rmap.py 127.0.0.1 --port 5000 \
      --identity Group_05 \
      --server-pub server/keys/server_public.asc \
      --outdir rmap_pdf

Notes:
- --identity MUST match the filename stem in keys/clients/<identity>.asc (case sensitive).
- Your private key must be keys/clients/<identity>_private.asc
- If your private key is passphrase-protected, set:
    export CLIENT_PASSPHRASE='your-passphrase'
"""

import os
import sys
import json
import base64
import argparse
import time
from pathlib import Path

import requests
from pgpy import PGPKey, PGPMessage

# Import rmap from installed wheel; fall back to local src for dev
try:
    from rmap.identity_manager import IdentityManager
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent / "server" / "src"))
    from rmap.identity_manager import IdentityManager  # type: ignore

# --- Paths -------------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parent
if (ROOT_DIR / "keys" / "clients").is_dir():
    # running from tatou/server/
    ROOT = ROOT_DIR.parent
    KEYS = ROOT_DIR / "keys"
else:
    # running from project root tatou/
    ROOT = ROOT_DIR
    KEYS = ROOT / "server" / "keys"

CLIENTS = KEYS / "clients"


# --- Helpers -----------------------------------------------------------------

def load_priv(identity: str) -> PGPKey:
    """Load (and unlock) the private key for the given identity."""
    priv = CLIENTS / f"{identity}_private.asc"
    if not priv.exists():
        print(f"[!] Missing private key: {priv}")
        sys.exit(2)

    key, _ = PGPKey.from_file(str(priv))
    pw = os.environ.get("CLIENT_PASSPHRASE")
    if key.is_protected:
        if not pw:
            print("[!] Key is protected; set CLIENT_PASSPHRASE")
            sys.exit(2)
        key.unlock(pw)
    return key


def build_im(server_pub: Path) -> IdentityManager:
    """Build an IdentityManager using our clients dir and the TARGET server's public key."""
    server_priv = KEYS / "server_private.asc"  # required by ctor; not used by this client
    if not server_pub.exists():
        print(f"[!] Server public key not found: {server_pub}")
        sys.exit(2)
    return IdentityManager(
        client_keys_dir=CLIENTS,
        server_public_key_path=server_pub,
        server_private_key_path=server_priv,
        server_private_key_passphrase=os.environ.get("RMAP_SERVER_PRIV_PASSPHRASE"),
    )


def _pgpmessage_from_b64(b64_payload: str) -> PGPMessage:
    """Accepts base64 of either BINARY or ASCII-armored PGP; returns PGPMessage."""
    raw = base64.b64decode(b64_payload)
    try:
        # works if payload is binary PGP
        return PGPMessage.from_blob(raw)
    except Exception:
        # if it was ASCII-armored, decode to str and try again
        return PGPMessage.from_blob(raw.decode("utf-8"))


# --- Main --------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Tiny RMAP client (strict endpoints).")
    ap.add_argument("server", help="server IP or host, e.g. 10.11.202.18")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--identity", default="Group_05")
    ap.add_argument("--server-pub", required=True, help="path to TARGET server public key (.asc)")
    ap.add_argument("--outdir", default=str(ROOT / "rmap_pdf"))
    args = ap.parse_args()

    # Keys + crypto manager
    priv = load_priv(args.identity)
    im = build_im(Path(args.server_pub))

    base = f"http://{args.server}:{args.port}"
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # ---------------------------
    # Client -> Server : Message 1
    # ---------------------------
    nonce_client = int(time.time() * 1_000_000) & 0xFFFFFFFF
    msg1_plain = {"nonceClient": nonce_client, "identity": args.identity}
    payload1 = {"payload": im.encrypt_for_server(msg1_plain)}

    try:
        r1 = requests.post(f"{base}/rmap-initiate", json=payload1, timeout=10)
    except Exception as e:
        print("[!] HTTP error calling /rmap-initiate:", e)
        sys.exit(1)

    print("rmap-initiate:", r1.status_code)
    if r1.status_code != 200 or not r1.headers.get("content-type", "").lower().startswith("application/json"):
        print("Body:", r1.text[:400])
        sys.exit(1)

    try:
        pgp_msg = _pgpmessage_from_b64(r1.json()["payload"])
        resp1_plain = json.loads(priv.decrypt(pgp_msg).message)
        nonce_server = int(resp1_plain["nonceServer"])
    except Exception as e:
        print("[!] Failed to decrypt/parse Response 1:", e)
        print("Payload head:", r1.json().get("payload", "")[:60])
        sys.exit(1)

    # ---------------------------
    # Client -> Server : Message 2
    # ---------------------------
    payload2 = {"payload": im.encrypt_for_server({"nonceServer": nonce_server})}

    try:
        r2 = requests.post(f"{base}/rmap-get-link", json=payload2, timeout=10)
    except Exception as e:
        print("[!] HTTP error calling /rmap-get-link:", e)
        sys.exit(1)

    print("rmap-get-link:", r2.status_code)
    if r2.status_code != 200 or not r2.headers.get("content-type", "").lower().startswith("application/json"):
        print("Body:", r2.text[:400])
        sys.exit(1)

    data = r2.json()
    if "link" not in data:
        print("No 'link' in response:", data)
        sys.exit(1)

    # ---------------------------
    # Download the PDF
    # ---------------------------
    try:
        r3 = requests.get(data["link"], timeout=15)
    except Exception as e:
        print("[!] HTTP error downloading PDF:", e)
        sys.exit(1)

    if r3.status_code != 200 or "application/pdf" not in r3.headers.get("content-type", "").lower():
        print("Download failed:", r3.status_code, r3.text[:400])
        sys.exit(1)

    dest = outdir / f"{args.server}__{args.identity}.pdf"
    dest.write_bytes(r3.content)
    print(f"[✓] Saved → {dest} ({len(r3.content)} bytes)")


if __name__ == "__main__":
    main()
