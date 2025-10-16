#!/usr/bin/env python3
import os, sys, json, base64, argparse, time
from pathlib import Path
import requests
from pgpy import PGPKey, PGPMessage

try:
    from rmap.identity_manager import IdentityManager
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent / "server" / "src"))
    from rmap.identity_manager import IdentityManager  # type: ignore

ROOT_DIR = Path(__file__).resolve().parent
if (ROOT_DIR / "keys" / "clients").is_dir():
    # running from tatou/server/
    ROOT = ROOT_DIR.parent
    KEYS = ROOT_DIR / "keys"
else:
    # running from project root tatou/
    ROOT = ROOT_DIR
    KEYS = ROOT / "server" / "keys"

CLIENTS = KEYS / "clients"   # <-- missing line was the crash

def load_priv(identity: str) -> PGPKey:
    priv = CLIENTS / f"{identity}_private.asc"   # use the identity arg
    if not priv.exists():
        print(f"[!] Missing private key: {priv}"); sys.exit(2)
    key, _ = PGPKey.from_file(str(priv))
    pw = os.environ.get("CLIENT_PASSPHRASE")
    if key.is_protected:
        if not pw:
            print("[!] Key is protected; set CLIENT_PASSPHRASE"); sys.exit(2)
        key.unlock(pw)
    return key

def build_im(server_pub: Path) -> IdentityManager:
    server_priv = KEYS / "server_private.asc"  # IM requires a path; not used by client
    if not server_pub.exists():
        print(f"[!] Server public key not found: {server_pub}"); sys.exit(2)
    return IdentityManager(
        client_keys_dir=CLIENTS,
        server_public_key_path=server_pub,
        server_private_key_path=server_priv,
        server_private_key_passphrase=os.environ.get("RMAP_SERVER_PRIV_PASSPHRASE"),
    )

def main():
    ap = argparse.ArgumentParser(description="Tiny RMAP client (strict endpoints).")
    ap.add_argument("server", help="server IP, e.g. 10.11.202.18")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--identity", default="Group_05")
    ap.add_argument("--server-pub", required=True, help="path to TARGET server public key .asc")
    ap.add_argument("--outdir", default=str(ROOT / "rmap_pdf"))
    args = ap.parse_args()

    priv = load_priv(args.identity)
    im = build_im(Path(args.server_pub))

    base = f"http://{args.server}:{args.port}"
    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)

    # Message 1
    nonce_client = int(time.time() * 1_000_000) & 0xFFFFFFFF
    msg1_plain = {"nonceClient": nonce_client, "identity": args.identity}
    payload1 = {"payload": im.encrypt_for_server(msg1_plain)}
    r1 = requests.post(f"{base}/rmap-initiate", json=payload1, timeout=10)
    print("rmap-initiate:", r1.status_code)
    if r1.status_code != 200 or not r1.headers.get("content-type","").lower().startswith("application/json"):
        print("Body:", r1.text[:200]); sys.exit(1)

    armored = base64.b64decode(r1.json()["payload"]).decode("utf-8")
    resp1_plain = json.loads(priv.decrypt(PGPMessage.from_blob(armored)).message)
    nonce_server = int(resp1_plain["nonceServer"])

    # Message 2
    payload2 = {"payload": im.encrypt_for_server({"nonceServer": nonce_server})}
    r2 = requests.post(f"{base}/rmap-get-link", json=payload2, timeout=10)
    print("rmap-get-link:", r2.status_code)
    if r2.status_code != 200 or not r2.headers.get("content-type","").lower().startswith("application/json"):
        print("Body:", r2.text[:200]); sys.exit(1)

    data = r2.json()
    if "link" not in data:
        print("No 'link' in response:", data); sys.exit(1)

    # Download
    r3 = requests.get(data["link"], timeout=15)
    if r3.status_code != 200 or "application/pdf" not in r3.headers.get("content-type","").lower():
        print("Download failed:", r3.status_code, r3.text[:200]); sys.exit(1)

    dest = Path(args.outdir) / f"{args.server}__{args.identity}.pdf"
    dest.write_bytes(r3.content)
    print(f"[✓] Saved → {dest} ({len(r3.content)} bytes)")

if __name__ == "__main__":
    main()
