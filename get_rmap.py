#!/usr/bin/env python3
import os, sys, json, base64, time, argparse
from pathlib import Path
import requests
from pgpy import PGPKey, PGPMessage

try:
    from rmap.identity_manager import IdentityManager
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent / "server" / "src"))
    from rmap.identity_manager import IdentityManager  # type: ignore

REPO = Path(__file__).resolve().parent
KEYS = REPO / "server" / "keys"
CLIENTS = KEYS / "clients"
SERVERS_DIR = KEYS / "servers"   # optional per-host server pub keys directory

IDENTITY = "Group_05"            # your group identity

def load_priv(identity: str):
    # LOAD THE CLIENT (YOUR) PRIVATE KEY, not server_private.asc
    path = CLIENTS / f"{identity}_private.asc"
    if not path.exists():
        print(f"[!] Missing private key: {path}")
        sys.exit(2)
    key, _ = PGPKey.from_file(str(path))
    pw = os.environ.get("CLIENT_PASSPHRASE")
    if key.is_protected and pw:
        key.unlock(pw)
    return key

def build_im_for_host(host: str):
    # use per-host server pub if present; else your default
    server_pub = SERVERS_DIR / f"{host}.asc"
    if not server_pub.exists():
        server_pub = KEYS / "server_public.asc"
    server_priv = KEYS / "server_private.asc"
    for p in (CLIENTS, server_pub, server_priv):
        if not p.exists():
            print(f"[!] Missing key material: {p}")
            sys.exit(2)
    return IdentityManager(
        client_keys_dir=CLIENTS,
        server_public_key_path=server_pub,
        server_private_key_path=server_priv,
        server_private_key_passphrase=os.environ.get("RMAP_SERVER_PRIV_PASSPHRASE"),
    )

def fetch_one(base: str, privkey: PGPKey, im: IdentityManager, out_dir: Path) -> bool:
    base = base.rstrip("/")
    try:
        # Message 1
        nonce_client = int(time.time() * 1_000_000) & 0xFFFFFFFF
        m1_plain = {"nonceClient": nonce_client, "identity": IDENTITY}
        r1 = requests.post(f"{base}/rmap-initiate", json={"payload": im.encrypt_for_server(m1_plain)}, timeout=10)
        j1 = r1.json() if r1.headers.get("content-type","").lower().startswith("application/json") else {}
        if r1.status_code != 200 or "payload" not in j1:
            print(f"[{base}] rmap-initiate failed: {r1.status_code} {r1.text[:200]}")
            return False

        # Decrypt Response 1 with YOUR private key
        armored = base64.b64decode(j1["payload"]).decode("utf-8")
        resp1_plain = json.loads(privkey.decrypt(PGPMessage.from_blob(armored)).message)
        nonce_server = int(resp1_plain["nonceServer"])

        # Message 2
        r2 = requests.post(f"{base}/rmap-get-link", json={"payload": im.encrypt_for_server({"nonceServer": nonce_server})}, timeout=10)
        j2 = r2.json() if r2.headers.get("content-type","").lower().startswith("application/json") else {}
        if r2.status_code != 200 or "link" not in j2:
            print(f"[{base}] rmap-get-link failed: {r2.status_code} {r2.text[:200]}")
            return False

        # One-time download
        r3 = requests.get(j2["link"], timeout=15)
        if r3.status_code != 200 or "application/pdf" not in r3.headers.get("content-type","").lower():
            print(f"[{base}] download failed: {r3.status_code} {r3.text[:200]}")
            return False

        ip = base.split("//",1)[1].split(":",1)[0]
        out_dir.mkdir(parents=True, exist_ok=True)
        dest = out_dir / f"{ip}__{IDENTITY}.pdf"
        dest.write_bytes(r3.content)
        print(f"[{base}] OK → {dest} ({len(r3.content)} bytes)")
        return True

    except requests.Timeout:
        print(f"[{base}] timeout")
    except Exception as e:
        print(f"[{base}] error: {e}")
    return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts-file", default="hosts.txt", help="one IP per line")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--out-dir", default="rmap_collection")
    args = ap.parse_args()

    privkey = load_priv(IDENTITY)
    hf = REPO / args.hosts_file
    if not hf.exists():
        print(f"[!] Missing hosts file {hf}. Generate it first.")
        sys.exit(1)
    hosts = [h.strip() for h in hf.read_text().splitlines() if h.strip()]

    out_dir = REPO / args.out_dir
    ok = 0
    for host in hosts:
        im = build_im_for_host(host)
        base = f"http://{host}:{args.port}"
        ok += fetch_one(base, privkey, im, out_dir)

    print(f"\nDone. Successful downloads: {ok}/{len(hosts)}")

if __name__ == "__main__":
    main()
