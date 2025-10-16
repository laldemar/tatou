#!/usr/bin/env python3
import os, sys, json, base64, argparse, time
from pathlib import Path
import requests
from pgpy import PGPKey, PGPMessage

# ---- where am I? adjust paths for being inside tatou/server/ ----
HERE = Path(__file__).resolve().parent  # .../tatou/server
if (HERE / "keys" / "clients").is_dir():
    # script is inside server/
    KEYS = HERE / "keys"                    # .../tatou/server/keys
    PROJECT_ROOT = HERE.parent              # .../tatou
else:
    # script is at project root
    PROJECT_ROOT = HERE                     # .../tatou
    KEYS = PROJECT_ROOT / "server" / "keys" # .../tatou/server/keys

CLIENTS = KEYS / "clients"
OUT_DIR = PROJECT_ROOT / "rmap_pdf"         # save to tatou/rmap_pdf

# ---- helpers ----
def load_priv() -> PGPKey:
    # you said your private key is exactly this filename
    priv_path = CLIENTS / "Group_05_private.asc"
    if not priv_path.exists():
        print(f"[!] Missing private key: {priv_path}")
        sys.exit(2)
    key, _ = PGPKey.from_file(str(priv_path))
    pw = os.environ.get("CLIENT_PASSPHRASE")
    if key.is_protected and pw:
        key.unlock(pw)
    return key

def build_identity_manager():
    try:
        from rmap.identity_manager import IdentityManager
    except ModuleNotFoundError:
        sys.path.insert(0, str(PROJECT_ROOT / "server" / "src"))
        from rmap.identity_manager import IdentityManager  # type: ignore

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

def try_message1(base_url: str, im, privkey: PGPKey, identity: str):
    candidates = [
        ("rmap-initiate", "rmap-get-link"),
        ("rmap/initiate", "rmap/get-link"),
    ]
    nonce_client = int(time.time() * 1_000_000) & 0xFFFFFFFF
    msg1_plain = {"nonceClient": nonce_client, "identity": identity}
    payload = im.encrypt_for_server(msg1_plain)

    for ep_init, ep_link in candidates:
        url = f"{base_url}/{ep_init}"
        try:
            r = requests.post(url, json={"payload": payload}, timeout=8)
            if r.status_code != 200:
                print(f"[{base_url}] {ep_init} → {r.status_code}")
                continue
            if not r.headers.get("content-type","").lower().startswith("application/json"):
                print(f"[{base_url}] {ep_init} returned non-JSON")
                continue
            j = r.json()
            if "payload" not in j:
                print(f"[{base_url}] {ep_init} missing 'payload'")
                continue
            armored = base64.b64decode(j["payload"]).decode("utf-8")
            resp1_plain = json.loads(privkey.decrypt(PGPMessage.from_blob(armored)).message)
            return ep_init, ep_link, resp1_plain
        except Exception as e:
            print(f"[{base_url}] {ep_init} error: {e}")
    return None, None, None

def save_pdf(resp, host_ip: str) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cd = resp.headers.get("content-disposition", "")
    if "filename=" in cd:
        fname = cd.split("filename=",1)[1].strip().strip('"').strip("'")
    else:
        fname = f"{host_ip}.pdf"
    dst = OUT_DIR / fname
    dst.write_bytes(resp.content)
    return dst

def main():
    parser = argparse.ArgumentParser(description="Fetch one group's PDF over RMAP (simple).")
    parser.add_argument("host", help="target host IP, e.g. 10.11.202.6")
    parser.add_argument("--port", type=int, default=5000)
    # your identity is fixed to Group_05, that’s what their server needs to look up
    args = parser.parse_args()

    identity = "Group_05"
    privkey = load_priv()
    im = build_identity_manager()

    base = f"http://{args.host}:{args.port}"
    print(f"[i] KEYS={KEYS}")
    print(f"[i] OUT_DIR={OUT_DIR}")
    print(f"[i] base={base} identity={identity}")

    ep_init, ep_link, resp1_plain = try_message1(base, im, privkey, identity)
    if not ep_init:
        print(f"[!] No working initiate endpoint at {base} (tried /rmap-initiate and /rmap/initiate).")
        sys.exit(1)

    try:
        nonce_server = int(resp1_plain["nonceServer"])
    except Exception:
        print("[!] Could not read nonceServer from Response 1.")
        sys.exit(1)

    url2 = f"{base}/{ep_link}"
    r2 = requests.post(url2, json={"payload": im.encrypt_for_server({"nonceServer": nonce_server})}, timeout=8)
    if r2.status_code != 200:
        print(f"[{base}] {ep_link} → {r2.status_code} {r2.text[:200]}")
        sys.exit(1)
    if not r2.headers.get("content-type","").lower().startswith("application/json"):
        print(f"[{base}] {ep_link} returned non-JSON")
        sys.exit(1)
    j2 = r2.json()
    if "link" not in j2:
        print(f"[{base}] {ep_link} missing 'link'")
        sys.exit(1)

    r3 = requests.get(j2["link"], timeout=12)
    if r3.status_code != 200 or "application/pdf" not in r3.headers.get("content-type","").lower():
        print(f"[{base}] download failed: {r3.status_code} {r3.text[:200]}")
        sys.exit(1)

    dst = save_pdf(r3, args.host)
    print(f"[✓] Saved → {dst} ({len(r3.content)} bytes)")

if __name__ == "__main__":
    main()
