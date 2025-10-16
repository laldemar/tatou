#!/usr/bin/env python3
import os, sys, json, base64, argparse, time
from pathlib import Path
import requests
from pgpy import PGPKey, PGPMessage

# ---------- Layout detection (works whether file is in project root or server/) ----------
HERE = Path(__file__).resolve().parent
if (HERE / "keys" / "clients").is_dir():
    # script is inside server/
    PROJECT_ROOT = HERE.parent
    KEYS = HERE / "keys"
else:
    # script is at project root
    PROJECT_ROOT = HERE
    KEYS = PROJECT_ROOT / "server" / "keys"

CLIENTS = KEYS / "clients"
SERVERS = KEYS / "servers"      # optional per-host server pub keys
OUT_DIR = PROJECT_ROOT / "rmap_pdf"

DEFAULT_IDENTITY = "Group_05"   # your group name as others stored it

# ---------- Crypto helpers ----------
def load_priv() -> PGPKey:
    priv_path = CLIENTS / f"{DEFAULT_IDENTITY}_private.asc"
    if not priv_path.exists():
        print(f"[!] Missing private key: {priv_path}")
        sys.exit(2)
    key, _ = PGPKey.from_file(str(priv_path))
    pw = os.environ.get("CLIENT_PASSPHRASE")
    if key.is_protected:
        if not pw:
            print("[!] Private key is protected. Set CLIENT_PASSPHRASE env var.")
            sys.exit(2)
        key.unlock(pw)
    return key

def derive_group_name_from_ip(ip: str) -> str:
    try:
        n = int(ip.strip().split(".")[-1])
        return f"Group_{n:02d}"
    except Exception:
        return ""  # unknown

def pick_server_public_key(host: str) -> Path:
    # 1) per-host server key by IP
    by_ip = SERVERS / f"{host}.asc"
    if by_ip.exists():
        return by_ip
    # 2) many teams reused the same pair; try their client pub by group number
    grp = derive_group_name_from_ip(host)
    if grp:
        candidate = CLIENTS / f"{grp}.asc"
        if candidate.exists():
            print(f"[i] Using client pub as server pub for {host}: {candidate.name}")
            return candidate
    # 3) last resort: our own server public (often wrong for other teams, but try)
    fallback = KEYS / "server_public.asc"
    print(f"[!] No target server key for {host}. Falling back to {fallback.name} (may fail).")
    return fallback

def build_identity_manager_for_host(host: str):
    try:
        from rmap.identity_manager import IdentityManager
    except ModuleNotFoundError:
        sys.path.insert(0, str(PROJECT_ROOT / "server" / "src"))
        from rmap.identity_manager import IdentityManager  # type: ignore

    server_pub = pick_server_public_key(host)
    server_priv = KEYS / "server_private.asc"  # not actually used for the client handshake, but IM requires a path
    if not (CLIENTS.is_dir() and server_pub.exists() and server_priv.exists()):
        print(f"[!] Missing key material. Checked:\n  - {CLIENTS}\n  - {server_pub}\n  - {server_priv}")
        sys.exit(2)

    return IdentityManager(
        client_keys_dir=CLIENTS,
        server_public_key_path=server_pub,
        server_private_key_path=server_priv,
        server_private_key_passphrase=os.environ.get("RMAP_SERVER_PRIV_PASSPHRASE"),
    )

# ---------- Protocol helpers ----------
def try_message1(base_url: str, im, privkey: PGPKey, identity: str):
    """
    Try common endpoint paths. POST first; if 405, retry GET ?payload=...
    Returns (ep_init, ep_link, resp1_plain) or (None, None, None).
    """
    candidates = [
        ("rmap-initiate", "rmap-get-link"),
        ("rmap/initiate", "rmap/get-link"),
        ("api/rmap-initiate", "api/rmap-get-link"),
        ("api/rmap/initiate", "api/rmap/get-link"),
        ("rmap/api/initiate", "rmap/api/get-link"),
        ("rmap/v1/initiate", "rmap/v1/get-link"),
        ("api/v1/rmap-initiate", "api/v1/rmap-get-link"),
    ]

    nonce_client = int(time.time() * 1_000_000) & 0xFFFFFFFF
    msg1_plain = {"nonceClient": nonce_client, "identity": identity}
    enc = im.encrypt_for_server(msg1_plain)

    for ep_init, ep_link in candidates:
        url = f"{base_url}/{ep_init}"
        try:
            # POST first
            r = requests.post(url, json={"payload": enc}, timeout=8)
            if r.status_code == 405:
                # retry GET with ?payload=
                r = requests.get(url, params={"payload": enc}, timeout=8)

            if r.status_code == 200 and r.headers.get("content-type", "").lower().startswith("application/json"):
                j = r.json()
                if "payload" in j:
                    armored = base64.b64decode(j["payload"]).decode("utf-8")
                    resp1_plain = json.loads(privkey.decrypt(PGPMessage.from_blob(armored)).message)
                    print(f"[i] Using endpoints: /{ep_init} + /{ep_link}")
                    return ep_init, ep_link, resp1_plain
            else:
                print(f"[{base_url}] {ep_init} → {r.status_code}")
        except requests.Timeout:
            print(f"[{base_url}] {ep_init} timeout")
        except Exception as e:
            print(f"[{base_url}] {ep_init} error: {e}")

    return None, None, None

def save_pdf(resp, host_ip: str) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cd = resp.headers.get("content-disposition", "")
    if "filename=" in cd:
        fname = cd.split("filename=", 1)[1].strip().strip('"').strip("'")
    else:
        fname = f"{host_ip}.pdf"
    dst = OUT_DIR / fname
    dst.write_bytes(resp.content)
    return dst

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description="Fetch one group's PDF over RMAP (robust client).")
    ap.add_argument("host", help="target host IP, e.g. 10.11.202.6")
    ap.add_argument("--port", type=int, default=5000, help="port (default 5000)")
    ap.add_argument("--identity", default=DEFAULT_IDENTITY, help="your identity string (how others stored your pub key)")
    args = ap.parse_args()

    privkey = load_priv()
    im = build_identity_manager_for_host(args.host)

    base = f"http://{args.host}:{args.port}"
    print(f"[i] KEYS={KEYS}")
    print(f"[i] OUT_DIR={OUT_DIR}")
    print(f"[i] base={base} identity={args.identity}")

    ep_init, ep_link, resp1_plain = try_message1(base, im, privkey, args.identity)
    if not ep_init:
        print(f"[!] No working initiate endpoint at {base}. Tried several variants.")
        sys.exit(1)

    # Message 2
    try:
        nonce_server = int(resp1_plain["nonceServer"])
    except Exception:
        print("[!] Could not read nonceServer from Response 1.")
        sys.exit(1)

    url2 = f"{base}/{ep_link}"
    enc2 = im.encrypt_for_server({"nonceServer": nonce_server})

    r2 = requests.post(url2, json={"payload": enc2}, timeout=8)
    if r2.status_code == 405:
        r2 = requests.get(url2, params={"payload": enc2}, timeout=8)

    if r2.status_code != 200 or not r2.headers.get("content-type", "").lower().startswith("application/json"):
        print(f"[{base}] {ep_link} failed: {r2.status_code} {r2.text[:200]}")
        sys.exit(1)

    j2 = r2.json()
    if "link" not in j2:
        print(f"[{base}] {ep_link} missing 'link' in response: {j2}")
        sys.exit(1)

    # Download
    r3 = requests.get(j2["link"], timeout=15)
    if r3.status_code != 200 or "application/pdf" not in r3.headers.get("content-type", "").lower():
        print(f"[{base}] download failed: {r3.status_code} {r3.text[:200]}")
        sys.exit(1)

    dst = save_pdf(r3, args.host)
    print(f"[✓] Saved → {dst} ({len(r3.content)} bytes)")

if __name__ == "__main__":
    main()
