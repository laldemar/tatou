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

IDENTITY = "Group_05"            # ← make sure this matches your client key name and what other groups expect
SUBNET_PREFIX = "10.11.202"      # VLAN subnet to scan by default

# Try common endpoint spellings some groups used
ENDPOINT_CANDIDATES = [
    ("rmap-initiate", "rmap-get-link"),
    ("rmap/initiate", "rmap/get-link"),
    ("api/rmap-initiate", "api/rmap-get-link"),
    ("api/rmap/initiate", "api/rmap/get-link"),
]

SCHEMES = ("http", "https")
PORTS = (5000, 8080, 80)

def load_priv(identity: str):
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

def try_initiate(bases: list[str], im: IdentityManager, nonce_client: int):
    """Try all base URLs and endpoint variants until /initiate works.
       Returns (base, ep_initiate, ep_getlink, resp1_plain) or (None,...)."""
    m1_plain = {"nonceClient": nonce_client, "identity": IDENTITY}
    payload = im.encrypt_for_server(m1_plain)
    for base in bases:
        for ep_init, ep_link in ENDPOINT_CANDIDATES:
            url = f"{base.rstrip('/')}/{ep_init}"
            try:
                r = requests.post(url, json={"payload": payload}, timeout=10)
                if r.status_code != 200:
                    # Helpful for debugging misroutes
                    if r.status_code in (301, 302, 307, 308):
                        print(f"[{base}] redirect at {url} → {r.headers.get('Location')}")
                    else:
                        # print small snippet for 404/500s
                        print(f"[{base}] {ep_init} failed: {r.status_code} {r.text[:120]!r}")
                    continue
                j = r.json() if r.headers.get("content-type","").lower().startswith("application/json") else {}
                if "payload" not in j:
                    print(f"[{base}] {ep_init} returned 200 but missing 'payload'.")
                    continue
                armored = base64.b64decode(j["payload"]).decode("utf-8")
                resp1_plain = json.loads(privkey.decrypt(PGPMessage.from_blob(armored)).message)
                return base, ep_init, ep_link, resp1_plain
            except requests.Timeout:
                print(f"[{base}] {ep_init} timeout")
            except Exception as e:
                print(f"[{base}] {ep_init} error: {e}")
    return None, None, None, None

def fetch_one(host: str, privkey: PGPKey, im: IdentityManager, out_dir: Path) -> bool:
    # Build list of base URLs to try (scheme × port)
    bases = []
    for scheme in SCHEMES:
        for port in PORTS:
            bases.append(f"{scheme}://{host}:{port}")
        # also try default port without explicit :port
        bases.append(f"{scheme}://{host}")

    try:
        # Message 1 (try variants)
        nonce_client = int(time.time() * 1_000_000) & 0xFFFFFFFF
        base, ep_init, ep_link, resp1_plain = try_initiate(bases, im, nonce_client)
        if not base:
            print(f"[{host}] Could not find a working initiate endpoint.")
            return False

        nonce_server = int(resp1_plain["nonceServer"])
        print(f"[{base}] using endpoints: /{ep_init} + /{ep_link}")

        # Message 2
        url2 = f"{base.rstrip('/')}/{ep_link}"
        r2 = requests.post(url2,
                           json={"payload": im.encrypt_for_server({"nonceServer": nonce_server})},
                           timeout=10)
        j2 = r2.json() if r2.headers.get("content-type","").lower().startswith("application/json") else {}
        if r2.status_code != 200 or "link" not in j2:
            print(f"[{base}] {ep_link} failed: {r2.status_code} {r2.text[:200]}")
            return False

        # Download once
        r3 = requests.get(j2["link"], timeout=15)
        if r3.status_code != 200 or "application/pdf" not in r3.headers.get("content-type","").lower():
            print(f"[{base}] download failed: {r3.status_code} {r3.text[:200]}")
            return False

        ip = host
        out_dir.mkdir(parents=True, exist_ok=True)
        # if the remote uses their own group name, keep your identity in filename to track who pulled it
        dest = out_dir / f"{ip}__{IDENTITY}.pdf"
        dest.write_bytes(r3.content)
        print(f"[{base}] OK → {dest} ({len(r3.content)} bytes)")
        return True

    except requests.Timeout:
        print(f"[{host}] timeout")
    except Exception as e:
        print(f"[{host}] error: {e}")
    return False

def auto_scan(subnet_prefix: str, ports: tuple[int, ...]) -> list[str]:
    print(f"[i] hosts.txt not found → scanning {subnet_prefix}.1..254")
    live = set()
    for i in range(1, 255):
        h = f"{subnet_prefix}.{i}"
        for p in ports:
            try:
                r = requests.get(f"http://{h}:{p}/healthz", timeout=1)
                if r.status_code == 200:
                    live.add(h)
                    break
            except Exception:
                pass
    print(f"[i] found {len(live)} live host(s)")
    return sorted(live)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", help="fetch from a single IP (skips hosts.txt)")
    ap.add_argument("--hosts-file", default="hosts.txt", help="one IP per line")
    ap.add_argument("--ports", default="5000,8080,80", help="ports to try (comma-separated)")
    ap.add_argument("--out-dir",
                    default=f"rmap_collection/{time.strftime('%Y%m%d_%H%M%S')}",
                    help="output directory (default includes timestamp)")
    ap.add_argument("--no-scan", action="store_true",
                    help="if hosts.txt is missing, do not scan; just error out")
    args = ap.parse_args()

    # Make PORTS overridable from CLI
    global PORTS
    try:
        PORTS = tuple(int(x) for x in args.ports.split(",") if x.strip())
    except ValueError:
        print("[!] --ports must be comma-separated integers, e.g. 5000,8080,80")
        sys.exit(2)

    global privkey
    privkey = load_priv(IDENTITY)

    # Build host list
    if args.host:
        hosts = [args.host.strip()]
    else:
        hf = REPO / args.hosts_file
        if hf.exists():
            hosts = [h.strip() for h in hf.read_text().splitlines() if h.strip()]
        else:
            if args.no_scan:
                print(f"[!] Missing hosts file {hf}.")
                sys.exit(1)
            hosts = auto_scan(SUBNET_PREFIX, PORTS)
            (REPO / args.hosts_file).write_text("\n".join(hosts) + ("\n" if hosts else ""))

    out_dir = REPO / args.out_dir
    ok = 0
    for host in hosts:
        im = build_im_for_host(host)
        ok += 1 if fetch_one(host, privkey, im, out_dir) else 0

    print(f"\nDone. Successful downloads: {ok}/{len(hosts)}")

if __name__ == "__main__":
    main()
