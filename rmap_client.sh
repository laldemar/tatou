#!/usr/bin/env bash
set -euo pipefail
SERVER_URL="${1:?server url like http://10.11.202.5:5000}"
IDENTITY="${2:?identity string, e.g. Group_03}"
CLIENT_PRIV="${3:?path to your private key .asc}"
SERVER_PUB="${4:?path to target server's public key .asc}"

tmpdir="$(mktemp -d)"; trap 'rm -rf "$tmpdir"' EXIT
export GNUPGHOME="$tmpdir/gnupg"; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"

# import keys into temp keyring
gpg --import "$CLIENT_PRIV" >/dev/null
gpg --import "$SERVER_PUB"  >/dev/null

# 1) Message 1: {"nonceClient": <u64>, "identity": "<IDENTITY>"}
NONCE_C="$(( (RANDOM<<48) ^ (RANDOM<<32) ^ (RANDOM<<16) ^ RANDOM ))"
MSG1_JSON="{\"nonceClient\": ${NONCE_C}, \"identity\": \"${IDENTITY}\"}"

# encrypt to server pub (armored) → base64
echo -n "$MSG1_JSON" | gpg --yes --armor --trust-model always --encrypt -r "$SERVER_PUB" 2>/dev/null \
  | base64 -w0 > "$tmpdir/payload1.b64"

# POST /rmap-initiate
RESP1="$(curl -fsS "$SERVER_URL/rmap-initiate" -H 'Content-Type: application/json' \
  -d "{\"payload\":\"$(cat "$tmpdir/payload1.b64")\"}")"

# extract payload field (no jq)
PAYLOAD1_B64="$(echo "$RESP1" | sed -n 's/.*"payload":"\([^"]*\)".*/\1/p')"
[ -n "$PAYLOAD1_B64" ] || { echo "Server error: $RESP1" >&2; exit 1; }

# decrypt Response 1 with client private key
echo -n "$PAYLOAD1_B64" | base64 -d | gpg --yes --decrypt 2>/dev/null > "$tmpdir/resp1.json"

# parse nonces
NONCE_C2="$(sed -n 's/.*"nonceClient":[[:space:]]*\([0-9]*\).*/\1/p' "$tmpdir/resp1.json")"
NONCE_S="$(sed -n 's/.*"nonceServer":[[:space:]]*\([0-9]*\).*/\1/p' "$tmpdir/resp1.json")"
[ "$NONCE_C2" = "$NONCE_C" ] || { echo "Nonce mismatch" >&2; exit 1; }

# 2) Message 2: {"nonceServer": <u64>}
MSG2_JSON="{\"nonceServer\": ${NONCE_S}}"
echo -n "$MSG2_JSON" | gpg --yes --armor --trust-model always --encrypt -r "$SERVER_PUB" 2>/dev/null \
  | base64 -w0 > "$tmpdir/payload2.b64"

RESP2="$(curl -fsS "$SERVER_URL/rmap-get-link" -H 'Content-Type: application/json' \
  -d "{\"payload\":\"$(cat "$tmpdir/payload2.b64")\"}")"

LINK="$(echo "$RESP2" | sed -n 's/.*"link":"\([^"]*\)".*/\1/p')"
[ -n "$LINK" ] || { echo "Server error: $RESP2" >&2; exit 1; }

echo "Link: $LINK"
curl -fsS "$LINK" -o "${IDENTITY}.pdf"
echo "Saved: ${IDENTITY}.pdf"
