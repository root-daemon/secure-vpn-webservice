#!/usr/bin/env bash
# Exports the Client VPN configuration and embeds a client certificate/key.
#   scripts/make-ovpn.sh [client-name]   (default: client1)
# Import the resulting vpn-clients/<name>.ovpn into the AWS VPN Client or
# any OpenVPN client.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKI="${PKI_DIR:-$ROOT/pki}"
NAME="${1:-client1}"
OUT_DIR="$ROOT/vpn-clients"

[[ -f "$PKI/issued/$NAME.crt" ]] || { echo "No certificate for $NAME. Run: scripts/pki.sh client $NAME" >&2; exit 1; }

endpoint_id="${CLIENT_VPN_ENDPOINT_ID:-$(terraform -chdir="$ROOT/terraform" output -raw client_vpn_endpoint_id)}"
region="${AWS_REGION:-$(terraform -chdir="$ROOT/terraform" output -raw region)}"

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"
out="$OUT_DIR/$NAME.ovpn"

umask 077
aws ec2 export-client-vpn-client-configuration \
  --region "$region" --client-vpn-endpoint-id "$endpoint_id" \
  --output text > "$out"

{
  echo
  echo "<cert>"
  openssl x509 -in "$PKI/issued/$NAME.crt"
  echo "</cert>"
  echo "<key>"
  cat "$PKI/issued/$NAME.key"
  echo "</key>"
} >> "$out"

echo "[ovpn] wrote $out"
echo "[ovpn] Import it into the AWS VPN Client (https://aws.amazon.com/vpn/client-vpn-download/) and connect."
