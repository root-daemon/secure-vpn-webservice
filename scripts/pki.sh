#!/usr/bin/env bash
# Private PKI for the project (plain OpenSSL, no extra tools).
#
#   scripts/pki.sh init                 # CA + VPN server cert + web cert + client1
#   scripts/pki.sh client <name>        # issue a client certificate for a user
#   scripts/pki.sh revoke <name>        # revoke a client cert and rebuild the CRL
#   scripts/pki.sh push-crl             # upload the CRL to the Client VPN endpoint
#   scripts/pki.sh list                 # show issued certificates and status
#
# Output lives in ./pki (git-ignored). Keep pki/private safe: it holds the CA key.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKI="${PKI_DIR:-$ROOT/pki}"
APP_FQDN="${APP_FQDN:-app.securevpn.internal}"
VPN_SERVER_CN="${VPN_SERVER_CN:-vpn-server.securevpn.internal}"
CA_CN="${CA_CN:-SecureVPN Private Root CA}"
KEY_BITS=2048 # AWS Client VPN supports RSA 1024/2048 for mutual auth
export SAN="${SAN:-DNS:unused.invalid}"

log() { printf '\033[1;34m[pki]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[pki] %s\033[0m\n' "$*" >&2; exit 1; }

write_config() {
  cat > "$PKI/openssl.cnf" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = $PKI
database         = \$dir/index.txt
new_certs_dir    = \$dir/newcerts
certificate      = \$dir/ca/ca.crt
private_key      = \$dir/private/ca.key
serial           = \$dir/serial
crlnumber        = \$dir/crlnumber
default_md       = sha256
default_days     = 825
default_crl_days = 180
policy           = policy_any
unique_subject   = no
email_in_dn      = no

[ policy_any ]
commonName = supplied

[ req ]
distinguished_name = req_dn
prompt             = no

[ req_dn ]
CN = placeholder

[ v3_ca ]
basicConstraints       = critical, CA:true
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always, issuer

[ server_ext ]
basicConstraints       = CA:false
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid, issuer
subjectAltName         = \$ENV::SAN

[ client_ext ]
basicConstraints       = CA:false
keyUsage               = critical, digitalSignature
extendedKeyUsage       = clientAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid, issuer
EOF
}

init_ca() {
  if [[ -f "$PKI/ca/ca.crt" ]]; then
    log "CA already exists at $PKI/ca/ca.crt (skipping)"
    return
  fi
  log "Creating private CA: $CA_CN"
  mkdir -p "$PKI"/{ca,issued,private,newcerts,crl,csr}
  chmod 700 "$PKI/private"
  : > "$PKI/index.txt"
  echo "unique_subject = no" > "$PKI/index.txt.attr"
  openssl rand -hex 16 > "$PKI/serial"
  echo 1000 > "$PKI/crlnumber"
  write_config

  openssl req -x509 -new -newkey "rsa:$KEY_BITS" -nodes -sha256 -days 3650 \
    -keyout "$PKI/private/ca.key" -out "$PKI/ca/ca.crt" \
    -subj "/CN=$CA_CN" -config "$PKI/openssl.cnf" -extensions v3_ca 2>/dev/null
  chmod 600 "$PKI/private/ca.key"
}

# issue <name> <common-name> <server|client> [san]
issue() {
  local name="$1" cn="$2" kind="$3" san="${4:-DNS:unused.invalid}"
  if [[ -f "$PKI/issued/$name.crt" ]]; then
    log "$name already issued (skipping)"
    return
  fi
  log "Issuing $kind certificate: $name (CN=$cn)"
  openssl req -new -newkey "rsa:$KEY_BITS" -nodes -sha256 \
    -keyout "$PKI/issued/$name.key" -out "$PKI/csr/$name.csr" \
    -subj "/CN=$cn" -config "$PKI/openssl.cnf" 2>/dev/null
  chmod 600 "$PKI/issued/$name.key"
  SAN="$san" openssl ca -batch -notext -config "$PKI/openssl.cnf" \
    -extensions "${kind}_ext" -in "$PKI/csr/$name.csr" -out "$PKI/issued/$name.crt" 2>/dev/null
}

gen_crl() {
  openssl ca -gencrl -config "$PKI/openssl.cnf" -out "$PKI/crl/crl.pem" 2>/dev/null
  log "CRL written to $PKI/crl/crl.pem"
}

require_ca() { [[ -f "$PKI/ca/ca.crt" ]] || die "No CA found. Run: scripts/pki.sh init"; }

valid_name() { [[ "$1" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$ ]] || die "Invalid name '$1' (letters, digits, . _ - only)"; }

cmd="${1:-}"
case "$cmd" in
  init)
    command -v openssl >/dev/null || die "openssl is required"
    init_ca
    issue vpn-server "$VPN_SERVER_CN" server "DNS:$VPN_SERVER_CN"
    issue web "$APP_FQDN" server "DNS:$APP_FQDN"
    issue client1 client1 client
    gen_crl
    log "Done. Trust $PKI/ca/ca.crt in your browser/OS to get a valid padlock for https://$APP_FQDN"
    ;;
  client)
    require_ca
    valid_name "${2:-}"
    issue "$2" "$2" client
    log "Next: scripts/make-ovpn.sh $2"
    ;;
  revoke)
    require_ca
    valid_name "${2:-}"
    [[ -f "$PKI/issued/$2.crt" ]] || die "No certificate named $2"
    openssl ca -config "$PKI/openssl.cnf" -revoke "$PKI/issued/$2.crt" 2>/dev/null
    mv "$PKI/issued/$2.crt" "$PKI/issued/$2.crt.revoked"
    mv "$PKI/issued/$2.key" "$PKI/issued/$2.key.revoked"
    gen_crl
    log "Revoked $2. Run 'scripts/pki.sh push-crl' to enforce it on the VPN endpoint."
    ;;
  push-crl)
    require_ca
    [[ -f "$PKI/crl/crl.pem" ]] || gen_crl
    endpoint_id="${CLIENT_VPN_ENDPOINT_ID:-$(terraform -chdir="$ROOT/terraform" output -raw client_vpn_endpoint_id)}"
    region="${AWS_REGION:-$(terraform -chdir="$ROOT/terraform" output -raw region)}"
    aws ec2 import-client-vpn-client-certificate-revocation-list \
      --region "$region" --client-vpn-endpoint-id "$endpoint_id" \
      --certificate-revocation-list "file://$PKI/crl/crl.pem" >/dev/null
    log "CRL imported into $endpoint_id. Revoked clients are now rejected."
    ;;
  list)
    require_ca
    printf '%-8s %-14s %s\n' STATUS EXPIRES SUBJECT
    awk -F'\t' '{ s = ($1 == "V") ? "valid" : ($1 == "R") ? "revoked" : $1; printf "%-8s %-14s %s\n", s, $2, $6 }' "$PKI/index.txt"
    ;;
  *)
    sed -n '2,10p' "$0"
    exit 1
    ;;
esac
