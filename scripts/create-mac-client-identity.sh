#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ] || [ "$#" -ne 2 ]; then
    printf '%s\n' 'usage: create-mac-client-identity.sh TARGET_ID OUTPUT_CERT_PEM' >&2
    exit 2
fi

target_id=$1
output_cert=$2
identity_label="Syn ${target_id} transport"
temporary_dir=$(mktemp -d)
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM
p12_password=$(openssl rand -hex 32)

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -days 365 \
    -nodes -subj "/CN=${identity_label}" \
    -keyout "$temporary_dir/client-key.pem" -out "$temporary_dir/client-cert.pem"
openssl pkcs12 -export -name "$identity_label" \
    -inkey "$temporary_dir/client-key.pem" -in "$temporary_dir/client-cert.pem" \
    -passout "pass:$p12_password" -out "$temporary_dir/client.p12"
security import "$temporary_dir/client.p12" -k "$HOME/Library/Keychains/login.keychain-db" \
    -P "$p12_password" -T /usr/bin/security
unset p12_password

install -m 0644 "$temporary_dir/client-cert.pem" "$output_cert"
printf 'client_identity_label=%s\nclient_certificate=%s\n' "$identity_label" "$output_cert"
