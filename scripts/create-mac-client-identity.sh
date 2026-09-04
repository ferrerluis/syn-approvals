#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ] || [ "$#" -ne 2 ]; then
    printf '%s\n' 'usage: create-mac-client-identity.sh TARGET_ID OUTPUT_CERT_PEM' >&2
    exit 2
fi

target_id=$1
output_cert=$2
case "$target_id" in ''|*[!a-zA-Z0-9_-]*) printf '%s\n' 'Invalid target ID' >&2; exit 2;; esac
if [ -e "$output_cert" ] || [ -L "$output_cert" ]; then
    printf '%s\n' 'Refusing to overwrite an existing certificate' >&2
    exit 1
fi
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
syn_app="$repo_dir/dist/Syn.app"
test -d "$syn_app"
codesign --verify --strict "$syn_app"
identity_label="Syn ${target_id} transport"
temporary_dir=$(mktemp -d)
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM
umask 077

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -sha256 -days 365 \
    -nodes -subj "/CN=${identity_label}" \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature' \
    -addext 'extendedKeyUsage=clientAuth' \
    -keyout "$temporary_dir/client-key.pem" -out "$temporary_dir/client-cert.pem"
# Apple's PKCS#12 importer requires a nonempty password. Pass a fresh wrapping
# password through stdin to both tools, never security(1)'s visible -P argument.
p12_password=$(openssl rand -hex 32)
printf '%s' "$p12_password" | openssl pkcs12 -export -name "$identity_label" \
    -inkey "$temporary_dir/client-key.pem" -in "$temporary_dir/client-cert.pem" \
    -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
    -passout stdin -out "$temporary_dir/client.p12"
printf '%s' "$p12_password" | swift "$repo_dir/scripts/import-mac-client-identity.swift" \
    "$temporary_dir/client.p12" "$syn_app" "$HOME/Library/Keychains/login.keychain-db"
unset p12_password

install -m 0644 "$temporary_dir/client-cert.pem" "$output_cert"
printf 'client_identity_label=%s\nclient_certificate=%s\n' "$identity_label" "$output_cert"
