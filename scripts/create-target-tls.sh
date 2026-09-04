#!/bin/sh
set -eu

if [ "$(uname -s)" != Linux ] || [ "$#" -ne 3 ]; then
    printf '%s\n' 'usage: create-target-tls.sh MAGIC_DNS_NAME MAC_CLIENT_CERT_PEM OUTPUT_DIR' >&2
    exit 2
fi

magic_dns_name=$1
client_certificate=$2
output_dir=$3
case "$magic_dns_name" in ''|*[!a-zA-Z0-9.-]*) printf '%s\n' 'Invalid target DNS name' >&2; exit 2;; esac
for name in target-key.pem target-cert.pem approver-ca.pem; do
    if [ -e "$output_dir/$name" ] || [ -L "$output_dir/$name" ]; then
        printf '%s\n' 'Refusing to overwrite existing TLS material' >&2
        exit 1
    fi
done
temporary_dir=$(mktemp -d)
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM
umask 077

test -f "$client_certificate"
install -d -m 0750 "$output_dir"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -sha256 -days 365 \
    -nodes -subj "/CN=${magic_dns_name}" \
    -addext "subjectAltName=DNS:${magic_dns_name}" \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature' \
    -addext 'extendedKeyUsage=serverAuth' \
    -keyout "$temporary_dir/target-key.pem" -out "$temporary_dir/target-cert.pem"
install -m 0640 "$temporary_dir/target-key.pem" "$output_dir/target-key.pem"
install -m 0644 "$temporary_dir/target-cert.pem" "$output_dir/target-cert.pem"
install -m 0644 "$client_certificate" "$output_dir/approver-ca.pem"
if getent group syn >/dev/null 2>&1; then
    chgrp syn "$output_dir" "$output_dir/target-key.pem" "$output_dir/target-cert.pem" "$output_dir/approver-ca.pem"
fi

printf '%s\n' 'Target TLS material created. Use synctl pair profile to produce the pinned Mac profile.'
