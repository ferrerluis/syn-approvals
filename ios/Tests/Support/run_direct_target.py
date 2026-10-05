#!/usr/bin/env python3
"""Controlled direct-TLS UI test target, never a Pi or a command executor.

Run with the test-only Python requirements and a public iOS enrollment file.
No private values, signed messages, argv, or TLS material are emitted to logs.
"""
import argparse
import asyncio
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from websockets.asyncio.server import serve

TARGET_ID = "ios-local-qa"
RELEASE_ID = "00000000000000"
COMMIT = "0" * 40

def encode(value):
    return cbor2.dumps(value, canonical=True)

def decode(data):
    value = cbor2.loads(data)
    if encode(value) != data:
        raise ValueError("noncanonical frame")
    return value

def private_file(path, data):
    with open(path, "xb") as stream:
        os.chmod(path, 0o600)
        stream.write(data)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enrollment", type=Path, required=True)
    parser.add_argument("--syn-sim", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=41782)
    args = parser.parse_args()
    enrollment = json.loads(args.enrollment.read_text())
    if enrollment.get("development") is not True:
        parser.error("this harness only accepts explicitly declared development identities")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="syn-ios-direct-") as tmp:
        directory = Path(tmp)
        subprocess.run([str(args.syn_sim), "keygen", "--private", str(directory / "target.pem"), "--public", str(directory / "target-public.pem")], check=True, capture_output=True)
        signing_key = serialization.load_pem_private_key((directory / "target.pem").read_bytes(), password=None)
        tls_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Syn controlled UI target")])
        now = datetime.now(timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(tls_key, hashes.SHA256()))
        private_file(directory / "server-key.pem", tls_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        private_file(directory / "server-cert.pem", certificate.public_bytes(serialization.Encoding.PEM))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(directory / "server-cert.pem", directory / "server-key.pem")
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cadata=enrollment["clientCertificatePEM"])
        client_certificate = x509.load_pem_x509_certificate(enrollment["clientCertificatePEM"].encode())
        client_fingerprint = client_certificate.fingerprint(hashes.SHA256())
        approval_bytes = base64.b64decode(enrollment["approvalPublicX963Base64"])
        approval_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), approval_bytes)
        approval_key_id = hashlib.sha256(approval_bytes).digest()
        profile = {"targetID": TARGET_ID, "displayName": "Controlled test target", "webSocketURL": f"wss://127.0.0.1:{args.port}",
            "targetPublicKeyBase64": base64.b64encode(signing_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).decode(),
            "serverCertificateSHA256Hex": certificate.fingerprint(hashes.SHA256()).hex(),
            "clientIdentityLabel": f"Syn iOS {enrollment['deviceID']} transport"}
        (args.output / "profile.json").write_text(json.dumps(profile))
        status = {"target": "controlled-local-fixture", "connected": False, "approvals_verified": 0, "repeat_requested": False}
        def record():
            (args.output / "status.json").write_text(json.dumps(status, indent=2) + "\n")
        record()
        async def handler(connection):
            peer = connection.transport.get_extra_info("ssl_object").getpeercert(binary_form=True)
            if hashlib.sha256(peer).digest() != client_fingerprint:
                await connection.close()
                return
            try:
                hello = {0:2,1:2,2:TARGET_ID,3:RELEASE_ID,4:COMMIT}
                await connection.send(encode({0:2,1:1,2:encode(hello)}))
                client_hello = decode(await asyncio.wait_for(connection.recv(), 5))
                if client_hello != {0:2,1:1,2:encode(hello)}:
                    raise ValueError("identity handshake mismatch")
                status["connected"] = True
                record()
                for count in range(2):
                    request_path = directory / f"request-{count}.cose"
                    subprocess.run([str(args.syn_sim), "request", "--target-private", str(directory / "target.pem"), "--target-id", TARGET_ID,
                        "--out", str(request_path), "/usr/bin/true"], check=True, capture_output=True)
                    signed = request_path.read_bytes()
                    request_path.unlink()
                    request_cose = decode(signed)
                    request = decode(request_cose.value[2])
                    deadline = time.monotonic() + 90
                    await connection.send(encode({0:2,1:2,2:signed}))
                    if count == 1:
                        status["repeat_requested"] = True
                        record()
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise ValueError("request expired")
                        wire = decode(await asyncio.wait_for(connection.recv(), remaining))
                        if wire[1] == 10:  # notifications are outside this controlled direct test
                            continue
                        if wire[0] != 2 or wire[1] != 4:
                            raise ValueError("unexpected message")
                        cose = decode(wire[2])
                        if not isinstance(cose, cbor2.CBORTag) or cose.tag != 18:
                            raise ValueError("invalid signed decision")
                        protected, unprotected, payload, signature = cose.value
                        if decode(protected) != {1:-7,4:approval_key_id} or unprotected != {} or len(signature) != 64:
                            raise ValueError("wrong signing identity")
                        r, ss = int.from_bytes(signature[:32]), int.from_bytes(signature[32:])
                        approval_key.verify(utils.encode_dss_signature(r, ss), encode(["Signature1", protected, b"", payload]), ec.ECDSA(hashes.SHA256()))
                        decision = decode(payload)
                        if (decision[0] != 2 or decision[1] != request[1] or decision[2] != hashlib.sha256(request_cose.value[2]).digest()
                            or decision[3] != TARGET_ID or decision[4] != 1 or decision[6] != approval_key_id or decision[7] != 1
                            or decision[8] != RELEASE_ID or decision[9] != COMMIT):
                            raise ValueError("decision does not bind this one request")
                        status["approvals_verified"] += 1
                        record()
                        await connection.send(encode({0:2,1:3,2:encode({0:request[1]})}))
                        break
                status["passed"] = True
                record()
                await connection.wait_closed()
            except Exception:
                status["failed"] = True
                record()
                await connection.close()
        async def run():
            async with serve(handler, "127.0.0.1", args.port, ssl=context, max_size=65536):
                await asyncio.Future()
        asyncio.run(run())

if __name__ == "__main__":
    main()
