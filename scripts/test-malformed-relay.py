#!/usr/bin/env python3
"""One-shot, root-only live fault injection. Never execute or log a request.

Use only with shadow sudo, retained root recovery, and an armed rollback timer.
Stop syn-agent first; this deliberately occupies its usual local socket. Restart
syn-agent immediately afterward. Existing sockets are never replaced.
"""

import os
import socket
import stat
import struct

SOCKET_PATH = "/run/syn/agent.sock"
MAX_FRAME = 65536


def read_exact(connection, size):
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise RuntimeError("request ended early")
        result.extend(chunk)
    return result


def main():
    if os.geteuid() != 0:
        raise SystemExit("This fault-injection fixture requires root")
    parent = os.stat("/run/syn", follow_symlinks=False)
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o077:
        raise SystemExit("Create /run/syn as root:root 0700 after stopping syn-agent")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.settimeout(45)
        server.bind(SOCKET_PATH)  # Fail if anything already occupies this path.
        identity = os.stat(SOCKET_PATH, follow_symlinks=False)
        os.chmod(SOCKET_PATH, 0o600)
        try:
            server.listen(1)
            print("malformed-relay-ready", flush=True)
            connection, _ = server.accept()
            with connection:
                connection.settimeout(5)
                _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != 0:
                    raise RuntimeError("unexpected local peer")
                size = int.from_bytes(read_exact(connection, 4), "big")
                if not 0 < size <= MAX_FRAME:
                    raise RuntimeError("request size rejected")
                read_exact(connection, size)  # Discard; no parsing, output, or persistence.
                # A bounded frame containing invalid canonical CBOR.
                connection.sendall(b"\x00\x00\x00\x01\xff")
                print("malformed-response-sent", flush=True)
        finally:
            current = os.stat(SOCKET_PATH, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                os.unlink(SOCKET_PATH)


if __name__ == "__main__":
    main()
