# Security test matrix

| Scenario | Required outcome |
| --- | --- |
| Valid request + fresh user-presence approval | Execute original invocation once |
| Explicit device-signed denial | Deny; no password fallback |
| No response for 300 seconds, interactive | Invoke PAM fallback |
| No response, non-interactive | Deny without prompt |
| Modified request or decision | Hard deny |
| Wrong target/request ID/hash | Hard deny |
| Replay or wrong live-request binding | Hard deny; no password fallback |
| Valid late approval | Reject approval; cannot override expiry/PAM outcome |
| Late invalid signature or signed denial | Hard deny; no password fallback |
| Slow socket header/body or blocked write | One absolute deadline; progress never restarts it |
| EOF partway through a frame | Malformed; no password fallback |
| Unknown protocol/adapter/schema | Hard deny |
| Shell, interpreter, or sudo mode excluded from remote approval; interactive terminal | Fresh local PAM; execute original invocation only on success, without notification or remote wait |
| Same restricted command with `sudo -n`, no terminal, a pipe, or invalid/raw terminal | Deny without PAM or notification |
| Restricted command; wrong/canceled password or PAM error | Deny; no remote request or fallback to an earlier approval |
| Restricted command repeated after successful local password | Require fresh authentication again; no sudo timestamp reuse |
| Invalid configuration, identity, or final environment | Hard deny before remote approval or manual authentication |
| Ctrl-C / closed request connection | Cancel and reject late decision |
| Compromised agent fabricates allow | Plug-in signature verification rejects |
| Agent is unavailable | Timeout path only; never implicit allow |
| Direct sudo-rs provider with NOPASSWD | Cannot elevate; setuid removed persistently |
| Syn plug-in missing/corrupt | Managed sudo fails closed |
| Package upgrade | Provider override and plug-in coupling remain valid |
| Interrupted install | No ungated passwordless sudo state |
| Mac Touch ID unavailable | macOS may offer account password |
| Mac sleeps | No remote approval; timeout fallback |

Parser fuzz targets cover COSE, CBOR payloads, local framing, WebSocket messages, sudo `key=value` arrays, invalid byte strings, oversize collections, and FFI panic boundaries.
