#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    printf 'usage: %s RECOVERY_SERVICE\n' "$0" >&2
    exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' 'recovery service context test must run as root' >&2
    exit 2
fi
if [ ! -x /usr/bin/sudo.ws ]; then
    printf '%s\n' '/usr/bin/sudo.ws is required for the recovery service context test' >&2
    exit 2
fi

source_unit=$1
test_name="syn-recovery-context-test-$$.service"
test_unit="/run/systemd/system/$test_name"

cleanup() {
    systemctl stop "$test_name" >/dev/null 2>&1 || true
    systemctl reset-failed "$test_name" >/dev/null 2>&1 || true
    rm -f "$test_unit"
    systemctl daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

# Run the same harmless sudo.ws validation under the packaged recovery unit's
# effective sandbox. Disable retries so a regression fails once and promptly.
awk '
    /^Description=/ { print "Description=Syn recovery service execution-context test"; next }
    /^ExecStart=/ { print "ExecStart=/usr/bin/sudo.ws -V"; next }
    /^Restart=/ { print "Restart=no"; next }
    { print }
' "$source_unit" > "$test_unit"
chmod 0644 "$test_unit"

systemctl daemon-reload
if ! systemctl start "$test_name"; then
    journalctl --no-pager --unit "$test_name" --lines 50 >&2 || true
    exit 1
fi

test "$(systemctl show "$test_name" --property=NoNewPrivileges --value)" = no
test "$(systemctl show "$test_name" --property=Result --value)" = success
test "$(systemctl show "$test_name" --property=ExecMainStatus --value)" = 0
