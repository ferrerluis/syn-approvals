# Recovery and uninstall

Read this before arming the sudo integration. Keep console or Ubuntu recovery access to the target.

## Normal timeout fallback

If no valid Mac decision arrives after 90 seconds, an interactive invocation asks for the normal Ubuntu password. Explicit denials and integrity errors do not fall back.

## Recovery mode

Before changing sudo behavior, prove that systemd can fire a harmless one-shot timer, then arm an absolute recovery deadline:

```sh
sudo synctl recovery prove --seconds 2 --apply
sudo synctl recovery arm --minutes 15 --apply
synctl --json recovery status
```

The generated timer uses an absolute wall-clock deadline with `Persistent=true`, so a reboot does not restart the 15-minute window. Its timestamp-only state is root-owned but readable so ordinary `status` and `doctor` calls work; install state and backups remain root-only. An elapsed timer fails closed, and the installer refuses to proceed unless the timer is active, enabled, and has at least ten minutes remaining.

After a healthy Syn-controlled sudo invocation, cancel it with:

```sh
sudo synctl recovery cancel --apply
```

Before Syn is installed, root may cancel a staged timer as long as the managed `NOPASSWD` rule does not exist. This gives a safe abort path without weakening the post-install check.

From an existing root shell or Ubuntu recovery root shell:

```sh
/usr/bin/synctl recover --restore-local-sudo --apply
```

Recovery performs this order:

1. remove the managed `NOPASSWD` rule;
2. restore the pre-Syn `sudo.conf` backup, removing the plug-in registration;
3. restore the pre-install `update-alternatives` selection;
4. remove only unchanged Syn-recorded stat overrides and restore provider ownership before modes (changing ownership can clear setuid);
5. stop and disable `syn-agent`;
6. validate the complete sudoers configuration and archive recovered installation state beside its preserved backup;
7. disarm the automatic recovery timer last.

It never deletes keys or recovery evidence automatically. Archiving the completed state lets a later guarded installation start clean without overwriting its backup. After ordinary password sudo is verified, remove `/etc/syn` and `/var/lib/syn` manually if permanent key deletion is intended.

## Interrupted installation

The installer writes a root-owned transaction record before changing sudo. It adds `NOPASSWD` last and removes it first. If a transaction is incomplete, `synctl doctor` reports the exact phase and `recover` uses the recorded previous state.

## Manual last resort

If `synctl` is unavailable, use a recovery root shell to:

1. remove `/etc/sudoers.d/90-syn-managed-user`;
2. remove the Syn `Plugin` line from `/etc/sudo.conf`;
3. run `visudo.ws -cf /etc/sudoers`;
4. restore the previous sudo alternative recorded in `/var/lib/syn/install-state.json`;
5. remove only the stat overrides listed in that same state file.

Do not guess provider paths or remove all dpkg stat overrides.
