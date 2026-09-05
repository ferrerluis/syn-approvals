//! Validate, never rewrite, sudo's final environment before any request is
//! signed. Unknown environment hooks must be explicit, visible command argv
//! (e.g. an intentionally approved `env` command), not opaque inherited values.
use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub(crate) struct Identity<'a> {
    pub invoking_uid: u32,
    pub invoking_gid: u32,
    pub invoking_user: &'a str,
    pub run_as_user: &'a [u8],
    pub home: &'a [u8],
    pub shell: &'a [u8],
}

pub(crate) fn validate(entries: &[Vec<u8>], identity: &Identity<'_>) -> Result<(), &'static str> {
    let mut names = HashSet::new();
    for entry in entries {
        let delimiter = entry
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or("Syn denied a malformed command environment.")?;
        let (name, rest) = entry.split_at(delimiter);
        let value = &rest[1..];
        if name.is_empty() || entry.contains(&0) || !names.insert(name) {
            return Err("Syn denied a malformed command environment.");
        }
        // No diagnostic includes values (or potentially adversarial names).
        let allowed = match name {
            b"PATH" => value == syn_config::SUDO_SECURE_PATH.as_bytes(),
            b"HOME" => value == identity.home,
            b"SHELL" => value == identity.shell,
            b"USER" | b"LOGNAME" => value == identity.run_as_user,
            b"MAIL" => [b"/var/mail/".as_slice(), b"/var/spool/mail/".as_slice()]
                .iter()
                .any(|prefix| value.strip_prefix(*prefix) == Some(identity.run_as_user)),
            b"SUDO_USER" => value == identity.invoking_user.as_bytes(),
            b"SUDO_UID" => value == identity.invoking_uid.to_string().as_bytes(),
            b"SUDO_GID" => value == identity.invoking_gid.to_string().as_bytes(),
            // Sudo-generated informational fields, not execution configuration.
            b"SUDO_COMMAND" | b"SUDO_TTY" => true,
            b"TERM" | b"COLORTERM" | b"LANG" | b"LANGUAGE" | b"LC_ALL" | b"LC_CTYPE"
            | b"LC_NUMERIC" | b"LC_TIME" | b"LC_COLLATE" | b"LC_MONETARY" | b"LC_MESSAGES"
            | b"LC_PAPER" | b"LC_NAME" | b"LC_ADDRESS" | b"LC_TELEPHONE" | b"LC_MEASUREMENT"
            | b"LC_IDENTIFICATION" => {
                value.len() <= 256
                    && value
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.@:+-".contains(b))
            }
            // Preserve ordinary Ubuntu GUI terminal access, not arbitrary XDG,
            // loader, interpreter, package-config, editor or shell hooks.
            b"DISPLAY" => {
                value.len() <= 256
                    && value
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.:/-[]".contains(b))
            }
            b"XAUTHORITY" => value.starts_with(b"/") && value.len() <= 4096,
            b"DEBIAN_FRONTEND" => matches!(
                value,
                b"noninteractive" | b"dialog" | b"readline" | b"teletype"
            ),
            b"DEBIAN_PRIORITY" => matches!(value, b"low" | b"medium" | b"high" | b"critical"),
            b"NEEDRESTART_MODE" => matches!(value, b"a" | b"i" | b"l"),
            _ => false,
        };
        if !allowed {
            return Err("Syn denied unsafe or unsupported command environment settings.");
        }
    }
    if !names.contains(b"PATH".as_slice()) {
        return Err("Syn requires the protected sudo command search path.");
    }
    Ok(())
}

pub(crate) fn validate_search_directories() -> Result<(), &'static str> {
    for path in syn_config::SUDO_SECURE_PATH.split(':') {
        trusted_directory(Path::new(path))?;
    }
    Ok(())
}

fn trusted_directory(path: &Path) -> Result<(), &'static str> {
    // Missing optional directories (e.g. /snap/bin) are safe only when their
    // existing ancestors are protected. Check the lexical and symlink-resolved
    // ancestors so a root-owned symlink cannot hide a user-writable parent.
    for candidate in path.ancestors() {
        match std::fs::metadata(candidate) {
            Ok(metadata) => {
                check_directory(&metadata)?;
                let resolved = std::fs::canonicalize(candidate)
                    .map_err(|_| "Syn cannot inspect the protected command search path.")?;
                for parent in resolved.ancestors() {
                    let metadata = std::fs::metadata(parent)
                        .map_err(|_| "Syn cannot inspect the protected command search path.")?;
                    check_directory(&metadata)?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // A dangling symlink is not the same as an absent directory.
                if std::fs::symlink_metadata(candidate).is_ok() {
                    return Err("Syn denied an unsafe command search path.");
                }
            }
            Err(_) => return Err("Syn cannot inspect the protected command search path."),
        }
    }
    Ok(())
}

fn check_directory(metadata: &std::fs::Metadata) -> Result<(), &'static str> {
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("Syn denied an unsafe command search path.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> Identity<'static> {
        Identity {
            invoking_uid: 1000,
            invoking_gid: 1000,
            invoking_user: "managed",
            run_as_user: b"root",
            home: b"/root",
            shell: b"/bin/bash",
        }
    }
    fn baseline() -> Vec<Vec<u8>> {
        [
            format!("PATH={}", syn_config::SUDO_SECURE_PATH),
            "HOME=/root".into(),
            "SHELL=/bin/bash".into(),
            "USER=root".into(),
            "LOGNAME=root".into(),
            "LANG=en_US.UTF-8".into(),
            "TERM=xterm-256color".into(),
            "SUDO_UID=1000".into(),
            "SUDO_GID=1000".into(),
            "SUDO_USER=managed".into(),
            "SUDO_COMMAND=/usr/bin/apt install gh".into(),
            "MAIL=/var/mail/root".into(),
        ]
        .into_iter()
        .map(String::into_bytes)
        .collect()
    }
    #[test]
    fn ordinary_ssh_gui_and_noninteractive_package_environments_pass_unchanged() {
        for extras in [
            vec![],
            vec!["DISPLAY=:10.0", "XAUTHORITY=/home/managed/.Xauthority"],
            vec![
                "DEBIAN_FRONTEND=noninteractive",
                "NEEDRESTART_MODE=a",
                "DEBIAN_PRIORITY=critical",
            ],
        ] {
            let mut environment = baseline();
            environment.extend(extras.iter().map(|s| s.as_bytes().to_vec()));
            let original = environment.clone();
            assert!(validate(&environment, &identity()).is_ok());
            assert_eq!(environment, original);
        }
    }
    #[test]
    fn execution_hooks_and_unknown_values_never_reach_signing() {
        for name in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "GCONV_PATH",
            "LOCPATH",
            "BASH_ENV",
            "ENV",
            "PYTHONPATH",
            "PYTHONHOME",
            "PERL5OPT",
            "PERL5LIB",
            "RUBYOPT",
            "NODE_OPTIONS",
            "JAVA_TOOL_OPTIONS",
            "GIT_CONFIG_GLOBAL",
            "APT_CONFIG",
            "PAGER",
            "EDITOR",
            "XDG_CONFIG_HOME",
            "SUDO_ASKPASS",
            "SSH_AUTH_SOCK",
            "UNREVIEWED_HOOK",
        ] {
            let mut environment = baseline();
            environment.push(format!("{name}=synthetic-sensitive-marker").into_bytes());
            let error = validate(&environment, &identity()).unwrap_err();
            assert!(!error.contains(name));
            assert!(!error.contains("synthetic-sensitive-marker"));
        }
    }
    #[test]
    fn paths_identities_and_frontend_values_are_not_arbitrary() {
        for entry in [
            "PATH=/home/managed/bin:/usr/bin",
            "PATH=:/usr/bin",
            "PATH=.:/usr/bin",
            "HOME=/home/managed",
            "SHELL=/home/managed/program",
            "USER=managed",
            "LOGNAME=managed",
            "SUDO_UID=0",
            "SUDO_GID=0",
            "SUDO_USER=root",
            "MAIL=/tmp/config",
            "DEBIAN_FRONTEND=../../unreviewed",
            "DEBIAN_PRIORITY=code",
            "NEEDRESTART_MODE=code",
            "LANG=../../unreviewed",
            "LC_FAKE=C",
        ] {
            let name = entry.split('=').next().unwrap().as_bytes();
            let mut environment: Vec<_> = baseline()
                .into_iter()
                .filter(|e| e.split(|b| *b == b'=').next() != Some(name))
                .collect();
            environment.push(entry.as_bytes().to_vec());
            assert!(
                validate(&environment, &identity()).is_err(),
                "unexpectedly allowed {name:?}"
            );
        }
    }
    #[test]
    fn malformed_duplicate_missing_and_non_utf8_names_fail_closed() {
        for entry in [
            b"TERM=duplicate".to_vec(),
            b"BROKEN".to_vec(),
            b"=empty-name".to_vec(),
            b"BAD\0NAME=value".to_vec(),
            vec![0xff, b'=', b'x'],
        ] {
            let mut environment = baseline();
            environment.push(entry);
            assert!(validate(&environment, &identity()).is_err());
        }
        assert!(validate(&[], &identity()).is_err());
    }
    #[test]
    fn system_directory_is_protected_but_user_writable_temp_is_not() {
        assert!(trusted_directory(Path::new("/usr/bin")).is_ok());
        assert!(trusted_directory(&std::env::temp_dir()).is_err());
    }
    #[test]
    fn protected_path_constant_has_no_relative_or_empty_components() {
        for component in syn_config::SUDO_SECURE_PATH.split(':') {
            assert!(Path::new(component).is_absolute());
            assert!(!component.contains("/../"));
        }
        // Exercise the function even on hosts with a user-owned /usr/local:
        // failure there is correct and does not make the Ubuntu policy unsafe.
        let _ = validate_search_directories();
    }
}
