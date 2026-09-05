//! Complete alternate-provider inventory and persistent protection. No sudo
//! provider is executed here. Administrator restrictions are never removed.
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use syn_config::StatOverrideRecord;

pub fn inventory() -> Result<BTreeSet<PathBuf>> {
    let output = Command::new("/usr/bin/update-alternatives")
        .args(["--list", "sudo"])
        .output()?;
    if !output.status.success() {
        bail!("cannot enumerate sudo providers");
    }
    let output = String::from_utf8(output.stdout)?;
    let mut candidates: Vec<PathBuf> = output.lines().map(PathBuf::from).collect();
    // Include known directly callable entry points even if alternatives drift.
    for path in [
        "/usr/bin/sudo",
        "/usr/bin/sudo-rs",
        "/usr/lib/cargo/bin/sudo",
    ] {
        match fs::symlink_metadata(path) {
            Ok(_) => candidates.push(path.into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let mut providers = BTreeSet::new();
    for path in candidates {
        if !path.is_absolute() {
            bail!("sudo provider path is not absolute");
        }
        let canonical = fs::canonicalize(&path).context("cannot resolve sudo provider")?;
        if canonical != Path::new("/usr/bin/sudo.ws") {
            check_provider_parents(&canonical)?;
            providers.insert(canonical);
        }
    }
    // Ubuntu 26.04 includes sudo-rs. An empty inventory is not proof of safety.
    if providers.is_empty() {
        bail!("no alternate sudo provider found on the supported Ubuntu target");
    }
    Ok(providers)
}

pub fn read_override(path: &Path) -> Result<Option<String>> {
    let output = Command::new("/usr/bin/dpkg-statoverride")
        .arg("--list")
        .arg(path)
        .output()?;
    match output.status.code() {
        Some(0) if !output.stdout.is_empty() => {
            Ok(Some(String::from_utf8(output.stdout)?.trim().to_owned()))
        }
        Some(1) if output.stdout.is_empty() => Ok(None),
        _ => bail!("cannot inspect persistent sudo provider override"),
    }
}

fn protected_mode(line: &str, path: &Path) -> Result<u32> {
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() != 4
        || !matches!(fields[0], "root" | "0")
        || !matches!(fields[1], "root" | "0")
        || Path::new(fields[3]) != path
    {
        bail!("alternate provider override is not a protected root-owned entry");
    }
    let mode = u32::from_str_radix(fields[2], 8)?;
    if mode > 0o777 || mode & 0o022 != 0 {
        bail!("alternate provider override permits privilege or untrusted writes");
    }
    Ok(mode)
}

fn check_metadata(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o022 != 0
    {
        bail!("alternate sudo provider must be a protected root-owned regular file");
    }
    Ok(())
}

fn check_provider_parents(path: &Path) -> Result<()> {
    for parent in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!("alternate provider has an unprotected parent directory");
        }
    }
    Ok(())
}

pub fn prepare() -> Result<Vec<StatOverrideRecord>> {
    inventory()?
        .into_iter()
        .map(|path| {
            let metadata = fs::symlink_metadata(&path)?;
            check_metadata(&metadata)?;
            let existing = read_override(&path)?;
            let record = record_provider(path, metadata.mode() & 0o7777, existing)?;
            Ok(record)
        })
        .collect()
}

fn record_provider(
    path: PathBuf,
    mode: u32,
    existing: Option<String>,
) -> Result<StatOverrideRecord> {
    if let Some(line) = &existing {
        if protected_mode(line, &path)? != mode {
            bail!("administrator override does not match live provider permissions");
        }
    }
    // Crucially, 0755 WITHOUT an override still needs a Syn-owned override.
    Ok(StatOverrideRecord {
        path,
        previous_mode: mode,
        previous_owner: 0,
        previous_group: 0,
        preserved_override: existing,
    })
}

fn check_inventory(records: &[StatOverrideRecord], live: BTreeSet<PathBuf>) -> Result<()> {
    let recorded: BTreeSet<_> = records.iter().map(|r| r.path.clone()).collect();
    if recorded.len() != records.len() || recorded != live {
        bail!("sudo provider inventory changed; refusing passwordless coupling");
    }
    Ok(())
}

pub fn protect(records: &[StatOverrideRecord]) -> Result<()> {
    check_inventory(records, inventory()?)?;
    for record in records {
        if record.preserved_override.is_some() {
            verify_preserved(record)?;
            continue;
        }
        let metadata = fs::symlink_metadata(&record.path)?;
        check_metadata(&metadata)?;
        if metadata.mode() & 0o7777 != record.previous_mode
            || read_override(&record.path)?.is_some()
        {
            bail!("sudo provider changed since preparation");
        }
        let result = Command::new("/usr/bin/dpkg-statoverride")
            .args(["--update", "--add", "root", "root", "0755"])
            .arg(&record.path)
            .status()?;
        if !result.success() {
            bail!("cannot persistently disable alternate sudo provider");
        }
    }
    verify(records)
}

pub fn verify_preserved(record: &StatOverrideRecord) -> Result<()> {
    let expected = record
        .preserved_override
        .as_deref()
        .context("no administrator override recorded")?;
    verify_record(
        record,
        read_override(&record.path)?.as_deref(),
        fs::symlink_metadata(&record.path)?,
        Some(expected),
    )
}

fn verify_record(
    record: &StatOverrideRecord,
    live: Option<&str>,
    metadata: fs::Metadata,
    preserved: Option<&str>,
) -> Result<()> {
    check_provider_parents(&record.path)?;
    check_metadata(&metadata)?;
    verify_protection(record, live, metadata.mode() & 0o7777, preserved)
}

fn verify_protection(
    record: &StatOverrideRecord,
    live: Option<&str>,
    live_mode: u32,
    preserved: Option<&str>,
) -> Result<()> {
    let live = live.context("persistent sudo provider override is missing")?;
    let mode = protected_mode(live, &record.path)?;
    if let Some(expected) = preserved {
        if live.split_whitespace().ne(expected.split_whitespace()) {
            bail!("administrator provider override changed");
        }
    } else if mode != 0o755 {
        bail!("Syn provider override changed");
    }
    if live_mode != mode {
        bail!("provider permissions differ from persistent protection");
    }
    Ok(())
}

pub fn verify(records: &[StatOverrideRecord]) -> Result<()> {
    check_inventory(records, inventory()?)?;
    for record in records {
        verify_record(
            record,
            read_override(&record.path)?.as_deref(),
            fs::symlink_metadata(&record.path)?,
            record.preserved_override.as_deref(),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn path() -> PathBuf {
        "/usr/lib/cargo/bin/sudo".into()
    }

    #[test]
    fn both_packaged_and_temporarily_disabled_providers_need_persistent_protection() {
        for mode in [0o4755, 0o755] {
            let record = record_provider(path(), mode, None).unwrap();
            assert_eq!(record.previous_mode, mode);
            assert!(record.preserved_override.is_none());
        }
    }

    #[test]
    fn administrator_restrictions_are_recorded_and_never_owned_by_syn() {
        for mode in ["755", "0750", "700", "500", "0"] {
            let line = format!("root root {mode} {}", path().display());
            let record = record_provider(
                path(),
                u32::from_str_radix(mode, 8).unwrap(),
                Some(line.clone()),
            )
            .unwrap();
            assert_eq!(record.preserved_override, Some(line));
        }
    }

    #[test]
    fn unsafe_stale_and_ambiguous_overrides_are_rejected() {
        for line in [
            "root root 4755",
            "root root 2755",
            "root root 777",
            "user root 755",
            "root user 755",
        ] {
            assert!(
                record_provider(path(), 0o755, Some(format!("{line} {}", path().display())))
                    .is_err()
            );
        }
        assert!(record_provider(
            path(),
            0o4755,
            Some(format!("root root 755 {}", path().display()))
        )
        .is_err());
        assert!(protected_mode("root root 755 /another/provider", &path()).is_err());
        assert!(protected_mode("root root 755 /x\nroot root 755 /x", Path::new("/x")).is_err());
    }

    #[test]
    fn new_missing_and_duplicate_inventory_entries_fail_closed() {
        let record = record_provider(path(), 0o755, None).unwrap();
        assert!(check_inventory(&[record.clone()], BTreeSet::from([path()])).is_ok());
        assert!(check_inventory(&[], BTreeSet::from([path()])).is_err());
        assert!(check_inventory(&[record.clone()], BTreeSet::new()).is_err());
        assert!(check_inventory(&[record.clone(), record], BTreeSet::from([path()])).is_err());
    }

    #[test]
    fn legacy_state_still_deserializes_as_syn_owned_for_recovery() {
        let record: StatOverrideRecord = serde_json::from_str(r#"{
            "path":"/usr/lib/cargo/bin/sudo","previous_mode":2541,"previous_owner":0,"previous_group":0
        }"#).unwrap();
        assert!(record.preserved_override.is_none());
    }

    #[test]
    fn missing_override_or_restored_packaged_setuid_mode_never_passes_coupling() {
        let record = record_provider(path(), 0o755, None).unwrap();
        let line = format!("root root 755 {}", path().display());
        assert!(verify_protection(&record, Some(&line), 0o755, None).is_ok());
        assert!(verify_protection(&record, None, 0o755, None).is_err());
        assert!(verify_protection(&record, None, 0o4755, None).is_err());
        assert!(verify_protection(&record, Some(&line), 0o4755, None).is_err());
    }

    #[test]
    fn provider_parents_cannot_be_user_controlled() {
        assert!(check_provider_parents(Path::new("/usr/bin/true")).is_ok());
        let candidate = std::env::temp_dir().join("never-created-provider");
        assert!(check_provider_parents(&candidate).is_err());
    }

    #[test]
    fn administrator_restrictions_must_remain_exact_during_verification_and_recovery() {
        let original = format!("root root 700 {}", path().display());
        let record = record_provider(path(), 0o700, Some(original.clone())).unwrap();
        assert!(verify_protection(&record, Some(&original), 0o700, Some(&original)).is_ok());
        let changed = format!("root root 755 {}", path().display());
        assert!(verify_protection(&record, Some(&changed), 0o755, Some(&original)).is_err());
        assert!(verify_protection(&record, None, 0o700, Some(&original)).is_err());
    }

    #[test]
    #[ignore = "read-only check for an already protected Ubuntu 26.04 validation target"]
    fn live_provider_inventory_and_overrides_read_only() {
        let records = prepare().unwrap();
        assert!(!records.is_empty());
        verify(&records).unwrap();
        for record in &records {
            assert!(record.preserved_override.is_some());
            verify_preserved(record).unwrap();
        }
    }
}
