use std::fs;
use std::io::{ErrorKind, Read};
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::atomic_write;

const RECOVERY_DIRECTORY: &str = "/var/lib/syn/recovery";
const ACTIVATION_WORKER_STATE: &str = "/var/lib/syn/recovery/activation-worker.json";
const ACTIVATION_LEASE_STATE: &str = "/var/lib/syn/recovery/activation-lease.json";
const TRANSITION_LOCK: &str = "/var/lib/syn/recovery/transition.lock";
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const TERM_GRACE: Duration = Duration::from_secs(2);
const KILL_GRACE: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerIdentity {
    schema_version: u16,
    pid: i32,
    process_group: i32,
    proc_start_time: u64,
    boot_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LeaseIdentity {
    schema_version: u16,
    worker_pid: i32,
    worker_start_time: u64,
    boot_id: String,
    lease_path: PathBuf,
    lease_device: u64,
    lease_inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessStat {
    state: char,
    process_group: i32,
    start_time: u64,
}

pub struct ActivationGuard {
    identity: WorkerIdentity,
    lease_identity: LeaseIdentity,
    _lease: fs::File,
    active: bool,
}

pub struct TransitionLock {
    file: fs::File,
}

impl ActivationGuard {
    pub fn register() -> Result<Self> {
        ensure_recovery_directory()?;
        isolate_current_process_group()?;
        let pid = i32::try_from(std::process::id()).context("activation PID is too large")?;
        let stat = read_process_stat(pid)?.context("activation process disappeared")?;
        if stat.process_group != pid {
            bail!("activation worker does not own an isolated process group");
        }
        let boot_id = read_boot_id(Path::new(BOOT_ID_PATH))?;
        let _transition = TransitionLock::acquire()?;
        if let Some(existing) = read_worker_identity()? {
            if identity_has_live_workers(&existing)? {
                bail!("another activation worker is already running");
            }
            remove_recorded_lease_for_worker(&existing)?;
            remove_worker_identity()?;
        } else {
            remove_orphaned_lease()?;
        }
        let lease_path = worker_lease_path(pid, stat.start_time, &boot_id);
        let lease = create_inheritable_lease(&lease_path)?;
        let lease_metadata = lease.metadata()?;
        let identity = WorkerIdentity {
            // Keep this exact v2 shape readable by the retained A helper so a
            // B activation cannot break A-to-B recovery.
            schema_version: 2,
            pid,
            process_group: stat.process_group,
            proc_start_time: stat.start_time,
            boot_id: boot_id.clone(),
        };
        let lease_identity = LeaseIdentity {
            schema_version: 1,
            worker_pid: pid,
            worker_start_time: stat.start_time,
            boot_id,
            lease_path,
            lease_device: lease_metadata.dev(),
            lease_inode: lease_metadata.ino(),
        };
        atomic_write(
            Path::new(ACTIVATION_LEASE_STATE),
            &serde_json::to_vec_pretty(&lease_identity)?,
            0o600,
        )?;
        if let Err(error) = atomic_write(
            Path::new(ACTIVATION_WORKER_STATE),
            &serde_json::to_vec_pretty(&identity)?,
            0o600,
        ) {
            let _ = remove_worker_lease(&lease_identity);
            let _ = remove_lease_identity();
            return Err(error);
        }
        Ok(Self {
            identity,
            lease_identity,
            _lease: lease,
            active: true,
        })
    }

    pub fn verify_current(&self) -> Result<()> {
        if !self.active || read_worker_identity()?.as_ref() != Some(&self.identity) {
            bail!("activation worker ownership was lost");
        }
        if !identity_is_live(&self.identity)? || !lease_is_valid(&self.lease_identity)? {
            bail!("activation worker identity no longer matches its process and lease");
        }
        Ok(())
    }

    /// Stop advertising this process as killable before its own rollback.
    /// The returned lock keeps another activation or external recovery from
    /// entering the privileged transition until the caller is ready.
    pub fn deactivate_for_internal_recovery(&mut self) -> Result<TransitionLock> {
        let transition = TransitionLock::acquire()?;
        if read_worker_identity()?.as_ref() != Some(&self.identity) {
            bail!("activation worker ownership was lost before rollback");
        }
        remove_worker_lease(&self.lease_identity)?;
        remove_lease_identity()?;
        remove_worker_identity()?;
        self.active = false;
        Ok(transition)
    }
}

impl Drop for ActivationGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(_transition) = TransitionLock::acquire() {
            if read_worker_identity().ok().flatten().as_ref() == Some(&self.identity) {
                let _ = remove_worker_lease(&self.lease_identity);
                let _ = remove_lease_identity();
                let _ = remove_worker_identity();
            }
        }
    }
}

impl TransitionLock {
    pub fn acquire() -> Result<Self> {
        ensure_recovery_directory()?;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(TRANSITION_LOCK)
            .context("open activation/recovery transition lock")?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o7777 != 0o600
        {
            bail!("activation/recovery transition lock has unsafe ownership or mode");
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("lock activation/recovery transition");
        }
        Ok(Self { file })
    }
}

impl Drop for TransitionLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Stop a possibly hung activation before serializing recovery. The initial
/// stop deliberately happens without taking the transition lock: a worker may
/// have died while holding that lock, and recovery must remain bounded.
pub fn begin_external_recovery() -> Result<TransitionLock> {
    ensure_recovery_directory()?;
    if let Some(identity) = read_worker_identity()? {
        stop_worker_lease_holders(&identity)?;
    }

    let transition = TransitionLock::acquire()?;
    // Close the registration race: a worker that appeared after the first read
    // cannot enter its final transition while recovery holds this lock.
    if let Some(identity) = read_worker_identity()? {
        stop_worker_lease_holders(&identity)?;
        remove_recorded_lease_for_worker(&identity)?;
        remove_worker_identity()?;
    } else {
        remove_orphaned_lease()?;
    }
    Ok(transition)
}

fn stop_worker_lease_holders(identity: &WorkerIdentity) -> Result<()> {
    validate_worker_identity(identity)?;
    if identity.boot_id != read_boot_id(Path::new(BOOT_ID_PATH))? {
        return Ok(());
    }
    let Some(lease) = read_lease_identity_for_worker(identity)? else {
        if identity_is_live(identity)? {
            bail!("live activation worker has no safe process lease");
        }
        return Ok(());
    };
    if !lease_is_valid(&lease)? {
        if identity_is_live(identity)? {
            bail!("live activation worker has an invalid process lease");
        }
        return Ok(());
    }
    signal_lease_holders(&lease, libc::SIGTERM)?;
    if wait_for_lease_holders_exit(&lease, TERM_GRACE)? {
        return Ok(());
    }
    signal_lease_holders(&lease, libc::SIGKILL)?;
    if !wait_for_lease_holders_exit(&lease, KILL_GRACE)? {
        bail!("activation workers did not exit after SIGKILL");
    }
    Ok(())
}

fn identity_has_live_workers(identity: &WorkerIdentity) -> Result<bool> {
    validate_worker_identity(identity)?;
    if identity.boot_id != read_boot_id(Path::new(BOOT_ID_PATH))? {
        return Ok(false);
    }
    let Some(lease) = read_lease_identity_for_worker(identity)? else {
        return identity_is_live(identity);
    };
    if !lease_is_valid(&lease)? {
        return identity_is_live(identity);
    }
    Ok(!lease_holder_pidfds(&lease)?.is_empty())
}

fn signal_lease_holders(identity: &LeaseIdentity, signal: i32) -> Result<()> {
    for (pid, pidfd) in lease_holder_pidfds(identity)? {
        if pid == i32::try_from(std::process::id()).context("recovery PID is too large")? {
            bail!("refusing to signal the recovery process itself");
        }
        pidfd_send_signal(&pidfd, signal)?;
    }
    Ok(())
}

fn wait_for_lease_holders_exit(identity: &LeaseIdentity, timeout: Duration) -> Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        if lease_holder_pidfds(identity)?.is_empty() {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn identity_is_live(identity: &WorkerIdentity) -> Result<bool> {
    validate_worker_identity(identity)?;
    if identity.boot_id != read_boot_id(Path::new(BOOT_ID_PATH))? {
        return Ok(false);
    }
    Ok(read_process_stat(identity.pid)?
        .as_ref()
        .is_some_and(|stat| identity_matches_stat(identity, stat)))
}

fn identity_matches_stat(identity: &WorkerIdentity, stat: &ProcessStat) -> bool {
    !matches!(stat.state, 'Z' | 'X')
        && stat.process_group == identity.process_group
        && stat.start_time == identity.proc_start_time
}

fn validate_worker_identity(identity: &WorkerIdentity) -> Result<()> {
    if identity.schema_version != 2
        || identity.pid <= 1
        || identity.process_group != identity.pid
        || identity.proc_start_time == 0
        || !valid_boot_id(&identity.boot_id)
    {
        bail!("activation worker identity is invalid");
    }
    Ok(())
}

fn validate_lease_identity(identity: &LeaseIdentity) -> Result<()> {
    if identity.schema_version != 1
        || identity.worker_pid <= 1
        || identity.worker_start_time == 0
        || !valid_boot_id(&identity.boot_id)
        || identity.lease_device == 0
        || identity.lease_inode == 0
        || identity.lease_path
            != worker_lease_path(
                identity.worker_pid,
                identity.worker_start_time,
                &identity.boot_id,
            )
    {
        bail!("activation lease identity is invalid");
    }
    Ok(())
}

fn lease_matches_worker(lease: &LeaseIdentity, worker: &WorkerIdentity) -> bool {
    lease.worker_pid == worker.pid
        && lease.worker_start_time == worker.proc_start_time
        && lease.boot_id == worker.boot_id
}

fn worker_lease_path(pid: i32, start_time: u64, boot_id: &str) -> PathBuf {
    Path::new(RECOVERY_DIRECTORY).join(format!(
        "activation-lease-{}-{pid}-{start_time}",
        boot_id.replace('-', "")
    ))
}

fn create_inheritable_lease(path: &Path) -> Result<fs::File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .context("create activation lease")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    let descriptor_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    if descriptor_flags < 0
        || unsafe {
            libc::fcntl(
                file.as_raw_fd(),
                libc::F_SETFD,
                descriptor_flags & !libc::FD_CLOEXEC,
            )
        } < 0
    {
        let error = std::io::Error::last_os_error();
        let _ = fs::remove_file(path);
        return Err(error).context("make activation lease inheritable");
    }
    file.sync_all()?;
    fs::File::open(RECOVERY_DIRECTORY)?.sync_all()?;
    Ok(file)
}

fn lease_is_valid(identity: &LeaseIdentity) -> Result<bool> {
    validate_lease_identity(identity)?;
    let metadata = match fs::symlink_metadata(&identity.lease_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    Ok(metadata.is_file()
        && metadata.uid() == 0
        && metadata.gid() == 0
        && metadata.mode() & 0o7777 == 0o400
        && metadata.dev() == identity.lease_device
        && metadata.ino() == identity.lease_inode)
}

fn remove_worker_lease(identity: &LeaseIdentity) -> Result<()> {
    validate_lease_identity(identity)?;
    match fs::symlink_metadata(&identity.lease_path) {
        Ok(metadata)
            if metadata.is_file()
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o7777 == 0o400
                && metadata.dev() == identity.lease_device
                && metadata.ino() == identity.lease_inode =>
        {
            fs::remove_file(&identity.lease_path)?;
            fs::File::open(RECOVERY_DIRECTORY)?.sync_all()?;
            Ok(())
        }
        Ok(_) => bail!("activation lease no longer matches its recorded identity"),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn remove_recorded_lease_for_worker(worker: &WorkerIdentity) -> Result<()> {
    if let Some(lease) = read_lease_identity_for_worker(worker)? {
        remove_worker_lease(&lease)?;
        remove_lease_identity()?;
    }
    Ok(())
}

fn remove_orphaned_lease() -> Result<()> {
    if let Some(lease) = read_lease_identity()? {
        remove_worker_lease(&lease)?;
        remove_lease_identity()?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn lease_holder_pidfds(identity: &LeaseIdentity) -> Result<Vec<(i32, OwnedFd)>> {
    validate_lease_identity(identity)?;
    let mut holders = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
        else {
            continue;
        };
        let Some(pidfd) = pidfd_open(pid)? else {
            continue;
        };
        // Open the pidfd first, then check the live process's descriptors. If
        // the numeric PID is reused during the scan, the new process cannot
        // possess this root-created, unlinked-to-users lease inode.
        if process_holds_lease(pid, identity)? {
            holders.push((pid, pidfd));
        }
    }
    Ok(holders)
}

#[cfg(target_os = "linux")]
fn process_holds_lease(pid: i32, identity: &LeaseIdentity) -> Result<bool> {
    let descriptors = match fs::read_dir(format!("/proc/{pid}/fd")) {
        Ok(descriptors) => descriptors,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::NotFound | ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error.into()),
    };
    for descriptor in descriptors {
        let descriptor = match descriptor {
            Ok(descriptor) => descriptor,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::NotFound | ErrorKind::PermissionDenied
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let metadata = match fs::metadata(descriptor.path()) {
            Ok(metadata) => metadata,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::NotFound | ErrorKind::PermissionDenied
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if metadata.dev() == identity.lease_device && metadata.ino() == identity.lease_inode {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(not(target_os = "linux"))]
struct UnsupportedPidFd;

#[cfg(not(target_os = "linux"))]
fn lease_holder_pidfds(_identity: &LeaseIdentity) -> Result<Vec<(i32, UnsupportedPidFd)>> {
    bail!("activation recovery requires Linux pidfds")
}

#[cfg(target_os = "linux")]
fn pidfd_open(pid: i32) -> Result<Option<OwnedFd>> {
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(None);
        }
        return Err(error).context("open activation worker pidfd");
    }
    // SAFETY: pidfd_open returned a new owned descriptor.
    Ok(Some(unsafe { OwnedFd::from_raw_fd(descriptor as i32) }))
}

#[cfg(target_os = "linux")]
fn pidfd_send_signal(pidfd: &OwnedFd, signal: i32) -> Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0_u32,
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error).context("signal activation worker through pidfd");
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn pidfd_send_signal(_pidfd: &UnsupportedPidFd, _signal: i32) -> Result<()> {
    bail!("activation recovery requires Linux pidfds")
}

fn read_worker_identity() -> Result<Option<WorkerIdentity>> {
    read_worker_identity_at(Path::new(ACTIVATION_WORKER_STATE))
}

fn read_worker_identity_at(path: &Path) -> Result<Option<WorkerIdentity>> {
    let mut file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > 16 * 1024
    {
        bail!("activation worker state has unsafe ownership, mode, or size");
    }
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut contents)?;
    let identity: WorkerIdentity = serde_json::from_slice(&contents)?;
    validate_worker_identity(&identity)?;
    Ok(Some(identity))
}

fn read_lease_identity() -> Result<Option<LeaseIdentity>> {
    read_lease_identity_at(Path::new(ACTIVATION_LEASE_STATE))
}

fn read_lease_identity_for_worker(worker: &WorkerIdentity) -> Result<Option<LeaseIdentity>> {
    let Some(lease) = read_lease_identity()? else {
        return Ok(None);
    };
    if !lease_matches_worker(&lease, worker) {
        bail!("activation lease does not belong to the recorded worker");
    }
    Ok(Some(lease))
}

fn read_lease_identity_at(path: &Path) -> Result<Option<LeaseIdentity>> {
    let mut file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > 16 * 1024
    {
        bail!("activation lease state has unsafe ownership, mode, or size");
    }
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut contents)?;
    let identity: LeaseIdentity = serde_json::from_slice(&contents)?;
    validate_lease_identity(&identity)?;
    Ok(Some(identity))
}

fn read_boot_id(path: &Path) -> Result<String> {
    let value = fs::read_to_string(path)
        .with_context(|| format!("read Linux boot identity from {}", path.display()))?;
    let value = value.trim().to_ascii_lowercase();
    if !valid_boot_id(&value) {
        bail!("Linux boot identity is malformed");
    }
    Ok(value)
}

fn valid_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
}

fn remove_worker_identity() -> Result<()> {
    match fs::remove_file(ACTIVATION_WORKER_STATE) {
        Ok(()) => {
            fs::File::open(RECOVERY_DIRECTORY)?.sync_all()?;
            Ok(())
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn remove_lease_identity() -> Result<()> {
    match fs::remove_file(ACTIVATION_LEASE_STATE) {
        Ok(()) => {
            fs::File::open(RECOVERY_DIRECTORY)?.sync_all()?;
            Ok(())
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn isolate_current_process_group() -> Result<()> {
    let result = unsafe { libc::setpgid(0, 0) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("isolate activation worker process group");
    }
    Ok(())
}

fn read_process_stat(pid: i32) -> Result<Option<ProcessStat>> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    match fs::read_to_string(path) {
        Ok(contents) => parse_process_stat(&contents).map(Some),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn parse_process_stat(contents: &str) -> Result<ProcessStat> {
    let close = contents
        .rfind(')')
        .context("process stat command name is malformed")?;
    let fields: Vec<_> = contents[close + 1..].split_whitespace().collect();
    if fields.len() < 20 {
        bail!("process stat is missing required fields");
    }
    Ok(ProcessStat {
        state: fields[0]
            .chars()
            .next()
            .context("process stat state is missing")?,
        process_group: fields[2].parse()?,
        start_time: fields[19].parse()?,
    })
}

fn ensure_recovery_directory() -> Result<()> {
    let path = Path::new(RECOVERY_DIRECTORY);
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o700
    {
        bail!("recovery directory has unsafe ownership or mode");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn worker(boot_id: &str) -> WorkerIdentity {
        WorkerIdentity {
            schema_version: 2,
            pid: 77,
            process_group: 77,
            proc_start_time: 100,
            boot_id: boot_id.into(),
        }
    }

    fn lease(boot_id: &str) -> LeaseIdentity {
        LeaseIdentity {
            schema_version: 1,
            worker_pid: 77,
            worker_start_time: 100,
            boot_id: boot_id.into(),
            lease_path: worker_lease_path(77, 100, boot_id),
            lease_device: 1,
            lease_inode: 2,
        }
    }

    #[test]
    fn proc_stat_parser_handles_spaces_and_parentheses_and_reads_kernel_identity() {
        let stat = "4242 (worker name (phase)) S 1 4242 9 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 123456 0";
        assert_eq!(
            parse_process_stat(stat).unwrap(),
            ProcessStat {
                state: 'S',
                process_group: 4242,
                start_time: 123456,
            }
        );
    }

    #[test]
    fn proc_stat_parser_rejects_missing_identity_fields() {
        assert!(parse_process_stat("7 (worker) S 1 7").is_err());
        assert!(parse_process_stat("7 worker S 1 7").is_err());
    }

    #[test]
    fn retained_worker_identity_keeps_the_exact_v2_shape() {
        let boot_id = "12345678-1234-1234-1234-123456789abc";
        let valid = worker(boot_id);
        assert!(validate_worker_identity(&valid).is_ok());
        let serialized = serde_json::to_value(&valid).unwrap();
        assert_eq!(serialized.as_object().unwrap().len(), 5);
        assert!(serialized.get("lease_path").is_none());
        assert_eq!(
            serde_json::from_value::<WorkerIdentity>(serialized).unwrap(),
            valid
        );
        assert!(serde_json::from_str::<WorkerIdentity>(
            r#"{"schema_version":2,"pid":77,"process_group":77,"proc_start_time":100,"boot_id":"12345678-1234-1234-1234-123456789abc","lease_path":"unexpected"}"#
        )
        .is_err());
        for invalid in [
            WorkerIdentity {
                schema_version: 1,
                ..valid.clone()
            },
            WorkerIdentity {
                process_group: 78,
                ..valid.clone()
            },
            WorkerIdentity {
                proc_start_time: 0,
                ..valid.clone()
            },
            WorkerIdentity {
                boot_id: "not-a-boot-id".into(),
                ..valid.clone()
            },
        ] {
            assert!(validate_worker_identity(&invalid).is_err());
        }
    }

    #[test]
    fn lease_identity_is_exact_and_bound_to_the_worker() {
        let boot_id = "12345678-1234-1234-1234-123456789abc";
        let valid = lease(boot_id);
        let recorded_worker = worker(boot_id);
        assert!(validate_lease_identity(&valid).is_ok());
        assert!(lease_matches_worker(&valid, &recorded_worker));
        for invalid in [
            LeaseIdentity {
                schema_version: 2,
                ..valid.clone()
            },
            LeaseIdentity {
                lease_path: "/var/lib/syn/recovery/reused".into(),
                ..valid.clone()
            },
            LeaseIdentity {
                lease_inode: 0,
                ..valid.clone()
            },
        ] {
            assert!(validate_lease_identity(&invalid).is_err());
        }
        assert!(!lease_matches_worker(
            &valid,
            &WorkerIdentity {
                proc_start_time: 101,
                ..recorded_worker
            }
        ));
    }

    #[test]
    fn pid_reuse_does_not_match_the_recorded_worker() {
        let boot_id = "12345678-1234-1234-1234-123456789abc";
        let identity = worker(boot_id);
        assert!(identity_matches_stat(
            &identity,
            &ProcessStat {
                state: 'S',
                process_group: 77,
                start_time: 100,
            }
        ));
        for stat in [
            ProcessStat {
                state: 'S',
                process_group: 77,
                start_time: 101,
            },
            ProcessStat {
                state: 'Z',
                process_group: 77,
                start_time: 100,
            },
            ProcessStat {
                state: 'S',
                process_group: 78,
                start_time: 100,
            },
        ] {
            assert!(!identity_matches_stat(&identity, &stat));
        }
    }

    #[test]
    fn recovery_waits_are_bounded() {
        assert_eq!(TERM_GRACE, Duration::from_secs(2));
        assert_eq!(KILL_GRACE, Duration::from_secs(2));
    }

    #[test]
    fn lease_identity_changes_with_every_process_or_boot_identity() {
        let boot_id = "12345678-1234-1234-1234-123456789abc";
        let lease = worker_lease_path(77, 100, boot_id);
        assert_eq!(
            lease,
            Path::new(RECOVERY_DIRECTORY)
                .join("activation-lease-12345678123412341234123456789abc-77-100")
        );
        assert_ne!(lease, worker_lease_path(78, 100, boot_id));
        assert_ne!(lease, worker_lease_path(77, 101, boot_id));
        assert_ne!(
            lease,
            worker_lease_path(77, 100, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn open_lease_descriptor_identifies_only_its_exact_inode() {
        let path = std::env::temp_dir().join(format!(
            "syn-lease-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let metadata = file.metadata().unwrap();
        let mut identity = lease("12345678-1234-1234-1234-123456789abc");
        identity.lease_device = metadata.dev();
        identity.lease_inode = metadata.ino();
        assert!(process_holds_lease(std::process::id() as i32, &identity).unwrap());
        identity.lease_inode = identity.lease_inode.saturating_add(1);
        assert!(!process_holds_lease(std::process::id() as i32, &identity).unwrap());
        drop(file);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn missing_worker_state_is_an_ordinary_absence() {
        let path = std::env::temp_dir().join(format!(
            "syn-missing-worker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        assert!(read_worker_identity_at(&path).unwrap().is_none());
    }

    #[test]
    fn boot_id_validation_is_strict_and_normalizes_kernel_newline() {
        assert!(valid_boot_id("12345678-1234-1234-1234-123456789abc"));
        assert!(!valid_boot_id("12345678-1234-1234-1234-123456789ABC"));
        assert!(!valid_boot_id("12345678123412341234123456789abc"));

        let path = std::env::temp_dir().join(format!(
            "syn-boot-id-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        fs::write(&path, b"12345678-1234-1234-1234-123456789ABC\n").unwrap();
        assert_eq!(
            read_boot_id(&path).unwrap(),
            "12345678-1234-1234-1234-123456789abc"
        );
        fs::remove_file(path).unwrap();
    }
}
