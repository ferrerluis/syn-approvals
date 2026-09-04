//! Temporary cancellation handlers for sudo's synchronous approval callback.
//!
//! sudo records signals but does not service them until the callback returns.
//! Its documented plug-in contract permits temporary handlers, provided the
//! original handlers are restored. Never hold these handlers across PAM.

use std::io;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

pub(crate) const IO_SLICE: Duration = Duration::from_millis(100);
const SIGNALS: [i32; 7] = [
    libc::SIGHUP,
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGTERM,
    libc::SIGALRM,
    libc::SIGUSR1,
    libc::SIGUSR2,
];

// AtomicI32 is lock-free on the supported ARM64 target. The handler performs
// no allocation, locking, formatting, or other non-signal-safe operation.
static CANCELED: AtomicI32 = AtomicI32::new(0);

extern "C" fn cancel(signal: libc::c_int) {
    let _ = CANCELED.compare_exchange(0, signal, Ordering::Relaxed, Ordering::Relaxed);
}

pub(crate) fn check() -> io::Result<()> {
    if CANCELED.load(Ordering::Relaxed) != 0 {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "Syn invocation canceled",
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn wait_until(deadline: Instant) {
    while check().is_ok() {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        std::thread::sleep(remaining.min(IO_SLICE));
    }
}

pub(crate) struct SignalGuard {
    saved: Vec<(i32, libc::sigaction)>,
}

impl SignalGuard {
    pub(crate) fn install() -> Result<Self, &'static str> {
        let mut guard = Self {
            saved: Vec::with_capacity(SIGNALS.len()),
        };
        CANCELED.store(0, Ordering::Relaxed);
        // SAFETY: zero initializes the platform C structure; sigemptyset
        // initializes its mask before sigaction reads it.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = cancel as usize;
        // No SA_RESTART: cancellation should wake a blocked IO operation.
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        for signal in SIGNALS {
            let mut previous = unsafe { std::mem::zeroed() };
            // SAFETY: both structures are valid for this syscall. A failed
            // partial installation is restored by guard's Drop implementation.
            if unsafe { libc::sigaction(signal, &action, &mut previous) } != 0 {
                return Err("unable to install cancellation handlers");
            }
            guard.saved.push((signal, previous));
        }
        Ok(guard)
    }

    pub(crate) fn finish(mut self) -> bool {
        self.restore();
        CANCELED.load(Ordering::Relaxed) != 0
    }

    fn restore(&mut self) {
        if self.saved.is_empty() {
            return;
        }
        // Block the handled signals on the invoking thread while restoring
        // their dispositions. A signal arriving at this boundary is delivered
        // to sudo's restored handler, which prevents execution itself.
        let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut old_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut mask);
            for signal in SIGNALS {
                libc::sigaddset(&mut mask, signal);
            }
            if libc::sigprocmask(libc::SIG_BLOCK, &mask, &mut old_mask) != 0 {
                libc::_exit(1);
            }
        }
        for (signal, previous) in self.saved.drain(..).rev() {
            // SAFETY: restore exactly the sigaction captured on entry. If
            // restoration fails, terminate instead of returning altered state.
            if unsafe { libc::sigaction(signal, &previous, std::ptr::null_mut()) } != 0 {
                unsafe { libc::_exit(1) };
            }
        }
        let signal = CANCELED.load(Ordering::Relaxed);
        // Re-deliver the captured cancellation to sudo for its normal signal
        // accounting. It stays pending until the original mask is restored.
        unsafe {
            if signal != 0 && libc::raise(signal) != 0 {
                libc::_exit(1);
            }
            if libc::sigprocmask(libc::SIG_SETMASK, &old_mask, std::ptr::null_mut()) != 0 {
                libc::_exit(1);
            }
        }
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    static ORIGINAL_CALLED: AtomicI32 = AtomicI32::new(0);
    extern "C" fn original(signal: i32) {
        ORIGINAL_CALLED.store(signal, Ordering::Relaxed);
    }

    // Signal dispositions are process-wide. Run this in a fresh, single-test
    // subprocess instead of touching another parallel unit test's handlers.
    #[test]
    fn cancellation_wakes_io_and_restores_sudo_handler() {
        const CHILD: &str = "SYN_CANCELLATION_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cancellation::tests::cancellation_wakes_io_and_restores_sudo_handler",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(result.success());
            return;
        }
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = original as usize;
        action.sa_flags = libc::SA_RESTART;
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
        }
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) },
            0
        );
        for blocked_read in [false, true] {
            ORIGINAL_CALLED.store(0, Ordering::Relaxed);
            let guard = SignalGuard::install().unwrap();
            let thread = unsafe { libc::pthread_self() };
            let sender = std::thread::spawn(move || {
                std::thread::sleep(IO_SLICE);
                assert_eq!(unsafe { libc::pthread_kill(thread, libc::SIGINT) }, 0);
            });
            let started = Instant::now();
            if blocked_read {
                let (mut reader, _writer) = UnixStream::pair().unwrap();
                let error =
                    crate::linux::read_frame(&mut reader, started + Duration::from_secs(30))
                        .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            } else {
                wait_until(started + Duration::from_secs(30));
            }
            assert!(started.elapsed() < Duration::from_secs(2));
            sender.join().unwrap();
            assert!(guard.finish());
            assert_eq!(ORIGINAL_CALLED.load(Ordering::Relaxed), libc::SIGINT);
            let mut restored: libc::sigaction = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::sigaction(libc::SIGINT, std::ptr::null(), &mut restored) },
                0
            );
            assert_eq!(restored.sa_sigaction, original as usize);
            assert_ne!(restored.sa_flags & libc::SA_RESTART, 0);
        }
    }
}
