//! Where the process and socket tables come from.
//!
//! Each backend reads its operating system with the user's own privileges and
//! hands the UI a [`Snapshot`]; nothing else in the app knows which one ran.
//! - Linux (and any other non-macOS build): `/proc`, see [`procfs`].
//! - macOS: libproc through `sysinfo` for processes and `lsof` for sockets,
//!   see [`macos`].
//! - Demo mode: a fixed synthetic dataset, see [`demo`].

mod demo;
#[cfg(any(target_os = "macos", test))]
mod lsof;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(not(target_os = "macos"), test))]
mod net_poller;
#[cfg(any(not(target_os = "macos"), test))]
mod proc_poller;
#[cfg(not(target_os = "macos"))]
mod procfs;

pub use demo::HOSTNAMES as DEMO_HOSTNAMES;

use crate::model::{NetRow, ProcessRow};

/// The system a snapshot describes. It picks the wording of the UI and the
/// prompt (capture source, verification commands, UID ranges).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Linux,
    MacOs,
}

impl Platform {
    /// The platform this binary was built for. Everything that is not macOS
    /// uses the `/proc` backend, as every build did before macOS support.
    pub fn host() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Linux
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Linux => "Linux",
            Self::MacOs => "macOS",
        }
    }

    /// Where the data is read from, as shown in the UI and the prompt.
    pub fn source_label(self) -> &'static str {
        match self {
            Self::Linux => "/proc",
            Self::MacOs => "libproc + lsof",
        }
    }

    /// Lowest UID of a regular account: 1000 on most Linux distributions,
    /// 501 on macOS. Below it (and above root) are system accounts.
    pub fn first_user_uid(self) -> u32 {
        match self {
            Self::Linux => 1000,
            Self::MacOs => 501,
        }
    }

    /// `nobody`: 65534 on Linux, -2 (as unsigned) on macOS.
    pub fn nobody_uid(self) -> u32 {
        match self {
            Self::Linux => 65534,
            Self::MacOs => u32::MAX - 1,
        }
    }
}

/// One reading of the process and socket tables.
pub struct Snapshot {
    pub processes: Vec<ProcessRow>,
    pub connections: Vec<NetRow>,
    pub status: String,
}

/// A backend. `capture` runs on the polling thread, so it may block briefly.
pub trait CaptureSource: Send {
    fn platform(&self) -> Platform;

    fn capture(&mut self) -> Snapshot;

    /// Synthetic data: the app then skips reverse DNS and the OS keyring.
    fn is_demo(&self) -> bool {
        false
    }
}

/// The backend for the machine this binary runs on.
pub fn system_source() -> Box<dyn CaptureSource> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacSource::new())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(procfs::ProcSource)
    }
}

/// Synthetic data shaped like a capture on `platform`.
pub fn demo_source(platform: Platform) -> Box<dyn CaptureSource> {
    Box::new(demo::DemoSource::new(platform))
}

/// Replace every control character (newlines, tabs, escapes, NUL leftovers)
/// with a space. A process controls its own `comm` and argv, so without this a
/// newline inside an argument could smuggle text past line-based redaction.
pub fn strip_control(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_become_spaces() {
        assert_eq!(
            strip_control("echo start\nexport KEY=x\r\t\u{1b}[0m"),
            "echo start export KEY=x   [0m"
        );
    }

    #[test]
    fn host_platform_matches_the_build_target() {
        assert_eq!(
            Platform::host() == Platform::MacOs,
            cfg!(target_os = "macos")
        );
        assert_eq!(Platform::MacOs.nobody_uid(), (-2i32) as u32);
    }
}
