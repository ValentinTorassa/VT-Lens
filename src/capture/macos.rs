//! macOS backend. There is no `/proc`: processes come from libproc (the
//! process list, names, arguments and UIDs through the `sysinfo` crate, plus
//! one `proc_pidinfo(PROC_PIDTASKINFO)` call per process for memory, threads
//! and run state) and sockets from `lsof` (see `lsof.rs`). No root needed,
//! with the limits that brings: every process is listed, but the memory,
//! threads, arguments and sockets of other users' processes (root's
//! included) are only readable as root, so they show as 0 / unknown.

use std::collections::HashMap;
use std::ffi::OsStr;

use sysinfo::{ProcessRefreshKind, ProcessStatus, ProcessesToUpdate, System, UpdateKind};

use super::{CaptureSource, Platform, Snapshot, lsof, strip_control};
use crate::model::ProcessRow;

pub struct MacSource {
    system: System,
}

impl MacSource {
    pub fn new() -> Self {
        Self {
            system: System::new(),
        }
    }
}

impl CaptureSource for MacSource {
    fn platform(&self) -> Platform {
        Platform::MacOs
    }

    fn capture(&mut self) -> Snapshot {
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cmd(UpdateKind::OnlyIfNotSet)
                .with_user(UpdateKind::OnlyIfNotSet),
        );

        let connections = lsof::read_connections();
        let mut socket_counts: HashMap<u32, usize> = HashMap::new();
        for row in &connections {
            if let Some(owner) = &row.owner {
                *socket_counts.entry(owner.pid).or_default() += 1;
            }
        }

        let mut processes: Vec<ProcessRow> = self
            .system
            .processes()
            .iter()
            .map(|(pid, process)| {
                let pid = pid.as_u32();
                let name = clean(process.name());
                let cmdline = process
                    .cmd()
                    .iter()
                    .map(|arg| clean(arg))
                    .filter(|arg| !arg.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ");
                let task = task_info(pid);
                ProcessRow {
                    pid,
                    start_id: (process.start_time() > 0).then_some(process.start_time()),
                    cmdline: if cmdline.is_empty() {
                        name.clone()
                    } else {
                        cmdline
                    },
                    name,
                    state: state_label(process.status(), task.as_ref()).to_string(),
                    rss_kb: task.as_ref().map_or(0, |task| task.rss_kb),
                    threads: task.as_ref().map_or(0, |task| task.threads),
                    socket_count: socket_counts.get(&pid).copied().unwrap_or(0),
                    uid: process.user_id().map(|uid| **uid),
                }
            })
            .collect();
        processes.sort_by_key(|row| row.pid);

        let status = format!(
            "{} processes · {} connections · connection-level capture (no root: lsof sees only your own processes)",
            processes.len(),
            connections.len()
        );

        Snapshot {
            processes,
            connections,
            status,
        }
    }
}

fn clean(text: &OsStr) -> String {
    strip_control(&text.to_string_lossy()).trim().to_string()
}

/// Same letters Linux puts in `/proc/<pid>/status`. The kernel reports every
/// live macOS process as SRUN, so like `ps` the state comes from its threads:
/// running if any thread is on a CPU, sleeping otherwise.
fn state_label(status: ProcessStatus, task: Option<&TaskInfo>) -> &'static str {
    match (status, task) {
        (ProcessStatus::Zombie, _) => "Z (zombie)",
        (ProcessStatus::Stop, _) => "T (stopped)",
        (_, Some(task)) if task.running_threads > 0 => "R (running)",
        (_, Some(_)) => "S (sleeping)",
        (_, None) => "? (unknown)",
    }
}

struct TaskInfo {
    rss_kb: u64,
    threads: u32,
    running_threads: u32,
}

/// `proc_pidinfo(PROC_PIDTASKINFO)`, the call behind `ps` and `top`'s memory
/// and thread columns. It fails for other users' processes unless run as root.
fn task_info(pid: u32) -> Option<TaskInfo> {
    let mut info = std::mem::MaybeUninit::<libc::proc_taskinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    // SAFETY: the buffer is a zeroed proc_taskinfo and `size` is its exact
    // size; the kernel writes at most `size` bytes and returns the count.
    let written = unsafe {
        libc::proc_pidinfo(
            libc::c_int::try_from(pid).ok()?,
            libc::PROC_PIDTASKINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if written != size {
        return None;
    }
    // SAFETY: proc_pidinfo filled the whole struct (written == size).
    let info = unsafe { info.assume_init() };
    Some(TaskInfo {
        rss_kb: info.pti_resident_size / 1024,
        threads: u32::try_from(info.pti_threadnum).unwrap_or(0),
        running_threads: u32::try_from(info.pti_numrunning).unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_this_process_without_root() {
        let me = std::process::id();
        let snapshot = MacSource::new().capture();
        let row = snapshot
            .processes
            .iter()
            .find(|row| row.pid == me)
            .expect("own process listed");
        assert!(row.rss_kb > 0, "{row:?}");
        assert!(row.threads >= 1, "{row:?}");
        assert!(row.uid.is_some(), "{row:?}");
        assert!(!row.name.is_empty());
    }

    #[test]
    fn sees_a_socket_this_process_opens() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let me = std::process::id();
        let snapshot = MacSource::new().capture();
        let row = snapshot
            .connections
            .iter()
            .find(|row| row.local_addr == format!("127.0.0.1:{port}"))
            .expect("listening socket listed by lsof");
        assert_eq!(row.state, "LISTEN");
        assert_eq!(row.owner.as_ref().map(|owner| owner.pid), Some(me));
        let process = snapshot.processes.iter().find(|p| p.pid == me).unwrap();
        assert!(process.socket_count >= 1);
    }
}
