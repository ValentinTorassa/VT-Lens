//! Linux backend: everything comes from `/proc`, readable without root.

use std::collections::HashMap;

use super::net_poller::{read_connections, socket_owners};
use super::proc_poller::read_processes;
use super::{CaptureSource, Platform, Snapshot};

pub struct ProcSource;

impl CaptureSource for ProcSource {
    fn platform(&self) -> Platform {
        Platform::Linux
    }

    fn capture(&mut self) -> Snapshot {
        let owners = socket_owners();
        let mut processes = read_processes();
        let mut socket_counts: HashMap<u32, usize> = HashMap::new();

        for owner in owners.values() {
            *socket_counts.entry(owner.pid).or_default() += 1;
        }

        for process in &mut processes {
            process.socket_count = socket_counts.get(&process.pid).copied().unwrap_or(0);
        }

        let connections = read_connections(&owners);
        let status = format!(
            "{} processes · {} connections · connection-level capture (no root)",
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
