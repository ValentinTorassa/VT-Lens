//! Two fixed captures held in memory. No disk, network or LLM side effects.
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::evidence::{endpoint_label, safe_process_name};
use crate::model::{NetRow, ProcessRow, SocketId};
use crate::redaction::redact_with_terms;

pub struct Capture {
    pub processes: Vec<ProcessRow>,
    pub connections: Vec<NetRow>,
    pub at: Instant,
}

impl Capture {
    pub fn new(processes: &[ProcessRow], connections: &[NetRow], at: Instant) -> Self {
        Self {
            processes: processes.to_vec(),
            connections: connections.to_vec(),
            at,
        }
    }
}

pub struct Comparison {
    pub appeared: Vec<ProcessRow>,
    pub disappeared: Vec<ProcessRow>,
    pub opened: Vec<NetRow>,
    pub missing: Vec<NetRow>,
    pub state_changes: Vec<(NetRow, NetRow)>,
    pub elapsed: Duration,
}

fn process_key(p: &ProcessRow) -> (u32, Option<u64>, &str, Option<u32>) {
    (p.pid, p.start_id, &p.name, p.uid)
}

type SocketKey<'a> = (
    SocketId,
    &'a str,
    &'a str,
    &'a str,
    Option<(u32, Option<u64>)>,
);
fn socket_key<'a>(row: &'a NetRow, processes: &[ProcessRow]) -> SocketKey<'a> {
    let owner = row.owner.as_ref().map(|o| {
        (
            o.pid,
            processes
                .iter()
                .find(|p| p.pid == o.pid)
                .and_then(|p| p.start_id),
        )
    });
    (
        row.socket_id,
        &row.protocol,
        &row.local_addr,
        &row.remote_addr,
        owner,
    )
}

impl Comparison {
    pub fn between(before: &Capture, after: &Capture) -> Self {
        let old: HashMap<_, _> = before
            .processes
            .iter()
            .map(|p| (process_key(p), p))
            .collect();
        let new: HashMap<_, _> = after
            .processes
            .iter()
            .map(|p| (process_key(p), p))
            .collect();
        let sockets: HashMap<_, _> = before
            .connections
            .iter()
            .map(|c| (socket_key(c, &before.processes), c))
            .collect();
        let current: HashMap<_, _> = after
            .connections
            .iter()
            .map(|c| (socket_key(c, &after.processes), c))
            .collect();
        Self {
            appeared: after
                .processes
                .iter()
                .filter(|p| !old.contains_key(&process_key(p)))
                .cloned()
                .collect(),
            disappeared: before
                .processes
                .iter()
                .filter(|p| !new.contains_key(&process_key(p)))
                .cloned()
                .collect(),
            opened: after
                .connections
                .iter()
                .filter(|c| !sockets.contains_key(&socket_key(c, &after.processes)))
                .cloned()
                .collect(),
            missing: before
                .connections
                .iter()
                .filter(|c| !current.contains_key(&socket_key(c, &before.processes)))
                .cloned()
                .collect(),
            state_changes: after
                .connections
                .iter()
                .filter_map(|c| {
                    let old = sockets.get(&socket_key(c, &after.processes))?;
                    (old.state != c.state).then(|| ((*old).clone(), c.clone()))
                })
                .collect(),
            elapsed: after.at.saturating_duration_since(before.at),
        }
    }

    /// Uses the existing evidence allowlist: never include command lines or raw addresses.
    pub fn markdown(&self, private_terms: &str) -> String {
        let mut out = format!(
            "# Comparación antes / después\n\nIntervalo: {:.1} s. Capturas visibles sin root.\n\n",
            self.elapsed.as_secs_f64()
        );
        out.push_str("Son diferencias de visibilidad, no prueba de que un proceso terminó o un socket se cerró.\nNo incluye actividad transitoria entre capturas. Sin hora de inicio, un PID reutilizado puede ser indistinguible.\n\n");
        for (title, rows) in [
            ("Procesos nuevos", &self.appeared),
            ("Procesos que dejaron de verse", &self.disappeared),
        ] {
            out.push_str(&format!("## {title}: {}\n", rows.len()));
            for p in rows {
                out.push_str(&format!(
                    "- PID {} · {}\n",
                    p.pid,
                    safe_process_name(&p.name)
                ));
            }
            out.push('\n');
        }
        for (title, rows) in [
            ("Sockets nuevos", &self.opened),
            ("Sockets que dejaron de verse", &self.missing),
        ] {
            out.push_str(&format!("## {title}: {}\n", rows.len()));
            for c in rows {
                out.push_str(&format!(
                    "- {} · {} → {} · {}\n",
                    c.protocol,
                    endpoint_label(&c.local_addr, true),
                    endpoint_label(&c.remote_addr, false),
                    c.state
                ));
            }
            out.push('\n');
        }
        out.push_str(&format!(
            "## Cambios de estado: {}\n",
            self.state_changes.len()
        ));
        for (old, new) in &self.state_changes {
            out.push_str(&format!(
                "- {} · {} → {} · {} → {}\n",
                new.protocol,
                endpoint_label(&new.local_addr, true),
                endpoint_label(&new.remote_addr, false),
                old.state,
                new.state
            ));
        }
        redact_with_terms(&out, private_terms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SocketOwner;

    fn process(start: u64) -> ProcessRow {
        ProcessRow {
            pid: 42,
            start_id: Some(start),
            name: "demo".into(),
            cmdline: "SECRET=synthetic-secret".into(),
            ..Default::default()
        }
    }
    fn socket(remote: &str, state: &str) -> NetRow {
        NetRow {
            protocol: "tcp".into(),
            local_addr: "192.0.2.1:5000".into(),
            remote_addr: remote.into(),
            state: state.into(),
            socket_id: SocketId::Fd { pid: 42, fd: 7 },
            tx_queue: 0,
            rx_queue: 0,
            owner: Some(SocketOwner {
                pid: 42,
                process: "demo".into(),
            }),
        }
    }
    #[test]
    fn pid_reuse_and_reused_fd_are_new_identities() {
        let at = Instant::now();
        let before = Capture::new(
            &[process(1)],
            &[socket("203.0.113.1:443", "ESTABLISHED")],
            at,
        );
        let after = Capture::new(
            &[process(2)],
            &[socket("203.0.113.2:443", "ESTABLISHED")],
            at + Duration::from_secs(3),
        );
        let diff = Comparison::between(&before, &after);
        assert_eq!(
            (
                diff.appeared.len(),
                diff.disappeared.len(),
                diff.opened.len(),
                diff.missing.len()
            ),
            (1, 1, 1, 1)
        );
        assert_eq!(diff.elapsed.as_secs(), 3);
        let md = diff.markdown("demo");
        for secret in [
            "synthetic-secret",
            "SECRET=",
            "192.0.2.1",
            "203.0.113.2",
            "demo",
        ] {
            assert!(!md.contains(secret));
        }
    }
    #[test]
    fn state_change_is_not_a_new_socket() {
        let at = Instant::now();
        let a = Capture::new(&[process(1)], &[socket("203.0.113.1:443", "SYN_SENT")], at);
        let b = Capture::new(
            &[process(1)],
            &[socket("203.0.113.1:443", "ESTABLISHED")],
            at,
        );
        let diff = Comparison::between(&a, &b);
        assert!(
            diff.appeared.is_empty()
                && diff.disappeared.is_empty()
                && diff.opened.is_empty()
                && diff.missing.is_empty()
        );
        assert_eq!(diff.state_changes.len(), 1);
        assert!(diff.markdown("").contains("SYN_SENT → ESTABLISHED"));
    }
}
