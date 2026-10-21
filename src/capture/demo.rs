//! Demo mode (`vt-lens --demo`): a fixed synthetic dataset for screenshots,
//! videos and labs. Nothing here comes from the machine. Every address is in a
//! documentation range (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
//! 2001:db8::/32) or loopback, and every hostname is under example.com/.net/.org.

use super::{CaptureSource, Platform, Snapshot};
use crate::model::{NetRow, ProcessRow, SocketId, SocketOwner};

/// Reverse-DNS names shown for the demo peers (display only, never exported).
/// Demo mode never performs real lookups.
pub const HOSTNAMES: &[(&str, &str)] = &[
    ("198.51.100.42:443", "www.example.com:443"),
    ("203.0.113.17:443", "cdn.example.net:443"),
    ("[2001:db8:0:1::443]:443", "static.example.org:443"),
    ("203.0.113.80:993", "imap.example.com:993"),
    ("198.51.100.7:443", "sync.example.com:443"),
];

// (pid, name, cmdline, rss_kb, threads, uid class: 0 root, 1 system, 2 user)
const PROCESSES: &[(u32, &str, &str, u64, u32, u8)] = &[
    (1, "init", "init", 12_288, 1, 0),
    (412, "resolver", "resolver --stub 127.0.0.1:53", 9_840, 2, 1),
    (688, "sshd", "sshd -D", 7_312, 1, 0),
    (1420, "browser", "browser --profile demo", 420_000, 24, 2),
    (
        1842,
        "web-server",
        "web-server --listen 127.0.0.1:8080",
        86_000,
        6,
        2,
    ),
    (
        1903,
        "api-test",
        "api-test http://127.0.0.1:8080/health",
        18_500,
        2,
        2,
    ),
    (2301, "ssh-agent", "ssh-agent", 4_600, 1, 2),
    (2714, "database", "database --config demo", 152_000, 8, 1),
    (
        3105,
        "mail-client",
        "mail-client --account demo",
        210_400,
        14,
        2,
    ),
    (3380, "vt-lens", "vt-lens --demo", 74_000, 5, 2),
    (
        3512,
        "sync-agent",
        "sync-agent --folder ~/Demo",
        64_200,
        9,
        2,
    ),
    (3790, "editor", "editor notes.md", 128_000, 11, 2),
];

// (protocol, local, remote, state, owner pid; 0 = no owner, as for TIME_WAIT)
const CONNECTIONS: &[(&str, &str, &str, &str, u32)] = &[
    (
        "tcp",
        "192.0.2.10:53918",
        "198.51.100.42:443",
        "ESTABLISHED",
        1420,
    ),
    (
        "tcp",
        "192.0.2.10:53920",
        "203.0.113.17:443",
        "ESTABLISHED",
        1420,
    ),
    (
        "tcp6",
        "[2001:db8::10]:40112",
        "[2001:db8:0:1::443]:443",
        "ESTABLISHED",
        1420,
    ),
    (
        "udp",
        "192.0.2.10:51111",
        "198.51.100.42:443",
        "ESTABLISHED",
        1420,
    ),
    ("tcp", "127.0.0.1:8080", "0.0.0.0:0", "LISTEN", 1842),
    (
        "tcp",
        "127.0.0.1:8080",
        "127.0.0.1:51432",
        "ESTABLISHED",
        1842,
    ),
    (
        "tcp",
        "127.0.0.1:51432",
        "127.0.0.1:8080",
        "ESTABLISHED",
        1903,
    ),
    ("tcp", "127.0.0.1:5432", "0.0.0.0:0", "LISTEN", 2714),
    ("tcp", "0.0.0.0:22", "0.0.0.0:0", "LISTEN", 688),
    ("tcp6", "[::]:22", "[::]:0", "LISTEN", 688),
    ("udp", "127.0.0.1:53", "0.0.0.0:0", "CLOSE", 412),
    ("tcp", "127.0.0.1:53", "0.0.0.0:0", "LISTEN", 412),
    (
        "tcp",
        "192.0.2.10:49822",
        "203.0.113.80:993",
        "ESTABLISHED",
        3105,
    ),
    (
        "tcp",
        "192.0.2.10:50210",
        "198.51.100.7:443",
        "ESTABLISHED",
        3512,
    ),
    (
        "tcp",
        "192.0.2.10:50198",
        "198.51.100.7:443",
        "TIME_WAIT",
        0,
    ),
];

pub struct DemoSource {
    platform: Platform,
}

impl DemoSource {
    pub fn new(platform: Platform) -> Self {
        Self { platform }
    }

    fn uid(&self, class: u8) -> u32 {
        match (class, self.platform) {
            (0, _) => 0,
            (1, Platform::Linux) => 112,
            (1, Platform::MacOs) => 270,
            _ => self.platform.first_user_uid(),
        }
    }
}

impl CaptureSource for DemoSource {
    fn platform(&self) -> Platform {
        self.platform
    }

    fn is_demo(&self) -> bool {
        true
    }

    fn capture(&mut self) -> Snapshot {
        let connections: Vec<NetRow> = CONNECTIONS
            .iter()
            .enumerate()
            // lsof lists sockets per process, so macOS never shows ownerless ones.
            .filter(|(_, row)| row.4 != 0 || self.platform == Platform::Linux)
            .map(|(index, &(protocol, local, remote, state, pid))| {
                let owner = PROCESSES
                    .iter()
                    .find(|process| process.0 == pid)
                    .map(|process| SocketOwner {
                        pid,
                        process: process.1.into(),
                    });
                // Linux names sockets by inode, macOS by the owner's fd.
                let socket_id = match self.platform {
                    Platform::Linux => SocketId::Inode(48_210 + index as u64 * 7),
                    Platform::MacOs => SocketId::Fd {
                        pid,
                        fd: 20 + index as u32,
                    },
                };
                NetRow {
                    protocol: protocol.into(),
                    local_addr: local.into(),
                    remote_addr: remote.into(),
                    state: state.into(),
                    tx_queue: 0,
                    rx_queue: 0,
                    socket_id,
                    owner,
                }
            })
            .collect();

        let processes = PROCESSES
            .iter()
            .map(
                |&(pid, name, cmdline, rss_kb, threads, uid_class)| ProcessRow {
                    start_id: Some(u64::from(pid)),
                    pid,
                    name: if pid == 1 && self.platform == Platform::MacOs {
                        "launchd".into()
                    } else {
                        name.into()
                    },
                    cmdline: cmdline.into(),
                    state: "S (sleeping)".into(),
                    rss_kb,
                    threads,
                    socket_count: connections
                        .iter()
                        .filter(|row| row.owner.as_ref().map(|owner| owner.pid) == Some(pid))
                        .count(),
                    uid: Some(self.uid(uid_class)),
                },
            )
            .collect();

        Snapshot {
            processes,
            connections,
            // ASCII on purpose: the Markdown export keeps only [A-Za-z0-9 ()_-]
            // of the status line, which turned "sintéticos" into "sintticos".
            status: "DEMO - synthetic data (nothing captured from this machine)".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{EndpointClass, classify};
    use std::net::{IpAddr, SocketAddr};

    /// Only documentation ranges, loopback and wildcards may appear.
    fn is_synthetic(addr: &str) -> bool {
        let ip = addr.parse::<SocketAddr>().expect(addr).ip();
        match ip {
            IpAddr::V4(v4) => {
                let [a, b, c, _] = v4.octets();
                v4.is_loopback()
                    || v4.is_unspecified()
                    || (a, b, c) == (192, 0, 2)
                    || (a, b, c) == (198, 51, 100)
                    || (a, b, c) == (203, 0, 113)
            }
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unspecified() || v6.segments()[..2] == [0x2001, 0x0db8]
            }
        }
    }

    #[test]
    fn demo_uses_documentation_addresses_only() {
        for platform in [Platform::Linux, Platform::MacOs] {
            let snapshot = DemoSource::new(platform).capture();
            for row in &snapshot.connections {
                assert!(is_synthetic(&row.local_addr), "{}", row.local_addr);
                assert!(is_synthetic(&row.remote_addr), "{}", row.remote_addr);
            }
            let ids: std::collections::HashSet<_> = snapshot
                .connections
                .iter()
                .map(|row| row.socket_id)
                .collect();
            assert_eq!(
                ids.len(),
                snapshot.connections.len(),
                "socket ids must be unique"
            );
            assert!(
                snapshot
                    .connections
                    .iter()
                    .any(|row| classify(&row.remote_addr) == EndpointClass::External)
            );
        }
        for (addr, host) in HOSTNAMES {
            assert!(is_synthetic(addr), "{addr}");
            let name = host.rsplit_once(':').unwrap().0;
            assert!(
                [".example.com", ".example.net", ".example.org"]
                    .iter()
                    .any(|suffix| name.ends_with(suffix)),
                "{host}"
            );
        }
    }
}
