//! macOS sockets from `lsof`, read in its field mode (`-F`), which is meant for
//! programs: one field per line, the first character names the field.
//!
//! `lsof -nP -iTCP -iUDP -F pcfdtPnT -T qs` prints a process set (`p` PID,
//! `c` command) followed by one file set per socket (`f` fd, `t` IPv4/IPv6,
//! `d` kernel socket handle, `P` TCP/UDP, `n` addresses, `T` TCP state and
//! queue sizes). Without root, lsof only sees the user's own processes.

// On Linux this module is compiled only for its unit tests.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::collections::HashSet;

use super::strip_control;
use crate::model::{NetRow, SocketId, SocketOwner};

/// Absolute path, so a `lsof` earlier in `$PATH` is never run instead.
const LSOF: &str = "/usr/sbin/lsof";
const ARGS: &[&str] = &[
    "-nP", // no DNS or port-name lookups
    "-w",  // no warnings on stderr
    "+c", "0", // full command names
    "-iTCP", "-iUDP", "-F", "pcfdtPnT", "-T", "qs", // TCP queue sizes and state
];

/// Runs lsof and parses its output. An error or a missing lsof yields no rows.
pub fn read_connections() -> Vec<NetRow> {
    // lsof exits 1 when it finds nothing; the output is still well formed.
    match std::process::Command::new(LSOF).args(ARGS).output() {
        Ok(output) => parse(&String::from_utf8_lossy(&output.stdout)),
        Err(_) => Vec::new(),
    }
}

#[derive(Default)]
struct File {
    fd: Option<u32>,
    ipv6: bool,
    device: Option<String>,
    protocol: Option<String>,
    name: Option<String>,
    state: Option<String>,
    rx_queue: u64,
    tx_queue: u64,
}

/// Parses `-F pcfdtPnT -T qs` output into rows. A socket shared by several
/// processes (inherited across fork) is listed once per process; like the
/// Linux backend, the first owner wins.
pub fn parse(output: &str) -> Vec<NetRow> {
    let mut rows = Vec::new();
    let mut seen_devices = HashSet::new();
    let mut owner: Option<SocketOwner> = None;
    let mut file: Option<File> = None;

    let mut flush = |file: &mut Option<File>, owner: &Option<SocketOwner>| {
        if let (Some(done), Some(owner)) = (file.take(), owner)
            && let Some(row) = to_row(done, owner)
        {
            let duplicate = match &row.1 {
                Some(device) => !seen_devices.insert(device.clone()),
                None => false,
            };
            if !duplicate {
                rows.push(row.0);
            }
        }
    };

    for line in output.lines() {
        let mut chars = line.chars();
        let Some(field) = chars.next() else {
            continue;
        };
        let value = chars.as_str();
        match field {
            'p' => {
                flush(&mut file, &owner);
                owner = value.parse().ok().map(|pid| SocketOwner {
                    pid,
                    process: pid.to_string(),
                });
            }
            'c' => {
                if let Some(owner) = owner.as_mut() {
                    let name = strip_control(value).trim().to_string();
                    if !name.is_empty() {
                        owner.process = name;
                    }
                }
            }
            'f' => {
                flush(&mut file, &owner);
                file = Some(File {
                    fd: value.parse().ok(),
                    ..File::default()
                });
            }
            't' | 'd' | 'P' | 'n' | 'T' => {
                let Some(file) = file.as_mut() else {
                    continue;
                };
                match field {
                    't' => file.ipv6 = value == "IPv6",
                    'd' => file.device = Some(value.to_string()),
                    'P' => file.protocol = Some(value.to_ascii_lowercase()),
                    'n' => file.name = Some(value.to_string()),
                    _ => match value.split_once('=') {
                        Some(("ST", state)) => file.state = Some(state.to_string()),
                        Some(("QR", queue)) => file.rx_queue = queue.parse().unwrap_or(0),
                        Some(("QS", queue)) => file.tx_queue = queue.parse().unwrap_or(0),
                        _ => {}
                    },
                }
            }
            _ => {}
        }
    }
    flush(&mut file, &owner);

    rows.sort_by(|left, right| {
        left.owner_label()
            .cmp(&right.owner_label())
            .then(left.protocol.cmp(&right.protocol))
            .then(left.local_addr.cmp(&right.local_addr))
    });
    rows
}

/// Builds a row in the same shape the Linux backend produces: `tcp`/`tcp6`,
/// `0.0.0.0:0` or `[::]:0` for a missing peer, Linux state names.
fn to_row(file: File, owner: &SocketOwner) -> Option<(NetRow, Option<String>)> {
    let fd = file.fd?;
    let protocol = file.protocol?;
    if protocol != "tcp" && protocol != "udp" {
        return None;
    }
    let name = file.name?;
    let (local, remote) = match name.split_once("->") {
        Some((local, remote)) => (local, Some(remote)),
        None => (name.as_str(), None),
    };
    let local_addr = normalize_endpoint(local, file.ipv6);
    let remote_addr = remote
        .map(|remote| normalize_endpoint(remote, file.ipv6))
        .unwrap_or_else(|| wildcard(file.ipv6, "0"));
    let state = match (&file.state, remote) {
        (Some(state), _) => linux_state_name(state).to_string(),
        // An unconnected UDP socket; Linux reports it as CLOSE (07).
        (None, None) => "CLOSE".to_string(),
        // A connected UDP socket (connect(2) on UDP, e.g. QUIC or DNS).
        (None, Some(_)) => "ESTABLISHED".to_string(),
    };

    let row = NetRow {
        protocol: if file.ipv6 {
            format!("{protocol}6")
        } else {
            protocol
        },
        local_addr,
        remote_addr,
        state,
        tx_queue: file.tx_queue,
        rx_queue: file.rx_queue,
        socket_id: SocketId::Fd { pid: owner.pid, fd },
        owner: Some(owner.clone()),
    };
    Some((row, file.device))
}

fn wildcard(ipv6: bool, port: &str) -> String {
    if ipv6 {
        format!("[::]:{port}")
    } else {
        format!("0.0.0.0:{port}")
    }
}

/// lsof prints `*:5353` for a wildcard, `*:*` for an unbound socket and
/// `[fe80::1%en0]:123` for a scoped IPv6 address. The rest of the app parses
/// endpoints as `SocketAddr`, which takes neither `*` nor interface names.
fn normalize_endpoint(endpoint: &str, ipv6: bool) -> String {
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return endpoint.to_string();
    };
    let port = if port == "*" { "0" } else { port };
    if host == "*" {
        return wildcard(ipv6, port);
    }
    match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(inner) => {
            let address = inner.split_once('%').map_or(inner, |(address, _)| address);
            format!("[{address}]:{port}")
        }
        None => format!("{host}:{port}"),
    }
}

/// lsof uses the BSD names; the UI, filters and evidence use Linux's.
fn linux_state_name(state: &str) -> &str {
    match state {
        "FIN_WAIT_1" => "FIN_WAIT1",
        "FIN_WAIT_2" => "FIN_WAIT2",
        "SYN_RECEIVED" => "SYN_RECV",
        "CLOSED" => "CLOSE",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic lsof output: documentation addresses, made-up processes.
    const SAMPLE: &str = "\
p1420
cbrowser helper
f23
tIPv4
d0x5c1d2e3f4a5b6c7d
PTCP
n192.0.2.10:53918->198.51.100.42:443
TST=ESTABLISHED
TQR=0
TQS=31
f24
tIPv6
d0x1a2b3c4d5e6f7081
PTCP
n*:8080
TST=LISTEN
TQR=0
TQS=0
f25
tIPv4
d0x0f0e0d0c0b0a0908
PUDP
n*:5353
f26
tIPv6
d0x2233445566778899
PUDP
n[fe80::1%en0]:51000->[2001:db8::53]:53
f27
tIPv4
d0x99aabbccddeeff00
PUDP
n*:*
p1903
capi-test
f9
tIPv4
d0x5c1d2e3f4a5b6c7d
PTCP
n192.0.2.10:53918->198.51.100.42:443
TST=ESTABLISHED
f10
tIPv4
d0x7766554433221100
PTCP
n127.0.0.1:51432->127.0.0.1:8080
TST=FIN_WAIT_2
TQR=0
TQS=0
";

    #[test]
    fn parses_field_output_into_linux_shaped_rows() {
        let rows = parse(SAMPLE);
        let find = |fd: u32| {
            rows.iter()
                .find(|row| matches!(row.socket_id, SocketId::Fd { fd: f, .. } if f == fd))
                .unwrap_or_else(|| panic!("fd {fd} missing"))
        };

        let established = find(23);
        assert_eq!(established.protocol, "tcp");
        assert_eq!(established.local_addr, "192.0.2.10:53918");
        assert_eq!(established.remote_addr, "198.51.100.42:443");
        assert_eq!(established.state, "ESTABLISHED");
        assert_eq!(established.tx_queue, 31);
        assert_eq!(established.owner_label(), "browser helper (1420)");
        assert_eq!(established.socket_id, SocketId::Fd { pid: 1420, fd: 23 });

        let listen = find(24);
        assert_eq!(listen.protocol, "tcp6");
        assert_eq!(listen.local_addr, "[::]:8080");
        assert_eq!(listen.remote_addr, "[::]:0");
        assert_eq!(listen.state, "LISTEN");

        let mdns = find(25);
        assert_eq!(
            (mdns.protocol.as_str(), mdns.local_addr.as_str()),
            ("udp", "0.0.0.0:5353")
        );
        assert_eq!(
            (mdns.remote_addr.as_str(), mdns.state.as_str()),
            ("0.0.0.0:0", "CLOSE")
        );

        let scoped = find(26);
        assert_eq!(scoped.protocol, "udp6");
        assert_eq!(scoped.local_addr, "[fe80::1]:51000");
        assert_eq!(scoped.remote_addr, "[2001:db8::53]:53");
        assert_eq!(scoped.state, "ESTABLISHED");

        assert_eq!(find(27).local_addr, "0.0.0.0:0");
        assert_eq!(find(10).state, "FIN_WAIT2");

        // fd 9 of pid 1903 is the same kernel socket as fd 23 of pid 1420.
        assert!(
            rows.iter()
                .all(|row| row.socket_id != SocketId::Fd { pid: 1903, fd: 9 })
        );
        assert_eq!(rows.len(), 6);

        // Every endpoint must parse the way the rest of the app reads it.
        for row in &rows {
            for addr in [&row.local_addr, &row.remote_addr] {
                assert!(addr.parse::<std::net::SocketAddr>().is_ok(), "{addr}");
            }
        }
    }

    #[test]
    fn tolerates_garbage_and_strips_control_characters() {
        let rows = parse(
            "p77\ncevil\u{1b}[31mname\nfX\nPTCP\nn1.2.3.4:1\nf3\nPTCP\nn192.0.2.1:22->192.0.2.2:5000\nzunknown\n\n",
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].owner_label(), "evil [31mname (77)");
        assert!(parse("").is_empty());
        assert!(
            parse("f3\nPTCP\nn192.0.2.1:22\n").is_empty(),
            "a file without a process is dropped"
        );
    }
}
