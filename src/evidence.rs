//! Evidence that may leave the machine (LLM prompt, Markdown export).
//!
//! It is built from an allowlist of structured fields instead of scrubbing free
//! text: the process basename (sanitized), PID and resource counters, the UID
//! *class*, protocol, socket state, inode, and each endpoint reduced to its
//! address class plus port. Command lines, raw IPs, hostnames and account
//! names never enter it, so there is nothing for a redaction pattern to miss.
//! The free-text redaction in `redaction.rs` still runs over the final prompt,
//! as a second layer for whatever the user types into the editable preview.

use std::net::{IpAddr, SocketAddr};

use crate::model::{NetRow, ProcessRow};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointClass {
    Localhost,
    PrivateLan,
    Listening,
    Multicast,
    External,
    Unknown,
}

fn parse_endpoint(addr: &str) -> Option<SocketAddr> {
    addr.trim().parse::<SocketAddr>().ok()
}

/// IPv4-mapped IPv6 (::ffff:a.b.c.d) is classified as the IPv4 address it carries.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // RFC 1918, link-local, and 100.64.0.0/10 (CGNAT, also Tailscale)
            v4.is_private() || v4.is_link_local() || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 // ULA, link-local
        }
    }
}

fn is_multicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_multicast() || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_multicast(),
    }
}

/// Classify a remote endpoint as printed by the capture ("1.2.3.4:443",
/// "[::1]:631"). A wildcard address or port 0 means there is no peer.
pub fn classify(addr: &str) -> EndpointClass {
    let Some(sa) = parse_endpoint(addr) else {
        return EndpointClass::Unknown;
    };
    let ip = canonical(sa.ip());
    if ip.is_unspecified() || sa.port() == 0 {
        EndpointClass::Listening
    } else if ip.is_loopback() {
        EndpointClass::Localhost
    } else if is_multicast(ip) {
        EndpointClass::Multicast
    } else if is_private(ip) {
        EndpointClass::PrivateLan
    } else {
        EndpointClass::External
    }
}

/// An endpoint reduced to "class/family:port"; the address itself is dropped.
/// A local wildcard reads as every interface; a remote wildcard as no peer.
pub fn endpoint_label(addr: &str, local: bool) -> String {
    let Some(sa) = parse_endpoint(addr) else {
        return "desconocido".to_string();
    };
    let ip = canonical(sa.ip());
    let family = if ip.is_ipv4() { "v4" } else { "v6" };
    let class = if ip.is_unspecified() {
        if local { "todas-las-interfaces" } else { return "sin-par".to_string() }
    } else if ip.is_loopback() {
        "loopback"
    } else if is_multicast(ip) {
        "multicast"
    } else if is_private(ip) {
        "red-privada"
    } else {
        "externa"
    };
    format!("{class}/{family}:{}", sa.port())
}

/// comm is set by the process itself; keep a short, plain token.
pub fn safe_process_name(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+') { c } else { '_' })
        .take(32)
        .collect();
    if clean.trim_matches('_').is_empty() { "(sin nombre)".to_string() } else { clean }
}

fn safe_token(value: &str, max: usize) -> String {
    value.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '(' | ')' | '_' | '-')).take(max).collect()
}

fn safe_digits(value: &str) -> String {
    value.chars().filter(char::is_ascii_digit).take(20).collect()
}

pub fn uid_class(uid: Option<u32>) -> &'static str {
    match uid {
        None => "desconocido",
        Some(0) => "root",
        Some(65534) => "nobody",
        Some(1..=999) => "sistema",
        Some(_) => "usuario",
    }
}

pub struct EvidenceInput<'a> {
    pub processes: &'a [ProcessRow],
    pub connections: &'a [NetRow],
    pub selected_pid: Option<u32>,
    pub selected_inode: Option<&'a str>,
    /// Connections currently shown (filters applied); used when no process is selected.
    pub sample: &'a [NetRow],
}

fn owner_pid(conn: &NetRow) -> Option<u32> {
    conn.owner.as_ref().map(|o| o.pid)
}

fn connection_line(conn: &NetRow) -> String {
    format!(
        "{} {} -> {} [{}] inode={}",
        safe_token(&conn.protocol, 8),
        endpoint_label(&conn.local_addr, true),
        endpoint_label(&conn.remote_addr, false),
        safe_token(&conn.state, 16),
        safe_digits(&conn.inode),
    )
}

fn push_selected_connection(out: &mut String, conn: &NetRow) {
    out.push_str("Selected connection:\n");
    out.push_str(&format!("* protocol: {}\n", safe_token(&conn.protocol, 8)));
    out.push_str(&format!("* local: {}\n", endpoint_label(&conn.local_addr, true)));
    out.push_str(&format!("* remote: {}\n", endpoint_label(&conn.remote_addr, false)));
    out.push_str(&format!("* state: {}\n", safe_token(&conn.state, 16)));
    out.push_str(&format!("* inode: {}\n", safe_digits(&conn.inode)));
    out.push_str(&format!("* classification: {:?}\n\n", classify(&conn.remote_addr)));
}

pub fn build_evidence(input: &EvidenceInput) -> String {
    let mut out = String::new();
    let selected_conn = input
        .selected_inode
        .and_then(|inode| input.connections.iter().find(|c| c.inode == inode));

    let Some(pid) = input.selected_pid else {
        out.push_str("No process selected.\n\n");
        if let Some(conn) = selected_conn {
            push_selected_connection(&mut out, conn);
        }
        out.push_str("Recent Network Connections (Sample):\n");
        if input.sample.is_empty() {
            out.push_str("No current network connections were found in the latest snapshot.\n\n");
        }
        for (idx, conn) in input.sample.iter().take(20).enumerate() {
            let owner = conn
                .owner
                .as_ref()
                .map(|o| format!("{} ({})", safe_process_name(&o.process), o.pid))
                .unwrap_or_else(|| "unknown".to_string());
            let marker = if Some(conn.inode.as_str()) == input.selected_inode { " [SELECTED_CONNECTION]" } else { "" };
            out.push_str(&format!("{}. {} owner={}{}\n", idx + 1, connection_line(conn), owner, marker));
        }
        if input.sample.len() > 20 {
            out.push_str(&format!("... and {} more connections.\n", input.sample.len() - 20));
        }
        return out;
    };

    match input.processes.iter().find(|p| p.pid == pid) {
        Some(p) => {
            out.push_str("Selected process:\n");
            out.push_str(&format!("* pid: {}\n", p.pid));
            out.push_str(&format!("* comm (binario): {}\n", safe_process_name(&p.name)));
            out.push_str(&format!("* state: {}\n", safe_token(&p.state, 24)));
            out.push_str(&format!("* uid_class: {}\n", uid_class(p.uid)));
            out.push_str(&format!("* rss_mb: {:.1}\n", p.rss_mb()));
            out.push_str(&format!("* threads: {}\n", p.threads));
            out.push_str(&format!("* sockets_reported: {}\n", p.socket_count));
            out.push_str("* cmdline: omitida (los argumentos no salen del equipo)\n\n");
        }
        None => out.push_str(&format!("Selected process PID: {pid}\n\n")),
    }

    let pid_conns: Vec<&NetRow> = input.connections.iter().filter(|c| owner_pid(c) == Some(pid)).collect();
    let count = |class: EndpointClass| pid_conns.iter().filter(|c| classify(&c.remote_addr) == class).count();
    out.push_str("Connection summary for this PID:\n");
    out.push_str(&format!("* total_current_connections: {}\n", pid_conns.len()));
    out.push_str(&format!("* external: {}\n", count(EndpointClass::External)));
    out.push_str(&format!("* localhost: {}\n", count(EndpointClass::Localhost)));
    out.push_str(&format!("* listening: {}\n", pid_conns.iter().filter(|c| c.state == "LISTEN").count()));
    out.push_str(&format!(
        "* udp_multicast: {}\n\n",
        pid_conns.iter().filter(|c| c.protocol.starts_with("udp") || classify(&c.remote_addr) == EndpointClass::Multicast).count()
    ));

    if let Some(conn) = selected_conn {
        push_selected_connection(&mut out, conn);
    }

    out.push_str("Related connections:\n");
    if pid_conns.is_empty() {
        out.push_str(
            "No current network connections were found for this PID in the latest snapshot.\n\
             Possible causes:\n\
             * the process closed the sockets\n\
             * the snapshot changed\n\
             * the process has socket-like file descriptors but no active TCP/UDP entries\n\
             * active filters are hiding results\n\n",
        );
    }
    for (idx, conn) in pid_conns.iter().take(20).enumerate() {
        let marker = if Some(conn.inode.as_str()) == input.selected_inode { " [SELECTED_CONNECTION]" } else { "" };
        out.push_str(&format!("{}. {}{}\n", idx + 1, connection_line(conn), marker));
    }
    if pid_conns.len() > 20 {
        out.push_str(&format!("... and {} more connections.\n", pid_conns.len() - 20));
    }
    out
}

/// Markdown export built from the same allowlist as the prompt evidence.
pub fn build_markdown(input: &EvidenceInput, status: &str) -> String {
    let mut md = String::from("# VT Lens Evidence\n\n");
    md.push_str(&format!("Status: {}\n\n", safe_token(status, 120)));
    md.push_str("Addresses are reduced to class and port; command lines, IPs and hostnames are not exported.\n\n");

    let focused_pid = input.selected_pid.or_else(|| {
        input
            .selected_inode
            .and_then(|inode| input.connections.iter().find(|c| c.inode == inode))
            .and_then(owner_pid)
    });
    if let Some(pid) = focused_pid {
        md.push_str("## Selected Process\n\n");
        md.push_str(&format!("- PID: {pid}\n"));
        if let Some(p) = input.processes.iter().find(|p| p.pid == pid) {
            md.push_str(&format!("- Comm: {}\n", safe_process_name(&p.name)));
            md.push_str(&format!("- State: {}\n", safe_token(&p.state, 24)));
            md.push_str(&format!("- UID class: {}\n", uid_class(p.uid)));
            md.push_str(&format!("- RSS: {:.1} MB\n", p.rss_mb()));
            md.push_str(&format!("- Threads: {}\n", p.threads));
            md.push_str(&format!("- Sockets: {}\n", p.socket_count));
        }
        md.push('\n');
    }

    if let Some(conn) = input.selected_inode.and_then(|inode| input.connections.iter().find(|c| c.inode == inode)) {
        md.push_str("## Focused Network Connection\n\n");
        md.push_str(&format!("- Protocol: {}\n", safe_token(&conn.protocol, 8)));
        md.push_str(&format!("- Local: `{}`\n", endpoint_label(&conn.local_addr, true)));
        md.push_str(&format!("- Remote: `{}`\n", endpoint_label(&conn.remote_addr, false)));
        md.push_str(&format!("- State: {}\n", safe_token(&conn.state, 16)));
        md.push_str(&format!("- Owner PID: {}\n", owner_pid(conn).map(|p| p.to_string()).unwrap_or_else(|| "unknown".into())));
        md.push_str(&format!("- Inode: {}\n", safe_digits(&conn.inode)));
        md.push_str(&format!("- Queues: tx={} rx={}\n\n", conn.tx_queue, conn.rx_queue));
    }

    md.push_str("## Network Sample\n\n| Proto | Local | Remote | State | Owner | Queues |\n| --- | --- | --- | --- | --- | --- |\n");
    for conn in input.sample.iter().take(50) {
        md.push_str(&format!(
            "| {} | `{}` | `{}` | {} | {} | tx={} rx={} |\n",
            safe_token(&conn.protocol, 8),
            endpoint_label(&conn.local_addr, true),
            endpoint_label(&conn.remote_addr, false),
            safe_token(&conn.state, 16),
            owner_pid(conn).map(|p| p.to_string()).unwrap_or_else(|| "unknown".into()),
            conn.tx_queue,
            conn.rx_queue,
        ));
    }
    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SocketOwner;

    fn conn(local: &str, remote: &str, state: &str, pid: u32, process: &str, inode: &str) -> NetRow {
        NetRow {
            protocol: "tcp".into(),
            local_addr: local.into(),
            remote_addr: remote.into(),
            state: state.into(),
            tx_queue: 0,
            rx_queue: 0,
            inode: inode.into(),
            owner: Some(SocketOwner { pid, process: process.into() }),
        }
    }

    #[test]
    fn classifies_by_parsed_address_not_substring() {
        assert_eq!(classify("127.0.0.1:631"), EndpointClass::Localhost);
        assert_eq!(classify("127.53.1.1:53"), EndpointClass::Localhost);
        assert_eq!(classify("10.127.0.1:443"), EndpointClass::PrivateLan);
        assert_eq!(classify("8.127.3.4:443"), EndpointClass::External);
        assert_eq!(classify("100.100.2.3:443"), EndpointClass::PrivateLan);
        assert_eq!(classify("172.32.0.1:443"), EndpointClass::External);
        assert_eq!(classify("[::1]:631"), EndpointClass::Localhost);
        assert_eq!(classify("[::ffff:127.0.0.1]:8080"), EndpointClass::Localhost);
        assert_eq!(classify("[fe80::1]:22"), EndpointClass::PrivateLan);
        assert_eq!(classify("[fd7a:115c:a1e0::1]:22"), EndpointClass::PrivateLan);
        assert_eq!(classify("[ff02::fb]:5353"), EndpointClass::Multicast);
        assert_eq!(classify("224.0.0.251:5353"), EndpointClass::Multicast);
        assert_eq!(classify("0.0.0.0:0"), EndpointClass::Listening);
        assert_eq!(classify("[::]:0"), EndpointClass::Listening);
        assert_eq!(classify("[2001:db8::1]:443"), EndpointClass::External);
        assert_eq!(classify("garbage"), EndpointClass::Unknown);
    }

    #[test]
    fn endpoint_labels_drop_the_address() {
        assert_eq!(endpoint_label("203.0.113.7:443", false), "externa/v4:443");
        assert_eq!(endpoint_label("0.0.0.0:22", true), "todas-las-interfaces/v4:22");
        assert_eq!(endpoint_label("0.0.0.0:0", false), "sin-par");
        assert_eq!(endpoint_label("[::1]:631", true), "loopback/v6:631");
        assert_eq!(endpoint_label("192.168.100.3:22", false), "red-privada/v4:22");
    }

    #[test]
    fn uid_and_names_are_reduced() {
        assert_eq!(uid_class(Some(0)), "root");
        assert_eq!(uid_class(Some(110)), "sistema");
        assert_eq!(uid_class(Some(1000)), "usuario");
        assert_eq!(uid_class(None), "desconocido");
        assert_eq!(safe_process_name("node\nKEY=x"), "node_KEY_x");
        assert_eq!(safe_process_name("\u{1b}\u{1b}"), "(sin nombre)");
        assert_eq!(safe_process_name(&"a".repeat(80)).len(), 32);
    }

    /// Canaries in every free-text field must never reach the prompt evidence
    /// or the Markdown export, with or without a process selected.
    #[test]
    fn evidence_carries_only_allowlisted_fields() {
        let processes = vec![ProcessRow {
            pid: 4242,
            name: "agent".into(),
            cmdline: "agent --token=CANARY-TOKEN /home/alice/secret-project OPENAI_API_KEY=CANARY-KEY".into(),
            state: "S (sleeping)".into(),
            rss_kb: 2048,
            threads: 3,
            socket_count: 2,
            uid: Some(1000),
        }];
        let connections = vec![
            conn("192.168.100.3:53918", "203.0.113.99:443", "ESTABLISHED", 4242, "agent", "111"),
            conn("127.0.0.1:8080", "0.0.0.0:0", "LISTEN", 4242, "agent", "222"),
        ];
        for selected_pid in [Some(4242), None] {
            let input = EvidenceInput {
                processes: &processes,
                connections: &connections,
                selected_pid,
                selected_inode: Some("111"),
                sample: &connections,
            };
            for text in [build_evidence(&input), build_markdown(&input, "2 processes")] {
                for canary in ["CANARY", "alice", "secret-project", "203.0.113", "192.168.100", "127.0.0.1", "--token"] {
                    assert!(!text.contains(canary), "{canary} leaked (pid {selected_pid:?}):\n{text}");
                }
                assert!(text.contains("externa/v4:443"), "{text}");
                assert!(text.contains("loopback/v4:8080"), "{text}");
            }
        }
        let evidence = build_evidence(&EvidenceInput {
            processes: &processes,
            connections: &connections,
            selected_pid: Some(4242),
            selected_inode: None,
            sample: &connections,
        });
        assert!(evidence.contains("* comm (binario): agent"));
        assert!(evidence.contains("* uid_class: usuario"));
        assert!(evidence.contains("* external: 1"));
    }
}
