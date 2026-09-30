use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use super::strip_control;
use crate::model::{NetRow, SocketOwner};

pub fn socket_owners() -> HashMap<String, SocketOwner> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return HashMap::new();
    };

    let mut owners = HashMap::new();

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let pid_text = file_name.to_string_lossy();

        if !pid_text.chars().all(|character| character.is_ascii_digit()) {
            continue;
        }

        let Ok(pid) = pid_text.parse::<u32>() else {
            continue;
        };

        let process = fs::read_to_string(entry.path().join("comm"))
            .map(|value| strip_control(value.trim()).trim().to_string())
            .unwrap_or_else(|_| pid_text.to_string());

        let fd_dir = entry.path().join("fd");
        let Ok(fds) = fs::read_dir(fd_dir) else {
            continue;
        };

        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };

            if let Some(inode) = socket_inode_from_link(target) {
                owners.entry(inode).or_insert_with(|| SocketOwner {
                    pid,
                    process: process.clone(),
                });
            }
        }
    }

    owners
}

pub fn read_connections(owners: &HashMap<String, SocketOwner>) -> Vec<NetRow> {
    let sources = [
        ("/proc/net/tcp", "tcp", false),
        ("/proc/net/udp", "udp", false),
        ("/proc/net/tcp6", "tcp6", true),
        ("/proc/net/udp6", "udp6", true),
    ];

    let mut rows = Vec::new();

    for (path, protocol, ipv6) in sources {
        let Ok(contents) = fs::read_to_string(path) else {
            continue;
        };

        for line in contents.lines().skip(1) {
            if let Some(row) = parse_proc_net_line(line, protocol, ipv6, owners) {
                rows.push(row);
            }
        }
    }

    rows.sort_by(|left, right| {
        left.owner_label()
            .cmp(&right.owner_label())
            .then(left.protocol.cmp(&right.protocol))
            .then(left.local_addr.cmp(&right.local_addr))
    });
    rows
}

fn socket_inode_from_link(target: PathBuf) -> Option<String> {
    let text = target.to_string_lossy();
    text.strip_prefix("socket:[")
        .and_then(|value| value.strip_suffix(']'))
        .map(ToOwned::to_owned)
}

fn parse_proc_net_line(
    line: &str,
    protocol: &str,
    ipv6: bool,
    owners: &HashMap<String, SocketOwner>,
) -> Option<NetRow> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }

    let inode = parts[9].to_string();
    let (tx_queue, rx_queue) = parse_queue(parts[4]).unwrap_or((0, 0));

    Some(NetRow {
        protocol: protocol.to_string(),
        local_addr: parse_addr_port(parts[1], ipv6)?,
        remote_addr: parse_addr_port(parts[2], ipv6)?,
        state: state_label(parts[3]).to_string(),
        tx_queue,
        rx_queue,
        owner: owners.get(&inode).cloned(),
        inode,
    })
}

fn parse_queue(value: &str) -> Option<(u64, u64)> {
    let (tx, rx) = value.split_once(':')?;
    Some((
        u64::from_str_radix(tx, 16).ok()?,
        u64::from_str_radix(rx, 16).ok()?,
    ))
}

fn parse_addr_port(value: &str, ipv6: bool) -> Option<String> {
    let (addr, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;

    if ipv6 {
        Some(format!("[{}]:{}", parse_ipv6(addr)?, port))
    } else {
        Some(format!("{}:{}", parse_ipv4(addr)?, port))
    }
}

fn parse_ipv4(value: &str) -> Option<String> {
    if value.len() != 8 {
        return None;
    }

    let mut bytes = Vec::new();
    for offset in (0..value.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&value[offset..offset + 2], 16).ok()?);
    }

    Some(format!(
        "{}.{}.{}.{}",
        bytes[3], bytes[2], bytes[1], bytes[0]
    ))
}

/// /proc/net/tcp6 prints the address as four 32-bit words, each in host byte
/// order (little-endian on x86 and arm64), so every word's bytes are reversed.
fn parse_ipv6(value: &str) -> Option<std::net::Ipv6Addr> {
    if value.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for word in 0..4 {
        let raw = u32::from_str_radix(&value[word * 8..word * 8 + 8], 16).ok()?;
        let ordered = if cfg!(target_endian = "little") { raw.swap_bytes() } else { raw };
        bytes[word * 4..word * 4 + 4].copy_from_slice(&ordered.to_be_bytes());
    }
    Some(std::net::Ipv6Addr::from(bytes))
}

fn state_label(value: &str) -> &'static str {
    match value {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_little_endian_proc_addr() {
        assert_eq!(parse_ipv4("0100007F").as_deref(), Some("127.0.0.1"));
        assert_eq!(parse_addr_port("0100007F:1F90", false).as_deref(), Some("127.0.0.1:8080"));
    }

    #[test]
    fn parses_ipv6_in_kernel_word_order() {
        assert_eq!(parse_addr_port("00000000000000000000000001000000:0277", true).as_deref(), Some("[::1]:631"));
        assert_eq!(parse_addr_port("00000000000000000000000000000000:0016", true).as_deref(), Some("[::]:22"));
        // 2001:db8::1 as the kernel prints it
        assert_eq!(parse_addr_port("B80D0120000000000000000001000000:01BB", true).as_deref(), Some("[2001:db8::1]:443"));
        // IPv4-mapped 127.0.0.1
        assert_eq!(parse_addr_port("0000000000000000FFFF00000100007F:1F90", true).as_deref(), Some("[::ffff:127.0.0.1]:8080"));
        assert_eq!(parse_addr_port("zz:0016", true), None);
    }

    #[test]
    fn parses_proc_net_line() {
        let mut owners = HashMap::new();
        owners.insert(
            "12345".to_string(),
            SocketOwner {
                pid: 42,
                process: "demo".to_string(),
            },
        );

        let row = parse_proc_net_line(
            "0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0",
            "tcp",
            false,
            &owners,
        )
        .expect("row");

        assert_eq!(row.local_addr, "127.0.0.1:8080");
        assert_eq!(row.state, "LISTEN");
        assert_eq!(row.owner_label(), "demo (42)");
    }
}
