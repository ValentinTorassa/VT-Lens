use std::fs;
use std::path::Path;

use crate::model::ProcessRow;

pub fn read_processes() -> Vec<ProcessRow> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };

    let mut rows = Vec::new();

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let pid_text = file_name.to_string_lossy();

        if !pid_text.chars().all(|character| character.is_ascii_digit()) {
            continue;
        }

        let Ok(pid) = pid_text.parse::<u32>() else {
            continue;
        };

        let proc_dir = entry.path();
        let name = read_trimmed(proc_dir.join("comm")).unwrap_or_else(|| pid_text.to_string());
        let cmdline = read_cmdline(proc_dir.join("cmdline")).unwrap_or_else(|| name.clone());
        let status = fs::read_to_string(proc_dir.join("status")).unwrap_or_default();

        rows.push(ProcessRow {
            pid,
            name,
            cmdline,
            state: parse_status_string(&status, "State").unwrap_or_default(),
            rss_kb: parse_status_kb(&status, "VmRSS").unwrap_or(0),
            threads: parse_status_u32(&status, "Threads").unwrap_or(0),
            socket_count: 0,
        });
    }

    rows.sort_by_key(|row| row.pid);
    rows
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_cmdline(path: impl AsRef<Path>) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let parts: Vec<String> = bytes
        .split(|byte| *byte == 0)
        .filter_map(|part| std::str::from_utf8(part).ok())
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect();

    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

fn parse_status_string(status: &str, key: &str) -> Option<String> {
    parse_status_value(status, key).map(ToOwned::to_owned)
}

fn parse_status_kb(status: &str, key: &str) -> Option<u64> {
    parse_status_value(status, key)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn parse_status_u32(status: &str, key: &str) -> Option<u32> {
    parse_status_value(status, key)?.parse().ok()
}

fn parse_status_value<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}:")))
        .map(str::trim)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_values() {
        let status = "Name:\tbash\nState:\tS (sleeping)\nVmRSS:\t  2048 kB\nThreads:\t3\n";

        assert_eq!(parse_status_string(status, "State").as_deref(), Some("S (sleeping)"));
        assert_eq!(parse_status_kb(status, "VmRSS"), Some(2048));
        assert_eq!(parse_status_u32(status, "Threads"), Some(3));
    }
}
