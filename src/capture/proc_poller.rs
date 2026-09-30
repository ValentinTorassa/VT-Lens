use std::fs;
use std::path::Path;

use super::strip_control;
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
            uid: parse_status_uid(&status),
        });
    }

    rows.sort_by_key(|row| row.pid);
    rows
}

fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| strip_control(value.trim()).trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_cmdline(path: impl AsRef<Path>) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let parts: Vec<String> = bytes
        .split(|byte| *byte == 0)
        .filter_map(|part| std::str::from_utf8(part).ok())
        .map(|part| strip_control(part).trim().to_string())
        .filter(|part| !part.is_empty())
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

/// `Uid:` lists real, effective, saved and filesystem UIDs; keep the real one.
fn parse_status_uid(status: &str) -> Option<u32> {
    parse_status_value(status, "Uid")?.split_whitespace().next()?.parse().ok()
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
        assert_eq!(parse_status_uid("Uid:\t1000\t1000\t1000\t1000\n"), Some(1000));
    }

    #[test]
    fn cmdline_arguments_lose_control_characters() {
        let dir = std::env::temp_dir().join(format!("vt-lens-cmdline-{}", std::process::id()));
        std::fs::write(&dir, b"bash\0-c\0echo start\nexport OPENAI_API_KEY=canary\0").unwrap();
        let cmdline = read_cmdline(&dir).unwrap();
        let _ = std::fs::remove_file(&dir);
        assert!(!cmdline.contains('\n'), "{cmdline:?}");
        assert_eq!(cmdline, "bash -c echo start export OPENAI_API_KEY=canary");
    }
}
