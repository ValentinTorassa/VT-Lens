pub mod net_poller;
pub mod proc_poller;

pub use net_poller::{read_connections, socket_owners};
pub use proc_poller::read_processes;

/// Replace every control character (newlines, tabs, escapes, NUL leftovers)
/// with a space. A process controls its own `comm` and argv, so without this a
/// newline inside an argument could smuggle text past line-based redaction.
pub fn strip_control(text: &str) -> String {
    text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

#[cfg(test)]
mod tests {
    use super::strip_control;

    #[test]
    fn control_characters_become_spaces() {
        assert_eq!(strip_control("echo start\nexport KEY=x\r\t\u{1b}[0m"), "echo start export KEY=x   [0m");
    }
}
