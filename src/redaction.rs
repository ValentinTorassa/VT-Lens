//! Free-text redaction for anything that leaves the process, including the
//! editable preview. The evidence itself is already built from an allowlist
//! (evidence.rs); this is the second layer for text the user types or pastes.

use regex::Regex;
use std::net::Ipv6Addr;
use std::sync::OnceLock;

const CREDENTIAL: &str = "[credencial redactada]";

fn rules() -> &'static [(Regex, &'static str)] {
    static RULES: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    RULES.get_or_init(|| {
        [
            (r"(?im)^(\s*[*\-]?\s*cmdline:).*$", "$1 [redactado: argumentos]"),
            (r"(?im)^(\s*[*\-]?\s*(?:name|owner|process|user|username):).*$", "$1 [redactado: identidad]"),
            // scheme://user:password@host -> keep the scheme and host
            (r"(?i)\b([a-z][a-z0-9+.\-]*://)[^\s/:@]+:[^\s/@]+@", "${1}[credenciales redactadas]@"),
            (r"(?i)\bBearer\s+[A-Za-z0-9._~+/=\-]{12,}", "Bearer [redactado]"),
            (r"(?i)\bBasic\s+[A-Za-z0-9+/=]{12,}", "Basic [redactado]"),
            // Well-known token formats, wherever they appear
            (r"\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|(?:AKIA|ASIA)[0-9A-Z]{16}|xox[abposr]-[A-Za-z0-9\-]{10,}|AIza[0-9A-Za-z_\-]{35}|glpat-[A-Za-z0-9_\-]{20,})\b", CREDENTIAL),
            // --password X, --api-key=X, -token X
            (r#"(?i)(--?[a-z0-9\-]*(?:token|secret|passwd|password|pass|pwd|api[_\-]?key|apikey|auth)[a-z0-9\-]*)(?:\s*=\s*|\s+)(?:"[^"]*"|'[^']*'|\S+)"#, "$1 [redactado]"),
            // ANY_NAME_WITH_TOKEN/KEY/SECRET/PASS...=value, as a whole line or inline
            (r#"(?im)^\s*[*\-]?\s*[A-Za-z0-9_.\-]*(?:token|key|secret|passwd|password|pass|pwd|credential|credentials)[A-Za-z0-9_.\-]*\s*[:=].*$"#, CREDENTIAL),
            (r#"(?i)\b[A-Za-z0-9_.\-]*(?:token|key|secret|passwd|password|pass|pwd|credential|credentials)[A-Za-z0-9_.\-]*\s*[:=]\s*(?:"[^"]*"|'[^']*'|\S+)"#, CREDENTIAL),
            (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "[correo redactado]"),
            (r"(?:/home/|/Users/|/root/|/var/home/)[^\s`|]+", "[ruta personal redactada]"),
            (r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", "[IP redactada]"),
        ]
        .into_iter()
        .map(|(pattern, replacement)| (Regex::new(pattern).expect("redaction regex"), replacement))
        .collect()
    })
}

/// Replace IPv6 literals. A candidate is a maximal run of hex digits, ':' and
/// '.' with at least two colons, not glued to a word character, that parses
/// as an Ipv6Addr. Times (12:34:56), MACs, `std::sync` and the like survive.
fn redact_ipv6(text: &str) -> String {
    let bytes = text.as_bytes();
    let in_run = |b: u8| b.is_ascii_hexdigit() || b == b':' || b == b'.';
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if in_run(bytes[i]) {
            let start = i;
            while i < bytes.len() && in_run(bytes[i]) {
                i += 1;
            }
            let run = &text[start..i];
            let candidate = run.trim_end_matches('.');
            let before_ok = start == 0 || !word(bytes[start - 1]);
            let after_ok = i >= bytes.len() || !word(bytes[i]);
            if before_ok && after_ok && candidate.matches(':').count() >= 2 && candidate.parse::<Ipv6Addr>().is_ok() {
                out.push_str("[IPv6 redactada]");
                out.push_str(&run[candidate.len()..]);
            } else {
                out.push_str(run);
            }
        } else {
            let ch = text[i..].chars().next().expect("char boundary");
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn shannon_entropy(token: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    for c in token.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let len = token.chars().count() as f64;
    counts
        .values()
        .map(|&n| {
            let p = n as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Long, mixed-character, high-entropy tokens look like keys even without a
/// known prefix or label. Pure digits (inodes, PIDs) and hex hashes stay.
fn redact_high_entropy(text: &str) -> String {
    static TOKEN: OnceLock<Regex> = OnceLock::new();
    let token = TOKEN.get_or_init(|| Regex::new(r"[A-Za-z0-9+/_=\-]{24,}").expect("token regex"));
    token
        .replace_all(text, |caps: &regex::Captures| {
            let t = &caps[0];
            let has_upper = t.chars().any(|c| c.is_ascii_uppercase());
            let has_lower = t.chars().any(|c| c.is_ascii_lowercase());
            let has_digit = t.chars().any(|c| c.is_ascii_digit());
            if has_upper && has_lower && has_digit && shannon_entropy(t) > 4.0 {
                "[posible secreto redactado]".to_string()
            } else {
                t.to_string()
            }
        })
        .into_owned()
}

/// Sanitize text that will leave the local process, including editable previews.
pub fn redact(text: &str) -> String {
    let clean = rules().iter().fold(text.to_owned(), |current, (pattern, replacement)| {
        pattern.replace_all(&current, *replacement).into_owned()
    });
    redact_high_entropy(&redact_ipv6(&clean))
}

/// Private terms are session-local, separated by commas or newlines and never persisted.
pub fn redact_with_terms(text: &str, private_terms: &str) -> String {
    let mut clean = redact(text);
    for term in private_terms.split([',', '\n']).map(str::trim).filter(|term| !term.is_empty()) {
        let pattern = Regex::new(&format!("(?i){}", regex::escape(term))).expect("escaped private term");
        clean = pattern.replace_all(&clean, "[término privado]").into_owned();
    }
    clean
}

#[cfg(test)]
mod tests {
    use super::{redact, redact_with_terms};

    fn assert_hidden(clean: &str, secrets: &[&str]) {
        for secret in secrets {
            assert!(!clean.contains(secret), "leaked {secret:?} in:\n{clean}");
        }
    }

    #[test]
    fn hides_credentials_paths_and_endpoints_but_keeps_ports() {
        let raw = "* cmdline: app --token=synthetic-secret /home/test/private\n\
                   * remote: 203.0.113.7:443\n\
                   - Local: `[2001:db8::1]:8080`\n\
                   Authorization: Bearer syntheticbearervalue12345\n\
                   owner@example.test";
        let clean = redact(raw);
        assert_hidden(&clean, &["synthetic-secret", "/home/test", "203.0.113.7", "2001:db8", "syntheticbearervalue12345", "owner@example.test"]);
        assert!(clean.contains(":443"));
        assert!(clean.contains(":8080"));
    }

    #[test]
    fn structured_fields_and_private_canaries_do_not_leave_the_preview() {
        let raw = "* name: private-project-agent\n- Cmdline: `tool --password=\"two word secret\"`\n- Owner: private-user\n* password: \"two word secret\"\n* remote: 203.0.113.9:443\nPrivateProject";
        let clean = redact_with_terms(raw, "PrivateProject, private-project-agent");
        for canary in ["private-project-agent", "private-user", "two word secret", "203.0.113.9", "PrivateProject"] {
            assert!(!clean.to_lowercase().contains(&canary.to_lowercase()), "leaked: {canary}; preview: {clean}");
        }
        assert!(clean.contains(":443"));
    }

    /// A pasted command whose second line was never labelled "cmdline:".
    #[test]
    fn env_style_key_names_are_redacted_on_any_line() {
        let raw = "bash -c echo start\nexport OPENAI_API_KEY=sk-canary-aaaaaaaaaaaaaaaaaaaa\nGITHUB_TOKEN=ghp_canarycanarycanarycanary1234\nAWS_SECRET_ACCESS_KEY: wJalrXUtnFEMIcanary\nDB_PASS=hunter2canary\nmy.api_key = 'quoted canary'";
        assert_hidden(&redact(raw), &["sk-canary", "ghp_canary", "wJalrXUtnFEMIcanary", "hunter2canary", "quoted canary"]);
    }

    #[test]
    fn flags_url_credentials_and_known_prefixes_are_redacted() {
        let raw = "psql --password s3cretCanary --api-key=k3yCanary -token tokCanary\n\
                   postgres://admin:pwCanary@db.internal:5432/app\n\
                   AKIAABCDEFGHIJKLMNOP xoxb-12345-canarycanary AIzaSyA1234567890abcdefghijklmnopqrstu\n\
                   github_pat_11ABCDEFG0canarycanarycanary";
        let clean = redact(raw);
        assert_hidden(&clean, &["s3cretCanary", "k3yCanary", "tokCanary", "pwCanary", "AKIAABCDEFGHIJKLMNOP", "xoxb-12345", "AIzaSyA123", "github_pat_11"]);
        assert!(clean.contains("postgres://"));
        assert!(clean.contains("db.internal:5432"));
    }

    #[test]
    fn high_entropy_tokens_are_redacted_but_numbers_and_hashes_stay() {
        let raw = "opaque Zx9QwErTy7UiOp3AsDfGh1JkL0mNbV\ninode=123456789012345678901234 sha=0123456789abcdef0123456789abcdef";
        let clean = redact(raw);
        assert_hidden(&clean, &["Zx9QwErTy7UiOp3AsDfGh1JkL0mNbV"]);
        assert!(clean.contains("123456789012345678901234"));
        assert!(clean.contains("0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn ipv6_redaction_leaves_times_macs_and_paths_alone() {
        let clean = redact("at 12:34:56 mac aa:bb:cc:dd:ee:ff use std::sync::Mutex; peer [::1]:631 and fe80::1 and ::ffff:10.0.0.1");
        assert!(clean.contains("12:34:56"), "{clean}");
        assert!(clean.contains("aa:bb:cc:dd:ee:ff"), "{clean}");
        assert!(clean.contains("std::sync::Mutex"), "{clean}");
        assert_hidden(&clean, &["::1]", "fe80::1", "10.0.0.1"]);
        assert!(clean.contains("]:631"), "{clean}");
    }

    #[test]
    fn allowlisted_evidence_passes_through_intact() {
        let evidence = "* pid: 4242\n* comm (binario): firefox\n* uid_class: usuario\n1. tcp red-privada/v4:53918 -> externa/v4:443 [ESTABLISHED] inode=987654";
        assert_eq!(redact(evidence), evidence);
    }
}
