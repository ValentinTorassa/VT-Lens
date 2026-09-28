use regex::Regex;
use std::sync::OnceLock;

fn rules() -> &'static [(Regex, &'static str)] {
    static RULES: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    RULES.get_or_init(|| {
        [
            (r"(?im)^([*\-]?\s*cmdline:).*$", "$1 [redactado: argumentos]"),
            (r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{12,}", "Bearer [redactado]"),
            (r"(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|secret|token)\s*[:=]\s*\S+", "[credencial redactada]"),
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[correo redactado]"),
            (r"(?:/home/|/Users/)[^\s`|]+", "[ruta personal redactada]"),
            (r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", "[IP redactada]"),
            (r"(?i)(?:[0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}", "[IPv6 redactada]"),
        ]
        .into_iter()
        .map(|(pattern, replacement)| (Regex::new(pattern).expect("redaction regex"), replacement))
        .collect()
    })
}

/// Sanitize text that will leave the local process, including editable previews.
pub fn redact(text: &str) -> String {
    rules().iter().fold(text.to_owned(), |current, (pattern, replacement)| {
        pattern.replace_all(&current, *replacement).into_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::redact;

    #[test]
    fn hides_credentials_paths_and_endpoints_but_keeps_ports() {
        let raw = "* cmdline: app --token=synthetic-secret /home/test/private\n\
                   * remote: 203.0.113.7:443\n\
                   - Local: `[2001:db8::1]:8080`\n\
                   Authorization: Bearer syntheticbearervalue12345\n\
                   owner@example.test";
        let clean = redact(raw);
        for private in ["synthetic-secret", "/home/test", "203.0.113.7", "2001:db8", "syntheticbearervalue12345", "owner@example.test"] {
            assert!(!clean.contains(private), "private text survived: {private}");
        }
        assert!(clean.contains(":443"));
        assert!(clean.contains(":8080"));
    }
}
