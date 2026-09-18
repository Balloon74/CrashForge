use crate::crash::{CrashKind, CrashObservation};
use sha2::{Digest, Sha256};

pub fn fingerprint(observation: &CrashObservation) -> String {
    let kind = match &observation.kind {
        CrashKind::Signal { number, name } => format!("signal:{name}:{number}"),
        CrashKind::Sanitizer { tool, error_type } => {
            format!("sanitizer:{tool}:{error_type}")
        }
        CrashKind::AbnormalExit { code } => format!("exit:{code}"),
    };

    let canonical = format!("{kind}\n{}", observation.normalized_details);
    let digest = Sha256::digest(canonical.as_bytes());
    let hex = format!("{digest:x}");
    format!("CF-{}", &hex[..8])
}

pub(crate) fn normalize_diagnostic(input: &str) -> String {
    input
        .lines()
        .map(strip_ansi)
        .map(|line| normalize_line(&line))
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .take(32)
        .collect::<Vec<_>>()
        .join("\n")
}

fn strip_ansi(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut escape = false;
    for character in input.chars() {
        if escape {
            if character.is_ascii_alphabetic() {
                escape = false;
            }
        } else if character == '\u{1b}' {
            escape = true;
        } else {
            output.push(character);
        }
    }
    output
}

fn normalize_line(line: &str) -> String {
    line.split_whitespace()
        .map(normalize_token)
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalize_token(token: &str) -> String {
    let mut normalized = token.to_string();
    if let Some(address_start) = normalized.find("0x") {
        let suffix = &normalized[address_start + 2..];
        let address_end = suffix
            .find(|character: char| !character.is_ascii_hexdigit())
            .unwrap_or(suffix.len());
        if address_end > 0 {
            normalized.replace_range(address_start..address_start + 2 + address_end, "0xADDR");
        }
    }

    if normalized.starts_with('/') {
        if let Some((_, suffix)) = normalized.rsplit_once('/') {
            normalized = suffix.to_string();
        }
    }

    normalized
}
