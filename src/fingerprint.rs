use crate::crash::{CrashKind, CrashObservation};
use sha2::{Digest, Sha256};

pub fn fingerprint(observation: &CrashObservation) -> String {
    let identity = match &observation.kind {
        CrashKind::Signal { number, name } => format!("signal:{name}:{number}"),
        CrashKind::Sanitizer { tool, error_type } => {
            if observation.stable_frames.is_empty() {
                if let Some(signal) = signal_identity(&observation.normalized_details) {
                    signal
                } else {
                    format!("sanitizer:{tool}:{error_type}")
                }
            } else {
                format!("sanitizer:{tool}:{error_type}")
            }
        }
        CrashKind::AbnormalExit { code } => format!("exit:{code}"),
    };

    let canonical = if observation.stable_frames.is_empty() {
        identity
    } else {
        format!("{identity}\n{}", observation.stable_frames.join("\n"))
    };
    let digest = Sha256::digest(canonical.as_bytes());
    let hex = format!("{digest:x}");
    format!("CF-{}", &hex[..8])
}

pub(crate) fn stable_frame_identities(input: &str) -> Vec<String> {
    input.lines().filter_map(stable_frame_identity).collect()
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

fn stable_frame_identity(line: &str) -> Option<String> {
    let cleaned_line = strip_ansi(line);
    let line = cleaned_line.trim();
    let mut chars = line.strip_prefix('#')?.chars();
    let frame_number_len = chars
        .by_ref()
        .take_while(|character| character.is_ascii_digit())
        .count();
    if frame_number_len == 0 {
        return None;
    }
    let frame_number = &line[1..1 + frame_number_len];
    let mut tokens = line[1 + frame_number_len..].split_whitespace();
    let mut identity = Vec::new();
    for token in tokens.by_ref() {
        let normalized_token = normalize_frame_token(token);
        if identity.is_empty() && is_instruction_address(&normalized_token) {
            continue;
        }
        identity.push(normalized_token);
    }
    identity.retain(|token| !token.is_empty());
    if identity.is_empty() {
        None
    } else {
        Some(format!("frame:{frame_number} {}", identity.join(" ")))
    }
}

fn signal_identity(details: &str) -> Option<String> {
    details.lines().find_map(|line| {
        let line = line.strip_prefix("signal=")?;
        let identity = line.split_whitespace().next()?;
        Some(format!("signal:{identity}"))
    })
}

fn is_instruction_address(token: &str) -> bool {
    let address = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"));
    address.is_some_and(|value| {
        !value.is_empty() && value.chars().all(|character| character.is_ascii_hexdigit())
    })
}

fn normalize_frame_token(token: &str) -> String {
    let mut normalized = token
        .trim_matches(|character| character == '(' || character == ')' || character == ',')
        .to_string();
    if let Some((prefix, suffix)) = normalized.rsplit_once('/') {
        if !prefix.is_empty() {
            normalized = suffix.to_string();
        }
    }
    strip_line_suffix(&normalized)
}

fn strip_line_suffix(token: &str) -> String {
    let Some((prefix, last)) = token.rsplit_once(':') else {
        return token.to_string();
    };
    if !last.chars().all(|character| character.is_ascii_digit()) {
        return token.to_string();
    }
    if let Some((path, line)) = prefix.rsplit_once(':') {
        if line.chars().all(|character| character.is_ascii_digit()) {
            return path.to_string();
        }
    }
    prefix.to_string()
}
