use crate::crash::{signal_name, CrashKind, CrashObservation};
use sha2::{Digest, Sha256};

pub fn fingerprint(observation: &CrashObservation) -> String {
    let identity = match &observation.kind {
        CrashKind::Signal { number, name } => format!("signal:{name}:{number}"),
        CrashKind::Sanitizer { tool, error_type } => {
            if observation.stable_frames.is_empty() {
                if let Some(number) = observation.observed_signal {
                    format!("signal:{}:{number}", signal_name(number))
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
    hash_canonical(&canonical)
}

/// v0.1 identity for verifying manifests written before confidence was recorded.
/// Keep diagnostic normalization compatible with v0.1 for this path.
pub fn legacy_fingerprint(observation: &CrashObservation) -> String {
    let kind = match &observation.kind {
        CrashKind::Signal { number, name } => format!("signal:{name}:{number}"),
        CrashKind::Sanitizer { tool, error_type } => format!("sanitizer:{tool}:{error_type}"),
        CrashKind::AbnormalExit { code } => format!("exit:{code}"),
    };
    hash_canonical(&format!("{kind}\n{}", observation.normalized_details))
}

fn hash_canonical(canonical: &str) -> String {
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
    let mut body = line[1 + frame_number_len..].trim();
    while let Some(token) = body.split_whitespace().next() {
        if !is_instruction_address(token.trim_matches(['(', ')', ','])) {
            break;
        }
        body = body[token.len()..].trim_start();
    }
    let (function, location) = split_frame_location(body);
    let mut identity = function.split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some(location) = location {
        // Normalize the complete location, including spaces, independently of the
        // function. A slash in a C++ operator is part of the symbol, not a path.
        let location = location.trim_matches(['(', ')', ',']);
        let basename = location.rsplit('/').next().unwrap_or(location);
        let location = strip_line_suffix(basename);
        if !identity.is_empty() {
            identity.push(' ');
        }
        identity.push_str(&location);
    }
    if identity.is_empty() {
        None
    } else {
        Some(format!("frame:{frame_number} {identity}"))
    }
}

fn split_frame_location(body: &str) -> (&str, Option<&str>) {
    if let Some(function_body) = body.strip_prefix("in ") {
        let function_end = function_end(function_body);
        if function_end < function_body.len() {
            let function = &body[..3 + function_end];
            let location = function_body[function_end..].trim_start();
            return (function, (!location.is_empty()).then_some(location));
        }
        return (body, None);
    }

    let mut depth = 0usize;
    let mut boundary = true;
    for (index, character) in body.char_indices() {
        if depth == 0 && boundary {
            let tail = &body[index..];
            let path = tail.strip_prefix('(').unwrap_or(tail);
            if path.starts_with('/') || path.starts_with("./") || path.starts_with("../") {
                return (body[..index].trim_end(), Some(tail));
            }
        }
        match character {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ => {}
        }
        boundary = character.is_whitespace();
    }
    // A relative source location can follow a complete function signature, or
    // be a final filename:line[:column] field after a bare function name.
    if strip_line_suffix(body) != body {
        if let Some(end) = body.rfind(')') {
            let tail = &body[end + 1..];
            if tail.starts_with(char::is_whitespace) && !tail.trim().is_empty() {
                return (body[..=end].trim_end(), Some(tail.trim()));
            }
        }
        if let Some((function, location)) = body.rsplit_once(char::is_whitespace) {
            return (function.trim_end(), Some(location));
        }
    }
    (body, None)
}

fn function_end(function_body: &str) -> usize {
    let Some(open) = function_body.find('(') else {
        return function_body
            .find(char::is_whitespace)
            .unwrap_or(function_body.len());
    };

    let mut depth = 0usize;
    for (index, character) in function_body[open..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return open + index + character.len_utf8();
                }
            }
            _ => {}
        }
    }
    function_body.len()
}

fn is_instruction_address(token: &str) -> bool {
    let address = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"));
    address.is_some_and(|value| {
        !value.is_empty() && value.chars().all(|character| character.is_ascii_hexdigit())
    })
}

fn strip_line_suffix(token: &str) -> String {
    let Some((prefix, last)) = token.rsplit_once(':') else {
        return token.to_string();
    };
    if last.is_empty() || !last.chars().all(|character| character.is_ascii_digit()) {
        return token.to_string();
    }
    if let Some((path, line)) = prefix.rsplit_once(':') {
        if !line.is_empty() && line.chars().all(|character| character.is_ascii_digit()) {
            return path.to_string();
        }
    }
    prefix.to_string()
}
