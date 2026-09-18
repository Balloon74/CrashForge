use crate::runner::ExecutionResult;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrashKind {
    Signal { number: i32, name: String },
    Sanitizer { tool: String, error_type: String },
    AbnormalExit { code: i32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FingerprintConfidence {
    High,
    Medium,
    Low,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrashObservation {
    pub kind: CrashKind,
    pub normalized_details: String,
    pub stable_frames: Vec<String>,
    pub confidence: FingerprintConfidence,
}

pub fn classify(result: &ExecutionResult) -> Option<CrashObservation> {
    if result.timed_out {
        return None;
    }

    let stderr = String::from_utf8_lossy(&result.stderr);
    let stable_frames = crate::fingerprint::stable_frame_identities(&stderr);
    if let Some(error_type) = asan_error_type(&stderr) {
        let normalized_details = crate::fingerprint::normalize_diagnostic(&stderr);
        let normalized_details = result.signal.map_or(normalized_details.clone(), |number| {
            format!(
                "signal={}:{}\n{normalized_details}",
                signal_name(number),
                number
            )
        });
        return Some(CrashObservation {
            kind: CrashKind::Sanitizer {
                tool: "AddressSanitizer".into(),
                error_type,
            },
            normalized_details,
            confidence: if stable_frames.is_empty() {
                FingerprintConfidence::Low
            } else {
                FingerprintConfidence::High
            },
            stable_frames,
        });
    }

    if let Some(number) = result.signal {
        let name = signal_name(number).to_string();
        return Some(CrashObservation {
            kind: CrashKind::Signal {
                number,
                name: name.clone(),
            },
            normalized_details: format!(
                "signal={name}\n{}",
                crate::fingerprint::normalize_diagnostic(&stderr)
            ),
            confidence: if stable_frames.is_empty() {
                FingerprintConfidence::Low
            } else {
                FingerprintConfidence::Medium
            },
            stable_frames,
        });
    }

    result
        .exit_code
        .filter(|code| *code != 0)
        .map(|code| CrashObservation {
            kind: CrashKind::AbnormalExit { code },
            normalized_details: format!(
                "exit={code}\n{}",
                crate::fingerprint::normalize_diagnostic(&stderr)
            ),
            stable_frames,
            confidence: FingerprintConfidence::Low,
        })
}

pub fn kind_name(kind: &CrashKind) -> &'static str {
    match kind {
        CrashKind::Signal { .. } => "signal",
        CrashKind::Sanitizer { .. } => "sanitizer",
        CrashKind::AbnormalExit { .. } => "abnormal_exit",
    }
}

pub fn signal_name(number: i32) -> &'static str {
    match number {
        6 => "SIGABRT",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        4 => "SIGILL",
        7 => "SIGBUS",
        13 => "SIGPIPE",
        _ => "SIGUNKNOWN",
    }
}

fn asan_error_type(stderr: &str) -> Option<String> {
    let marker = "AddressSanitizer:";
    let start = stderr.find(marker)? + marker.len();
    let error_type = stderr[start..].split_whitespace().next()?.trim();
    if error_type.is_empty() {
        None
    } else {
        Some(error_type.to_string())
    }
}
