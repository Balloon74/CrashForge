use crate::crash::{classify, kind_name, CrashKind, FingerprintConfidence};
use crate::error::{message, CrashForgeError, Result};
use crate::fingerprint::{fingerprint, legacy_fingerprint};
use crate::minimizer::{minimize, MinimizerLimits};
use crate::runner::{run as run_target, RunOptions, Target};
use crate::storage::{
    case_directory, list_cases, load_case, save_case, CrashManifest, MinimizationStats,
};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::tempdir;

const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_MAX_RUNS: usize = 10_000;

#[derive(Debug, Parser)]
#[command(
    name = "crashforge",
    version,
    about = "Turn crashes into reproducible regression cases"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Run {
        #[arg(long, default_value_t = DEFAULT_TIMEOUT_MS)]
        timeout_ms: u64,
        #[arg(long, default_value_t = DEFAULT_MAX_RUNS)]
        max_runs: usize,
        program: PathBuf,
        input: PathBuf,
    },
    Test,
    Inspect {
        id: String,
    },
    Reproduce {
        id: String,
    },
    List,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run {
            timeout_ms,
            max_runs,
            program,
            input,
        } => run_command(program, input, timeout_ms, max_runs),
        Commands::Test => test_command(),
        Commands::Inspect { id } => inspect_command(&id),
        Commands::Reproduce { id } => reproduce_command(&id),
        Commands::List => list_command(),
    }
}

fn run_command(program: PathBuf, input: PathBuf, timeout_ms: u64, max_runs: usize) -> Result<()> {
    if timeout_ms == 0 {
        return Err(message("--timeout-ms must be greater than zero"));
    }
    if max_runs == 0 {
        return Err(message("--max-runs must be greater than zero"));
    }

    let working_directory = std::env::current_dir()?;
    let program = resolve_program(&working_directory, &program)?;
    let input = resolve_file(&working_directory, &input)?;
    let original = fs::read(&input)?;
    let options = RunOptions {
        timeout: Duration::from_millis(timeout_ms),
    };
    let baseline_target = Target {
        program: program.clone(),
        input: input.clone(),
        working_dir: working_directory.clone(),
    };
    let baseline_result = run_target(&baseline_target, &options)?;
    let baseline_observation = classify(&baseline_result).ok_or_else(|| {
        message(format!(
            "target did not produce a crash or abnormal exit (exit code {:?})",
            baseline_result.exit_code
        ))
    })?;
    let baseline_fingerprint = fingerprint(&baseline_observation);

    println!("CrashForge 0.2\n");
    println!(
        "✓ Crash detected: {}",
        describe_crash(&baseline_observation.kind)
    );
    println!("Fingerprint: {baseline_fingerprint}");
    println!(
        "  Confidence: {}",
        confidence_name(baseline_observation.confidence)
    );
    println!("→ Minimizing");

    let candidate_directory = tempdir()?;
    let candidate_path = candidate_directory.path().join("candidate.input");
    let candidate_target = Target {
        program,
        input: candidate_path.clone(),
        working_dir: working_directory.clone(),
    };
    let mut predicate_error = None;
    let minimization_started = std::time::Instant::now();
    let result = minimize(
        &original,
        MinimizerLimits {
            max_runs: max_runs.max(1),
        },
        |candidate| {
            if let Err(error) = fs::write(&candidate_path, candidate) {
                predicate_error = Some(error.into());
                return false;
            }
            match run_target(&candidate_target, &options) {
                Ok(execution) => classify(&execution)
                    .map(|observation| fingerprint(&observation) == baseline_fingerprint)
                    .unwrap_or(false),
                Err(error) => {
                    predicate_error = Some(error);
                    false
                }
            }
        },
    );
    debug_assert!(minimization_started.elapsed() >= result.elapsed);
    if let Some(error) = predicate_error {
        return Err(error);
    }

    if fs::write(&candidate_path, &result.bytes).is_err() {
        return Err(message("could not write the final minimized candidate"));
    }
    let verification = run_target(&candidate_target, &options)?;
    let verified_fingerprint = classify(&verification)
        .map(|observation| fingerprint(&observation))
        .ok_or_else(|| message("the minimized input no longer produces a crash"))?;
    if verified_fingerprint != baseline_fingerprint {
        return Err(message(format!(
            "minimized input fingerprint mismatch: expected {baseline_fingerprint}, observed {verified_fingerprint}"
        )));
    }

    let reduction_percent = if original.is_empty() {
        0.0
    } else {
        100.0 * (original.len() - result.bytes.len()) as f64 / original.len() as f64
    };
    let stats = MinimizationStats {
        original_size: original.len(),
        minimized_size: result.bytes.len(),
        reduction_percent,
        minimization_runs: result.runs,
        minimization_ms: result.elapsed.as_millis().try_into().unwrap_or(u64::MAX),
    };

    println!(
        "  {} B → {} B · {} executions · {} ms · {:.3}% reduction",
        stats.original_size,
        stats.minimized_size,
        stats.minimization_runs,
        stats.minimization_ms,
        stats.reduction_percent
    );
    if !result.complete {
        println!(
            "  Minimization incomplete: candidate-run budget exhausted after {} executions.",
            stats.minimization_runs
        );
    }
    println!("Verified: ✓ {baseline_fingerprint}");

    let manifest = CrashManifest {
        id: baseline_fingerprint,
        signal: signal_for(&baseline_observation.kind),
        crash_kind: kind_name(&baseline_observation.kind).into(),
        fingerprint_strength: confidence_name(baseline_observation.confidence).into(),
        original_size: stats.original_size,
        minimized_size: stats.minimized_size,
        stats,
        fingerprint_confidence: Some(confidence_name(baseline_observation.confidence).into()),
        program: candidate_target.program,
        working_directory,
        timeout_ms,
        status: "active".into(),
    };
    let root = storage_root()?;
    match save_case(&root, &manifest, &original, &result.bytes) {
        Ok(path) => println!("Saved: ✓ {}", path.display()),
        Err(CrashForgeError::Collision(path)) => {
            println!("Already stored: {}", path.display())
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

fn reproduce_command(id: &str) -> Result<()> {
    let root = storage_root()?;
    let manifest = load_case(&root, id)?;
    let observed = reproduce_manifest(&root, &manifest)?;
    let expected = manifest.id.clone();
    if observed.fingerprint != expected {
        return Err(message(format!(
            "fingerprint mismatch: expected {expected}, observed {}",
            observed.fingerprint
        )));
    }
    println!("Reproducing {id}...\n");
    println!("Expected: {}", manifest.crash_kind);
    println!("Observed: {}", observed.description);
    println!("\nFingerprint match.\n\nCrash reproduced successfully.");
    Ok(())
}

fn test_command() -> Result<()> {
    let root = storage_root()?;
    let cases = list_cases(&root)?;
    println!("CrashForge Regression Tests\n");
    let mut passed = 0;
    for manifest in &cases {
        let result = reproduce_manifest(&root, manifest);
        match result {
            Ok(observed) if observed.fingerprint == manifest.id => {
                println!("{}    PASS", manifest.id);
                passed += 1;
            }
            Ok(observed) => println!(
                "{}    FAIL (observed {})",
                manifest.id, observed.fingerprint
            ),
            Err(error) => println!("{}    FAIL ({error})", manifest.id),
        }
    }
    println!(
        "\n{} historical crashes\n{} reproduced\n{} regression{}",
        cases.len(),
        passed,
        cases.len().saturating_sub(passed),
        if cases.len().saturating_sub(passed) == 1 {
            ""
        } else {
            "s"
        }
    );
    if passed != cases.len() {
        return Err(message("one or more regression cases failed"));
    }
    Ok(())
}

fn inspect_command(id: &str) -> Result<()> {
    let manifest = load_case(&storage_root()?, id)?;
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}

fn list_command() -> Result<()> {
    let cases = list_cases(&storage_root()?)?;
    if cases.is_empty() {
        println!("No stored crashes.");
        return Ok(());
    }
    println!("ID           Kind          Original   Minimized   Reduction    Runs");
    for case in cases {
        println!(
            "{:<12} {:<13} {:>8}   {:>9}   {:>8.3}% {:>7}",
            case.id,
            case.crash_kind,
            case.original_size,
            case.minimized_size,
            case.stats.reduction_percent,
            case.stats.minimization_runs
        );
    }
    Ok(())
}

struct ObservedCrash {
    fingerprint: String,
    description: String,
}

fn reproduce_manifest(root: &Path, manifest: &CrashManifest) -> Result<ObservedCrash> {
    let directory = case_directory(root, &manifest.id)?;
    let target = Target {
        program: manifest.program.clone(),
        input: directory.join("minimized.txt"),
        working_dir: manifest.working_directory.clone(),
    };
    let result = run_target(
        &target,
        &RunOptions {
            timeout: Duration::from_millis(manifest.timeout_ms),
        },
    )?;
    let observation = classify(&result).ok_or_else(|| message("stored case did not fail"))?;
    let uses_legacy_fingerprint = manifest.fingerprint_confidence.is_none()
        && matches!(
            manifest.fingerprint_strength.as_str(),
            "Diagnostic" | "SignalFallback"
        );
    Ok(ObservedCrash {
        fingerprint: if uses_legacy_fingerprint {
            legacy_fingerprint(&observation)
        } else {
            fingerprint(&observation)
        },
        description: describe_crash(&observation.kind),
    })
}

fn storage_root() -> Result<PathBuf> {
    Ok(std::env::current_dir()?.join(".crashforge"))
}

fn resolve_program(working_directory: &Path, program: &Path) -> Result<PathBuf> {
    let candidate = if program.is_absolute() {
        program.to_path_buf()
    } else {
        working_directory.join(program)
    };
    Ok(fs::canonicalize(candidate)?)
}

fn resolve_file(working_directory: &Path, input: &Path) -> Result<PathBuf> {
    let candidate = if input.is_absolute() {
        input.to_path_buf()
    } else {
        working_directory.join(input)
    };
    Ok(fs::canonicalize(candidate)?)
}

fn signal_for(kind: &CrashKind) -> Option<String> {
    match kind {
        CrashKind::Signal { name, .. } => Some(name.clone()),
        _ => None,
    }
}

fn confidence_name(confidence: FingerprintConfidence) -> &'static str {
    match confidence {
        FingerprintConfidence::High => "High",
        FingerprintConfidence::Medium => "Medium",
        FingerprintConfidence::Low => "Low",
    }
}

fn describe_crash(kind: &CrashKind) -> String {
    match kind {
        CrashKind::Signal { name, .. } => name.clone(),
        CrashKind::Sanitizer { tool, error_type } => format!("{tool}: {error_type}"),
        CrashKind::AbnormalExit { code } => format!("abnormal exit ({code})"),
    }
}
