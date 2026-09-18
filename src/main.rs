fn main() {
    if let Err(error) = crashforge::cli::run() {
        eprintln!("CrashForge error: {error}");
        std::process::exit(1);
    }
}
