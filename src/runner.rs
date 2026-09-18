use crate::error::{message, Result};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Target {
    pub program: PathBuf,
    pub input: PathBuf,
    pub working_dir: PathBuf,
}

#[derive(Clone, Debug)]
pub struct RunOptions {
    pub timeout: Duration,
}

#[derive(Debug)]
pub struct ExecutionResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub duration: Duration,
}

pub fn run(target: &Target, options: &RunOptions) -> Result<ExecutionResult> {
    let started = Instant::now();
    let mut command = Command::new(&target.program);
    command
        .arg(&target.input)
        .current_dir(&target.working_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(unix)]
    configure_process_group(&mut command);

    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| message("target stdout was not captured"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| message("target stderr was not captured"))?;

    let stdout_reader = thread::spawn(move || read_pipe(stdout));
    let stderr_reader = thread::spawn(move || read_pipe(stderr));

    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }

        if started.elapsed() >= options.timeout {
            timed_out = true;
            terminate_child(&mut child);
            break child.wait()?;
        }

        thread::sleep(Duration::from_millis(5));
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| message("stdout reader thread panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| message("stderr reader thread panicked"))??;

    #[cfg(unix)]
    let signal = std::os::unix::process::ExitStatusExt::signal(&status);
    #[cfg(not(unix))]
    let signal = None;

    Ok(ExecutionResult {
        stdout,
        stderr,
        exit_code: status.code(),
        signal,
        timed_out,
        duration: started.elapsed(),
    })
}

fn read_pipe(mut pipe: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn terminate_child(child: &mut Child) {
    #[cfg(unix)]
    {
        let pid = child.id() as libc::pid_t;
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }

    let _ = child.kill();
}
