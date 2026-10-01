use super::*;

pub(super) struct Output {
    pub(super) success: bool,
    pub(super) stdout: Vec<u8>,
    pub(super) diagnostic: String,
}
pub(super) trait Runner {
    fn run(&self, program: &OsStr, arguments: &[OsString]) -> Result<Output, HostKeyError>;
    fn run_bounded(
        &self,
        program: &OsStr,
        arguments: &[OsString],
        timeout: std::time::Duration,
    ) -> Result<Output, HostKeyError> {
        let _ = timeout;
        self.run(program, arguments)
    }
    fn pause(&self, duration: std::time::Duration) {
        std::thread::sleep(duration);
    }
    fn elapsed(&self, started: std::time::Instant) -> std::time::Duration {
        started.elapsed()
    }
}
pub(super) struct ProcessRunner;
impl Runner for ProcessRunner {
    fn run(&self, program: &OsStr, arguments: &[OsString]) -> Result<Output, HostKeyError> {
        self.run_bounded(program, arguments, std::time::Duration::from_secs(12))
    }
    fn run_bounded(
        &self,
        program: &OsStr,
        arguments: &[OsString],
        timeout: std::time::Duration,
    ) -> Result<Output, HostKeyError> {
        use std::io::Read;
        let mut child = Command::new(program)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        // Readers retain bounded bytes as they arrive. A descendant inheriting
        // a pipe cannot extend the process deadline by keeping it open.
        let collect = |mut pipe: Box<dyn Read + Send>, limit: usize| {
            let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let bytes = captured.clone();
            let (send, done) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let result = (|| {
                    let mut buffer = [0; 4096];
                    loop {
                        match pipe.read(&mut buffer) {
                            Ok(0) => return Ok::<_, io::Error>(()),
                            Ok(count) => {
                                let mut bytes = bytes.lock().unwrap();
                                let available = (limit + 1).saturating_sub(bytes.len());
                                bytes.extend_from_slice(&buffer[..count.min(available)]);
                            }
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(error) => return Err(error),
                        }
                    }
                })();
                let _ = send.send(result);
            });
            (captured, done)
        };
        let (stdout, stdout_done) = collect(Box::new(stdout), MAX_TOOL_OUTPUT);
        let (stderr, stderr_done) = collect(Box::new(stderr), 2048);
        let deadline = std::time::Instant::now() + timeout;
        let mut timed_out = false;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                timed_out = true;
                let _ = child.kill();
                break child.wait()?;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        for done in [stdout_done, stderr_done] {
            match done.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
                Ok(result) => result?,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => timed_out = true,
                Err(_) => return Err(HostKeyError::Tool("SSH output reader failed".into())),
            }
        }
        let stdout = stdout.lock().unwrap().clone();
        let mut stderr = stderr.lock().unwrap().clone();
        if stdout.len() > MAX_TOOL_OUTPUT {
            return Err(HostKeyError::Tool("SSH tool output exceeded limit".into()));
        }
        let truncated = stderr.len() > 2048;
        stderr.truncate(2048);
        // External diagnostics are displayed in the TUI as plain bounded text.
        // Remove terminal controls, including escape, CR, and bidi formatting.
        let safe: String = String::from_utf8_lossy(&stderr)
            .chars()
            .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
            .filter(|c| !matches!(*c as u32, 0x202a..=0x202e | 0x2066..=0x2069))
            .collect();
        let mut diagnostic = if timed_out {
            "SSH discovery tool or its output pipes timed out".to_owned()
        } else {
            status.to_string()
        };
        if !safe.trim().is_empty() {
            diagnostic.push_str(": ");
            diagnostic.push_str(safe.trim());
        }
        if truncated {
            diagnostic.push_str(" [diagnostics truncated]");
        }
        Ok(Output {
            success: status.success() && !timed_out,
            stdout,
            diagnostic,
        })
    }
}
