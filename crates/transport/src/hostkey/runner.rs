use super::*;

pub(super) struct Output {
    pub(super) success: bool,
    pub(super) stdout: Vec<u8>,
}
pub(super) trait Runner {
    fn run(&self, program: &OsStr, arguments: &[OsString]) -> Result<Output, HostKeyError>;
}
pub(super) struct ProcessRunner;
impl Runner for ProcessRunner {
    fn run(&self, program: &OsStr, arguments: &[OsString]) -> Result<Output, HostKeyError> {
        let output = Command::new(program)
            .args(arguments)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()?;
        if output.stdout.len() > MAX_TOOL_OUTPUT {
            return Err(HostKeyError::Tool("SSH tool output exceeded limit".into()));
        }
        Ok(Output {
            success: output.status.success(),
            stdout: output.stdout,
        })
    }
}
