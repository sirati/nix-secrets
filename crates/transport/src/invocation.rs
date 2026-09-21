use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    pub ssh_destination: Option<OsString>,
    pub folder: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
pub struct InvocationError(pub &'static str);

impl fmt::Display for InvocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for InvocationError {}

impl Invocation {
    pub fn parse<I, S>(arguments: I) -> Result<Self, InvocationError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let values: Vec<OsString> = arguments.into_iter().map(Into::into).collect();
        let separator = values
            .iter()
            .position(|value| value == OsStr::new("--"))
            .ok_or(InvocationError("missing -- before repository folder"))?;
        if values.len() != separator + 2 {
            return Err(InvocationError(
                "expected exactly one repository folder after --",
            ));
        }
        let destination = match separator {
            0 => None,
            1 if !values[0].is_empty() && values[0] != OsStr::new("-") => Some(values[0].clone()),
            _ => {
                return Err(InvocationError(
                    "expected either no SSH argument or one destination",
                ))
            }
        };
        Ok(Self {
            ssh_destination: destination,
            folder: PathBuf::from(&values[separator + 1]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_local_and_remote_forms() {
        assert_eq!(
            Invocation::parse(["--", "~/repo"]).unwrap().ssh_destination,
            None
        );
        let remote = Invocation::parse(["admin@example", "--", "/repo"]).unwrap();
        assert_eq!(remote.ssh_destination.unwrap(), "admin@example");
    }

    #[test]
    fn rejects_ssh_option_injection() {
        assert!(Invocation::parse(["-oProxyCommand=bad", "host", "--", "/repo"]).is_err());
    }
}
