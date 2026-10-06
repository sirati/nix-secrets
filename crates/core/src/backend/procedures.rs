//! The live procedures of this backend; see [`crate::procedure`].
//!
//! A procedure belongs to the process that registered it. Its token is an
//! unguessable secret, and the backend accepts it only from that process or
//! one of its descendants, as the kernel reports the peer of the requesting
//! connection. A process that learned a token some other way still cannot
//! join a procedure it does not descend from.
use super::{Request, Response};
use crate::framing::{read_json, write_json};
use crate::procedure::{
    MAX_DECLARED_STEPS, MAX_LABEL_BYTES, MAX_PROCEDURES, MAX_TITLE_BYTES, ProcedureStep,
    clean_text, split_token,
};
use crate::secret_request::is_same_or_descendant;
use std::collections::BTreeMap;
use std::io;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

struct Live {
    secret: String,
    /// The registering process; requesters must descend from it.
    owner: u32,
    step: ProcedureStep,
    /// The current step may take more than one request; see
    /// [`Procedures::next_step`].
    repeatable: bool,
}

#[derive(Default)]
pub(super) struct Procedures {
    live: Mutex<BTreeMap<String, Live>>,
    next: AtomicU64,
}

fn random_hex(bytes: usize) -> Result<String, String> {
    let mut random = vec![0_u8; bytes];
    getrandom::fill(&mut random).map_err(|error| error.to_string())?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Compares secrets in time independent of where they differ.
fn same_secret(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

impl Procedures {
    /// Registers a procedure of `owner`; returns its first state and token.
    pub(super) fn begin(
        &self,
        owner: u32,
        title: &str,
        steps: Option<u32>,
    ) -> Result<(ProcedureStep, String), String> {
        let title = clean_text(title, MAX_TITLE_BYTES);
        if title.is_empty() {
            return Err("a procedure needs a title".into());
        }
        if steps.is_some_and(|steps| steps == 0 || steps > MAX_DECLARED_STEPS) {
            return Err(format!(
                "a procedure declares between 1 and {MAX_DECLARED_STEPS} steps"
            ));
        }
        let mut live = self.live.lock().map_err(|_| "procedure registry poisoned")?;
        if live.len() >= MAX_PROCEDURES {
            return Err("too many procedures are running; retry when one ends".into());
        }
        let id = format!(
            "proc-{}-{}",
            self.next.fetch_add(1, Ordering::Relaxed),
            random_hex(6)?
        );
        let secret = random_hex(32)?;
        let step = ProcedureStep {
            id: id.clone(),
            title,
            step: 0,
            steps,
            label: "starting".into(),
            deployment: false,
        };
        live.insert(
            id.clone(),
            Live {
                secret: secret.clone(),
                owner,
                step: step.clone(),
                repeatable: false,
            },
        );
        Ok((step, format!("{id}:{secret}")))
    }

    pub(super) fn end(&self, id: &str) {
        if let Ok(mut live) = self.live.lock() {
            live.remove(id);
        }
    }

    pub(super) fn snapshot(&self) -> Vec<ProcedureStep> {
        self.live
            .lock()
            .map(|live| live.values().map(|live| live.step.clone()).collect())
            .unwrap_or_default()
    }

    /// Verifies that `peer` may act in the procedure of `token` and numbers
    /// its request as the next step.
    ///
    /// A `repeatable` request with the same label as the repeatable step
    /// before it stays on that step: an SSH login to one destination is one
    /// step however many connections it takes, so a declared total stays
    /// right when a requester reconnects.
    pub(super) fn next_step(
        &self,
        token: &str,
        peer: u32,
        label: &str,
        deployment: bool,
        repeatable: bool,
    ) -> Result<ProcedureStep, String> {
        let (id, secret) = split_token(token).ok_or("the procedure token is malformed")?;
        let mut live = self.live.lock().map_err(|_| "procedure registry poisoned")?;
        let procedure = live
            .get_mut(id)
            .filter(|procedure| same_secret(&procedure.secret, secret))
            .ok_or("the procedure has ended or the token is wrong")?;
        if !is_same_or_descendant(peer, procedure.owner) {
            return Err(format!(
                "this process does not belong to procedure {id}; only the command started by \
                 `nix-secrets procedure` and its descendants may join it"
            ));
        }
        let label = clean_text(label, MAX_LABEL_BYTES);
        let repeat = repeatable
            && procedure.repeatable
            && procedure.step.step > 0
            && procedure.step.label == label;
        if !repeat {
            procedure.step.step = procedure.step.step.saturating_add(1);
        }
        procedure.step.label = label;
        procedure.step.deployment = deployment;
        procedure.repeatable = repeatable;
        Ok(procedure.step.clone())
    }
}

/// Serves [`Request::BeginProcedure`]: the procedure lives as long as this
/// connection, which carries nothing else.
pub(super) fn serve(
    stream: &mut UnixStream,
    operators: &super::secrets::Operators,
    peer: u32,
    title: String,
    steps: Option<u32>,
) -> io::Result<()> {
    let (step, token) = match operators.procedures.begin(peer, &title, steps) {
        Ok(begun) => begun,
        Err(message) => return write_json(stream, &Response::Error { message }),
    };
    let id = step.id.clone();
    operators.broadcast_step(step);
    // How its command exited, if the owner said so before closing.
    let mut exit = None;
    let result = (|| {
        write_json(
            stream,
            &Response::ProcedureBegun {
                id: id.clone(),
                token,
            },
        )?;
        loop {
            match read_json::<Request>(stream) {
                Ok(Some(Request::EndProcedure { exit_code })) => {
                    exit = exit_code;
                    return write_json(
                        stream,
                        &Response::ProcedureEnded {
                            id: id.clone(),
                            exit_code,
                        },
                    );
                }
                Ok(Some(_)) => {
                    write_json(
                        stream,
                        &Response::Error {
                            message: "a procedure connection only ends the procedure".into(),
                        },
                    )?;
                }
                Ok(None) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    })();
    operators.procedures.end(&id);
    operators.broadcast_end(&id, exit);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_descendants_of_the_owner_with_the_exact_token_join() {
        let procedures = Procedures::default();
        let own = std::process::id();
        let (first, token) = procedures.begin(own, "Update\x07 ns1", Some(3)).unwrap();
        assert_eq!(first.title, "Update  ns1");
        assert_eq!(first.step, 0);
        let step = procedures
            .next_step(&token, own, "sign closure for ns1", false, false)
            .unwrap();
        assert_eq!((step.step, step.label.as_str()), (1, "sign closure for ns1"));
        // A descendant joins as the next step.
        let mut child = std::process::Command::new("sleep").arg("5").spawn().unwrap();
        let step = procedures
            .next_step(&token, child.id(), "deploy secrets to ns1", true, false)
            .unwrap();
        assert_eq!(step.step, 2);
        assert!(step.deployment);
        // A process that does not descend from the owner is refused, even
        // with the right token.
        let (_, foreign) = procedures.begin(child.id(), "Other", None).unwrap();
        let error = procedures.next_step(&foreign, own, "x", false, false).unwrap_err();
        assert!(error.contains("does not belong"), "{error}");
        child.kill().unwrap();
        child.wait().unwrap();
        // A wrong secret is refused like an unknown procedure.
        let (id, _) = split_token(&token).unwrap();
        let forged = format!("{id}:{}", "0".repeat(64));
        assert!(procedures.next_step(&forged, own, "x", false, false).is_err());
        assert!(procedures.next_step("garbage", own, "x", false, false).is_err());
        procedures.end(id);
        assert!(procedures.next_step(&token, own, "x", false, false).is_err());
        assert_eq!(procedures.snapshot().len(), 1);
    }

    #[test]
    fn repeated_logins_to_one_destination_stay_one_step() {
        let procedures = Procedures::default();
        let own = std::process::id();
        let (_, token) = procedures.begin(own, "Update ns1", Some(3)).unwrap();
        let next = |label: &str, repeatable| {
            procedures
                .next_step(&token, own, label, false, repeatable)
                .unwrap()
                .step
        };
        assert_eq!(next("sign artifacts for ns1", false), 1);
        // Not repeatable: the same label again is a new step.
        assert_eq!(next("sign artifacts for ns1", false), 2);
        assert_eq!(next("SSH authentication to update@ns1", true), 3);
        // The upload and every reconnect while waiting for the reboot.
        assert_eq!(next("SSH authentication to update@ns1", true), 3);
        assert_eq!(next("SSH authentication to update@ns1", true), 3);
        // Another destination is another step.
        assert_eq!(next("SSH authentication to update@ns2", true), 4);
        assert_eq!(next("deploy secrets to ns1", false), 5);
        // A login after something else is a new step again.
        assert_eq!(next("SSH authentication to update@ns2", true), 6);
    }

    #[test]
    fn titles_and_declared_steps_are_validated() {
        let procedures = Procedures::default();
        assert!(procedures.begin(1, " \x1b ", None).is_err());
        assert!(procedures.begin(1, "x", Some(0)).is_err());
        assert!(procedures.begin(1, "x", Some(MAX_DECLARED_STEPS + 1)).is_err());
        for _ in 0..MAX_PROCEDURES {
            procedures.begin(1, "x", None).unwrap();
        }
        assert!(procedures.begin(1, "x", None).is_err());
    }
}
