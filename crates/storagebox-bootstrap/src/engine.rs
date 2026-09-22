use crate::{
    ClientContribution, EntropySink, Error, GeneratedKey, KeyGenerator, Merge, StorageBoxTask,
    merge_authorized_keys,
};
use time::{Date, OffsetDateTime, format_description};
use zeroize::Zeroizing;

pub trait RemoteSession {
    fn read_authorized_keys(&mut self) -> Result<Vec<u8>, Error>;
    fn replace_authorized_keys_atomically(&mut self, contents: &[u8]) -> Result<(), Error>;
}

/// Opens a password-authenticated session after exact host-key verification.
/// Implementations must not place `password` in argv, the environment, or storage.
pub trait SshBackend {
    type Session: RemoteSession;
    fn connect(&mut self, task: &StorageBoxTask, password: &[u8]) -> Result<Self::Session, Error>;
}

pub trait Clock {
    fn utc_date(&self) -> Result<Date, Error>;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn utc_date(&self) -> Result<Date, Error> {
        Ok(OffsetDateTime::now_utc().date())
    }
}

pub struct Engine<B, S, G, C> {
    pub backend: B,
    pub entropy: S,
    pub generator: G,
    pub clock: C,
}

impl<B: SshBackend, S: EntropySink, G: KeyGenerator, C: Clock> Engine<B, S, G, C> {
    pub fn run(
        &mut self,
        task: &StorageBoxTask,
        password: Zeroizing<Vec<u8>>,
        contribution: ClientContribution,
        existing_private_key: Option<&str>,
    ) -> Result<GeneratedKey, Error> {
        task.validate()?;
        let key = match existing_private_key {
            Some(value) => GeneratedKey::from_private_pem(value)?,
            None => {
                self.entropy.write_all(contribution.expose())?;
                self.entropy.flush()?;
                self.generator.generate()?
            }
        };
        let mut session = self.backend.connect(task, password.as_slice())?;
        let current = session.read_authorized_keys()?;
        let format = format_description::parse_borrowed::<2>("[year]-[month]-[day]")
            .map_err(|_| Error::KeyGeneration)?;
        let date = self
            .clock
            .utc_date()?
            .format(&format)
            .map_err(|_| Error::KeyGeneration)?;
        match merge_authorized_keys(&current, &task.marker_prefix(), &key.public_key, &date)? {
            Merge::Unchanged(_) => {}
            Merge::Replaced(contents) => session.replace_authorized_keys_atomically(&contents)?,
        }
        Ok(key)
    }
}
