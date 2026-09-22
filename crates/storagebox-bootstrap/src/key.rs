use crate::Error;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone)]
pub struct ClientContribution([u8; 32]);

impl ClientContribution {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for ClientContribution {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub trait EntropySink: Write {}
impl<T: Write> EntropySink for T {}

pub struct DevUrandom(File);

impl DevUrandom {
    pub fn open() -> Result<Self, Error> {
        Ok(Self(OpenOptions::new().write(true).open("/dev/urandom")?))
    }
}

impl Write for DevUrandom {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.write(data)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

pub trait KeyGenerator {
    fn generate(&mut self) -> Result<GeneratedKey, Error>;
}

pub struct OsKeyGenerator;

impl KeyGenerator for OsKeyGenerator {
    fn generate(&mut self) -> Result<GeneratedKey, Error> {
        let key =
            PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|_| Error::KeyGeneration)?;
        GeneratedKey::from_private_key(key)
    }
}

pub struct GeneratedKey {
    pub private_pem: Zeroizing<String>,
    pub public_key: String,
}

impl GeneratedKey {
    fn from_private_key(key: PrivateKey) -> Result<Self, Error> {
        let private_pem = key
            .to_openssh(LineEnding::LF)
            .map_err(|_| Error::KeyGeneration)?;
        let public_key = key
            .public_key()
            .to_openssh()
            .map_err(|_| Error::KeyGeneration)?;
        Ok(Self {
            private_pem,
            public_key,
        })
    }

    pub fn from_private_pem(pem: &str) -> Result<Self, Error> {
        let key = PrivateKey::from_openssh(pem).map_err(|_| Error::InvalidPrivateKey)?;
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(Error::InvalidPrivateKey);
        }
        Self::from_private_key(key).map_err(|_| Error::InvalidPrivateKey)
    }
}
