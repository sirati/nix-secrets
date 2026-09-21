use std::fmt;
use std::io::{self, Read, Write};
use zeroize::Zeroize;

const MAGIC: [u8; 4] = *b"NSF1";
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    OpenManager = 1,
    OpenDeployer = 2,
    Data = 3,
    Close = 4,
    Failure = 5,
}

impl TryFrom<u8> for FrameKind {
    type Error = FrameError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::OpenManager),
            2 => Ok(Self::OpenDeployer),
            3 => Ok(Self::Data),
            4 => Ok(Self::Close),
            5 => Ok(Self::Failure),
            _ => Err(FrameError::Invalid("unknown frame kind")),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Frame {
    pub kind: FrameKind,
    pub payload: Vec<u8>,
}

impl Drop for Frame {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    Invalid(&'static str),
    TooLarge,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Invalid(message) => f.write_str(message),
            Self::TooLarge => f.write_str("frame exceeds size limit"),
        }
    }
}
impl std::error::Error for FrameError {}
impl From<io::Error> for FrameError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl Frame {
    pub fn read_from(reader: &mut impl Read) -> Result<Self, FrameError> {
        let mut header = [0_u8; 9];
        reader.read_exact(&mut header)?;
        if header[..4] != MAGIC {
            return Err(FrameError::Invalid("invalid frame magic"));
        }
        let kind = FrameKind::try_from(header[4])?;
        let length = u32::from_be_bytes(header[5..9].try_into().expect("fixed header")) as usize;
        if length > MAX_FRAME_BYTES {
            return Err(FrameError::TooLarge);
        }
        let mut payload = vec![0; length];
        reader.read_exact(&mut payload)?;
        Ok(Self { kind, payload })
    }

    pub fn write_to(&self, writer: &mut impl Write) -> Result<(), FrameError> {
        if self.payload.len() > MAX_FRAME_BYTES {
            return Err(FrameError::TooLarge);
        }
        writer.write_all(&MAGIC)?;
        writer.write_all(&[self.kind as u8])?;
        writer.write_all(&(self.payload.len() as u32).to_be_bytes())?;
        writer.write_all(&self.payload)?;
        writer.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frames_round_trip_binary_payloads() {
        let original = Frame {
            kind: FrameKind::Data,
            payload: vec![0, 255, b'\n'],
        };
        let mut bytes = Vec::new();
        original.write_to(&mut bytes).unwrap();
        assert_eq!(Frame::read_from(&mut bytes.as_slice()).unwrap(), original);
    }
    #[test]
    fn oversized_frame_is_rejected_before_allocation() {
        let mut bytes = Vec::from(MAGIC);
        bytes.push(FrameKind::Data as u8);
        bytes.extend_from_slice(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes());
        assert!(matches!(
            Frame::read_from(&mut bytes.as_slice()),
            Err(FrameError::TooLarge)
        ));
    }
}
