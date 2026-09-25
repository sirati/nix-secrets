use super::*;

impl BackendClient {
    pub fn subscribe_changes(&mut self) -> io::Result<()> {
        match self.exchange(&Request::SubscribeChanges)? {
            Response::Subscribed => Ok(()),
            Response::Error { message } => Err(io::Error::other(message)),
            response => Err(unexpected(response)),
        }
    }

    pub fn next_change(&mut self) -> io::Result<BackendEvent> {
        loop {
            match read_json(&mut self.stream)? {
                Some(Response::Change { update }) => return Ok(update),
                Some(Response::Heartbeat) => {}
                Some(Response::Error { message }) => return Err(io::Error::other(message)),
                Some(response) => return Err(unexpected(response)),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "change stream closed",
                    ))
                }
            }
        }
    }
}
