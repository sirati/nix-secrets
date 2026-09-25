use super::*;
pub(super) fn with_broker(
    broker: &Mutex<ApprovalBroker>,
    operation: impl FnOnce(&mut ApprovalBroker) -> Result<Response, BrokerError>,
) -> Result<Response, String> {
    let mut state = broker
        .lock()
        .map_err(|_| "approval broker lock is poisoned".to_owned())?;
    operation(&mut state).map_err(broker_error)
}

fn broker_error(error: BrokerError) -> String {
    match error {
        BrokerError::Invalid(message) => message.to_owned(),
        BrokerError::Full => "approval broker capacity reached".to_owned(),
        BrokerError::Unknown => "unknown approval request".to_owned(),
        BrokerError::Unavailable => "approval request is unavailable".to_owned(),
        BrokerError::WrongLease => "approval lease is invalid".to_owned(),
    }
}
