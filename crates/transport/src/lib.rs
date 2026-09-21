#![forbid(unsafe_code)]

mod deployment;
mod hostkey;
mod invocation;
mod openssh;
mod protocol;
mod receiver;

pub use deployment::{
    read_wire_json, serve_deployment, write_wire_json, DeployEntry, DeploymentBatch,
    DeploymentClient, DeploymentError, DeploymentResult, DeploymentSelection, Destination,
    ExpectedSecret, ExpectedTarget, PreparedDeployment, TargetSecret, TargetState,
};
pub use hostkey::{
    Decision, HostIdentity, HostKeyDecision, HostKeyError, HostKeyPreflight, HostKeyStatus,
    HostKeyVerifier, PresentedKey,
};
pub use invocation::{Invocation, InvocationError};
pub use openssh::{OpenSsh, SshError, SshSession};
pub use protocol::{Frame, FrameError, FrameKind, MAX_FRAME_BYTES};
pub use receiver::{
    login_shell_arguments, run_receiver, ReceiverError, DEPLOYER_SOCKET, MANAGER_SOCKET,
};
