#![forbid(unsafe_code)]

mod deployment;
mod hostkey;
mod invocation;
mod openssh;
mod protocol;
mod receiver;

pub use deployment::{
    read_wire_json, serve_deployment, write_wire_json, AppliedOutput, DeployEntry, DeploymentBatch,
    DeploymentClient, DeploymentError, DeploymentResult, DeploymentSelection, Destination,
    ExpectedSecret, ExpectedTarget, ExpectedTask, GenerateEntry, GeneratedRecord,
    PreparedDeployment, PublicInfoAttestation, StorageBoxBootstrap, TargetSecret, TargetState,
    SharedSource, TargetTask, TaskEntry, DEPLOYMENT_PROTOCOL_VERSION, GENERATION_PROTOCOL_VERSION,
    LEGACY_DEPLOYMENT_PROTOCOL_VERSION, LOCAL_SSH_KEY, SHARED_SOURCE_PROTOCOL_VERSION,
    STORAGE_BOX_SSH_KEY,
};
pub use hostkey::{
    fingerprint, ChangedHostKey, Decision, HostIdentity, HostKeyDecision, HostKeyError,
    HostKeyPreflight, HostKeyStatus, HostKeyVerifier, KnownKey, PresentedKey,
};
pub use invocation::{Invocation, InvocationError};
pub use openssh::identity::{agent_keys, choose, client_config, describe_line, ClientConfig};
pub use openssh::{Offer, OpenSsh, SshError, SshSession};
pub use protocol::{Frame, FrameError, FrameKind, MAX_FRAME_BYTES};
pub use receiver::{
    login_shell_arguments, run_receiver, ReceiverError, DEPLOYER_SOCKET, MANAGER_SOCKET,
};
