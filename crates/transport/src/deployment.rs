/// Version 2 adds target-side value generation. Version 3 adds generating a
/// shared source the target does not own ([`SharedSource`]). A client still
/// deploys to an older target what that target supports. Version 4 lets
/// the target leave out a value whose prerequisite is absent on it and
/// report it (`not_deployed`), and accepts public information with several
/// known_hosts lines, hosts and key types.
pub const DEPLOYMENT_PROTOCOL_VERSION: u16 = 4;
pub const NOT_DEPLOYED_PROTOCOL_VERSION: u16 = 4;
pub const GENERATION_PROTOCOL_VERSION: u16 = 2;
pub const SHARED_SOURCE_PROTOCOL_VERSION: u16 = 3;
pub const LEGACY_DEPLOYMENT_PROTOCOL_VERSION: u16 = 1;
pub const MAX_DEPLOYMENT_JSON: usize = 64 * 1024 * 1024;
mod client;
mod server;
mod task_schema;
mod types;
mod validation;

pub use client::{DeploymentClient, PreparedDeployment};
pub use server::{read_wire_json, serve_deployment, write_wire_json};
pub use types::PublicInfoAttestation;
pub use types::*;
#[cfg(test)]
use validation::{validate_batch, validate_target, verify_generators};

#[cfg(test)]
mod tests;
