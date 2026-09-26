/// Version 2 adds target-side value generation. A client still deploys to
/// a version 1 target when it needs no generation.
pub const DEPLOYMENT_PROTOCOL_VERSION: u16 = 2;
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
