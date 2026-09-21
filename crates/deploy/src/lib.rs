#![forbid(unsafe_code)]

mod deploy;
mod fsutil;
mod manifest;
mod schema;
mod validate;

pub use deploy::{DeployError, Deployer};
pub use manifest::{load_and_validate_manifest, load_target_state, system_hostname};
pub use schema::{DeploymentBatch, ResolvedBatch, SecretClass, SecretDeployment};
