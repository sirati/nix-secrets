#![forbid(unsafe_code)]

pub mod async_ui;
pub mod cli;
pub mod client;
mod clipboard;
pub mod command;
pub mod controller;
pub mod deployment;
pub mod generator;
pub mod keypair;
pub mod model;
pub mod pipe_secret;
pub mod socket;
pub mod startup;
mod task;
pub mod tree;
pub mod ui;
#[cfg(test)]
mod ui_tests;
