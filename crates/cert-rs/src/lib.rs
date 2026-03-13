#![deny(clippy::all)]
#![deny(clippy::expect_used)]
#![deny(clippy::unwrap_used)]
#![warn(clippy::cargo)]
#![warn(clippy::complexity)]
#![warn(clippy::nursery)]
// #![warn(clippy::pedantic)]
#![warn(clippy::perf)]
#![allow(dead_code)] // FIX: For exploratory dev.
#![allow(clippy::multiple_crate_versions)] // FIX: For exploratory dev.

pub mod api;
// mod authorization;
mod b64;
// mod csr;
mod error;
mod time;

// pub mod account;
// pub mod challenge;
pub mod directory;
// pub mod order;

pub use error::{Error, Result};
