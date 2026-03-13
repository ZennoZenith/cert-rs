#![deny(clippy::all)]
// #![deny(clippy::unwrap_used)]
// #![deny(clippy::expect_used)]
// #![warn(clippy::pedantic)]
// #![warn(clippy::nursery)]
// #![warn(clippy::cargo)]
// #![warn(clippy::complexity)]
// #![warn(clippy::perf)]

mod api;
mod authorization;
mod b64;
mod csr;
mod error;
mod time;

pub mod account;
pub mod challenge;
pub mod directory;
pub mod order;

pub use api::AcmeApi;
pub use error::{Error, Result};
