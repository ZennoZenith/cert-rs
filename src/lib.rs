// Licensed under either of the Apache License, Version 2.0 or the MIT license.
// See LICENSE-APACHE or LICENSE-MIT for details.

#![deny(clippy::all)]
#![deny(clippy::expect_used)]
#![deny(clippy::unwrap_used)]
#![warn(clippy::cargo)]
#![warn(clippy::complexity)]
#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(clippy::perf)]
#![allow(clippy::multiple_crate_versions)] // FIX:

mod api;
mod authentication;
mod b64;
mod client;
mod csr;
mod error;
mod time;

pub mod account;
pub mod authorization;
pub mod challenge;
pub mod directory;
pub mod order;

pub use api::{AcmeError, AcmeErrorType};
pub use client::Client;
pub use directory::{LetsEncrypt, ZeroSsl};
pub use error::{Error, Result};
