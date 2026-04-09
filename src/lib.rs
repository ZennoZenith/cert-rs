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

pub(crate) const CRATE_USER_AGENT: &str = concat!("cert-rs/", env!("CARGO_PKG_VERSION"));
pub(crate) const JOSE_JSON: &str = "application/jose+json";
pub(crate) const REPLAY_NONCE: &str = "Replay-Nonce";
pub(crate) const LANGUAGE: &str = "en-US,en;q=0.9";

mod api;
mod authentication;
mod b64;
mod client;
mod csr;
mod error;
mod retry;
mod time;

pub mod account;
pub mod authorization;
pub mod challenge;
pub mod directory;
pub mod order;

pub use api::{Error as ApiError, Problem, ProblemType};
pub use authentication::{
    EcCurve, Key, Kid, OkpCurve, RsaKeyBits,
    key_dto::{KeyDto, VersionedKeyDto},
    singing_algo::{EcSigningAlgorithm, OkpSigningAlgorithm, RsaSigningAlgorithm},
};
pub use client::Client;
pub use directory::{LetsEncrypt, ZeroSsl};
pub use error::{Error, Result};
pub use retry::RetryPolicy;
