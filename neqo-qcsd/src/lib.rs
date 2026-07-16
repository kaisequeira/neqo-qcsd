// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Client-side defenses (QCSD) for shaping QUIC traffic.
//!
//! This crate deliberately has no dependency on Neqo transport or HTTP/3.
//! [`QcsdController`] consumes endpoint observations and emits actions that an
//! adapter can apply without exposing Neqo's internal types.

mod config;
mod controller;
mod defense;
mod resource;
mod trace;

pub use config::{DefenseConfig, FrontConfig, QcsdConfig, TamarawConfig};
pub use controller::{
    MissedSlotReason, QcsdAction, QcsdController, QcsdEndpointId, QcsdObservation, QcsdRequestRole,
    QcsdStreamId,
};
pub use defense::{Capacity, Defense, Front, SharedDefense, StaticSchedule, Tamaraw};
pub use resource::{HeaderPolicy, HeaderPolicyMode, Resource, ResourceManifest};
pub use trace::{Direction, Packet, Trace};

/// Errors raised while loading or executing a QCSD experiment.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A configuration value is outside the supported range.
    #[error("invalid QCSD configuration: {0}")]
    InvalidConfig(String),
    /// An input schedule could not be parsed.
    #[error("invalid schedule on line {line}: {message}")]
    InvalidSchedule {
        /// One-based input line number.
        line: usize,
        /// Description of the invalid value.
        message: String,
    },
    /// An input/output operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// TOML configuration parsing failed.
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    /// Resource manifest parsing failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Result type used by the QCSD crate.
pub type Result<T> = std::result::Result<T, Error>;
