// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use serde::{Deserialize, Serialize};

/// Stable identifier assigned by the runner to a QUIC connection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct QcsdEndpointId(pub u64);

/// Transport-independent QUIC stream identifier.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct QcsdStreamId(pub u64);

/// Stable identifier assigned to one generated defense event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct QcsdSlotId(pub u64);

/// Stable identifier assigned to one chaff request instance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct QcsdChaffRequestId(pub u64);

/// Whether an HTTP request carries application data or QCSD chaff.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QcsdRequestRole {
    /// A request explicitly supplied by the experiment.
    Application,
    /// A same-origin request generated to provide downstream capacity.
    Chaff {
        /// Resource manifest identifier.
        resource_id: u32,
        /// Unique request instance, when assigned by the modern controller.
        #[serde(default)]
        request_id: Option<QcsdChaffRequestId>,
    },
}
