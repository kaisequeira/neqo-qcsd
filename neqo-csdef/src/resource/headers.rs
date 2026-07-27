// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use serde::{Deserialize, Serialize};

/// How recorded application request headers are replayed.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HeaderPolicyMode {
    /// Ignore per-resource discovery headers and send only explicit overrides.
    Minimal,
    /// Replay safe browser discovery headers, excluding conditional and range fields.
    #[default]
    FreshBrowser,
    /// Replay safe discovery headers with explicitly selected conditional/range behavior.
    Custom,
}

/// Manifest-wide application header replay policy.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderPolicy {
    /// Replay mode.
    #[serde(default)]
    pub mode: HeaderPolicyMode,
    /// Headers applied after resource-specific values. Repeated names replace discovered values.
    #[serde(default)]
    pub overrides: Vec<(String, String)>,
    /// Permit conditional cache request headers in custom mode.
    #[serde(default)]
    pub allow_conditional: bool,
    /// Permit the `Range` request header in custom mode.
    #[serde(default)]
    pub allow_range: bool,
}

pub(super) fn validate_headers(headers: &[(String, String)]) -> crate::Result<()> {
    for (name, value) in headers {
        let normalized = name.to_ascii_lowercase();
        if name.is_empty()
            || name.starts_with(':')
            || !name.bytes().all(is_header_name_byte)
            || is_connection_specific(&normalized, value)
        {
            return Err(crate::Error::InvalidConfig(format!(
                "header {name:?} is not valid for an HTTP/3 request"
            )));
        }
        if is_sensitive(&normalized) {
            return Err(crate::Error::InvalidConfig(format!(
                "sensitive header {name:?} must be injected at runtime, not stored in a manifest"
            )));
        }
        if value.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n')) {
            return Err(crate::Error::InvalidConfig(format!(
                "header {name:?} contains an unsafe value"
            )));
        }
    }
    Ok(())
}

pub(super) fn is_conditional(name: &str) -> bool {
    matches!(
        name,
        "if-match" | "if-modified-since" | "if-none-match" | "if-range" | "if-unmodified-since"
    )
}

const fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_connection_specific(name: &str, value: &str) -> bool {
    matches!(
        name,
        "connection" | "host" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
    ) || (name == "te" && !value.eq_ignore_ascii_case("trailers"))
}

fn is_sensitive(name: &str) -> bool {
    matches!(
        name,
        "authorization" | "cookie" | "cookie2" | "proxy-authorization"
    )
}
