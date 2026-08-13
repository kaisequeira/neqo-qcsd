// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{collections::HashSet, fs, path::Path};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// A same-origin resource that can supply downstream chaff capacity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    /// Stable manifest-local identifier.
    pub id: u32,
    /// Absolute HTTPS URL.
    pub url: String,
    /// Browser-style resource type used as a selection tie-breaker.
    #[serde(default = "default_resource_type", rename = "type")]
    pub kind: String,
    /// Previously observed encoded content length.
    #[serde(default)]
    pub content_length: Option<u64>,
    /// Previously observed unencoded body length.
    #[serde(default)]
    pub data_length: u64,
    /// Select only explicitly prioritized resources when any are prioritized.
    #[serde(default)]
    pub chaff_priority: bool,
    /// Whether a probe successfully downloaded the resource.
    #[serde(default, alias = "done")]
    pub known_valid: bool,
    /// Resource identifiers that must complete first.
    #[serde(default)]
    pub depends_on: Vec<u32>,
    /// Exact application request headers captured during workload preparation.
    ///
    /// Header names are normalized to lowercase when they are returned to an adapter.
    /// Headers that are unsafe to replay are rejected when the manifest is loaded.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

/// Immutable response identity established for one compact chaff request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedChaffResponse {
    /// Final HTTP status code.
    pub status: u16,
    /// Normalized content coding. An absent `content-encoding` field is `identity`.
    pub content_encoding: String,
    /// Complete response-body extent in bytes.
    pub body_bytes: u64,
    /// Lowercase SHA-256 of the complete response body.
    pub body_sha256: String,
}

/// Evidence bindings for a compact, nonblocking HTTP/3 chaff request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChaffQualification {
    /// Qualification schema version.
    pub schema_version: u32,
    /// Qualified request method. Current and historical schemas support only `GET`.
    pub method: String,
    /// Exact production nonblocking HTTP/3 request-stream bytes, including HEADERS framing.
    pub request_stream_bytes: u64,
    /// Concurrent request count covered by response qualification for all defenses.
    ///
    /// Explicit in every current schema-two artifact.
    pub qualified_parallel_chaff_streams: usize,
    /// Exact one-shot request count covered by Walkie-Talkie prefix qualification.
    pub walkie_talkie_required_chaff_streams: usize,
    /// Stable response identity established before a defense run.
    pub expected_response: ExpectedChaffResponse,
    /// SHA-256 binding the repeated response-identity qualification receipts.
    pub response_qualification_sha256: String,
    /// SHA-256 binding the repeated shaped staged prefix-pack receipts.
    pub prefix_pack_qualification_sha256: String,
    /// Raw SHA-256 of the acyclic numeric prefix-pack specification.
    pub prefix_spec_sha256: String,
}

/// A resource usable only through the distinct qualified-chaff manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedChaffResource {
    /// Stable manifest-local identifier.
    pub id: u32,
    /// Absolute HTTPS URL.
    pub url: String,
    /// Browser-style resource type retained from the application workload.
    #[serde(default = "default_resource_type", rename = "type")]
    pub kind: String,
    /// Qualified complete response-body length.
    pub content_length: Option<u64>,
    /// Qualified complete response-body length.
    pub data_length: u64,
    /// Selection priority retained from the application workload.
    #[serde(default)]
    pub chaff_priority: bool,
    /// Whether the compact request was qualified successfully.
    pub known_valid: bool,
    /// Qualified selected-resource projections are dependency-free.
    #[serde(default)]
    pub depends_on: Vec<u32>,
    /// Exact compact request headers qualified for this representation.
    pub headers: Vec<(String, String)>,
    /// Immutable request/response and evidence bindings.
    pub chaff_qualification: ChaffQualification,
}

/// Strict, separately namespaced manifest for runtime chaff requests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChaffManifest {
    /// Qualified-chaff manifest schema version.
    pub schema_version: u32,
    /// Exact artifact discriminator preventing application-manifest confusion.
    pub artifact_type: String,
    /// Raw SHA-256 of the exact frozen application workload file.
    pub application_workload_sha256: String,
    /// Application navigation root bound to staged activation component zero.
    pub application_resource_id: u32,
    /// Frozen application-source resource selected for compact chaff replay.
    ///
    /// This identity is independent of `application_resource_id`; Cloudflare's
    /// selected resource happens to be the root, while other workloads select a
    /// larger same-origin subresource.
    pub selected_chaff_resource_id: u32,
    /// Maximum concurrent chaff-request cohort response-qualified for any defense.
    pub qualified_parallel_chaff_streams: usize,
    /// Exact one-shot chaff-request cohort used by Walkie-Talkie.
    pub walkie_talkie_required_chaff_streams: usize,
    /// Exactly one independently qualified, dependency-free chaff projection.
    pub resources: Vec<QualifiedChaffResource>,
}

fn default_resource_type() -> String {
    "Unknown".into()
}

fn validate_headers(headers: &[(String, String)]) -> Result<()> {
    for (name, value) in headers {
        let normalized = name.to_ascii_lowercase();
        if name.is_empty()
            || name.starts_with(':')
            || !name.bytes().all(is_header_name_byte)
            || is_connection_specific(&normalized, value)
        {
            return Err(Error::InvalidConfig(format!(
                "header {name:?} is not valid for an HTTP/3 request"
            )));
        }
        if is_sensitive(&normalized) {
            return Err(Error::InvalidConfig(format!(
                "sensitive header {name:?} must be injected at runtime, not stored in a manifest"
            )));
        }
        if is_conditional(&normalized) || normalized == "range" {
            return Err(Error::InvalidConfig(format!(
                "conditional or range header {name:?} cannot be replayed from a manifest"
            )));
        }
        if value.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n')) {
            return Err(Error::InvalidConfig(format!(
                "header {name:?} contains an unsafe value"
            )));
        }
    }
    Ok(())
}

/// Normalize and retain only frozen request headers that are safe for chaff replay.
///
/// Manifest loading rejects unsafe headers. This defense-in-depth sanitizer also
/// covers actions constructed directly in code, and is shared by the runner and
/// HTTP/3 adapter so recorded and transmitted request headers cannot diverge.
#[must_use]
pub fn sanitize_chaff_headers(headers: Vec<(String, String)>) -> Vec<(String, String)> {
    headers
        .into_iter()
        .filter_map(|(name, value)| {
            let name = name.to_ascii_lowercase();
            (!name.is_empty()
                && !name.starts_with(':')
                && name.bytes().all(is_header_name_byte)
                && !is_connection_specific(&name, &value)
                && !is_sensitive(&name)
                && !is_conditional(&name)
                && name != "range"
                && !value.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n')))
            .then_some((name, value))
        })
        .collect()
}

fn is_conditional(name: &str) -> bool {
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

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Normalize a response `content-encoding` value for identity comparison.
///
/// An absent field is represented by `None` and normalizes to `identity`.
/// Duplicate fields and comma-separated coding stacks are deliberately rejected
/// by callers; qualification accepts exactly one stable representation.
#[must_use]
pub fn normalize_content_encoding(value: Option<&str>) -> Option<String> {
    let value = value.unwrap_or("identity").trim().to_ascii_lowercase();
    (!value.is_empty()
        && !value.contains(',')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    .then_some(value)
}

impl Resource {
    /// Best known reusable response size.
    #[must_use]
    pub fn effective_length(&self) -> u64 {
        self.content_length.unwrap_or(1).max(self.data_length)
    }
    /// Normalized `https://authority` used for exact same-origin routing.
    #[must_use]
    pub fn origin(&self) -> Option<String> {
        let remainder = self.url.strip_prefix("https://")?;
        let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
        let authority = &remainder[..authority_end];
        (!authority.is_empty()).then(|| format!("https://{authority}"))
    }

    pub(crate) fn type_rank(&self) -> u8 {
        match self.kind.as_str() {
            "Image" => 4,
            "Font" | "Stylesheet" | "Script" => 3,
            "Document" => 2,
            _ => 1,
        }
    }
}

impl QualifiedChaffResource {
    fn as_resource(&self) -> Resource {
        Resource {
            id: self.id,
            url: self.url.clone(),
            kind: self.kind.clone(),
            content_length: self.content_length,
            data_length: self.data_length,
            chaff_priority: self.chaff_priority,
            known_valid: self.known_valid,
            depends_on: self.depends_on.clone(),
            headers: self.headers.clone(),
        }
    }

    fn validate(
        &self,
        schema_version: u32,
        qualified_parallel_chaff_streams: usize,
        walkie_talkie_required_chaff_streams: usize,
    ) -> Result<()> {
        let resource = self.as_resource();
        ResourceManifest {
            resources: vec![resource.clone()],
        }
        .validate()?;
        let qualification = &self.chaff_qualification;
        if qualification.schema_version != schema_version
            || qualification.method != "GET"
            || qualification.qualified_parallel_chaff_streams != qualified_parallel_chaff_streams
            || qualification.walkie_talkie_required_chaff_streams
                != walkie_talkie_required_chaff_streams
        {
            return Err(Error::InvalidConfig(
                "qualified chaff qualification schema, method, or required stream count is invalid"
                    .into(),
            ));
        }
        if qualification.request_stream_bytes == 0 {
            return Err(Error::InvalidConfig(
                "qualified chaff request_stream_bytes must be positive".into(),
            ));
        }
        let response = &qualification.expected_response;
        if !(200..300).contains(&response.status)
            || response.body_bytes == 0
            || (schema_version == 2 && response.body_bytes < 1_200)
            || normalize_content_encoding(Some(&response.content_encoding)).as_deref()
                != Some(response.content_encoding.as_str())
            || !is_lower_hex_sha256(&response.body_sha256)
        {
            return Err(Error::InvalidConfig(
                "qualified chaff expected_response identity is invalid or not normalized".into(),
            ));
        }
        for (label, hash) in [
            (
                "response_qualification_sha256",
                &qualification.response_qualification_sha256,
            ),
            (
                "prefix_pack_qualification_sha256",
                &qualification.prefix_pack_qualification_sha256,
            ),
            ("prefix_spec_sha256", &qualification.prefix_spec_sha256),
        ] {
            if !is_lower_hex_sha256(hash) {
                return Err(Error::InvalidConfig(format!(
                    "qualified chaff {label} must be a lowercase SHA-256"
                )));
            }
        }
        if !self.known_valid
            || !self.depends_on.is_empty()
            || self.content_length != Some(response.body_bytes)
            || self.data_length != response.body_bytes
            || resource.effective_length() != response.body_bytes
        {
            return Err(Error::InvalidConfig(
                "qualified chaff resource must be known-valid, dependency-free, and bind both length fields exactly to expected_response.body_bytes"
                    .into(),
            ));
        }
        let normalized_names: Vec<_> = self
            .headers
            .iter()
            .map(|(name, _)| name.to_ascii_lowercase())
            .collect();
        if normalized_names != ["accept", "accept-encoding", "accept-language"]
            || self
                .headers
                .iter()
                .any(|(name, _)| name != &name.to_ascii_lowercase())
        {
            return Err(Error::InvalidConfig(
                "qualified chaff headers must be the exact lowercase accept, accept-encoding, accept-language projection in that order"
                    .into(),
            ));
        }
        Ok(())
    }
}

impl ChaffManifest {
    /// Load and strictly validate a current schema-two qualified-chaff manifest.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, parsed, or validated.
    pub fn from_json_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let input = fs::read_to_string(path)?;
        Self::from_json(&input)
    }

    /// Parse and strictly validate a current schema-two qualified-chaff manifest.
    ///
    /// # Errors
    ///
    /// Returns an error when the schema or any qualification binding is invalid.
    pub fn from_json(input: &str) -> Result<Self> {
        let manifest: Self = serde_json::from_str(input)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Parse a frozen schema-one manifest for historical audit code only.
    ///
    /// Current defended execution must use [`Self::from_json`], which rejects
    /// schema one even when this historical representation is otherwise valid.
    ///
    /// # Errors
    ///
    /// Returns an error when the artifact is not the exact historical schema.
    pub fn from_historical_schema_one_json(input: &str) -> Result<Self> {
        let mut value: serde_json::Value = serde_json::from_str(input)?;
        let top = value.as_object_mut().ok_or_else(|| {
            Error::InvalidConfig("historical qualified chaff manifest must be an object".into())
        })?;
        for field in [
            "selected_chaff_resource_id",
            "qualified_parallel_chaff_streams",
            "walkie_talkie_required_chaff_streams",
        ] {
            if top.contains_key(field) {
                return Err(Error::InvalidConfig(format!(
                    "historical schema one must not contain schema-two field {field}"
                )));
            }
        }
        top.insert("selected_chaff_resource_id".into(), 0.into());
        top.insert("qualified_parallel_chaff_streams".into(), 0.into());
        top.insert("walkie_talkie_required_chaff_streams".into(), 0.into());
        let resources = top
            .get_mut("resources")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or_else(|| {
                Error::InvalidConfig("historical qualified chaff resources must be an array".into())
            })?;
        for resource in resources {
            let qualification = resource
                .as_object_mut()
                .and_then(|resource| resource.get_mut("chaff_qualification"))
                .and_then(serde_json::Value::as_object_mut)
                .ok_or_else(|| {
                    Error::InvalidConfig("historical chaff qualification must be an object".into())
                })?;
            for field in [
                "qualified_parallel_chaff_streams",
                "walkie_talkie_required_chaff_streams",
            ] {
                if qualification.contains_key(field) {
                    return Err(Error::InvalidConfig(format!(
                        "historical schema one qualification must not contain schema-two field {field}"
                    )));
                }
                qualification.insert(field.into(), 0.into());
            }
        }
        let manifest: Self = serde_json::from_value(value)?;
        manifest.validate_historical_schema_one()?;
        Ok(manifest)
    }

    /// Validate the distinct schema-two selected-resource chaff contract.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong discriminator, resource count, or qualification.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 2 || self.artifact_type != "qcsd-qualified-chaff-manifest" {
            return Err(Error::InvalidConfig(
                "current qualified chaff manifest requires schema_version 2 and artifact_type qcsd-qualified-chaff-manifest"
                    .into(),
            ));
        }
        if !is_lower_hex_sha256(&self.application_workload_sha256) {
            return Err(Error::InvalidConfig(
                "qualified chaff application_workload_sha256 must be a lowercase SHA-256".into(),
            ));
        }
        if self.application_resource_id != 0
            || !(5..=20).contains(&self.qualified_parallel_chaff_streams)
            || !(1..=20).contains(&self.walkie_talkie_required_chaff_streams)
            || self.qualified_parallel_chaff_streams
                != self.walkie_talkie_required_chaff_streams.max(5)
        {
            return Err(Error::InvalidConfig(
                "qualified chaff manifest requires root id zero, exact Walkie-Talkie streams in 1..=20, and response-qualified parallel streams equal max(5, Walkie-Talkie streams)"
                    .into(),
            ));
        }
        if self.resources.len() != 1 || self.resources[0].id != self.selected_chaff_resource_id {
            return Err(Error::InvalidConfig(
                "qualified chaff manifest requires exactly one resource matching selected_chaff_resource_id"
                    .into(),
            ));
        }
        self.resources[0].validate(
            2,
            self.qualified_parallel_chaff_streams,
            self.walkie_talkie_required_chaff_streams,
        )
    }

    fn validate_historical_schema_one(&self) -> Result<()> {
        if self.schema_version != 1
            || self.artifact_type != "qcsd-qualified-chaff-manifest"
            || !is_lower_hex_sha256(&self.application_workload_sha256)
            || self.resources.len() != 1
            || self.resources[0].id != self.application_resource_id
            || self.selected_chaff_resource_id != 0
            || self.qualified_parallel_chaff_streams != 0
            || self.walkie_talkie_required_chaff_streams != 0
        {
            return Err(Error::InvalidConfig(
                "historical qualified chaff manifest is not exact schema one".into(),
            ));
        }
        self.resources[0].validate(1, 0, 0)
    }

    /// Generic resource view consumed by the transport-independent controller.
    #[must_use]
    pub fn resource_manifest(&self) -> ResourceManifest {
        ResourceManifest {
            resources: self
                .resources
                .iter()
                .map(QualifiedChaffResource::as_resource)
                .collect(),
        }
    }

    /// Qualification associated with a manifest-local resource identifier.
    #[must_use]
    pub fn qualification(&self, resource_id: u32) -> Option<&ChaffQualification> {
        self.resources
            .iter()
            .find(|resource| resource.id == resource_id)
            .map(|resource| &resource.chaff_qualification)
    }
}

/// Resource/dependency input for application and chaff requests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceManifest {
    /// Resources in stable identifier order.
    pub resources: Vec<Resource>,
}

#[derive(Deserialize)]
struct LegacyGraph {
    nodes: Vec<LegacyResource>,
    links: Vec<LegacyLink>,
}

#[derive(Deserialize)]
struct LegacyResource {
    id: u32,
    url: String,
    #[serde(rename = "type", default = "default_resource_type")]
    resource_type: String,
    #[serde(default, rename = "done")]
    known_valid: bool,
    #[serde(default)]
    content_length: Option<u64>,
    #[serde(default)]
    chaff_priority: bool,
    #[serde(default)]
    data_length: u64,
}

#[derive(Deserialize)]
struct LegacyLink {
    source: u32,
    target: u32,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ManifestInput {
    Versioned(ResourceManifest),
    Legacy(LegacyGraph),
}

impl ResourceManifest {
    fn initial_chaff_selection_matching(&self, origins: Option<&[String]>) -> Option<&Resource> {
        let eligible = self.resources.iter().filter(|resource| {
            resource.known_valid
                && resource.depends_on.is_empty()
                && resource.effective_length() > 0
                && origins.is_none_or(|origins| {
                    resource
                        .origin()
                        .is_some_and(|origin| origins.contains(&origin))
                })
        });
        let priority_only = eligible.clone().any(|resource| resource.chaff_priority);
        eligible
            .filter(|resource| !priority_only || resource.chaff_priority)
            .max_by_key(|resource| {
                (
                    resource.effective_length(),
                    resource.type_rank(),
                    resource.id,
                )
            })
    }

    /// Initial selected chaff length restricted to the complete endpoint-origin set.
    #[must_use]
    pub fn initial_chaff_selection_effective_length_for_origins(
        &self,
        origins: &[String],
    ) -> Option<u64> {
        self.initial_chaff_selection_matching(Some(origins))
            .map(Resource::effective_length)
    }

    /// Whether build-time manifest structure contains a possible response of
    /// at least `minimum_length` before any dependency completes.
    ///
    /// Origin filtering and priority-only selection require the complete run
    /// endpoint set and are validated synchronously by the runner.
    #[must_use]
    pub fn has_structural_initial_chaff_candidate(&self, minimum_length: u64) -> bool {
        self.resources.iter().any(|resource| {
            resource.known_valid
                && resource.depends_on.is_empty()
                && resource.effective_length() >= minimum_length
        })
    }

    /// Load either the current resource shape or the published QCSD graph shape.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, parsed, or validated.
    pub fn from_json_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let input = fs::read_to_string(path)?;
        Self::from_json(&input)
    }

    /// Parse either supported JSON shape.
    ///
    /// # Errors
    ///
    /// Returns an error when the JSON schema or manifest contents are invalid.
    pub fn from_json(input: &str) -> Result<Self> {
        let manifest = match serde_json::from_str(input)? {
            ManifestInput::Versioned(manifest) => manifest,
            ManifestInput::Legacy(graph) => Self::from_legacy(graph)?,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    fn from_legacy(graph: LegacyGraph) -> Result<Self> {
        let mut resources: Vec<_> = graph
            .nodes
            .into_iter()
            .map(|resource| Resource {
                id: resource.id,
                url: resource.url,
                kind: resource.resource_type,
                content_length: resource.content_length,
                data_length: resource.data_length,
                chaff_priority: resource.chaff_priority,
                known_valid: resource.known_valid,
                depends_on: Vec::new(),
                headers: Vec::new(),
            })
            .collect();
        resources.sort_by_key(|resource| resource.id);
        for link in graph.links {
            let target = resources
                .iter_mut()
                .find(|resource| resource.id == link.target)
                .ok_or_else(|| {
                    Error::InvalidConfig(format!(
                        "legacy dependency target {} does not exist",
                        link.target
                    ))
                })?;
            target.depends_on.push(link.source);
        }
        Ok(Self { resources })
    }

    /// Validate identifiers, dependencies, and URL schemes.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid URLs, headers, or dependencies.
    pub fn validate(&self) -> Result<()> {
        let ids: HashSet<_> = self.resources.iter().map(|resource| resource.id).collect();
        if ids.len() != self.resources.len() {
            return Err(Error::InvalidConfig(
                "resource manifest identifiers must be unique".into(),
            ));
        }
        for resource in &self.resources {
            if resource.origin().is_none() {
                return Err(Error::InvalidConfig(format!(
                    "resource {} is not an absolute HTTPS URL",
                    resource.id
                )));
            }
            if resource
                .depends_on
                .iter()
                .any(|dependency| !ids.contains(dependency))
            {
                return Err(Error::InvalidConfig(format!(
                    "resource {} references an unknown dependency",
                    resource.id
                )));
            }
            if resource.depends_on.contains(&resource.id) {
                return Err(Error::InvalidConfig(format!(
                    "resource {} depends on itself",
                    resource.id
                )));
            }
            validate_headers(&resource.headers)?;
        }
        self.validate_acyclic()?;
        Ok(())
    }

    fn validate_acyclic(&self) -> Result<()> {
        let mut visiting = HashSet::new();
        let mut visited = HashSet::new();
        for resource in &self.resources {
            self.visit_dependency(resource.id, &mut visiting, &mut visited)?;
        }
        Ok(())
    }

    fn visit_dependency(
        &self,
        resource_id: u32,
        visiting: &mut HashSet<u32>,
        visited: &mut HashSet<u32>,
    ) -> Result<()> {
        if visited.contains(&resource_id) {
            return Ok(());
        }
        if !visiting.insert(resource_id) {
            return Err(Error::InvalidConfig(format!(
                "resource dependency graph contains a cycle at {resource_id}"
            )));
        }
        let resource = self
            .resources
            .iter()
            .find(|candidate| candidate.id == resource_id)
            .ok_or_else(|| {
                Error::InvalidConfig(format!(
                    "resource dependency graph references unknown resource {resource_id}"
                ))
            })?;
        for dependency in &resource.depends_on {
            self.visit_dependency(*dependency, visiting, visited)?;
        }
        visiting.remove(&resource_id);
        visited.insert(resource_id);
        Ok(())
    }

    /// Resolve safe application request headers for one resource.
    ///
    /// Pseudo-headers are never accepted from a manifest; the HTTP/3 adapter
    /// regenerates them from the request URL and method.
    ///
    /// # Errors
    ///
    /// Returns an error when the resource is not part of this manifest or any
    /// stored header is unsafe to replay.
    pub fn application_headers(&self, resource_id: u32) -> Result<Vec<(String, String)>> {
        self.validate()?;
        let resource = self
            .resources
            .iter()
            .find(|resource| resource.id == resource_id)
            .ok_or_else(|| Error::InvalidConfig(format!("unknown resource {resource_id}")))?;
        Ok(resource
            .headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .collect())
    }

    /// Serialize the resolved current form.
    ///
    /// # Errors
    ///
    /// Returns an error if Serde cannot serialize the manifest.
    pub fn to_json_pretty(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ChaffManifest, ChaffQualification, ExpectedChaffResponse, QualifiedChaffResource,
        ResourceManifest, sanitize_chaff_headers,
    };

    const LEGACY: &str = r#"{
        "nodes": [
            {"id":0,"url":"https://example.com/","type":"Document","done":true,"content_length":5000,"data_length":5000},
            {"id":1,"url":"https://example.com/a.js","type":"Script","done":true,"content_length":3000,"data_length":3000},
            {"id":2,"url":"https://example.com/a.png","type":"Image","done":true,"content_length":9000,"data_length":9000,"chaff_priority":true}
        ],
        "links": [{"source":0,"target":1}]
    }"#;

    fn qualified_manifest() -> ChaffManifest {
        ChaffManifest {
            schema_version: 2,
            artifact_type: "qcsd-qualified-chaff-manifest".into(),
            application_workload_sha256: "a".repeat(64),
            application_resource_id: 0,
            selected_chaff_resource_id: 6,
            qualified_parallel_chaff_streams: 20,
            walkie_talkie_required_chaff_streams: 20,
            resources: vec![QualifiedChaffResource {
                id: 6,
                url: "https://example.com/font.woff2".into(),
                kind: "Font".into(),
                content_length: Some(2_048),
                data_length: 2_048,
                chaff_priority: true,
                known_valid: true,
                depends_on: Vec::new(),
                headers: vec![
                    ("accept".into(), "text/html".into()),
                    ("accept-encoding".into(), "gzip, br".into()),
                    ("accept-language".into(), "en-AU".into()),
                ],
                chaff_qualification: ChaffQualification {
                    schema_version: 2,
                    method: "GET".into(),
                    request_stream_bytes: 42,
                    qualified_parallel_chaff_streams: 20,
                    walkie_talkie_required_chaff_streams: 20,
                    expected_response: ExpectedChaffResponse {
                        status: 200,
                        content_encoding: "br".into(),
                        body_bytes: 2_048,
                        body_sha256: "b".repeat(64),
                    },
                    response_qualification_sha256: "c".repeat(64),
                    prefix_pack_qualification_sha256: "d".repeat(64),
                    prefix_spec_sha256: "e".repeat(64),
                },
            }],
        }
    }

    #[test]
    fn imports_legacy_dependency_graph() {
        let manifest = ResourceManifest::from_json(LEGACY).expect("valid legacy graph");
        assert_eq!(manifest.resources[1].depends_on, [0]);
        assert!(manifest.resources[2].chaff_priority);
        ResourceManifest::from_json(&manifest.to_json_pretty().expect("serialize"))
            .expect("current-form round trip");
    }

    #[test]
    fn qualified_chaff_is_a_strict_distinct_selected_resource_schema() {
        let manifest = qualified_manifest();
        manifest.validate().expect("qualified manifest");
        let json = serde_json::to_string(&manifest).expect("serialize");
        assert_eq!(
            ChaffManifest::from_json(&json).expect("round trip"),
            manifest
        );
        assert!(ResourceManifest::from_json(&json).is_err());

        let mut historical = manifest.clone();
        historical.schema_version = 1;
        historical.selected_chaff_resource_id = 0;
        historical.qualified_parallel_chaff_streams = 0;
        historical.walkie_talkie_required_chaff_streams = 0;
        historical.resources[0].id = 0;
        historical.resources[0].chaff_qualification.schema_version = 1;
        historical.resources[0]
            .chaff_qualification
            .qualified_parallel_chaff_streams = 0;
        historical.resources[0]
            .chaff_qualification
            .walkie_talkie_required_chaff_streams = 0;
        let mut historical_value = serde_json::to_value(&historical).expect("historical value");
        let historical_object = historical_value.as_object_mut().expect("object");
        historical_object.remove("selected_chaff_resource_id");
        historical_object.remove("qualified_parallel_chaff_streams");
        historical_object.remove("walkie_talkie_required_chaff_streams");
        let historical_qualification = historical_object["resources"][0]["chaff_qualification"]
            .as_object_mut()
            .expect("qualification object");
        historical_qualification.remove("qualified_parallel_chaff_streams");
        historical_qualification.remove("walkie_talkie_required_chaff_streams");
        let historical_json =
            serde_json::to_string(&historical_value).expect("serialize historical");
        assert!(ChaffManifest::from_json(&historical_json).is_err());
        ChaffManifest::from_historical_schema_one_json(&historical_json)
            .expect("explicit historical parser accepts schema one");

        let mut extra = serde_json::to_value(&manifest).expect("value");
        extra["unexpected"] = serde_json::json!(true);
        assert!(ChaffManifest::from_json(&extra.to_string()).is_err());

        let mut missing_selected = serde_json::to_value(&manifest).expect("value");
        missing_selected
            .as_object_mut()
            .expect("object")
            .remove("selected_chaff_resource_id");
        assert!(ChaffManifest::from_json(&missing_selected.to_string()).is_err());
    }

    #[test]
    fn qualified_chaff_rejects_unqualified_or_mutated_request_and_response_identity() {
        let mut manifest = qualified_manifest();
        manifest.resources[0]
            .chaff_qualification
            .request_stream_bytes = 0;
        assert!(manifest.validate().is_err());

        let mut manifest = qualified_manifest();
        manifest.resources[0]
            .chaff_qualification
            .expected_response
            .status = 404;
        assert!(manifest.validate().is_err());

        let mut manifest = qualified_manifest();
        manifest.resources[0]
            .chaff_qualification
            .expected_response
            .content_encoding = "gzip, br".into();
        assert!(manifest.validate().is_err());

        let mut manifest = qualified_manifest();
        manifest.resources[0]
            .chaff_qualification
            .expected_response
            .body_sha256 = "A".repeat(64);
        assert!(manifest.validate().is_err());

        let mut manifest = qualified_manifest();
        manifest.resources[0].data_length = 2_047;
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn qualified_chaff_separates_cross_mode_response_concurrency_from_walkie_talkie_count() {
        let mut manifest = qualified_manifest();
        manifest.qualified_parallel_chaff_streams = 5;
        manifest.walkie_talkie_required_chaff_streams = 3;
        manifest.resources[0]
            .chaff_qualification
            .qualified_parallel_chaff_streams = 5;
        manifest.resources[0]
            .chaff_qualification
            .walkie_talkie_required_chaff_streams = 3;
        manifest.validate().expect("cross-mode five, WT three");

        manifest.qualified_parallel_chaff_streams = 3;
        assert!(manifest.validate().is_err());
        manifest.qualified_parallel_chaff_streams = 5;
        manifest.resources[0]
            .chaff_qualification
            .walkie_talkie_required_chaff_streams = 4;
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn qualified_chaff_requires_exact_lowercase_ael_without_changing_application_headers() {
        for headers in [
            vec![
                ("Accept".into(), "text/html".into()),
                ("accept-encoding".into(), "gzip, br".into()),
                ("accept-language".into(), "en-AU".into()),
            ],
            vec![
                ("accept-encoding".into(), "gzip, br".into()),
                ("accept".into(), "text/html".into()),
                ("accept-language".into(), "en-AU".into()),
            ],
            vec![
                ("accept".into(), "text/html".into()),
                ("accept-encoding".into(), "gzip, br".into()),
                ("accept-language".into(), "en-AU".into()),
                ("user-agent".into(), "full application header".into()),
            ],
        ] {
            let mut manifest = qualified_manifest();
            manifest.resources[0].headers = headers;
            assert!(manifest.validate().is_err());
        }

        let application = r#"{
            "resources":[{
                "id":0,
                "url":"https://example.com/",
                "headers":[
                    ["accept","text/html"],
                    ["accept-encoding","gzip, br"],
                    ["accept-language","en-AU"],
                    ["user-agent","full application header"]
                ]
            }]
        }"#;
        let parsed = ResourceManifest::from_json(application).expect("application manifest");
        assert_eq!(parsed.resources[0].headers.len(), 4);
        assert_eq!(parsed.resources[0].headers[3].0, "user-agent");
    }

    #[test]
    fn rejects_dependency_cycles() {
        let input = r#"{
            "resources":[
                {"id":0,"url":"https://example.com/a","depends_on":[1]},
                {"id":1,"url":"https://example.com/b","depends_on":[0]}
            ]
        }"#;
        let error = ResourceManifest::from_json(input).expect_err("cycle must fail");
        assert!(error.to_string().contains("cycle"));
    }

    #[test]
    fn rejects_obsolete_version_markers() {
        let input = r#"{
            "schema_version":2,
            "resources":[{"id":0,"url":"https://example.com/"}]
        }"#;
        assert!(ResourceManifest::from_json(input).is_err());
    }

    #[test]
    fn returns_exact_application_headers_with_normalized_names() {
        let mut manifest = ResourceManifest::from_json(LEGACY).expect("valid graph");
        manifest.resources[0].headers = vec![
            ("Accept".into(), "text/html".into()),
            ("Accept-Language".into(), "en-AU".into()),
            ("TE".into(), "trailers".into()),
        ];
        assert_eq!(
            manifest.application_headers(0).expect("resolve"),
            [
                ("accept".into(), "text/html".into()),
                ("accept-language".into(), "en-AU".into()),
                ("te".into(), "trailers".into())
            ]
        );
    }

    #[test]
    fn rejects_unsafe_headers_instead_of_filtering_them() {
        for (name, value) in [
            ("Cookie", "value"),
            ("Authorization", "value"),
            ("Connection", "close"),
            ("Host", "example.com"),
            ("TE", "gzip"),
            (":authority", "example.com"),
            ("If-None-Match", "old"),
            ("Range", "bytes=0-9"),
        ] {
            let input = format!(
                r#"{{"resources":[{{"id":0,"url":"https://example.com/","headers":[["{name}","{value}"]]}}]}}"#
            );
            assert!(
                ResourceManifest::from_json(&input).is_err(),
                "accepted {name}"
            );
        }
    }

    #[test]
    fn rejects_removed_manifest_header_policy() {
        let input = r#"{
            "header_policy":{"mode":"minimal"},
            "resources":[{"id":0,"url":"https://example.com/"}]
        }"#;
        assert!(ResourceManifest::from_json(input).is_err());
    }

    #[test]
    fn chaff_sanitizer_preserves_frozen_headers_and_strips_every_unsafe_class() {
        let input = vec![
            ("Accept".into(), "text/html".into()),
            ("Accept-Encoding".into(), "gzip, deflate, br, zstd".into()),
            ("Accept-Language".into(), "en-AU,en;q=0.9".into()),
            ("Cookie".into(), "secret=1".into()),
            ("Cookie2".into(), "secret=2".into()),
            ("Authorization".into(), "Bearer secret".into()),
            ("Proxy-Authorization".into(), "Basic secret".into()),
            ("If-Match".into(), "etag".into()),
            ("If-Modified-Since".into(), "yesterday".into()),
            ("If-None-Match".into(), "etag".into()),
            ("If-Range".into(), "etag".into()),
            ("If-Unmodified-Since".into(), "today".into()),
            ("Range".into(), "bytes=0-99".into()),
            ("Connection".into(), "keep-alive".into()),
            ("Host".into(), "attacker.example".into()),
            ("Keep-Alive".into(), "timeout=5".into()),
            ("Proxy-Connection".into(), "keep-alive".into()),
            ("Transfer-Encoding".into(), "chunked".into()),
            ("Upgrade".into(), "websocket".into()),
            ("TE".into(), "deflate".into()),
            ("te".into(), "trailers".into()),
            (":authority".into(), "attacker.example".into()),
            (String::new(), "empty-name".into()),
            ("bad name".into(), "unsafe".into()),
            ("x-bad-cr".into(), "unsafe\rvalue".into()),
            ("x-bad-lf".into(), "unsafe\nvalue".into()),
            ("x-bad-nul".into(), "unsafe\0value".into()),
        ];
        let expected = vec![
            ("accept".into(), "text/html".into()),
            ("accept-encoding".into(), "gzip, deflate, br, zstd".into()),
            ("accept-language".into(), "en-AU,en;q=0.9".into()),
            ("te".into(), "trailers".into()),
        ];

        let sanitized = sanitize_chaff_headers(input);
        assert_eq!(sanitized, expected);
        assert_eq!(sanitize_chaff_headers(sanitized.clone()), sanitized);
        assert_eq!(
            sanitize_chaff_headers(vec![("Accept".into(), "text/html".into())]),
            vec![("accept".into(), "text/html".into())],
            "the sanitizer must not invent an Accept-Encoding policy"
        );
    }
}
