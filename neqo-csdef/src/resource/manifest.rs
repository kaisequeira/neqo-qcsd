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
    use super::{ResourceManifest, sanitize_chaff_headers};

    const LEGACY: &str = r#"{
        "nodes": [
            {"id":0,"url":"https://example.com/","type":"Document","done":true,"content_length":5000,"data_length":5000},
            {"id":1,"url":"https://example.com/a.js","type":"Script","done":true,"content_length":3000,"data_length":3000},
            {"id":2,"url":"https://example.com/a.png","type":"Image","done":true,"content_length":9000,"data_length":9000,"chaff_priority":true}
        ],
        "links": [{"source":0,"target":1}]
    }"#;

    #[test]
    fn imports_legacy_dependency_graph() {
        let manifest = ResourceManifest::from_json(LEGACY).expect("valid legacy graph");
        assert_eq!(manifest.resources[1].depends_on, [0]);
        assert!(manifest.resources[2].chaff_priority);
        ResourceManifest::from_json(&manifest.to_json_pretty().expect("serialize"))
            .expect("current-form round trip");
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
