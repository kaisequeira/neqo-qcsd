// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{collections::HashSet, fs, path::Path};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// How recorded application request headers are replayed.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HeaderPolicyMode {
    /// Ignore per-resource discovery headers and send only explicit overrides.
    #[default]
    Minimal,
    /// Replay safe browser discovery headers, excluding conditional and range fields.
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
    /// Additional request headers. Unsafe conditional headers are removed by the adapter.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

fn default_resource_type() -> String {
    "Unknown".into()
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

    fn type_rank(&self) -> u8 {
        match self.kind.as_str() {
            "Image" => 4,
            "Font" | "Stylesheet" | "Script" => 3,
            "Document" => 2,
            _ => 1,
        }
    }
}

/// Versioned resource/dependency input for application and chaff requests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceManifest {
    /// Manifest schema version.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Application-only request header policy. Chaff always uses the stricter QCSD policy.
    #[serde(default)]
    pub header_policy: HeaderPolicy,
    /// Resources in stable identifier order.
    pub resources: Vec<Resource>,
}

const fn default_schema_version() -> u32 {
    1
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
    /// Load either the versioned schema or the published QCSD graph schema.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, parsed, or validated.
    pub fn from_json_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let input = fs::read_to_string(path)?;
        Self::from_json(&input)
    }

    /// Parse either supported JSON schema.
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
        Ok(Self {
            schema_version: 1,
            header_policy: HeaderPolicy::default(),
            resources,
        })
    }

    /// Validate identifiers, dependencies, and URL schemes.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported schemas, invalid URLs, or bad dependencies.
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.schema_version, 1 | 2) {
            return Err(Error::InvalidConfig(format!(
                "unsupported resource manifest schema_version {}",
                self.schema_version
            )));
        }
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
        validate_headers(&self.header_policy.overrides)?;
        if self.header_policy.mode != HeaderPolicyMode::Custom
            && (self.header_policy.allow_conditional || self.header_policy.allow_range)
        {
            return Err(Error::InvalidConfig(
                "conditional/range header switches require custom header policy".into(),
            ));
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
            .expect("dependencies and identifiers validated first");
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
    /// Returns an error when the resource is not part of this manifest or the
    /// stored policy is invalid.
    pub fn application_headers(&self, resource_id: u32) -> Result<Vec<(String, String)>> {
        self.validate()?;
        let resource = self
            .resources
            .iter()
            .find(|resource| resource.id == resource_id)
            .ok_or_else(|| Error::InvalidConfig(format!("unknown resource {resource_id}")))?;
        let mut headers = if self.header_policy.mode == HeaderPolicyMode::Minimal {
            Vec::new()
        } else {
            resource
                .headers
                .iter()
                .filter(|(name, _)| self.header_allowed(name))
                .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
                .collect()
        };
        for (name, value) in &self.header_policy.overrides {
            let normalized = name.to_ascii_lowercase();
            headers.retain(|(candidate, _)| candidate != &normalized);
            headers.push((normalized, value.clone()));
        }
        Ok(headers)
    }

    fn header_allowed(&self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        if is_conditional(&name) {
            return self.header_policy.mode == HeaderPolicyMode::Custom
                && self.header_policy.allow_conditional;
        }
        if name == "range" {
            return self.header_policy.mode == HeaderPolicyMode::Custom
                && self.header_policy.allow_range;
        }
        true
    }

    /// Select large, known-valid resources using the published type preference.
    #[must_use]
    pub fn select_chaff(&self, count: usize, completed: &HashSet<u32>) -> Vec<&Resource> {
        let priority_only = self
            .resources
            .iter()
            .any(|resource| resource.chaff_priority);
        let mut resources: Vec<_> = self
            .resources
            .iter()
            .filter(|resource| !priority_only || resource.chaff_priority)
            .filter(|resource| resource.known_valid)
            .filter(|resource| {
                resource
                    .depends_on
                    .iter()
                    .all(|dependency| completed.contains(dependency))
            })
            .collect();
        resources.sort_by_key(|resource| (resource.effective_length(), resource.type_rank()));
        resources.into_iter().rev().take(count).collect()
    }

    /// Serialize the resolved versioned form.
    ///
    /// # Errors
    ///
    /// Returns an error if Serde cannot serialize the manifest.
    pub fn to_json_pretty(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
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
        if value.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n')) {
            return Err(Error::InvalidConfig(format!(
                "header {name:?} contains an unsafe value"
            )));
        }
    }
    Ok(())
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

fn is_conditional(name: &str) -> bool {
    matches!(
        name,
        "if-match" | "if-modified-since" | "if-none-match" | "if-range" | "if-unmodified-since"
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{HeaderPolicy, HeaderPolicyMode, ResourceManifest};

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
        let selected = manifest.select_chaff(2, &HashSet::new());
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].id, 2);
        ResourceManifest::from_json(&manifest.to_json_pretty().expect("serialize"))
            .expect("versioned round trip");
    }

    #[test]
    fn rejects_dependency_cycles() {
        let input = r#"{
            "schema_version":2,
            "resources":[
                {"id":0,"url":"https://example.com/a","depends_on":[1]},
                {"id":1,"url":"https://example.com/b","depends_on":[0]}
            ]
        }"#;
        let error = ResourceManifest::from_json(input).expect_err("cycle must fail");
        assert!(error.to_string().contains("cycle"));
    }

    #[test]
    fn resolves_application_header_policies() {
        let mut manifest = ResourceManifest::from_json(LEGACY).expect("valid graph");
        manifest.schema_version = 2;
        manifest.resources[0].headers = vec![
            ("Accept".into(), "text/html".into()),
            ("If-None-Match".into(), "old".into()),
            ("Range".into(), "bytes=0-9".into()),
        ];
        manifest.header_policy = HeaderPolicy {
            mode: HeaderPolicyMode::FreshBrowser,
            overrides: vec![("Accept-Language".into(), "en-AU".into())],
            allow_conditional: false,
            allow_range: false,
        };
        assert_eq!(
            manifest.application_headers(0).expect("resolve"),
            [
                ("accept".into(), "text/html".into()),
                ("accept-language".into(), "en-AU".into())
            ]
        );

        manifest.header_policy.mode = HeaderPolicyMode::Custom;
        manifest.header_policy.allow_conditional = true;
        manifest.header_policy.allow_range = true;
        assert_eq!(manifest.application_headers(0).expect("resolve").len(), 4);
    }

    #[test]
    fn rejects_sensitive_and_connection_headers() {
        for name in ["Cookie", "Authorization", "Connection", ":authority"] {
            let input = format!(
                r#"{{"schema_version":2,"resources":[{{"id":0,"url":"https://example.com/","headers":[["{name}","value"]]}}]}}"#
            );
            assert!(
                ResourceManifest::from_json(&input).is_err(),
                "accepted {name}"
            );
        }
    }
}
