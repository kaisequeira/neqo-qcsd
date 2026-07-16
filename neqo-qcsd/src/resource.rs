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
            resources,
        })
    }

    /// Validate identifiers, dependencies, and URL schemes.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported schemas, invalid URLs, or bad dependencies.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
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
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::ResourceManifest;

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
}
