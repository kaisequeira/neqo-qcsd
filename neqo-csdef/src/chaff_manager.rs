// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::{QcsdChaffRequestId, QcsdEndpointId, Resource, ResourceManifest};

const EMPTY_RESOURCE_LENGTH: u64 = 20;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedChaffRequest {
    pub request_id: QcsdChaffRequestId,
    pub endpoint: QcsdEndpointId,
    pub resource: Resource,
}

#[derive(Clone, Copy, Debug)]
struct PendingRequest {
    resource_id: u32,
    anticipated_length: u64,
}

/// Maintains the published low-watermark invariant for reusable chaff responses.
#[derive(Debug)]
pub struct ChaffManager {
    manifest: ResourceManifest,
    pending: BTreeMap<QcsdChaffRequestId, PendingRequest>,
    completed: HashSet<u32>,
    failed: HashSet<u32>,
    estimates: HashMap<u32, u64>,
    origin_cursors: HashMap<String, usize>,
    next_request_id: u64,
    use_empty_resources: bool,
}

impl ChaffManager {
    pub fn new(manifest: ResourceManifest, use_empty_resources: bool) -> Self {
        let estimates = manifest
            .resources
            .iter()
            .map(|resource| (resource.id, resource.effective_length()))
            .collect();
        Self {
            manifest,
            pending: BTreeMap::new(),
            completed: HashSet::new(),
            failed: HashSet::new(),
            estimates,
            origin_cursors: HashMap::new(),
            next_request_id: 0,
            use_empty_resources,
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn pending_capacity(&self) -> u64 {
        self.pending.values().fold(0, |total, request| {
            total.saturating_add(request.anticipated_length)
        })
    }

    pub fn estimate(&self, resource_id: u32) -> u64 {
        self.estimates.get(&resource_id).copied().unwrap_or(0)
    }

    /// Plan enough instances of the best resource to reach the watermark.
    ///
    /// Unlike the first modern port, a resource is intentionally reusable in
    /// parallel. Pending requests count both toward anticipated capacity and
    /// the concurrent stream limit.
    pub fn replenish(
        &mut self,
        available: u64,
        open_streams: usize,
        max_streams: usize,
        low_watermark: u64,
        endpoints: &[(QcsdEndpointId, String)],
    ) -> Vec<PlannedChaffRequest> {
        let mut anticipated = available.saturating_add(self.pending_capacity());
        let mut remaining_streams =
            max_streams.saturating_sub(open_streams.saturating_add(self.pending_count()));
        let mut planned = Vec::new();

        while anticipated < low_watermark && remaining_streams > 0 {
            let Some((resource, length)) = self.largest_eligible(endpoints) else {
                break;
            };
            let Some(origin) = resource.origin() else {
                break;
            };
            let Some(endpoint) = self.endpoint_for_origin(&origin, endpoints) else {
                break;
            };
            let request_id = QcsdChaffRequestId(self.next_request_id);
            self.next_request_id = self.next_request_id.saturating_add(1);
            self.pending.insert(
                request_id,
                PendingRequest {
                    resource_id: resource.id,
                    anticipated_length: length,
                },
            );
            planned.push(PlannedChaffRequest {
                request_id,
                endpoint,
                resource,
            });
            anticipated = anticipated.saturating_add(length);
            remaining_streams -= 1;
        }
        planned
    }

    fn largest_eligible(&self, endpoints: &[(QcsdEndpointId, String)]) -> Option<(Resource, u64)> {
        let eligible = self
            .manifest
            .resources
            .iter()
            .filter(|resource| resource.known_valid)
            .filter(|resource| !self.failed.contains(&resource.id))
            .filter(|resource| {
                resource
                    .depends_on
                    .iter()
                    .all(|dependency| self.completed.contains(dependency))
            })
            .filter(|resource| {
                resource.origin().is_some_and(|origin| {
                    endpoints
                        .iter()
                        .any(|(_, endpoint_origin)| endpoint_origin == &origin)
                })
            })
            .filter_map(|resource| {
                let observed = self.estimates.get(&resource.id).copied().unwrap_or(0);
                let length = if observed == 0 && self.use_empty_resources {
                    EMPTY_RESOURCE_LENGTH
                } else {
                    observed
                };
                (length > 0).then_some((resource, length))
            });
        let priority_only = eligible
            .clone()
            .any(|(resource, _)| resource.chaff_priority);
        eligible
            .filter(|(resource, _)| !priority_only || resource.chaff_priority)
            .max_by_key(|(resource, length)| (*length, resource.type_rank(), resource.id))
            .map(|(resource, length)| (resource.clone(), length))
    }

    fn endpoint_for_origin(
        &mut self,
        origin: &str,
        endpoints: &[(QcsdEndpointId, String)],
    ) -> Option<QcsdEndpointId> {
        let matching: Vec<_> = endpoints
            .iter()
            .filter(|(_, candidate)| candidate == origin)
            .map(|(endpoint, _)| *endpoint)
            .collect();
        if matching.is_empty() {
            return None;
        }
        let cursor = self.origin_cursors.entry(origin.to_owned()).or_default();
        let endpoint = matching[*cursor % matching.len()];
        *cursor = (*cursor + 1) % matching.len();
        Some(endpoint)
    }

    pub fn request_opened(&mut self, request_id: Option<QcsdChaffRequestId>) {
        if let Some(request_id) = request_id {
            self.pending.remove(&request_id);
        }
    }

    pub fn request_failed(&mut self, resource_id: u32, request_id: Option<QcsdChaffRequestId>) {
        if let Some(request_id) = request_id {
            self.pending.remove(&request_id);
        } else if let Some(request_id) = self.pending.iter().find_map(|(request_id, pending)| {
            (pending.resource_id == resource_id).then_some(*request_id)
        }) {
            self.pending.remove(&request_id);
        }
        self.failed.insert(resource_id);
    }

    pub fn resource_completed(&mut self, resource_id: u32, success: bool, bytes: u64) {
        if success {
            self.failed.remove(&resource_id);
            self.completed.insert(resource_id);
            if bytes > 0 {
                self.estimates.insert(resource_id, bytes);
            }
        } else {
            self.failed.insert(resource_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ChaffManager;
    use crate::{HeaderPolicy, QcsdEndpointId, Resource, ResourceManifest};

    fn resource(id: u32, length: u64, origin: &str) -> Resource {
        Resource {
            id,
            url: format!("{origin}/{id}"),
            kind: "Image".into(),
            content_length: Some(length),
            data_length: length,
            chaff_priority: false,
            known_valid: true,
            depends_on: Vec::new(),
            headers: Vec::new(),
        }
    }

    #[test]
    fn repeats_the_largest_resource_to_reach_the_watermark() {
        let manifest = ResourceManifest {
            header_policy: HeaderPolicy::default(),
            resources: vec![
                resource(1, 250_000, "https://example.com"),
                resource(2, 10_000, "https://example.com"),
            ],
        };
        let mut manager = ChaffManager::new(manifest, false);
        let planned = manager.replenish(
            0,
            0,
            5,
            1_000_000,
            &[(QcsdEndpointId(1), "https://example.com".into())],
        );
        assert_eq!(planned.len(), 4);
        assert!(planned.iter().all(|request| request.resource.id == 1));
        assert_eq!(manager.pending_capacity(), 1_000_000);
    }

    #[test]
    fn pending_requests_count_toward_stream_limit_and_capacity() {
        let manifest = ResourceManifest {
            header_policy: HeaderPolicy::default(),
            resources: vec![resource(1, 400, "https://example.com")],
        };
        let mut manager = ChaffManager::new(manifest, false);
        let endpoints = [(QcsdEndpointId(1), "https://example.com".into())];
        assert_eq!(manager.replenish(0, 0, 2, 1_000, &endpoints).len(), 2);
        assert!(manager.replenish(0, 0, 2, 1_000, &endpoints).is_empty());
    }

    #[test]
    fn failed_resources_are_not_reused() {
        let manifest = ResourceManifest {
            header_policy: HeaderPolicy::default(),
            resources: vec![resource(1, 400, "https://example.com")],
        };
        let mut manager = ChaffManager::new(manifest, false);
        let endpoints = [(QcsdEndpointId(1), "https://example.com".into())];
        let planned = manager.replenish(0, 0, 1, 1_000, &endpoints);
        manager.request_failed(1, Some(planned[0].request_id));
        assert!(manager.replenish(0, 0, 1, 1_000, &endpoints).is_empty());
    }

    #[test]
    fn empty_resource_fallback_is_explicit_and_conservative() {
        let manifest = ResourceManifest {
            header_policy: HeaderPolicy::default(),
            resources: vec![resource(1, 0, "https://example.com")],
        };
        let endpoints = [(QcsdEndpointId(1), "https://example.com".into())];
        assert!(
            ChaffManager::new(manifest.clone(), false)
                .replenish(0, 0, 2, 40, &endpoints)
                .is_empty()
        );
        let planned = ChaffManager::new(manifest, true).replenish(0, 0, 2, 40, &endpoints);
        assert_eq!(planned.len(), 2);
    }

    #[test]
    fn resources_are_routed_only_to_their_exact_origin() {
        let manifest = ResourceManifest {
            header_policy: HeaderPolicy::default(),
            resources: vec![
                resource(1, 400, "https://one.example"),
                resource(2, 800, "https://two.example"),
            ],
        };
        let endpoints = [(QcsdEndpointId(1), "https://one.example".into())];
        let planned = ChaffManager::new(manifest, false).replenish(0, 0, 1, 400, &endpoints);
        assert_eq!(planned[0].resource.id, 1);
        assert_eq!(planned[0].endpoint, QcsdEndpointId(1));
    }

    #[test]
    fn ineligible_priority_resource_does_not_starve_valid_fallback() {
        let mut blocked = resource(1, 900, "https://example.com");
        blocked.chaff_priority = true;
        blocked.known_valid = false;
        let manifest = ResourceManifest {
            header_policy: HeaderPolicy::default(),
            resources: vec![blocked, resource(2, 400, "https://example.com")],
        };
        let endpoints = [(QcsdEndpointId(1), "https://example.com".into())];
        let planned = ChaffManager::new(manifest, false).replenish(0, 0, 1, 400, &endpoints);
        assert_eq!(planned[0].resource.id, 2);
    }

    #[test]
    fn dependency_blocked_priority_resource_does_not_starve_valid_fallback() {
        let mut blocked = resource(1, 900, "https://example.com");
        blocked.chaff_priority = true;
        blocked.depends_on.push(99);
        let manifest = ResourceManifest {
            header_policy: HeaderPolicy::default(),
            resources: vec![blocked, resource(2, 400, "https://example.com")],
        };
        let endpoints = [(QcsdEndpointId(1), "https://example.com".into())];
        let planned = ChaffManager::new(manifest, false).replenish(0, 0, 1, 400, &endpoints);
        assert_eq!(planned[0].resource.id, 2);
    }

    #[test]
    fn failed_priority_resource_does_not_starve_valid_fallback() {
        let mut priority = resource(1, 900, "https://example.com");
        priority.chaff_priority = true;
        let manifest = ResourceManifest {
            header_policy: HeaderPolicy::default(),
            resources: vec![priority, resource(2, 400, "https://example.com")],
        };
        let endpoints = [(QcsdEndpointId(1), "https://example.com".into())];
        let mut manager = ChaffManager::new(manifest, false);
        manager.request_failed(1, None);
        let planned = manager.replenish(0, 0, 1, 400, &endpoints);
        assert_eq!(planned[0].resource.id, 2);
    }
}
