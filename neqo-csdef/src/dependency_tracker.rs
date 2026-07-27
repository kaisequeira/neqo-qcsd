// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option.

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{Error, Resource, ResourceManifest, Result};

/// Runtime state of one resource in a dependency-driven workload.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceRunState {
    Pending,
    InFlight,
    Succeeded,
    Failed,
    SkippedDependency,
}

impl ResourceRunState {
    /// Whether this state can no longer change during normal execution.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::SkippedDependency
        )
    }
}

/// Validated, deterministic runtime tracker for a resource dependency graph.
#[derive(Clone, Debug)]
pub struct DependencyTracker {
    manifest: ResourceManifest,
    states: BTreeMap<u32, ResourceRunState>,
}

impl DependencyTracker {
    /// Construct a tracker with every resource pending.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid resource or dependency graph.
    pub fn new(manifest: ResourceManifest) -> Result<Self> {
        manifest.validate()?;
        let states = manifest
            .resources
            .iter()
            .map(|resource| (resource.id, ResourceRunState::Pending))
            .collect();
        Ok(Self { manifest, states })
    }

    /// Immutable workload definition.
    #[must_use]
    pub const fn manifest(&self) -> &ResourceManifest {
        &self.manifest
    }

    /// Current state of a manifest resource.
    #[must_use]
    pub fn state(&self, resource_id: u32) -> Option<ResourceRunState> {
        self.states.get(&resource_id).copied()
    }

    /// Pending resources whose dependencies all succeeded, in manifest order.
    #[must_use]
    pub fn ready(&self) -> Vec<&Resource> {
        self.manifest
            .resources
            .iter()
            .filter(|resource| self.state(resource.id) == Some(ResourceRunState::Pending))
            .filter(|resource| {
                resource
                    .depends_on
                    .iter()
                    .all(|dependency| self.state(*dependency) == Some(ResourceRunState::Succeeded))
            })
            .collect()
    }

    /// Mark a ready resource as dispatched.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown resource, an invalid prior state, or
    /// incomplete dependencies.
    pub fn mark_in_flight(&mut self, resource_id: u32) -> Result<()> {
        if self.state(resource_id) != Some(ResourceRunState::Pending) {
            return Err(Error::InvalidConfig(format!(
                "resource {resource_id} cannot enter in_flight from {:?}",
                self.state(resource_id)
            )));
        }
        let resource = self.resource(resource_id)?;
        if !resource
            .depends_on
            .iter()
            .all(|dependency| self.state(*dependency) == Some(ResourceRunState::Succeeded))
        {
            return Err(Error::InvalidConfig(format!(
                "resource {resource_id} has incomplete dependencies"
            )));
        }
        self.states.insert(resource_id, ResourceRunState::InFlight);
        Ok(())
    }

    /// Mark an in-flight resource successful.
    ///
    /// # Errors
    ///
    /// Returns an error unless the resource is currently in flight.
    pub fn mark_succeeded(&mut self, resource_id: u32) -> Result<()> {
        self.transition_in_flight(resource_id, ResourceRunState::Succeeded)
    }

    /// Mark a resource failed and recursively skip all pending descendants.
    ///
    /// Returns newly skipped identifiers in deterministic breadth-first order.
    ///
    /// # Errors
    ///
    /// A descendant already skipped by an earlier failure is an idempotent
    /// no-op because another endpoint can retire it after the graph cascade.
    /// Returns an error for an unknown resource or any other terminal state.
    pub fn mark_failed(&mut self, resource_id: u32) -> Result<Vec<u32>> {
        match self.state(resource_id) {
            Some(ResourceRunState::Pending | ResourceRunState::InFlight) => {
                self.states.insert(resource_id, ResourceRunState::Failed);
            }
            Some(ResourceRunState::SkippedDependency) => return Ok(Vec::new()),
            state => {
                return Err(Error::InvalidConfig(format!(
                    "resource {resource_id} cannot fail from {state:?}"
                )));
            }
        }

        let mut skipped = Vec::new();
        let mut queue = VecDeque::from([resource_id]);
        while let Some(failed) = queue.pop_front() {
            let children: Vec<_> = self
                .manifest
                .resources
                .iter()
                .filter(|resource| resource.depends_on.contains(&failed))
                .map(|resource| resource.id)
                .collect();
            for child in children {
                if self.state(child) == Some(ResourceRunState::Pending) {
                    self.states
                        .insert(child, ResourceRunState::SkippedDependency);
                    skipped.push(child);
                    queue.push_back(child);
                }
            }
        }
        Ok(skipped)
    }

    fn transition_in_flight(&mut self, resource_id: u32, next: ResourceRunState) -> Result<()> {
        if self.state(resource_id) != Some(ResourceRunState::InFlight) {
            return Err(Error::InvalidConfig(format!(
                "resource {resource_id} is not in flight"
            )));
        }
        self.states.insert(resource_id, next);
        Ok(())
    }

    fn resource(&self, resource_id: u32) -> Result<&Resource> {
        self.manifest
            .resources
            .iter()
            .find(|resource| resource.id == resource_id)
            .ok_or_else(|| Error::InvalidConfig(format!("unknown resource {resource_id}")))
    }

    /// Whether all resources reached a terminal state.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.states.values().all(|state| state.is_terminal())
    }

    /// Whether every resource succeeded.
    #[must_use]
    pub fn is_successful(&self) -> bool {
        self.states
            .values()
            .all(|state| *state == ResourceRunState::Succeeded)
    }

    /// Stable state snapshot for run output.
    #[must_use]
    pub const fn states(&self) -> &BTreeMap<u32, ResourceRunState> {
        &self.states
    }
}

#[cfg(test)]
mod tests {
    use super::{DependencyTracker, ResourceRunState};
    use crate::{HeaderPolicy, Resource, ResourceManifest};

    fn manifest() -> ResourceManifest {
        ResourceManifest {
            header_policy: HeaderPolicy::default(),
            resources: vec![
                resource(0, vec![]),
                resource(1, vec![0]),
                resource(2, vec![1]),
                resource(3, vec![0]),
            ],
        }
    }

    fn resource(id: u32, depends_on: Vec<u32>) -> Resource {
        Resource {
            id,
            url: format!("https://example.com/{id}"),
            kind: "Document".into(),
            content_length: Some(100),
            data_length: 100,
            chaff_priority: false,
            known_valid: true,
            depends_on,
            headers: Vec::new(),
        }
    }

    #[test]
    fn yields_resources_in_dependency_order() {
        let mut tracker = DependencyTracker::new(manifest()).expect("valid");
        assert_eq!(
            tracker
                .ready()
                .iter()
                .map(|resource| resource.id)
                .collect::<Vec<_>>(),
            vec![0]
        );
        tracker.mark_in_flight(0).expect("ready");
        tracker.mark_succeeded(0).expect("in flight");
        assert_eq!(
            tracker
                .ready()
                .iter()
                .map(|resource| resource.id)
                .collect::<Vec<_>>(),
            vec![1, 3]
        );
    }

    #[test]
    fn failure_skips_all_descendants() {
        let mut tracker = DependencyTracker::new(manifest()).expect("valid");
        tracker.mark_in_flight(0).expect("ready");
        assert_eq!(tracker.mark_failed(0).expect("in flight"), vec![1, 3, 2]);
        assert_eq!(tracker.state(2), Some(ResourceRunState::SkippedDependency));
        assert!(tracker.is_complete());
        assert!(!tracker.is_successful());
        assert_eq!(
            tracker.mark_failed(2).expect("already skipped"),
            Vec::<u32>::new()
        );
    }

    #[test]
    fn rejects_dispatch_before_dependencies_complete() {
        let mut tracker = DependencyTracker::new(manifest()).expect("valid");
        let error = tracker
            .mark_in_flight(1)
            .expect_err("dependency is pending");
        assert!(error.to_string().contains("incomplete dependencies"));
    }
}
