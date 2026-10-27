// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.

//! Explicit CS-BuFLO padding-only source; never an application workload.
use std::collections::{BTreeMap, BTreeSet};
use serde::{Deserialize, Serialize};
use crate::{Error, Result};
use super::manifest::{ExpectedChaffResponse, Resource, ResourceManifest, normalize_content_encoding};

/// The isolated padding identifier domain cannot overlap formal IDs zero to19.
pub const CS_POOL_ID_MIN: u32 = 2_147_483_648;
/// At most64 declared padding candidates are accepted.
pub const CS_POOL_ID_MAX: u32 = CS_POOL_ID_MIN + 63;
/// Exact mode policy. Existing chaff schemas do not imply this policy.
pub const CS_SUPPLEMENTAL_POLICY: &str = "cs-separate-same-host-qualified-chaff-v1";

fn sha(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn invalid(message: &str) -> Error { Error::InvalidConfig(message.into()) }

/// A genuinely completed candidate response, authenticated by the SDK producer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CsPoolPreparedResponse {
    /// Padding-only ID in the declared candidate source.
    pub resource_id: u32,
    /// Actual successful HTTP status.
    pub status: u16,
    /// Actual complete response bytes.
    pub bytes: u64,
    /// Actual whole response-body SHA256.
    pub body_sha256: String,
    /// Partial responses cannot seed a qualified candidate.
    pub complete: bool,
}

/// Immutable prepared padding source, separate from the formal20 manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CsSupplementalPoolSource {
    /// Current prepared pool schema, exactly one.
    pub schema_version: u32,
    /// Distinct artifact discriminator.
    pub artifact_type: String,
    /// Explicit CS-only policy.
    pub policy: String,
    /// Original byte-identical formal resources.json SHA256.
    pub application_manifest_sha256: String,
    /// Actual current formal prepared-workload.json SHA256.
    pub application_workload_sha256: String,
    /// Separate candidate declaration SHA256.
    pub candidate_manifest_sha256: String,
    /// Whole actual discovery provenance SHA256.
    pub discovery_provenance_sha256: String,
    /// Whole actual candidate-probe original run/evidence inventory SHA256.
    pub probe_evidence_sha256: String,
    /// Genuine Native commit that executed the candidate probes.
    pub probe_native_commit: String,
    /// Declared resources in consecutive high-ID order; failures remain declared.
    pub resources: Vec<Resource>,
    /// Only genuinely complete successful responses appear here.
    pub expected_responses: Vec<CsPoolPreparedResponse>,
}

impl CsSupplementalPoolSource {
    /// Strict parse; context checks follow in `validate_against`.
    ///
    /// # Errors
    /// Rejects malformed JSON or any invalid prepared-source field.
    pub fn from_json(input: &str) -> Result<Self> {
        let source: Self = serde_json::from_str(input)?;
        source.validate()?;
        Ok(source)
    }

    /// Validate the declared source domain and actual response identities.
    ///
    /// # Errors
    /// Rejects invalid IDs, duplicate URLs, invented completion or source hashes.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.artifact_type != "qcsd-cs-supplemental-prepared-chaff-pool-source"
            || self.policy != CS_SUPPLEMENTAL_POLICY
            || !(1..=64).contains(&self.resources.len())
            || ![&self.application_manifest_sha256, &self.application_workload_sha256,
                 &self.candidate_manifest_sha256, &self.discovery_provenance_sha256,
                 &self.probe_evidence_sha256].into_iter().all(|v| sha(v))
            || self.probe_native_commit.len() != 40
            || !self.probe_native_commit.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        { return Err(invalid("invalid separate CS padding source schema or immutable identity")); }
        ResourceManifest { resources: self.resources.clone() }.validate()?;
        if self.resources.iter().map(|r| &r.url).collect::<BTreeSet<_>>().len() != self.resources.len() {
            return Err(invalid("separate CS candidate URLs must be distinct"));
        }
        let mut responses = BTreeMap::new();
        for response in &self.expected_responses {
            if !(CS_POOL_ID_MIN..=CS_POOL_ID_MAX).contains(&response.resource_id)
                || !(200..300).contains(&response.status) || response.bytes == 0
                || !response.complete || !sha(&response.body_sha256)
                || responses.insert(response.resource_id, response).is_some()
            { return Err(invalid("invalid or duplicate completed CS pool response")); }
        }
        for (index, resource) in self.resources.iter().enumerate() {
            if resource.id != CS_POOL_ID_MIN + u32::try_from(index).map_err(|_| invalid("pool index overflows"))?
                || resource.url.contains('#') || !resource.depends_on.is_empty()
                || resource.chaff_priority
            { return Err(invalid("CS pool must retain consecutive padding-only IDs and independent HTTPS URLs")); }
            match responses.remove(&resource.id) {
                Some(response) if resource.known_valid
                    && resource.content_length == Some(response.bytes)
                    && resource.data_length == response.bytes => {},
                None if !resource.known_valid && resource.content_length.is_none()
                    && resource.data_length == 0 => {},
                _ => return Err(invalid("CS prepared response and declared candidate identity differ")),
            }
        }
        if !responses.is_empty() { return Err(invalid("CS prepared response is not in the declared pool")); }
        Ok(())
    }

    /// Check both immutable sources and the original20 application domain.
    ///
    /// # Errors
    /// Rejects a changed formal workload, Native identity or HTTPS origin.
    pub fn validate_against(&self, formal: &ResourceManifest, formal_manifest_sha: &str,
                            formal_prepared_sha: &str, native_commit: &str) -> Result<()> {
        self.validate()?;
        formal.validate()?;
        if self.application_manifest_sha256 != formal_manifest_sha
            || self.application_workload_sha256 != formal_prepared_sha
            || self.probe_native_commit != native_commit
            || formal.resources.len() != 20
            || formal.resources.iter().enumerate().any(|(i, r)| r.id != u32::try_from(i).unwrap_or(u32::MAX)
                || !r.known_valid || !r.depends_on.is_empty() || r.chaff_priority)
        { return Err(invalid("CS pool does not bind the genuine current formal20 and Native")); }
        let origin = formal.resources[0].origin().ok_or_else(|| invalid("formal HTTPS root absent"))?;
        let urls: BTreeSet<_> = formal.resources.iter().map(|r| r.url.as_str()).collect();
        if urls.len() != 20 || self.resources.iter().any(|r|
            r.origin().as_ref() != Some(&origin) || urls.contains(r.url.as_str()))
        { return Err(invalid("CS supplemental pool must use separate URLs on the exact formal HTTPS origin")); }
        Ok(())
    }

    /// Deterministic largest genuinely completed body; never substitute smaller.
    ///
    /// # Errors
    /// Rejects absent1200-byte candidates or a selected body over16MiB.
    pub fn selected(&self) -> Result<(&Resource, &CsPoolPreparedResponse)> {
        self.validate()?;
        let selected = self.expected_responses.iter().filter(|r| r.bytes >= 1_200)
            .min_by(|a, b| b.bytes.cmp(&a.bytes).then(a.resource_id.cmp(&b.resource_id)))
            .ok_or_else(|| invalid("no completed separate CS chaff candidate reaches1200 bytes"))?;
        if selected.bytes > 16_777_216 { return Err(invalid("largest CS candidate exceeds16MiB; smaller substitution refused")); }
        let resource = self.resources.iter().find(|r| r.id == selected.resource_id)
            .ok_or_else(|| invalid("selected CS response lacks its declared resource"))?;
        Ok((resource, selected))
    }
}

/// New typed qualification; no legacy receipt is relabelled as schema eight.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CsSupplementalQualification {
    /// Exactly eight, matching this separate-source manifest.
    pub schema_version: u32,
    /// Exact separate-source response-only scope.
    pub qualification_scope: String,
    /// Exactly GET.
    pub method: String,
    /// Original compact HTTP3 request-stream extent.
    pub request_stream_bytes: u64,
    /// Exactly five parallel requests per invocation.
    pub qualified_parallel_chaff_streams: usize,
    /// Exactly three independent original invocations.
    pub qualification_runs: usize,
    /// All15 requests must complete successfully.
    pub qualified_completion_count: usize,
    /// Original stable body identity from all15 responses.
    pub expected_response: ExpectedChaffResponse,
    /// Digest of all complete typed qualification receipts.
    pub response_qualification_sha256: String,
}

/// One high-ID resource selected only from the separately bound pool.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CsSupplementalQualifiedResource {
    /// Complete selected resource identity; no application replacement occurs.
    pub resource: Resource,
    /// Original response qualifications for this exact compact request.
    pub chaff_qualification: CsSupplementalQualification,
}

/// Explicit CS-only schema-eight qualified chaff manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CsSupplementalChaffManifestV8 {
    /// Exactly eight; old schemas remain distinct.
    pub schema_version: u32,
    /// Exact artifact type.
    pub artifact_type: String,
    /// Explicit CS-only policy.
    pub policy: String,
    /// Exact separate-source response-only scope.
    pub qualification_scope: String,
    /// Original formal resources.json bytes.
    pub application_manifest_sha256: String,
    /// Actual current formal prepared source bytes.
    pub application_workload_sha256: String,
    /// Whole separately prepared pool Source bytes.
    pub chaff_pool_source_sha256: String,
    /// Original candidate declaration bytes.
    pub candidate_manifest_sha256: String,
    /// Original candidate-discovery provenance bytes.
    pub discovery_provenance_sha256: String,
    /// Complete three-run qualification evidence bytes.
    pub qualification_evidence_sha256: String,
    /// Original formal resource zero.
    pub application_resource_id: u32,
    /// Selected high padding-only identifier.
    pub selected_pool_resource_id: u32,
    /// Exactly five streams.
    pub qualified_parallel_chaff_streams: usize,
    /// Exactly one selected padding resource.
    pub resources: Vec<CsSupplementalQualifiedResource>,
}

impl CsSupplementalChaffManifestV8 {
    /// Strict parse with no old-schema fallback.
    ///
    /// # Errors
    /// Rejects malformed JSON or an invalid schema-eight manifest.
    pub fn from_json(input: &str) -> Result<Self> {
        let manifest: Self = serde_json::from_str(input)?;
        manifest.validate()?;
        Ok(manifest)
    }
    /// Validate all structural request/response qualification bounds.
    ///
    /// # Errors
    /// Rejects a wrong source, request or complete15-response identity.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 8 || self.artifact_type != "qcsd-cs-supplemental-same-host-qualified-chaff-manifest"
            || self.policy != CS_SUPPLEMENTAL_POLICY || self.qualification_scope != "response-only-separate-same-host-cs-pool-v1"
            || self.application_resource_id != 0 || self.qualified_parallel_chaff_streams != 5
            || !(CS_POOL_ID_MIN..=CS_POOL_ID_MAX).contains(&self.selected_pool_resource_id)
            || self.resources.len() != 1
            || ![&self.application_manifest_sha256, &self.application_workload_sha256,
                 &self.chaff_pool_source_sha256, &self.candidate_manifest_sha256,
                 &self.discovery_provenance_sha256, &self.qualification_evidence_sha256]
                 .into_iter().all(|v| sha(v))
        { return Err(invalid("invalid schema-eight separate CS chaff manifest identity")); }
        let selected = &self.resources[0]; let r = &selected.resource; let q = &selected.chaff_qualification;
        ResourceManifest { resources: vec![r.clone()] }.validate()?;
        let expected = &q.expected_response;
        if r.id != self.selected_pool_resource_id || !r.known_valid || r.chaff_priority
            || !r.depends_on.is_empty() || r.url.contains('#')
            || q.schema_version != 8 || q.qualification_scope != self.qualification_scope
            || q.method != "GET" || q.request_stream_bytes == 0
            || q.qualified_parallel_chaff_streams != 5 || q.qualification_runs != 3 || q.qualified_completion_count != 15
            || !(200..300).contains(&expected.status) || !(1_200..=16_777_216).contains(&expected.body_bytes)
            || !sha(&expected.body_sha256) || !sha(&q.response_qualification_sha256)
            || normalize_content_encoding(Some(&expected.content_encoding)) != Some(expected.content_encoding.clone())
            || r.content_length != Some(expected.body_bytes) || r.data_length != expected.body_bytes
            || r.headers.iter().map(|h| h.0.as_str()).collect::<Vec<_>>() != ["accept", "accept-encoding", "accept-language"]
        { return Err(invalid("schema-eight CS selected request or15-response identity is invalid")); }
        Ok(())
    }
    /// Controller-only selected chaff view; never an application workload.
    #[must_use]
    pub fn resource_manifest(&self) -> ResourceManifest {
        ResourceManifest { resources: self.resources.iter().map(|r| r.resource.clone()).collect() }
    }
    /// Lookup by the explicit padding-only identifier.
    #[must_use]
    pub fn qualification(&self, id: u32) -> Option<&CsSupplementalQualification> {
        self.resources.iter().find(|r| r.resource.id == id).map(|r| &r.chaff_qualification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORMAL_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PREPARED_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NATIVE: &str = "1111111111111111111111111111111111111111";

    // Synthetic, in-memory metadata only: no HTTP, NSS, runtime, or credit.
    fn resource(id: u32, url: String, bytes: u64) -> Resource {
        Resource {
            id,
            url,
            kind: if id == 0 { "Document" } else { "Other" }.into(),
            content_length: Some(bytes),
            data_length: bytes,
            chaff_priority: false,
            known_valid: true,
            depends_on: Vec::new(),
            headers: vec![
                ("accept".into(), "*/*".into()),
                ("accept-encoding".into(), "identity".into()),
                ("accept-language".into(), "en-US,en;q=0.9".into()),
            ],
        }
    }

    fn formal20() -> ResourceManifest {
        ResourceManifest {
            resources: (0_u32..20)
                .map(|id| resource(id, format!("https://example.test/formal-{id}.woff2"), 512))
                .collect(),
        }
    }

    fn pool() -> CsSupplementalPoolSource {
        CsSupplementalPoolSource {
            schema_version: 1,
            artifact_type: "qcsd-cs-supplemental-prepared-chaff-pool-source".into(),
            policy: CS_SUPPLEMENTAL_POLICY.into(),
            application_manifest_sha256: FORMAL_SHA.into(),
            application_workload_sha256: PREPARED_SHA.into(),
            candidate_manifest_sha256: "c".repeat(64),
            discovery_provenance_sha256: "d".repeat(64),
            probe_evidence_sha256: "e".repeat(64),
            probe_native_commit: NATIVE.into(),
            resources: vec![
                resource(CS_POOL_ID_MIN, "https://example.test/padding-small.woff2".into(), 1_200),
                resource(CS_POOL_ID_MIN + 1, "https://example.test/padding-large.woff2".into(), 4_096),
            ],
            expected_responses: vec![
                CsPoolPreparedResponse { resource_id: CS_POOL_ID_MIN, status: 200, bytes: 1_200, body_sha256: "1".repeat(64), complete: true },
                CsPoolPreparedResponse { resource_id: CS_POOL_ID_MIN + 1, status: 200, bytes: 4_096, body_sha256: "2".repeat(64), complete: true },
            ],
        }
    }

    fn qualified() -> CsSupplementalChaffManifestV8 {
        let source = pool();
        let (selected, response) = source.selected().expect("valid synthetic pool");
        CsSupplementalChaffManifestV8 {
            schema_version: 8,
            artifact_type: "qcsd-cs-supplemental-same-host-qualified-chaff-manifest".into(),
            policy: CS_SUPPLEMENTAL_POLICY.into(),
            qualification_scope: "response-only-separate-same-host-cs-pool-v1".into(),
            application_manifest_sha256: FORMAL_SHA.into(),
            application_workload_sha256: PREPARED_SHA.into(),
            chaff_pool_source_sha256: "f".repeat(64),
            candidate_manifest_sha256: source.candidate_manifest_sha256.clone(),
            discovery_provenance_sha256: source.discovery_provenance_sha256.clone(),
            qualification_evidence_sha256: "0".repeat(64),
            application_resource_id: 0,
            selected_pool_resource_id: selected.id,
            qualified_parallel_chaff_streams: 5,
            resources: vec![CsSupplementalQualifiedResource {
                resource: selected.clone(),
                chaff_qualification: CsSupplementalQualification {
                    schema_version: 8,
                    qualification_scope: "response-only-separate-same-host-cs-pool-v1".into(),
                    method: "GET".into(),
                    request_stream_bytes: 96,
                    qualified_parallel_chaff_streams: 5,
                    qualification_runs: 3,
                    qualified_completion_count: 15,
                    expected_response: ExpectedChaffResponse {
                        status: response.status,
                        content_encoding: "identity".into(),
                        body_bytes: response.bytes,
                        body_sha256: response.body_sha256.clone(),
                    },
                    response_qualification_sha256: "9".repeat(64),
                },
            }],
        }
    }

    fn reject_pool(label: &str, change: impl FnOnce(&mut CsSupplementalPoolSource)) {
        let mut source = pool();
        change(&mut source);
        assert!(source.validate().is_err(), "pool mutation accepted: {label}");
    }

    fn reject_qualified(label: &str, change: impl FnOnce(&mut CsSupplementalChaffManifestV8)) {
        let mut manifest = qualified();
        change(&mut manifest);
        assert!(manifest.validate().is_err(), "qualification mutation accepted: {label}");
    }

    fn set_response_bytes(source: &mut CsSupplementalPoolSource, index: usize, bytes: u64) {
        source.expected_responses[index].bytes = bytes;
        source.resources[index].content_length = Some(bytes);
        source.resources[index].data_length = bytes;
    }

    fn set_qualified_bytes(manifest: &mut CsSupplementalChaffManifestV8, bytes: u64) {
        let selected = &mut manifest.resources[0];
        selected.resource.content_length = Some(bytes);
        selected.resource.data_length = bytes;
        selected.chaff_qualification.expected_response.body_bytes = bytes;
    }

    #[test]
    fn complete_formal20_and_separate_pool_round_trip_without_mutation() {
        let formal = formal20();
        let before = serde_json::to_vec(&formal).expect("serialize formal fixture");
        let source = pool();
        source.validate_against(&formal, FORMAL_SHA, PREPARED_SHA, NATIVE).expect("valid full formal20 context");
        let encoded = serde_json::to_string(&source).expect("serialize source");
        assert_eq!(CsSupplementalPoolSource::from_json(&encoded).expect("strict pool round trip"), source);
        let (selected, response) = source.selected().expect("largest complete candidate");
        assert_eq!((selected.id, response.resource_id, response.bytes), (CS_POOL_ID_MIN + 1, CS_POOL_ID_MIN + 1, 4_096));
        assert_eq!(serde_json::to_vec(&formal).expect("serialize formal again"), before);
        assert_eq!(formal.resources.iter().map(|r| r.id).collect::<Vec<_>>(), (0_u32..20).collect::<Vec<_>>());
    }

    #[test]
    fn pool_context_rejects_changed_immutable_hashes_and_native() {
        let formal = formal20();
        let source = pool();
        assert!(source.validate_against(&formal, &"f".repeat(64), PREPARED_SHA, NATIVE).is_err());
        assert!(source.validate_against(&formal, FORMAL_SHA, &"f".repeat(64), NATIVE).is_err());
        assert!(source.validate_against(&formal, FORMAL_SHA, PREPARED_SHA, &"2".repeat(40)).is_err());
        let mut changed = source;
        changed.application_manifest_sha256 = "f".repeat(64);
        assert!(changed.validate_against(&formal, FORMAL_SHA, PREPARED_SHA, NATIVE).is_err());
    }

    #[test]
    fn pool_context_rejects_changed_formal_count_order_ids_and_state() {
        let source = pool();
        let mut formal = formal20();
        formal.resources.pop();
        assert!(source.validate_against(&formal, FORMAL_SHA, PREPARED_SHA, NATIVE).is_err());
        let mut formal = formal20();
        formal.resources.swap(0, 1);
        assert!(source.validate_against(&formal, FORMAL_SHA, PREPARED_SHA, NATIVE).is_err());
        let mut formal = formal20();
        formal.resources[19].id = 20;
        assert!(source.validate_against(&formal, FORMAL_SHA, PREPARED_SHA, NATIVE).is_err());
        let mut formal = formal20();
        formal.resources[1].known_valid = false;
        assert!(source.validate_against(&formal, FORMAL_SHA, PREPARED_SHA, NATIVE).is_err());
        let mut formal = formal20();
        formal.resources[1].depends_on = vec![0];
        assert!(source.validate_against(&formal, FORMAL_SHA, PREPARED_SHA, NATIVE).is_err());
        let mut formal = formal20();
        formal.resources[1].chaff_priority = true;
        assert!(source.validate_against(&formal, FORMAL_SHA, PREPARED_SHA, NATIVE).is_err());
        let mut formal = formal20();
        formal.resources[1].url = formal.resources[0].url.clone();
        assert!(source.validate_against(&formal, FORMAL_SHA, PREPARED_SHA, NATIVE).is_err());
    }

    #[test]
    fn pool_context_rejects_cross_origin_and_application_url_reuse() {
        let formal = formal20();
        let mut source = pool();
        source.resources[1].url = "https://other.example.test/padding.woff2".into();
        assert!(source.validate_against(&formal, FORMAL_SHA, PREPARED_SHA, NATIVE).is_err());
        let mut source = pool();
        source.resources[0].url = formal.resources[19].url.clone();
        assert!(source.validate_against(&formal, FORMAL_SHA, PREPARED_SHA, NATIVE).is_err());
    }

    #[test]
    fn pool_schema_and_source_digests_are_explicit() {
        reject_pool("old schema", |s| s.schema_version = 0);
        reject_pool("old artifact", |s| s.artifact_type = "prepared-workload".into());
        reject_pool("wrong policy", |s| s.policy = "legacy".into());
        reject_pool("formal SHA", |s| s.application_manifest_sha256 = "A".repeat(64));
        reject_pool("prepared SHA", |s| s.application_workload_sha256 = "b".repeat(63));
        reject_pool("candidate SHA", |s| s.candidate_manifest_sha256 = "g".repeat(64));
        reject_pool("discovery SHA", |s| s.discovery_provenance_sha256.clear());
        reject_pool("probe SHA", |s| s.probe_evidence_sha256 = "e".repeat(65));
        reject_pool("Native extent", |s| s.probe_native_commit = "1".repeat(39));
        reject_pool("Native alphabet", |s| s.probe_native_commit = "x".repeat(40));
    }

    #[test]
    fn pool_rejects_application_ids_gaps_duplicate_ids_and_urls() {
        reject_pool("application ID", |s| s.resources[0].id = 19);
        reject_pool("nonconsecutive high ID", |s| s.resources[1].id = CS_POOL_ID_MIN + 2);
        reject_pool("duplicate ID", |s| s.resources[1].id = CS_POOL_ID_MIN);
        reject_pool("duplicate URL", |s| s.resources[1].url = s.resources[0].url.clone());
        reject_pool("HTTP URL", |s| s.resources[0].url = "http://example.test/padding".into());
        reject_pool("fragment", |s| s.resources[0].url.push_str("#fragment"));
        reject_pool("dependency", |s| s.resources[1].depends_on = vec![CS_POOL_ID_MIN]);
        reject_pool("priority", |s| s.resources[0].chaff_priority = true);
    }

    #[test]
    fn declared_pool_size_is_bounded_including_sixty_four_candidates() {
        reject_pool("empty pool", |s| { s.resources.clear(); s.expected_responses.clear(); });
        let mut source = pool();
        for index in 2_u32..64 {
            let mut failed = resource(CS_POOL_ID_MIN + index, format!("https://example.test/failed-{index}.woff2"), 0);
            failed.known_valid = false;
            failed.content_length = None;
            source.resources.push(failed);
        }
        source.validate().expect("64 declared candidates, including failures");
        assert_eq!(source.selected().expect("valid prepared candidate remains").0.id, CS_POOL_ID_MIN + 1);
        let mut extra = resource(CS_POOL_ID_MAX + 1, "https://example.test/too-many.woff2".into(), 0);
        extra.known_valid = false;
        extra.content_length = None;
        source.resources.push(extra);
        assert!(source.validate().is_err());
    }

    #[test]
    fn completed_response_requires_exact_declared_resource_extent() {
        reject_pool("incomplete", |s| s.expected_responses[0].complete = false);
        reject_pool("non2xx", |s| s.expected_responses[0].status = 404);
        reject_pool("empty body", |s| s.expected_responses[0].bytes = 0);
        reject_pool("body SHA", |s| s.expected_responses[0].body_sha256 = "bad".into());
        reject_pool("response ID outside pool", |s| s.expected_responses[0].resource_id = 0);
        reject_pool("undeclared high response", |s| s.expected_responses[0].resource_id = CS_POOL_ID_MAX);
        reject_pool("duplicate response", |s| s.expected_responses.push(s.expected_responses[0].clone()));
        reject_pool("content length mismatch", |s| s.resources[0].content_length = Some(1_201));
        reject_pool("data length mismatch", |s| s.resources[0].data_length = 1_201);
        reject_pool("successful resource without completion", |s| { s.expected_responses.remove(0); });
        reject_pool("unprepared resource claims completion", |s| s.resources[0].known_valid = false);
    }

    #[test]
    fn completed_http_status_bounds_are_exact_2xx() {
        for status in [200, 299] {
            let mut source = pool();
            source.expected_responses[0].status = status;
            source.validate().expect("all2xx statuses are successful identities");
            let mut manifest = qualified();
            manifest.resources[0].chaff_qualification.expected_response.status = status;
            manifest.validate().expect("all2xx qualified statuses remain valid");
        }
        for status in [199, 300] {
            reject_pool("HTTP status outside2xx", |s| s.expected_responses[0].status = status);
            reject_qualified("qualified HTTP status outside2xx", |m| m.resources[0].chaff_qualification.expected_response.status = status);
        }
    }

    #[test]
    fn failed_declarations_remain_visible_but_cannot_be_selected() {
        let mut source = pool();
        source.expected_responses.clear();
        for r in &mut source.resources {
            r.known_valid = false;
            r.content_length = None;
            r.data_length = 0;
        }
        source.validate().expect("failed probes remain declared, without invented completion");
        assert!(source.selected().is_err());
        source.resources[0].data_length = 1;
        assert!(source.validate().is_err());
    }

    #[test]
    fn largest_selection_uses_lowest_id_for_equal_bodies_independent_of_response_order() {
        let mut source = pool();
        set_response_bytes(&mut source, 0, 4_096);
        source.expected_responses.reverse();
        assert_eq!(source.selected().expect("deterministic tie").0.id, CS_POOL_ID_MIN);
    }

    #[test]
    fn selection_retains_1200_minimum_and_16mib_maximum_without_smaller_fallback() {
        let mut source = pool();
        set_response_bytes(&mut source, 0, 1_199);
        set_response_bytes(&mut source, 1, 1_199);
        source.validate().expect("a prepared1199-byte response is valid metadata");
        assert!(source.selected().is_err());
        set_response_bytes(&mut source, 0, 1_200);
        assert_eq!(source.selected().expect("exact1200 boundary").0.id, CS_POOL_ID_MIN);
        set_response_bytes(&mut source, 1, 16_777_216);
        assert_eq!(source.selected().expect("exact16MiB boundary").1.bytes, 16_777_216);
        set_response_bytes(&mut source, 1, 16_777_217);
        source.validate().expect("oversize completion remains genuine declared metadata");
        assert!(source.selected().is_err(), "largest oversize candidate must not fall back to the1200-byte candidate");
    }

    #[test]
    fn qualified_manifest_round_trip_and_controller_view_keep_padding_separate() {
        let manifest = qualified();
        manifest.validate().expect("valid three-run five-stream qualification metadata");
        let encoded = serde_json::to_string(&manifest).expect("serialize schema8");
        assert_eq!(CsSupplementalChaffManifestV8::from_json(&encoded).expect("strict schema8 round trip"), manifest);
        let view = manifest.resource_manifest();
        assert_eq!(view.resources, vec![manifest.resources[0].resource.clone()]);
        assert!(view.resources.iter().all(|r| r.id >= CS_POOL_ID_MIN));
        assert!(manifest.qualification(0).is_none());
        assert_eq!(manifest.qualification(manifest.selected_pool_resource_id), Some(&manifest.resources[0].chaff_qualification));
        assert!(manifest.qualification(CS_POOL_ID_MAX).is_none());
    }

    #[test]
    fn qualified_schema_scope_ids_and_singleton_are_not_legacy_fallbacks() {
        reject_qualified("schema6", |m| m.schema_version = 6);
        reject_qualified("old artifact", |m| m.artifact_type = "qcsd-response-only-chaff-manifest".into());
        reject_qualified("wrong policy", |m| m.policy = "legacy".into());
        reject_qualified("old scope", |m| m.qualification_scope = "response-only".into());
        reject_qualified("formal root must be0", |m| m.application_resource_id = 1);
        reject_qualified("selected application ID", |m| m.selected_pool_resource_id = 19);
        reject_qualified("selected outside bounded pool", |m| m.selected_pool_resource_id = CS_POOL_ID_MAX + 1);
        reject_qualified("no selected resource", |m| m.resources.clear());
        reject_qualified("two selected resources", |m| m.resources.push(m.resources[0].clone()));
        reject_qualified("resource ID mismatch", |m| m.resources[0].resource.id = CS_POOL_ID_MIN);
    }

    #[test]
    fn qualified_source_and_evidence_digests_are_strict() {
        reject_qualified("formal SHA", |m| m.application_manifest_sha256 = "a".repeat(63));
        reject_qualified("prepared SHA", |m| m.application_workload_sha256 = "B".repeat(64));
        reject_qualified("pool SHA", |m| m.chaff_pool_source_sha256.clear());
        reject_qualified("candidate SHA", |m| m.candidate_manifest_sha256 = "x".repeat(64));
        reject_qualified("discovery SHA", |m| m.discovery_provenance_sha256 = "d".repeat(65));
        reject_qualified("evidence SHA", |m| m.qualification_evidence_sha256 = "not-a-digest".into());
        reject_qualified("response evidence SHA", |m| m.resources[0].chaff_qualification.response_qualification_sha256 = "9".repeat(63));
    }

    #[test]
    fn qualification_requires_exact_three_times_five_and_fifteen_complete_claims() {
        reject_qualified("top-level four streams", |m| m.qualified_parallel_chaff_streams = 4);
        reject_qualified("four requests", |m| m.resources[0].chaff_qualification.qualified_parallel_chaff_streams = 4);
        reject_qualified("six requests", |m| m.resources[0].chaff_qualification.qualified_parallel_chaff_streams = 6);
        reject_qualified("two runs", |m| m.resources[0].chaff_qualification.qualification_runs = 2);
        reject_qualified("four runs", |m| m.resources[0].chaff_qualification.qualification_runs = 4);
        reject_qualified("only fourteen completions", |m| m.resources[0].chaff_qualification.qualified_completion_count = 14);
        reject_qualified("extra completion", |m| m.resources[0].chaff_qualification.qualified_completion_count = 16);
        reject_qualified("old receipt schema", |m| m.resources[0].chaff_qualification.schema_version = 3);
        reject_qualified("different receipt scope", |m| m.resources[0].chaff_qualification.qualification_scope = "response-only".into());
    }

    #[test]
    fn qualified_request_and_response_extents_preserve_original_gates() {
        reject_qualified("HEAD is not GET", |m| m.resources[0].chaff_qualification.method = "HEAD".into());
        reject_qualified("empty request extent", |m| m.resources[0].chaff_qualification.request_stream_bytes = 0);
        reject_qualified("non2xx", |m| m.resources[0].chaff_qualification.expected_response.status = 404);
        reject_qualified("body SHA", |m| m.resources[0].chaff_qualification.expected_response.body_sha256 = "z".repeat(64));
        reject_qualified("unnormalized content coding", |m| m.resources[0].chaff_qualification.expected_response.content_encoding = "IDENTITY".into());
        reject_qualified("content length differs from qualified body", |m| m.resources[0].resource.content_length = Some(4_095));
        reject_qualified("data length differs from qualified body", |m| m.resources[0].resource.data_length = 4_095);
        let mut manifest = qualified();
        set_qualified_bytes(&mut manifest, 1_199);
        assert!(manifest.validate().is_err());
        set_qualified_bytes(&mut manifest, 1_200);
        manifest.validate().expect("exact1200 minimum");
        set_qualified_bytes(&mut manifest, 16_777_216);
        manifest.validate().expect("exact16MiB maximum");
        set_qualified_bytes(&mut manifest, 16_777_217);
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn qualified_resource_rejects_priority_dependencies_fragments_and_changed_ael_shape() {
        reject_qualified("unprepared selected resource", |m| m.resources[0].resource.known_valid = false);
        reject_qualified("priority", |m| m.resources[0].resource.chaff_priority = true);
        reject_qualified("dependency", |m| m.resources[0].resource.depends_on = vec![CS_POOL_ID_MIN]);
        reject_qualified("fragment", |m| m.resources[0].resource.url.push_str("#fragment"));
        reject_qualified("HTTP", |m| m.resources[0].resource.url = "http://example.test/padding".into());
        reject_qualified("missing AEL field", |m| { m.resources[0].resource.headers.pop(); });
        reject_qualified("reordered AEL", |m| m.resources[0].resource.headers.swap(0, 1));
        reject_qualified("duplicate AEL", |m| m.resources[0].resource.headers.push(("accept".into(), "*/*".into())));
        reject_qualified("uppercase AEL field", |m| m.resources[0].resource.headers[0].0 = "Accept".into());
    }

    #[test]
    fn parsers_reject_unknown_fields_and_old_flat_qualified_resource_shape() {
        let mut source = serde_json::to_value(pool()).expect("source JSON");
        source.as_object_mut().expect("source object").insert("unreviewed_source_field".into(), serde_json::json!(true));
        assert!(CsSupplementalPoolSource::from_json(&source.to_string()).is_err());
        let mut manifest = serde_json::to_value(qualified()).expect("manifest JSON");
        manifest.as_object_mut().expect("manifest object").insert("unreviewed_manifest_field".into(), serde_json::json!(true));
        assert!(CsSupplementalChaffManifestV8::from_json(&manifest.to_string()).is_err());
        let mut manifest = serde_json::to_value(qualified()).expect("manifest JSON");
        let mut flat = manifest["resources"][0]["resource"].clone();
        flat.as_object_mut().expect("resource object").insert("chaff_qualification".into(), manifest["resources"][0]["chaff_qualification"].clone());
        manifest["resources"][0] = flat;
        assert!(CsSupplementalChaffManifestV8::from_json(&manifest.to_string()).is_err());
    }

    #[test]
    fn strict_parsers_reject_unknown_nested_resource_response_and_qualification_fields() {
        for path in ["resources", "expected_responses"] {
            let mut source = serde_json::to_value(pool()).expect("source JSON");
            source[path][0].as_object_mut().expect("nested source object").insert("unreviewed".into(), serde_json::json!(true));
            assert!(CsSupplementalPoolSource::from_json(&source.to_string()).is_err(), "unknown nested source field in{path}");
        }
        let mut manifest = serde_json::to_value(qualified()).expect("manifest JSON");
        manifest["resources"][0].as_object_mut().expect("qualified wrapper").insert("unreviewed".into(), serde_json::json!(true));
        assert!(CsSupplementalChaffManifestV8::from_json(&manifest.to_string()).is_err());
        let mut manifest = serde_json::to_value(qualified()).expect("manifest JSON");
        manifest["resources"][0]["resource"].as_object_mut().expect("selected resource").insert("unreviewed".into(), serde_json::json!(true));
        assert!(CsSupplementalChaffManifestV8::from_json(&manifest.to_string()).is_err());
        let mut manifest = serde_json::to_value(qualified()).expect("manifest JSON");
        manifest["resources"][0]["chaff_qualification"].as_object_mut().expect("qualification").insert("unreviewed".into(), serde_json::json!(true));
        assert!(CsSupplementalChaffManifestV8::from_json(&manifest.to_string()).is_err());
        let mut manifest = serde_json::to_value(qualified()).expect("manifest JSON");
        manifest["resources"][0]["chaff_qualification"]["expected_response"].as_object_mut().expect("response identity").insert("unreviewed".into(), serde_json::json!(true));
        assert!(CsSupplementalChaffManifestV8::from_json(&manifest.to_string()).is_err());
    }

    #[test]
    fn cs_policy_never_accepts_ft_manifest_or_prepared_pool() {
        let mut manifest = serde_json::to_value(qualified()).expect("CS fixture");
        manifest["schema_version"] = serde_json::json!(7);
        manifest["artifact_type"] = serde_json::json!("qcsd-ft-supplemental-same-host-qualified-chaff-manifest");
        manifest["policy"] = serde_json::json!("ft-separate-same-host-qualified-chaff-v1");
        manifest["qualification_scope"] = serde_json::json!("response-only-separate-same-host-pool-v1");
        assert!(CsSupplementalChaffManifestV8::from_json(&manifest.to_string()).is_err());
        let mut source = pool();
        source.artifact_type = "qcsd-ft-supplemental-prepared-chaff-pool-source".into();
        source.policy = "ft-separate-same-host-qualified-chaff-v1".into();
        assert!(source.validate().is_err());
    }

    #[test]
    fn cs_schema_eight_rejects_nested_ft_qualification() {
        let mut manifest = qualified();
        manifest.resources[0].chaff_qualification.schema_version = 7;
        assert!(manifest.validate().is_err());
        let mut manifest = qualified();
        manifest.resources[0].chaff_qualification.qualification_scope = "response-only-separate-same-host-pool-v1".into();
        assert!(manifest.validate().is_err());
    }

}
