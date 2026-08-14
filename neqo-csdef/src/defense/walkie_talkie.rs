// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{collections::HashSet, fs, path::Path, time::Duration};

use serde::{Deserialize, Serialize};

use super::{
    Capacity, CapacityAdjustment, Defense, DefenseDiagnostics, DefenseMode, DefenseSignal,
    EventOutcome, ReceiverContinuationDisposition, SignalKind, WalkieTalkieBurstDiagnostics,
};
use crate::{Direction, Error, MissedSlotReason, Packet, Result, WalkieTalkieConfig};

const SCHEMA_VERSION: u32 = 6;
const ADAPTATION: &str = "qcsd-client-only";
const BURST_DEFINITION: &str = "global-application-batch-direction-transitions";
const CELL_BYTE_DOMAIN: &str = "http3-request-stream-offset.bytes";
const MATCHING_ALGORITHM: &str = "minimum-base-symmetric-mold-padding-cost-one-to-one";
const RECEIVER_APPLICATION_ORDER: &str = "after-symmetric-elementwise-mold";
const RECEIVER_CELLS_PER_NONZERO_INCOMING_COMPONENT: u32 = 1;
const RECEIVER_FORMULA: &str = "symmetric_incoming=adapted_incoming-1-if-adapted_incoming>0-else-0";
const RECEIVER_PARSER_ALLOWANCE_CEILING_BYTES: u64 = 1_000;
const RECEIVER_RAW_HEADROOM_BYTES_PER_NONZERO_INCOMING_COMPONENT: u64 = 1_200;
const SENDER_FRAMING_CELLS_PER_NONZERO_OUTGOING_COMPONENT: u32 = 1;
const SENDER_FRAMING_FORMULA: &str =
    "symmetric_outgoing=adapted_outgoing-1-if-adapted_outgoing>0-else-0";
const SENDER_FRAMING_POLICY: &str = "one-full-cell-per-positive-symmetric-outgoing-component-reserved-for-quic-http3-stream-framing-and-mandatory-control-overhead";
const RECEIVER_ALLOCATION_POLICY: &str =
    "single-peer-acknowledged-pristine-header-phase-controlled-chaff-stream-whole-cell";
const RECEIVER_BASE_ALLOCATION_POLICY: &str = "application-streams-before-peer-acknowledged-nonreserved-controlled-chaff-streams;exact-capacity-before-bounded-framing-claims";
const RECEIVER_CAUSAL_CAPACITY_PRECONDITION: &str = "every-molded-component-outgoing>0;effective-configured-max-chaff-streams>=total-receiver-continuation-reserve-horizon+1;schema-two-stateful-stage-capacity-recurrence-proves-higher-priority-due-application-stream-frames-plus-cumulative-one-shot-chaff-request-stream-frames-through-fin-fit-within-each-exact-full-molded-outgoing-target-through-final-component";
const RECEIVER_REQUEST_ACTIVATION_POLICY: &str = "zero-required-insert-count-nonblocking-qpack-chaff-header-block;positive-final-size-with-contiguous-unique-request-stream-offsets-[0,final-size)-and-fin-peer-acknowledged-under-molded-outgoing-cells";
const RECEIVER_REQUEST_PREFIX_DELIVERY_PRECONDITION: &str = "before-first-incoming-component-first-base-allocation-peer-acknowledged-nonblocking-chaff-request-survivors>=total-receiver-continuation-reserve-horizon+1;initial-survivor-gate-remains-latched-across-complete-schedule";
const RECEIVER_POST_OUTGOING_LOSS_LIVENESS_LIMITATION: &str = "loss-of-required-initial-peer-acknowledged-survivor-after-initial-request-chaff-batch-holds-base-and-continuation-allocation;no-new-chaff-request-replenishment-or-generic-post-loss-liveness-guarantee";
const RECEIVER_RESOURCE_PRECONDITION: &str = "schema-two-qualified-manifest-selects-known-valid-same-origin-source-resource;derived-selected-resource-projection-dependency-free-with-effective-length>=raw-headroom-bytes-per-nonzero-incoming-component;required-chaff-streams-defines-effective-configured-max-chaff-streams";
const RECEIVER_PROVISIONING_POLICY: &str = "fill-effective-configured-max-chaff-streams-once-before-first-due-molded-outgoing-actions;never-replenish-after-initial-request-chaff-batch";
const RECEIVER_RESERVE_POLICY: &str = "reserve-deterministic-acknowledged-pristine-candidates-for-all-remaining-nonzero-incoming-components-before-first-base-allocation-and-retain-distinct-reserves-across-later-positive-outgoing-components";
const RECEIVER_RESERVE_LIFECYCLE_POLICY: &str = "remove-exactly-first-reserve-once-at-corresponding-continuation-controller-allocation-even-when-positive-live-debt-releases-on-nonreserved-stream;refresh-only-from-initial-peer-acknowledged-preprovisioned-cohort-for-defense-pending-continuation-or-tagged-continuation-still-queued-for-allocation;retryable-unadvertised-continuation-allocation-rollback-or-requeue-reconstitutes-corresponding-all-future-horizon-reserve-before-further-base-allocation";
const RECEIVER_RELEASE_POLICY: &str = "after-issued-base-events-controller-requested-and-request-signals-observed;batch-gate-open;release-when-all-base-events-issued-or-real-reported-nonreserved-capacity-is-below-one-cell;recompute-live-unconsumed-base-each-retry;retain-single-coalescible-unadvertised-positive-outstanding-at-or-below-parser-ceiling-until-max-stream-data-advertised;prefer-single-coalesced-advertised-positive-outstanding-at-or-below-parser-ceiling-on-peer-acknowledged-nonreserved-header-blocked-stream;otherwise-release-whole-cell-to-oldest-retained-peer-acknowledged-pristine-reserve-regardless-of-live-base-debt;remove-oldest-reserve-once";
const RECEIVER_BATCH_END_RELEASE_POLICY: &str =
    "at-molded-batch-end-after-application-batch-complete-otherwise-no-batch-gate";
const RECEIVER_PREFIX_CONSUMABILITY_PRECONDITION: &str =
    "prepared-selected-pristine-first-prior-requested-plus-raw-headroom-bytes-are-consumable";
const RECEIVER_QUALIFIED_CHAFF_MANIFEST_POLICY: &str = "schema-two-qualified-navigation-root-and-selected-source-resource;explicit-application-resource-id-selected-chaff-resource-id-and-required-chaff-streams;selected-source-resource-known-valid-same-origin;derived-selected-resource-projection-dependency-free;exact-lowercase-accept-accept-encoding-accept-language-projection;application-request-headers-unchanged";
const RECEIVER_QUALIFIED_CHAFF_RESPONSE_POLICY: &str = "three-independent-staged-qualified-parallel-chaff-streams=max-five-and-walkie-talkie-required-chaff-streams-concurrent-unshaped-production-nonblocking-qpack-qualifications-derive-selected-resource-compact-status-normalized-content-encoding-body-bytes-body-sha256;one-shot-controller-config-uses-exact-walkie-talkie-required-chaff-streams;runtime-complete-responses-must-match-derived-identity;runtime-partial-responses-have-null-identity-match-fields";
const RECEIVER_STAGED_PREFIX_PACK_PRECONDITION: &str = "schema-two-every-component-staged-prefix-pack-after-peer-settings-and-drained-h3-control-qpack-warmup;each-molded-component-is-an-exact-declared-full-packet-target;opens-exact-bound-application-resources-and-cumulative-copies-of-selected-qualified-resource;active-chaff-cohort-is-nondecreasing-and-zero-delta-stages-are-allowed;all-post-cutoff-stream-transmissions-owned-by-one-of-exact-declared-stage-targets;each-stage-gate-requires-cumulative-application-requests-transmitted-contiguously-through-fin-and-required-active-chaff-requests-transmitted-contiguously-through-fin-and-peer-acknowledged-before-dependent-base-allocation;no-pending-request-causal-h3-control-or-qpack-encoder-stream-output;post-warmup-qpack-decoder-stream-output-recorded-and-excluded;zero-targetless-stream-bytes";
const RECEIVER_QUALIFICATION_BINDING_POLICY: &str = "schema-six-raw-sha256-per-workload-binds-schema-two-chaff-qualification-sidecar-prefix-pack-spec-and-qualified-chaff-manifest;runtime-requires-exact-current-artifact-hashes-application-resource-id-selected-chaff-resource-id-and-required-chaff-streams";

// Schema five is a frozen read-only audit oracle. These literals must remain
// independent of the runnable schema-six receiver-liveness contract.
const HISTORICAL_SCHEMA_FIVE_ALLOCATION_POLICY: &str =
    "single-peer-acknowledged-pristine-header-phase-controlled-chaff-stream-whole-cell";
const HISTORICAL_SCHEMA_FIVE_APPLICATION_ORDER: &str = "after-symmetric-elementwise-mold";
const HISTORICAL_SCHEMA_FIVE_BASE_ALLOCATION_POLICY: &str = "application-streams-before-peer-acknowledged-nonreserved-controlled-chaff-streams;exact-capacity-before-bounded-framing-claims";
const HISTORICAL_SCHEMA_FIVE_BATCH_END_RELEASE_POLICY: &str =
    "at-molded-batch-end-after-application-batch-complete-otherwise-no-batch-gate";
const HISTORICAL_SCHEMA_FIVE_CAUSAL_CAPACITY_PRECONDITION: &str = "first-molded-component-outgoing>0;max_chaff_streams>=maximum-receiver-continuation-reserve-horizon+1;required-preprovisioned-chaff-request-stream-frames-through-fin-fit-within-residual-normal-priority-stream-data-budget-after-higher-priority-due-application-stream-frames-at-each-positive-outgoing-horizon-start";
const HISTORICAL_SCHEMA_FIVE_CELLS_PER_NONZERO_INCOMING_COMPONENT: u32 = 1;
const HISTORICAL_SCHEMA_FIVE_FORMULA: &str =
    "adapted_incoming=symmetric_incoming+1-if-symmetric_incoming>0-else-0";
const HISTORICAL_SCHEMA_FIVE_PARSER_ALLOWANCE_CEILING_BYTES: u64 = 1_000;
const HISTORICAL_SCHEMA_FIVE_PREFIX_CONSUMABILITY_PRECONDITION: &str =
    "prepared-selected-pristine-first-prior-requested-plus-raw-headroom-bytes-are-consumable";
const HISTORICAL_SCHEMA_FIVE_REQUEST_PREFIX_DELIVERY_PRECONDITION: &str = "before-each-incoming-component-first-base-allocation-peer-acknowledged-nonblocking-chaff-request-survivors>=current-receiver-continuation-reserve-horizon+1";
const HISTORICAL_SCHEMA_FIVE_POST_OUTGOING_LOSS_LIVENESS_LIMITATION: &str = "insufficient-peer-acknowledged-survivors-after-positive-outgoing-targets-resolve-hold-base-and-continuation-allocation;no-targetless-chaff-stream-retransmission-or-generic-loss-liveness-guarantee";
const HISTORICAL_SCHEMA_FIVE_PROVISIONING_POLICY: &str =
    "fill-configured-chaff-stream-limit-before-due-molded-outgoing-actions";
const HISTORICAL_SCHEMA_FIVE_RAW_HEADROOM_BYTES_PER_NONZERO_INCOMING_COMPONENT: u64 = 1_200;
const HISTORICAL_SCHEMA_FIVE_RESERVE_POLICY: &str = "reserve-deterministic-acknowledged-pristine-candidates-for-current-zero-outgoing-continuation-horizon-before-first-base-allocation-of-each-nonzero-incoming-component";
const HISTORICAL_SCHEMA_FIVE_RESERVE_LIFECYCLE_POLICY: &str = "remove-exactly-first-reserve-once-at-corresponding-continuation-controller-allocation-even-when-positive-live-debt-releases-on-nonreserved-stream;refresh-only-for-defense-pending-continuation-or-tagged-continuation-still-queued-for-allocation;retryable-unadvertised-continuation-allocation-rollback-or-requeue-reconstitutes-corresponding-horizon-reserve-before-further-base-allocation";
const HISTORICAL_SCHEMA_FIVE_RELEASE_POLICY: &str = "after-all-base-events-controller-requested-and-request-signals-observed;reserve-deterministic-peer-acknowledged-pristine-candidates-for-current-zero-outgoing-continuation-horizon-before-first-base-allocation-and-retain-each-until-corresponding-continuation-release-or-session-end;recompute-live-unconsumed-base-each-retry;extend-single-coalesced-positive-outstanding-header-blocked-stream-else-reserved-peer-acknowledged-stream;outstanding-at-or-below-parser-ceiling";
const HISTORICAL_SCHEMA_FIVE_REQUEST_ACTIVATION_POLICY: &str = "zero-required-insert-count-nonblocking-qpack-chaff-header-block;positive-final-size-with-contiguous-unique-request-stream-offsets-[0,final-size)-and-fin-peer-acknowledged-under-molded-outgoing-cells";
const HISTORICAL_SCHEMA_FIVE_RESOURCE_PRECONDITION: &str = "initial-chaff-selection-yields-known-valid-dependency-free-same-origin-resource-with-effective-length>=raw-headroom-bytes-per-nonzero-incoming-component";

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Packet counts in one molded half-duplex burst pair.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BurstPair {
    /// Number of client-to-server shaped packets.
    pub outgoing: u32,
    /// Number of server-to-client receive-credit events.
    pub incoming: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MoldedFile {
    adaptation: String,
    burst_definition: String,
    cell_byte_domain: String,
    schema_version: u32,
    generated_by: String,
    matching_algorithm: String,
    paper_equivalent: bool,
    packet_size: u16,
    receiver_continuation: ReceiverContinuation,
    qualification_bindings: Vec<WalkieTalkieQualificationBinding>,
    profiles: Vec<MoldedProfile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalMoldedFileSchemaFive {
    adaptation: String,
    burst_definition: String,
    cell_byte_domain: String,
    schema_version: u32,
    generated_by: String,
    matching_algorithm: String,
    paper_equivalent: bool,
    packet_size: u16,
    receiver_continuation: HistoricalReceiverContinuationSchemaFive,
    profiles: Vec<MoldedProfile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalReceiverContinuationSchemaFive {
    allocation_policy: String,
    application_order: String,
    base_allocation_policy: String,
    batch_end_release_policy: String,
    causal_capacity_precondition: String,
    cells_per_nonzero_incoming_component: u32,
    formula: String,
    parser_allowance_ceiling_bytes: u64,
    prefix_consumability_precondition: String,
    post_outgoing_loss_liveness_limitation: String,
    provisioning_policy: String,
    raw_headroom_bytes_per_nonzero_incoming_component: u64,
    release_policy: String,
    request_activation_policy: String,
    request_prefix_delivery_precondition: String,
    resource_precondition: String,
    reserve_lifecycle_policy: String,
    reserve_policy: String,
}

/// Read-only summary returned by the explicit historical schema-five parser.
///
/// This type deliberately contains no executable defense state or constructor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HistoricalWalkieTalkieSchemaFiveDiagnostic {
    pub packet_size: u16,
    pub profile_count: usize,
    pub workload_ids: Vec<String>,
}

/// Exact artifact hashes, resource identities, and qualified stream counts for
/// one schema-six workload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalkieTalkieQualificationBinding {
    pub workload_id: String,
    pub chaff_qualification_sidecar_sha256: String,
    pub prefix_pack_spec_sha256: String,
    pub qualified_chaff_manifest_sha256: String,
    pub application_resource_id: u32,
    pub selected_chaff_resource_id: u32,
    pub qualified_parallel_chaff_streams: usize,
    pub walkie_talkie_required_chaff_streams: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverContinuation {
    allocation_policy: String,
    application_order: String,
    base_allocation_policy: String,
    batch_end_release_policy: String,
    causal_capacity_precondition: String,
    cells_per_nonzero_incoming_component: u32,
    formula: String,
    parser_allowance_ceiling_bytes: u64,
    prefix_consumability_precondition: String,
    post_outgoing_loss_liveness_limitation: String,
    provisioning_policy: String,
    raw_headroom_bytes_per_nonzero_incoming_component: u64,
    sender_framing_cells_per_nonzero_outgoing_component: u32,
    sender_framing_formula: String,
    sender_framing_policy: String,
    release_policy: String,
    request_activation_policy: String,
    request_prefix_delivery_precondition: String,
    resource_precondition: String,
    reserve_lifecycle_policy: String,
    reserve_policy: String,
    qualified_chaff_manifest_policy: String,
    qualified_chaff_response_policy: String,
    staged_prefix_pack_precondition: String,
    qualification_binding_policy: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MoldedProfile {
    real: String,
    decoy: String,
    matching_cost_packets: u64,
    training_inputs: PairTrainingInputs,
    variation: PairVariation,
    source_envelopes: SourceEnvelopes,
    batch_ends: PairBatchEnds,
    molded_batch_ends: Vec<usize>,
    total_scheduled_bytes: u64,
    bursts: Vec<BurstPair>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairTrainingInputs {
    real: Vec<String>,
    decoy: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairVariation {
    real: ProfileVariation,
    decoy: ProfileVariation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileVariation {
    visit_count: usize,
    varying_components: usize,
    maximum_component_spread: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceEnvelopes {
    real: Vec<BurstPair>,
    decoy: Vec<BurstPair>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairBatchEnds {
    real: Vec<usize>,
    decoy: Vec<usize>,
}

impl MoldedFile {
    fn select_profile(
        &self,
        configured_packet_size: u16,
        max_stream_data_excess: u64,
        workload_id: &str,
    ) -> Result<&MoldedProfile> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported Walkie-Talkie molded-sequence schema version {}; expected {SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.adaptation != ADAPTATION
            || self.paper_equivalent
            || self.burst_definition != BURST_DEFINITION
            || self.cell_byte_domain != CELL_BYTE_DOMAIN
            || self.matching_algorithm != MATCHING_ALGORITHM
        {
            return Err(Error::InvalidConfig(
                "Walkie-Talkie parameters must declare the QCSD client-only global-batch \
                 application-STREAM-cell adaptation and minimum base-symmetric-mould padding-cost \
                 one-to-one matching"
                    .into(),
            ));
        }
        if self.generated_by.trim().is_empty() || self.profiles.is_empty() {
            return Err(Error::InvalidConfig(
                "Walkie-Talkie bundle provenance and profiles must not be empty".into(),
            ));
        }
        if self.packet_size != configured_packet_size {
            return Err(Error::InvalidConfig(format!(
                "Walkie-Talkie molded packet size {} does not match configured packet size {configured_packet_size}",
                self.packet_size
            )));
        }
        self.receiver_continuation
            .validate(self.packet_size, max_stream_data_excess)?;

        let mut identities = HashSet::new();
        let mut selected = None;
        for (index, profile) in self.profiles.iter().enumerate() {
            profile.validate(self.packet_size, index, MoldContinuationContract::Current)?;
            for identity in [&profile.real, &profile.decoy] {
                if !identities.insert(identity.as_str()) {
                    return Err(Error::InvalidConfig(format!(
                        "Walkie-Talkie workload identity {identity:?} occurs in more than one pair"
                    )));
                }
                if identity == workload_id && selected.replace(profile).is_some() {
                    return Err(Error::InvalidConfig(format!(
                        "Walkie-Talkie workload {workload_id:?} matches more than one profile"
                    )));
                }
            }
        }
        let binding_ids: HashSet<_> = self
            .qualification_bindings
            .iter()
            .map(|binding| binding.workload_id.as_str())
            .collect();
        if binding_ids.len() != self.qualification_bindings.len()
            || binding_ids != identities
            || self.qualification_bindings.iter().any(|binding| {
                binding.workload_id.trim().is_empty()
                    || !is_lower_hex_sha256(&binding.chaff_qualification_sidecar_sha256)
                    || !is_lower_hex_sha256(&binding.prefix_pack_spec_sha256)
                    || !is_lower_hex_sha256(&binding.qualified_chaff_manifest_sha256)
                    || binding.application_resource_id != 0
                    || !(1..=20).contains(&binding.walkie_talkie_required_chaff_streams)
                    || binding.qualified_parallel_chaff_streams
                        != binding.walkie_talkie_required_chaff_streams.max(5)
            })
        {
            return Err(Error::InvalidConfig(
                "Walkie-Talkie schema-six qualification_bindings must uniquely and exactly cover every workload identity with lowercase raw SHA-256 values and valid schema-two resource and stream-count bindings"
                    .into(),
            ));
        }
        let selected = selected.ok_or_else(|| {
            Error::InvalidConfig(format!(
                "Walkie-Talkie bundle contains no profile for workload {workload_id:?}"
            ))
        })?;
        let unit_zero_outgoing_fixture =
            cfg!(test) && self.generated_by == "unit-test-incoming-first-fixture";
        if (selected.bursts.is_empty() || selected.bursts.iter().any(|pair| pair.outgoing == 0))
            && !unit_zero_outgoing_fixture
        {
            return Err(Error::InvalidConfig(
                "every Walkie-Talkie molded component must contain outgoing cells".into(),
            ));
        }
        Ok(selected)
    }
}

impl ReceiverContinuation {
    fn validate(&self, packet_size: u16, max_stream_data_excess: u64) -> Result<()> {
        if self.allocation_policy != RECEIVER_ALLOCATION_POLICY
            || self.application_order != RECEIVER_APPLICATION_ORDER
            || self.base_allocation_policy != RECEIVER_BASE_ALLOCATION_POLICY
            || self.batch_end_release_policy != RECEIVER_BATCH_END_RELEASE_POLICY
            || self.causal_capacity_precondition != RECEIVER_CAUSAL_CAPACITY_PRECONDITION
            || self.cells_per_nonzero_incoming_component
                != RECEIVER_CELLS_PER_NONZERO_INCOMING_COMPONENT
            || self.formula != RECEIVER_FORMULA
            || self.parser_allowance_ceiling_bytes != RECEIVER_PARSER_ALLOWANCE_CEILING_BYTES
            || self.prefix_consumability_precondition != RECEIVER_PREFIX_CONSUMABILITY_PRECONDITION
            || self.post_outgoing_loss_liveness_limitation
                != RECEIVER_POST_OUTGOING_LOSS_LIVENESS_LIMITATION
            || self.provisioning_policy != RECEIVER_PROVISIONING_POLICY
            || self.raw_headroom_bytes_per_nonzero_incoming_component
                != RECEIVER_RAW_HEADROOM_BYTES_PER_NONZERO_INCOMING_COMPONENT
            || self.sender_framing_cells_per_nonzero_outgoing_component
                != SENDER_FRAMING_CELLS_PER_NONZERO_OUTGOING_COMPONENT
            || self.sender_framing_formula != SENDER_FRAMING_FORMULA
            || self.sender_framing_policy != SENDER_FRAMING_POLICY
            || self.release_policy != RECEIVER_RELEASE_POLICY
            || self.request_activation_policy != RECEIVER_REQUEST_ACTIVATION_POLICY
            || self.request_prefix_delivery_precondition
                != RECEIVER_REQUEST_PREFIX_DELIVERY_PRECONDITION
            || self.resource_precondition != RECEIVER_RESOURCE_PRECONDITION
            || self.reserve_lifecycle_policy != RECEIVER_RESERVE_LIFECYCLE_POLICY
            || self.reserve_policy != RECEIVER_RESERVE_POLICY
            || self.qualified_chaff_manifest_policy != RECEIVER_QUALIFIED_CHAFF_MANIFEST_POLICY
            || self.qualified_chaff_response_policy != RECEIVER_QUALIFIED_CHAFF_RESPONSE_POLICY
            || self.staged_prefix_pack_precondition != RECEIVER_STAGED_PREFIX_PACK_PRECONDITION
            || self.qualification_binding_policy != RECEIVER_QUALIFICATION_BINDING_POLICY
        {
            return Err(Error::InvalidConfig(
                "Walkie-Talkie receiver_continuation metadata does not match the supported \
                 sender-framing and receiver-liveness adaptation"
                    .into(),
            ));
        }
        if self.raw_headroom_bytes_per_nonzero_incoming_component
            <= self.parser_allowance_ceiling_bytes
        {
            return Err(Error::InvalidConfig(
                "Walkie-Talkie receiver continuation requires one full packet of raw headroom \
                 strictly larger than its parser allowance ceiling"
                    .into(),
            ));
        }
        if self.raw_headroom_bytes_per_nonzero_incoming_component != u64::from(packet_size) {
            return Err(Error::InvalidConfig(
                "Walkie-Talkie receiver continuation headroom must equal one packet".into(),
            ));
        }
        if max_stream_data_excess > self.parser_allowance_ceiling_bytes {
            return Err(Error::InvalidConfig(format!(
                "Walkie-Talkie max_stream_data_excess {max_stream_data_excess} exceeds the \
                 artifact parser allowance ceiling {}",
                self.parser_allowance_ceiling_bytes
            )));
        }
        Ok(())
    }
}

impl HistoricalReceiverContinuationSchemaFive {
    fn validate(&self, packet_size: u16) -> Result<()> {
        if self.allocation_policy != HISTORICAL_SCHEMA_FIVE_ALLOCATION_POLICY
            || self.application_order != HISTORICAL_SCHEMA_FIVE_APPLICATION_ORDER
            || self.base_allocation_policy != HISTORICAL_SCHEMA_FIVE_BASE_ALLOCATION_POLICY
            || self.batch_end_release_policy != HISTORICAL_SCHEMA_FIVE_BATCH_END_RELEASE_POLICY
            || self.causal_capacity_precondition
                != HISTORICAL_SCHEMA_FIVE_CAUSAL_CAPACITY_PRECONDITION
            || self.cells_per_nonzero_incoming_component
                != HISTORICAL_SCHEMA_FIVE_CELLS_PER_NONZERO_INCOMING_COMPONENT
            || self.formula != HISTORICAL_SCHEMA_FIVE_FORMULA
            || self.parser_allowance_ceiling_bytes
                != HISTORICAL_SCHEMA_FIVE_PARSER_ALLOWANCE_CEILING_BYTES
            || self.prefix_consumability_precondition
                != HISTORICAL_SCHEMA_FIVE_PREFIX_CONSUMABILITY_PRECONDITION
            || self.post_outgoing_loss_liveness_limitation
                != HISTORICAL_SCHEMA_FIVE_POST_OUTGOING_LOSS_LIVENESS_LIMITATION
            || self.provisioning_policy != HISTORICAL_SCHEMA_FIVE_PROVISIONING_POLICY
            || self.raw_headroom_bytes_per_nonzero_incoming_component
                != HISTORICAL_SCHEMA_FIVE_RAW_HEADROOM_BYTES_PER_NONZERO_INCOMING_COMPONENT
            || self.release_policy != HISTORICAL_SCHEMA_FIVE_RELEASE_POLICY
            || self.request_activation_policy != HISTORICAL_SCHEMA_FIVE_REQUEST_ACTIVATION_POLICY
            || self.request_prefix_delivery_precondition
                != HISTORICAL_SCHEMA_FIVE_REQUEST_PREFIX_DELIVERY_PRECONDITION
            || self.resource_precondition != HISTORICAL_SCHEMA_FIVE_RESOURCE_PRECONDITION
            || self.reserve_lifecycle_policy != HISTORICAL_SCHEMA_FIVE_RESERVE_LIFECYCLE_POLICY
            || self.reserve_policy != HISTORICAL_SCHEMA_FIVE_RESERVE_POLICY
            || self.raw_headroom_bytes_per_nonzero_incoming_component != u64::from(packet_size)
        {
            return Err(Error::InvalidConfig(
                "historical Walkie-Talkie schema-five receiver metadata is invalid".into(),
            ));
        }
        Ok(())
    }
}

impl HistoricalMoldedFileSchemaFive {
    fn diagnostic(self) -> Result<HistoricalWalkieTalkieSchemaFiveDiagnostic> {
        if self.schema_version != 5
            || self.adaptation != ADAPTATION
            || self.paper_equivalent
            || self.burst_definition != BURST_DEFINITION
            || self.cell_byte_domain != CELL_BYTE_DOMAIN
            || self.matching_algorithm != MATCHING_ALGORITHM
            || self.generated_by.trim().is_empty()
            || self.profiles.is_empty()
        {
            return Err(Error::InvalidConfig(
                "historical Walkie-Talkie diagnostic accepts only strict schema-five artifacts"
                    .into(),
            ));
        }
        self.receiver_continuation.validate(self.packet_size)?;
        let mut workload_ids = Vec::with_capacity(self.profiles.len().saturating_mul(2));
        let mut identities = HashSet::new();
        for (index, profile) in self.profiles.iter().enumerate() {
            profile.validate(
                self.packet_size,
                index,
                MoldContinuationContract::HistoricalSchemaFive,
            )?;
            for identity in [&profile.real, &profile.decoy] {
                if !identities.insert(identity.as_str()) {
                    return Err(Error::InvalidConfig(format!(
                        "historical Walkie-Talkie workload identity {identity:?} occurs more than once"
                    )));
                }
                workload_ids.push(identity.clone());
            }
        }
        Ok(HistoricalWalkieTalkieSchemaFiveDiagnostic {
            packet_size: self.packet_size,
            profile_count: self.profiles.len(),
            workload_ids,
        })
    }
}

impl MoldedProfile {
    fn validate(
        &self,
        packet_size: u16,
        profile_index: usize,
        continuation_contract: MoldContinuationContract,
    ) -> Result<()> {
        if self.real.trim().is_empty() || self.decoy.trim().is_empty() {
            return Err(Error::InvalidConfig(format!(
                "Walkie-Talkie profile {profile_index} workload identities must not be empty"
            )));
        }
        if self.real == self.decoy {
            return Err(Error::InvalidConfig(format!(
                "Walkie-Talkie profile {profile_index} real and decoy labels must be distinct"
            )));
        }
        validate_training_inputs(
            &self.training_inputs.real,
            self.variation.real.visit_count,
            profile_index,
            "real",
        )?;
        validate_training_inputs(
            &self.training_inputs.decoy,
            self.variation.decoy.visit_count,
            profile_index,
            "decoy",
        )?;
        validate_variation(
            &self.variation.real,
            self.source_envelopes.real.len(),
            profile_index,
            "real",
        )?;
        validate_variation(
            &self.variation.decoy,
            self.source_envelopes.decoy.len(),
            profile_index,
            "decoy",
        )?;
        validate_bursts(
            &self.source_envelopes.real,
            profile_index,
            "real source envelope",
        )?;
        validate_bursts(
            &self.source_envelopes.decoy,
            profile_index,
            "decoy source envelope",
        )?;
        validate_bursts(&self.bursts, profile_index, "molded sequence")?;
        validate_batch_ends(
            &self.batch_ends.real,
            self.source_envelopes.real.len(),
            profile_index,
            "real",
        )?;
        validate_batch_ends(
            &self.batch_ends.decoy,
            self.source_envelopes.decoy.len(),
            profile_index,
            "decoy",
        )?;
        validate_batch_ends(
            &self.molded_batch_ends,
            self.bursts.len(),
            profile_index,
            "molded",
        )?;
        validate_derived_mold(self, packet_size, profile_index, continuation_contract)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MoldContinuationContract {
    HistoricalSchemaFive,
    Current,
}

fn validate_derived_mold(
    profile: &MoldedProfile,
    packet_size: u16,
    profile_index: usize,
    continuation_contract: MoldContinuationContract,
) -> Result<()> {
    let (symmetric_mold, expected_batch_ends) = mold(
        &profile.source_envelopes.real,
        &profile.batch_ends.real,
        &profile.source_envelopes.decoy,
        &profile.batch_ends.decoy,
    );
    let expected_mold = match continuation_contract {
        MoldContinuationContract::HistoricalSchemaFive => {
            adapt_historical_schema_five_receiver_continuation(&symmetric_mold)?
        }
        MoldContinuationContract::Current => adapt_continuations(&symmetric_mold)?,
    };
    if profile.bursts != expected_mold || profile.molded_batch_ends != expected_batch_ends {
        return Err(Error::InvalidConfig(format!(
            "Walkie-Talkie profile {profile_index} bursts and common batch boundaries \
             are not the declared continuation adaptation of the batch-aware element-wise \
             maximum of its source envelopes"
        )));
    }
    let molded_packets = total_packets(&profile.bursts)?;
    let source_packets = total_packets(&profile.source_envelopes.real)?
        .checked_add(total_packets(&profile.source_envelopes.decoy)?)
        .ok_or_else(|| {
            Error::InvalidConfig("Walkie-Talkie source packet count exceeds u64".into())
        })?;
    let expected_cost = molded_packets
        .checked_mul(2)
        .and_then(|value| value.checked_sub(source_packets))
        .ok_or_else(|| Error::InvalidConfig("Walkie-Talkie matching cost exceeds u64".into()))?;
    if profile.matching_cost_packets != expected_cost {
        return Err(Error::InvalidConfig(format!(
            "Walkie-Talkie profile {profile_index} matching_cost_packets is {}; \
             expected {expected_cost}",
            profile.matching_cost_packets
        )));
    }
    let expected_bytes = checked_scheduled_bytes(molded_packets, packet_size)?;
    if profile.total_scheduled_bytes != expected_bytes {
        return Err(Error::InvalidConfig(format!(
            "Walkie-Talkie profile {profile_index} total_scheduled_bytes is {}; \
             expected {expected_bytes}",
            profile.total_scheduled_bytes
        )));
    }
    Ok(())
}

fn checked_scheduled_bytes(molded_packets: u64, packet_size: u16) -> Result<u64> {
    molded_packets
        .checked_mul(u64::from(packet_size))
        .ok_or_else(|| {
            Error::InvalidConfig("Walkie-Talkie total scheduled bytes exceeds u64".into())
        })
}

fn adapt_continuations(symmetric_mold: &[BurstPair]) -> Result<Vec<BurstPair>> {
    symmetric_mold
        .iter()
        .map(|pair| {
            let outgoing = if pair.outgoing == 0 {
                0
            } else {
                pair.outgoing.checked_add(1).ok_or_else(|| {
                    Error::InvalidConfig(
                        "Walkie-Talkie sender framing continuation exceeds the u32 cell domain"
                            .into(),
                    )
                })?
            };
            let incoming = if pair.incoming == 0 {
                0
            } else {
                pair.incoming.checked_add(1).ok_or_else(|| {
                    Error::InvalidConfig(
                        "Walkie-Talkie receiver continuation exceeds the u32 cell domain".into(),
                    )
                })?
            };
            Ok(BurstPair { outgoing, incoming })
        })
        .collect()
}

fn adapt_historical_schema_five_receiver_continuation(
    symmetric_mold: &[BurstPair],
) -> Result<Vec<BurstPair>> {
    symmetric_mold
        .iter()
        .map(|pair| {
            let incoming = if pair.incoming == 0 {
                0
            } else {
                pair.incoming.checked_add(1).ok_or_else(|| {
                    Error::InvalidConfig(
                        "historical Walkie-Talkie schema-five receiver continuation exceeds the u32 cell domain"
                            .into(),
                    )
                })?
            };
            Ok(BurstPair {
                outgoing: pair.outgoing,
                incoming,
            })
        })
        .collect()
}

fn validate_training_inputs(
    inputs: &[String],
    visit_count: usize,
    profile_index: usize,
    side: &str,
) -> Result<()> {
    if inputs.is_empty()
        || inputs.len() != visit_count
        || inputs.iter().any(|value| {
            value.len() != 64
                || value
                    .bytes()
                    .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        })
    {
        return Err(Error::InvalidConfig(format!(
            "Walkie-Talkie profile {profile_index} {side} training inputs must be lowercase \
             SHA-256 hashes matching variation.visit_count"
        )));
    }
    Ok(())
}

fn validate_variation(
    variation: &ProfileVariation,
    envelope_length: usize,
    profile_index: usize,
    side: &str,
) -> Result<()> {
    if variation.visit_count == 0
        || (variation.varying_components == 0) != (variation.maximum_component_spread == 0)
        || variation.varying_components > envelope_length.saturating_mul(2)
    {
        return Err(Error::InvalidConfig(format!(
            "Walkie-Talkie profile {profile_index} {side} variation is inconsistent"
        )));
    }
    Ok(())
}

fn validate_bursts(bursts: &[BurstPair], profile_index: usize, label: &str) -> Result<()> {
    if bursts.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "Walkie-Talkie profile {profile_index} {label} must not be empty"
        )));
    }
    if let Some(index) = bursts
        .iter()
        .position(|pair| pair.outgoing == 0 && pair.incoming == 0)
    {
        return Err(Error::InvalidConfig(format!(
            "Walkie-Talkie profile {profile_index} {label} burst {index} has no packets"
        )));
    }
    Ok(())
}

fn validate_batch_ends(
    batch_ends: &[usize],
    source_length: usize,
    profile_index: usize,
    side: &str,
) -> Result<()> {
    if batch_ends.is_empty()
        || batch_ends.last().copied() != source_length.checked_sub(1)
        || batch_ends
            .iter()
            .zip(batch_ends.iter().skip(1))
            .any(|(left, right)| left >= right)
    {
        return Err(Error::InvalidConfig(format!(
            "Walkie-Talkie profile {profile_index} {side} batch boundaries must be sorted, \
             unique, in range, and terminate the source envelope"
        )));
    }
    Ok(())
}

fn total_packets(bursts: &[BurstPair]) -> Result<u64> {
    bursts.iter().try_fold(0_u64, |total, pair| {
        total
            .checked_add(u64::from(pair.outgoing) + u64::from(pair.incoming))
            .ok_or_else(|| Error::InvalidConfig("Walkie-Talkie packet count exceeds u64".into()))
    })
}

fn mold(
    real: &[BurstPair],
    real_batch_ends: &[usize],
    decoy: &[BurstPair],
    decoy_batch_ends: &[usize],
) -> (Vec<BurstPair>, Vec<usize>) {
    let real_batches = split_batches(real, real_batch_ends);
    let decoy_batches = split_batches(decoy, decoy_batch_ends);
    let mut molded = Vec::new();
    let mut molded_batch_ends = Vec::new();
    for batch_index in 0..real_batches.len().max(decoy_batches.len()) {
        let real_batch = real_batches.get(batch_index).copied().unwrap_or(&[]);
        let decoy_batch = decoy_batches.get(batch_index).copied().unwrap_or(&[]);
        for component_index in 0..real_batch.len().max(decoy_batch.len()) {
            molded.push(BurstPair {
                outgoing: real_batch
                    .get(component_index)
                    .map_or(0, |pair| pair.outgoing)
                    .max(
                        decoy_batch
                            .get(component_index)
                            .map_or(0, |pair| pair.outgoing),
                    ),
                incoming: real_batch
                    .get(component_index)
                    .map_or(0, |pair| pair.incoming)
                    .max(
                        decoy_batch
                            .get(component_index)
                            .map_or(0, |pair| pair.incoming),
                    ),
            });
        }
        molded_batch_ends.push(molded.len() - 1);
    }
    (molded, molded_batch_ends)
}

fn split_batches<'a>(bursts: &'a [BurstPair], batch_ends: &[usize]) -> Vec<&'a [BurstPair]> {
    let mut start = 0;
    batch_ends
        .iter()
        .map(|end| {
            let batch = &bursts[start..=*end];
            start = end + 1;
            batch
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Turn {
    Outgoing {
        index: usize,
        to_emit: u32,
        awaiting: u32,
    },
    Incoming {
        index: usize,
        credits_to_emit: u32,
        receiver_continuation_pending: bool,
        initial_credits_awaiting: u32,
        credited_bytes_outstanding: u64,
        observed_remaining_bytes: u64,
    },
    Done,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ObservedBurst {
    outgoing_cells: u64,
    incoming_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NaturalSegment {
    direction: Direction,
    bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct NaturalBurst {
    outgoing_cells: u64,
    incoming_cells: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RealizationFailure {
    ReceiveCreditRetired,
    IncomingSlotMissed(MissedSlotReason),
}

/// Walkie-Talkie half-duplex burst-molding defense.
#[derive(Debug)]
pub struct WalkieTalkie {
    qualification_binding: WalkieTalkieQualificationBinding,
    molded: Vec<BurstPair>,
    source_envelope: Vec<BurstPair>,
    source_batch_ends: Vec<usize>,
    batch_ends: HashSet<usize>,
    expected_application_batches: u64,
    observed_bursts: Vec<ObservedBurst>,
    turn: Turn,
    packet_size: u16,
    receiver_parser_allowance_ceiling_bytes: u64,
    last_receiver_continuation: Option<ReceiverContinuationDisposition>,
    target_outgoing_cells: u64,
    target_incoming_cells: u64,
    observed_outgoing_cells: u64,
    observed_incoming_bytes: u64,
    outgoing_overflow_bytes: u64,
    incoming_overflow_bytes: u64,
    unattributed_incoming_bytes: u64,
    incoming_chaff_bytes: u64,
    control_only_crossings: u64,
    application_stream_crossing_bytes: u64,
    natural_outgoing_bytes: u64,
    natural_incoming_bytes: u64,
    natural_batch_segments: Vec<NaturalSegment>,
    source_envelope_overflow_cells: u64,
    application_batch_active: bool,
    application_batch_assigned: bool,
    application_batches_started: u64,
    application_batches_completed: u64,
    batch_lifecycle_errors: u64,
    now: Duration,
    application_complete: bool,
    retried_outgoing_events: u64,
    incoming_capacity_reported: Option<u64>,
    incoming_capacity_reserved: u64,
    incoming_capacity_committed: u64,
    realization_failure: Option<RealizationFailure>,
    failed_incoming_shortfall_bytes: u64,
    reserved_chaff_capacity: u64,
}

impl WalkieTalkie {
    /// Load a runnable version-six molded sequence from `config.molded`.
    ///
    /// # Errors
    ///
    /// Returns an error when the configuration, file, or strict JSON envelope
    /// is invalid, including when its packet size differs from the config.
    pub fn new(
        config: &WalkieTalkieConfig,
        max_udp_payload_size: u16,
        max_stream_data_excess: u64,
    ) -> Result<Self> {
        Self::from_file(
            config,
            max_udp_payload_size,
            max_stream_data_excess,
            &config.molded,
        )
    }

    /// Load a runnable version-six molded sequence from `path`.
    ///
    /// # Errors
    ///
    /// Returns an error when the configuration, file, or strict JSON envelope
    /// is invalid, including when its packet size differs from the config.
    pub fn from_file<P: AsRef<Path>>(
        config: &WalkieTalkieConfig,
        max_udp_payload_size: u16,
        max_stream_data_excess: u64,
        path: P,
    ) -> Result<Self> {
        config.validate(max_udp_payload_size)?;
        let input = fs::read_to_string(path)?;
        Self::from_json_with_max_stream_data_excess(
            config,
            max_udp_payload_size,
            max_stream_data_excess,
            &input,
        )
    }

    /// Parse a runnable version-six molded sequence.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema version, unknown fields,
    /// empty/zero burst pairs, a packet-size mismatch, or unsafe limits.
    pub fn from_json(
        config: &WalkieTalkieConfig,
        max_udp_payload_size: u16,
        input: &str,
    ) -> Result<Self> {
        Self::from_json_with_max_stream_data_excess(
            config,
            max_udp_payload_size,
            RECEIVER_PARSER_ALLOWANCE_CEILING_BYTES,
            input,
        )
    }

    /// Parse a runnable version-six molded sequence for an explicit parser allowance.
    ///
    /// # Errors
    ///
    /// Returns the same strict-envelope errors as [`Self::from_json`], and an
    /// error when `max_stream_data_excess` exceeds the artifact's declared
    /// parser allowance ceiling.
    pub fn from_json_with_max_stream_data_excess(
        config: &WalkieTalkieConfig,
        max_udp_payload_size: u16,
        max_stream_data_excess: u64,
        input: &str,
    ) -> Result<Self> {
        config.validate(max_udp_payload_size)?;
        let file: MoldedFile = serde_json::from_str(input)?;
        let receiver_parser_allowance_ceiling_bytes =
            file.receiver_continuation.parser_allowance_ceiling_bytes;
        let selected = file.select_profile(
            config.packet_size,
            max_stream_data_excess,
            &config.workload_id,
        )?;
        let qualification_binding = file
            .qualification_bindings
            .iter()
            .find(|binding| binding.workload_id == config.workload_id)
            .cloned()
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "selected Walkie-Talkie workload has no qualification binding".into(),
                )
            })?;
        let (selected_source_envelope, selected_batch_ends) = if selected.real == config.workload_id
        {
            (&selected.source_envelopes.real, &selected.batch_ends.real)
        } else {
            (&selected.source_envelopes.decoy, &selected.batch_ends.decoy)
        };
        let expected_application_batches =
            u64::try_from(selected_batch_ends.len()).map_err(|_| {
                Error::InvalidConfig(
                    "Walkie-Talkie application batch count exceeds the diagnostic domain".into(),
                )
            })?;
        let molded = selected.bursts.clone();
        let source_envelope = selected_source_envelope.clone();
        let source_batch_ends = selected_batch_ends.clone();
        let batch_ends = selected.molded_batch_ends.iter().copied().collect();

        let first = molded[0];
        let observed_bursts = vec![ObservedBurst::default(); molded.len()];
        let target_outgoing_cells = molded.iter().map(|pair| u64::from(pair.outgoing)).sum();
        let target_incoming_cells = molded.iter().map(|pair| u64::from(pair.incoming)).sum();
        Ok(Self {
            qualification_binding,
            molded,
            source_envelope,
            source_batch_ends,
            batch_ends,
            expected_application_batches,
            observed_bursts,
            turn: Turn::Outgoing {
                index: 0,
                to_emit: first.outgoing,
                awaiting: 0,
            },
            packet_size: config.packet_size,
            receiver_parser_allowance_ceiling_bytes,
            last_receiver_continuation: None,
            target_outgoing_cells,
            target_incoming_cells,
            observed_outgoing_cells: 0,
            observed_incoming_bytes: 0,
            outgoing_overflow_bytes: 0,
            incoming_overflow_bytes: 0,
            unattributed_incoming_bytes: 0,
            incoming_chaff_bytes: 0,
            control_only_crossings: 0,
            application_stream_crossing_bytes: 0,
            natural_outgoing_bytes: 0,
            natural_incoming_bytes: 0,
            natural_batch_segments: Vec::new(),
            source_envelope_overflow_cells: 0,
            application_batch_active: false,
            application_batch_assigned: false,
            application_batches_started: 0,
            application_batches_completed: 0,
            batch_lifecycle_errors: 0,
            now: Duration::ZERO,
            application_complete: false,
            retried_outgoing_events: 0,
            incoming_capacity_reported: None,
            incoming_capacity_reserved: 0,
            incoming_capacity_committed: 0,
            realization_failure: None,
            failed_incoming_shortfall_bytes: 0,
            reserved_chaff_capacity: 0,
        })
    }

    /// Strictly parse a historical schema-five artifact for diagnostics only.
    ///
    /// The returned summary cannot be converted into runnable defense state.
    /// Schema six is rejected here and schema five is rejected by every
    /// runnable constructor.
    ///
    /// # Errors
    ///
    /// Returns an error for any non-schema-five or malformed historical artifact.
    pub fn historical_schema_five_diagnostic(
        input: &str,
    ) -> Result<HistoricalWalkieTalkieSchemaFiveDiagnostic> {
        serde_json::from_str::<HistoricalMoldedFileSchemaFive>(input)?.diagnostic()
    }

    /// Selected schema-six raw qualification hashes.
    #[must_use]
    pub const fn qualification_binding(&self) -> &WalkieTalkieQualificationBinding {
        &self.qualification_binding
    }

    fn record_now(&mut self, at: Duration) {
        debug_assert!(
            at >= self.now,
            "the controller must deliver Walkie-Talkie timestamps monotonically"
        );
        self.now = at;
    }

    fn enter_incoming(&mut self, index: usize) {
        let Some(pair) = self.molded.get(index).copied() else {
            self.turn = Turn::Done;
            return;
        };
        self.turn = Turn::Incoming {
            index,
            credits_to_emit: pair
                .incoming
                .saturating_sub(RECEIVER_CELLS_PER_NONZERO_INCOMING_COMPONENT),
            receiver_continuation_pending: pair.incoming > 0,
            initial_credits_awaiting: 0,
            credited_bytes_outstanding: 0,
            observed_remaining_bytes: u64::from(pair.incoming) * u64::from(self.packet_size),
        };
    }

    fn enter_next_outgoing(&mut self, index: usize) {
        let next_index = index.saturating_add(1);
        let Some(pair) = self.molded.get(next_index).copied() else {
            self.turn = Turn::Done;
            return;
        };
        if self.batch_ends.contains(&index)
            && self.application_batches_started < self.expected_application_batches
        {
            self.application_batch_assigned = false;
        }
        self.turn = Turn::Outgoing {
            index: next_index,
            to_emit: pair.outgoing,
            awaiting: 0,
        };
    }

    const fn awaiting_later_application_batch(&self) -> bool {
        // The runner dispatches the first globally ready batch before its
        // first defense poll.  Later outgoing turns can be entered from
        // inside a poll after observed ingress completes, so they must pause
        // until the runner has actually opened the next ready batch.
        self.application_batches_started > 0
            && self.application_batches_started < self.expected_application_batches
            && !self.application_batch_active
            && !self.application_batch_assigned
    }

    fn batch_gate_open(&self, index: usize) -> bool {
        if !self.batch_ends.contains(&index) {
            return true;
        }
        let molded_batch_ordinal =
            u64::try_from(self.batch_ends.iter().filter(|end| **end <= index).count())
                .unwrap_or(u64::MAX);
        let required_completions = molded_batch_ordinal.min(self.expected_application_batches);
        !self.application_batch_active && self.application_batches_completed >= required_completions
    }

    fn normalize_turn(&mut self) {
        loop {
            match self.turn {
                Turn::Outgoing {
                    index,
                    to_emit: 0,
                    awaiting: 0,
                } if !self.awaiting_later_application_batch() => {
                    self.enter_incoming(index);
                }
                Turn::Incoming {
                    index,
                    credits_to_emit: 0,
                    receiver_continuation_pending: false,
                    initial_credits_awaiting: 0,
                    credited_bytes_outstanding: 0,
                    observed_remaining_bytes: 0,
                    ..
                } if self.batch_gate_open(index) => {
                    self.enter_next_outgoing(index);
                }
                Turn::Outgoing { .. } | Turn::Incoming { .. } | Turn::Done => break,
            }
        }
    }

    fn on_incoming_payload(&mut self, bytes: u64, cover: bool) {
        self.observed_incoming_bytes = self.observed_incoming_bytes.saturating_add(bytes);
        if cover {
            self.incoming_chaff_bytes = self.incoming_chaff_bytes.saturating_add(bytes);
        }
        let Turn::Incoming {
            index,
            observed_remaining_bytes,
            ..
        } = &mut self.turn
        else {
            self.incoming_overflow_bytes = self.incoming_overflow_bytes.saturating_add(bytes);
            self.unattributed_incoming_bytes =
                self.unattributed_incoming_bytes.saturating_add(bytes);
            return;
        };

        self.observed_bursts[*index].incoming_bytes = self.observed_bursts[*index]
            .incoming_bytes
            .saturating_add(bytes);
        let attributed = bytes.min(*observed_remaining_bytes);
        *observed_remaining_bytes = observed_remaining_bytes.saturating_sub(bytes);
        self.incoming_overflow_bytes = self
            .incoming_overflow_bytes
            .saturating_add(bytes.saturating_sub(attributed));
        self.normalize_turn();
    }

    fn on_receive_credit_consumed(&mut self, bytes: u64) {
        if let Turn::Incoming {
            credited_bytes_outstanding,
            ..
        } = &mut self.turn
        {
            *credited_bytes_outstanding = credited_bytes_outstanding.saturating_sub(bytes);
        }
        self.normalize_turn();
    }

    fn on_application_bytes(&mut self, direction: Direction, bytes: u64) {
        if direction == Direction::Incoming && !matches!(self.turn, Turn::Incoming { .. }) {
            self.application_stream_crossing_bytes =
                self.application_stream_crossing_bytes.saturating_add(bytes);
            self.batch_lifecycle_errors = self.batch_lifecycle_errors.saturating_add(1);
        }
        match direction {
            Direction::Outgoing => {
                self.natural_outgoing_bytes = self.natural_outgoing_bytes.saturating_add(bytes);
            }
            Direction::Incoming => {
                self.natural_incoming_bytes = self.natural_incoming_bytes.saturating_add(bytes);
            }
        }
        if !self.application_batch_active {
            self.batch_lifecycle_errors = self.batch_lifecycle_errors.saturating_add(1);
            return;
        }
        if let Some(segment) = self
            .natural_batch_segments
            .last_mut()
            .filter(|segment| segment.direction == direction)
        {
            segment.bytes = segment.bytes.saturating_add(bytes);
        } else {
            self.natural_batch_segments
                .push(NaturalSegment { direction, bytes });
        }
    }

    fn natural_batch_bursts(&self) -> (Vec<NaturalBurst>, bool) {
        let packet_size = u64::from(self.packet_size);
        let mut valid = self
            .natural_batch_segments
            .first()
            .is_some_and(|segment| segment.direction == Direction::Outgoing)
            && self
                .natural_batch_segments
                .iter()
                .any(|segment| segment.direction == Direction::Incoming);
        let mut bursts = Vec::new();
        let mut index = 0;
        while let Some(segment) = self.natural_batch_segments.get(index) {
            if segment.direction == Direction::Incoming {
                valid = false;
                bursts.push(NaturalBurst {
                    outgoing_cells: 0,
                    incoming_cells: segment.bytes.div_ceil(packet_size),
                });
                index += 1;
                continue;
            }
            let mut burst = NaturalBurst {
                outgoing_cells: segment.bytes.div_ceil(packet_size),
                incoming_cells: 0,
            };
            index += 1;
            if let Some(incoming) = self
                .natural_batch_segments
                .get(index)
                .filter(|candidate| candidate.direction == Direction::Incoming)
            {
                burst.incoming_cells = incoming.bytes.div_ceil(packet_size);
                index += 1;
            }
            bursts.push(burst);
        }
        (bursts, valid)
    }

    fn finish_natural_batch(&mut self) {
        let (observed, valid) = self.natural_batch_bursts();
        if !valid {
            self.batch_lifecycle_errors = self.batch_lifecycle_errors.saturating_add(1);
        }
        let batch_index = usize::try_from(self.application_batches_completed).unwrap_or(usize::MAX);
        let expected_start = batch_index
            .checked_sub(1)
            .and_then(|previous| self.source_batch_ends.get(previous).copied())
            .map_or(0, |end| end.saturating_add(1));
        let expected = self
            .source_batch_ends
            .get(batch_index)
            .and_then(|end| self.source_envelope.get(expected_start..=(*end)))
            .unwrap_or(&[]);
        let overflow = observed
            .iter()
            .enumerate()
            .fold(0_u64, |overflow, (index, actual)| {
                let target = expected.get(index).copied().unwrap_or(BurstPair {
                    outgoing: 0,
                    incoming: 0,
                });
                overflow
                    .saturating_add(
                        actual
                            .outgoing_cells
                            .saturating_sub(u64::from(target.outgoing)),
                    )
                    .saturating_add(
                        actual
                            .incoming_cells
                            .saturating_sub(u64::from(target.incoming)),
                    )
            });
        self.source_envelope_overflow_cells =
            self.source_envelope_overflow_cells.saturating_add(overflow);
        self.natural_batch_segments.clear();
    }

    fn on_application_batch_started(&mut self) {
        if self.application_batch_active
            || self.application_batch_assigned
            || !matches!(self.turn, Turn::Outgoing { .. })
        {
            self.batch_lifecycle_errors = self.batch_lifecycle_errors.saturating_add(1);
        }
        if !self.application_batch_active {
            self.natural_batch_segments.clear();
        }
        self.application_batch_active = true;
        self.application_batch_assigned = true;
        self.application_batches_started = self.application_batches_started.saturating_add(1);
    }

    fn on_application_batch_completed(&mut self) {
        if !self.application_batch_active {
            self.batch_lifecycle_errors = self.batch_lifecycle_errors.saturating_add(1);
            return;
        }
        self.finish_natural_batch();
        self.application_batch_active = false;
        self.application_batches_completed = self.application_batches_completed.saturating_add(1);
        self.normalize_turn();
    }

    fn incoming_capacity_available(&self) -> u64 {
        self.incoming_capacity_reported
            .unwrap_or(0)
            .saturating_sub(self.reserved_chaff_capacity)
            .saturating_sub(self.incoming_capacity_reserved)
            .saturating_sub(self.incoming_capacity_committed)
    }

    fn receiver_continuation_due(
        &self,
        index: usize,
        credits_to_emit: u32,
        receiver_continuation_pending: bool,
        initial_credits_awaiting: u32,
    ) -> bool {
        receiver_continuation_pending
            && initial_credits_awaiting == 0
            && self.batch_gate_open(index)
            && (credits_to_emit == 0
                || self.incoming_capacity_reported.is_some()
                    && self.incoming_capacity_available() < u64::from(self.packet_size))
    }

    fn on_capacity(&mut self, capacity: Capacity) {
        let reported = capacity.available(DefenseMode::ChaffAndShape);
        if self.incoming_capacity_reported != Some(reported) {
            // A changed controller snapshot incorporates allocations accepted
            // since the previous snapshot.  Reservations for events that the
            // controller has not observed yet remain local and must still be
            // subtracted.  Repeating an identical snapshot deliberately does
            // not replenish either category.
            self.incoming_capacity_reported = Some(reported);
            self.incoming_capacity_committed = 0;
        }
    }

    fn fail_realization(&mut self, failure: RealizationFailure) {
        self.failed_incoming_shortfall_bytes = self.remaining_incoming_bytes();
        self.realization_failure = Some(failure);
        self.incoming_capacity_reserved = 0;
        self.incoming_capacity_committed = 0;
        self.turn = Turn::Done;
    }

    fn remaining_incoming_bytes(&self) -> u64 {
        match self.turn {
            Turn::Incoming {
                index,
                observed_remaining_bytes,
                ..
            } => observed_remaining_bytes.saturating_add(
                self.molded
                    .iter()
                    .skip(index.saturating_add(1))
                    .map(|pair| u64::from(pair.incoming) * u64::from(self.packet_size))
                    .sum(),
            ),
            Turn::Outgoing { index, .. } => self
                .molded
                .iter()
                .skip(index)
                .map(|pair| u64::from(pair.incoming) * u64::from(self.packet_size))
                .sum(),
            Turn::Done => self.failed_incoming_shortfall_bytes,
        }
    }

    fn on_receive_credit_retired(&mut self, bytes: u64) {
        if let Turn::Incoming {
            credited_bytes_outstanding,
            ..
        } = &mut self.turn
        {
            *credited_bytes_outstanding = credited_bytes_outstanding.saturating_sub(bytes);
        }
        if bytes > 0 {
            self.fail_realization(RealizationFailure::ReceiveCreditRetired);
        }
    }

    fn on_incoming_slot_missed(&mut self, reason: MissedSlotReason) {
        self.fail_realization(RealizationFailure::IncomingSlotMissed(reason));
    }

    fn commit_incoming_reservation(&mut self, bytes: u64) {
        let committed = bytes.min(self.incoming_capacity_reserved);
        self.incoming_capacity_reserved = self.incoming_capacity_reserved.saturating_sub(committed);
        self.incoming_capacity_committed =
            self.incoming_capacity_committed.saturating_add(committed);
    }

    fn on_incoming_credit_requested(&mut self, packet: Packet) {
        self.commit_incoming_reservation(u64::from(packet.length()));
        self.on_incoming_credit_resolution(EventOutcome::Satisfied {
            observed: packet.length(),
        });
    }

    fn on_incoming_credit_resolution(&mut self, outcome: EventOutcome) {
        let handled = match &mut self.turn {
            Turn::Incoming {
                initial_credits_awaiting,
                credited_bytes_outstanding,
                ..
            } if *initial_credits_awaiting > 0 => {
                *initial_credits_awaiting = initial_credits_awaiting.saturating_sub(1);
                if let EventOutcome::Satisfied { observed } = outcome {
                    *credited_bytes_outstanding =
                        credited_bytes_outstanding.saturating_add(u64::from(observed));
                }
                true
            }
            Turn::Outgoing { .. } | Turn::Incoming { .. } | Turn::Done => false,
        };
        if handled && let EventOutcome::Missed(reason) = outcome {
            self.on_incoming_slot_missed(reason);
        }
        self.normalize_turn();
    }

    fn on_outgoing_resolution(&mut self, outcome: EventOutcome) {
        let Turn::Outgoing {
            index,
            to_emit,
            awaiting,
        } = &mut self.turn
        else {
            return;
        };
        if *awaiting == 0 {
            return;
        }

        *awaiting = awaiting.saturating_sub(1);
        match outcome {
            EventOutcome::Satisfied { observed } => {
                self.observed_outgoing_cells = self.observed_outgoing_cells.saturating_add(1);
                self.observed_bursts[*index].outgoing_cells = self.observed_bursts[*index]
                    .outgoing_cells
                    .saturating_add(1);
                self.outgoing_overflow_bytes = self
                    .outgoing_overflow_bytes
                    .saturating_add(u64::from(observed.saturating_sub(self.packet_size)));
            }
            EventOutcome::Missed(_) => {
                *to_emit = to_emit.saturating_add(1);
                self.retried_outgoing_events = self.retried_outgoing_events.saturating_add(1);
            }
        }
        self.normalize_turn();
    }

    fn next_internal_deadline(&self) -> Option<Duration> {
        match self.turn {
            Turn::Outgoing { .. } if self.awaiting_later_application_batch() => None,
            Turn::Outgoing {
                to_emit, awaiting, ..
            } => (to_emit > 0 || awaiting == 0).then_some(self.now),
            Turn::Incoming {
                index,
                credits_to_emit,
                receiver_continuation_pending,
                observed_remaining_bytes,
                initial_credits_awaiting,
                credited_bytes_outstanding,
                ..
            } => (credits_to_emit > 0
                && self.incoming_capacity_available() >= u64::from(self.packet_size)
                || self.receiver_continuation_due(
                    index,
                    credits_to_emit,
                    receiver_continuation_pending,
                    initial_credits_awaiting,
                )
                || observed_remaining_bytes == 0
                    && !receiver_continuation_pending
                    && initial_credits_awaiting == 0
                    && credited_bytes_outstanding == 0
                    && self.batch_gate_open(index))
            .then_some(self.now),
            Turn::Done => None,
        }
    }
}

impl Defense for WalkieTalkie {
    fn observe(&mut self, signal: DefenseSignal) {
        let at = signal.at;
        self.record_now(at);

        match signal.kind {
            SignalKind::ReceiveCreditRequested { packet }
                if packet.direction() == Direction::Incoming =>
            {
                self.on_incoming_credit_requested(packet);
            }
            SignalKind::Resolved { packet, outcome }
                if packet.direction() == Direction::Outgoing
                    && packet.length() == self.packet_size =>
            {
                self.on_outgoing_resolution(outcome);
            }
            SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes,
                cover,
            } => self.on_incoming_payload(bytes, cover),
            SignalKind::ReceiveCreditRetired { bytes } => {
                self.on_receive_credit_retired(bytes);
            }
            SignalKind::ReceiveCreditConsumed { bytes } => {
                self.on_receive_credit_consumed(bytes);
            }
            SignalKind::Resolved {
                packet,
                outcome: EventOutcome::Missed(reason),
            } if packet.direction() == Direction::Incoming => {
                self.on_incoming_slot_missed(reason);
            }
            SignalKind::PayloadBytes {
                direction: Direction::Outgoing,
                bytes,
                cover: false,
            } if matches!(self.turn, Turn::Incoming { .. }) => {
                self.application_stream_crossing_bytes =
                    self.application_stream_crossing_bytes.saturating_add(bytes);
            }
            SignalKind::ApplicationBatchStarted => self.on_application_batch_started(),
            SignalKind::ApplicationBatchCompleted => self.on_application_batch_completed(),
            SignalKind::ApplicationComplete => self.application_complete = true,
            SignalKind::Wire {
                direction: Direction::Outgoing,
                ..
            } if matches!(self.turn, Turn::Incoming { .. }) => {
                // STREAM data is transport-gated throughout an incoming turn.
                // Any client datagram that still crosses is therefore necessary
                // ACK/path/control traffic, which the adaptation permits.
                self.control_only_crossings = self.control_only_crossings.saturating_add(1);
            }
            SignalKind::Wire { .. }
            | SignalKind::ClassifiedWire { .. }
            | SignalKind::PayloadBytes {
                direction: Direction::Outgoing,
                ..
            }
            | SignalKind::Capacity(_)
            | SignalKind::TrafficMorphingEgress { .. }
            | SignalKind::ReceiveCreditRequested { .. }
            | SignalKind::Resolved { .. } => {}
        }
        if let SignalKind::Capacity(capacity) = signal.kind {
            self.on_capacity(capacity);
        }
    }

    fn observe_application_bytes(&mut self, at: Duration, direction: Direction, bytes: u64) {
        self.record_now(at);
        self.on_application_bytes(direction, bytes);
    }

    fn next_event(&mut self, elapsed: Duration) -> Option<Packet> {
        let at = elapsed;
        self.record_now(at);
        self.last_receiver_continuation = None;
        if self.realization_failure.is_some() {
            return None;
        }
        self.normalize_turn();
        if self.awaiting_later_application_batch() && matches!(self.turn, Turn::Outgoing { .. }) {
            return None;
        }

        loop {
            let incoming_capacity_available = self.incoming_capacity_available();
            let receiver_continuation_due = match self.turn {
                Turn::Incoming {
                    index,
                    credits_to_emit,
                    receiver_continuation_pending,
                    initial_credits_awaiting,
                    ..
                } => self.receiver_continuation_due(
                    index,
                    credits_to_emit,
                    receiver_continuation_pending,
                    initial_credits_awaiting,
                ),
                Turn::Outgoing { .. } | Turn::Done => false,
            };
            match &mut self.turn {
                Turn::Outgoing {
                    to_emit, awaiting, ..
                } if *to_emit > 0 => {
                    let packet = Packet::new(at, Direction::Outgoing, self.packet_size).ok()?;
                    *to_emit = to_emit.saturating_sub(1);
                    *awaiting = awaiting.saturating_add(1);
                    return Some(packet);
                }
                Turn::Outgoing { awaiting, .. } if *awaiting > 0 => return None,
                Turn::Outgoing { .. } => {
                    self.normalize_turn();
                    if matches!(self.turn, Turn::Outgoing { .. }) {
                        return None;
                    }
                }
                Turn::Incoming {
                    receiver_continuation_pending,
                    initial_credits_awaiting,
                    ..
                } if receiver_continuation_due => {
                    self.incoming_capacity_reserved = self
                        .incoming_capacity_reserved
                        .saturating_add(u64::from(self.packet_size));
                    let packet = Packet::new(at, Direction::Incoming, self.packet_size).ok()?;
                    *receiver_continuation_pending = false;
                    *initial_credits_awaiting = initial_credits_awaiting.saturating_add(1);
                    self.last_receiver_continuation = Some(ReceiverContinuationDisposition {
                        cell_bytes: u64::from(self.packet_size),
                        parser_ceiling_bytes: self.receiver_parser_allowance_ceiling_bytes,
                    });
                    return Some(packet);
                }
                Turn::Incoming {
                    credits_to_emit,
                    initial_credits_awaiting,
                    ..
                } if *credits_to_emit > 0 => {
                    if incoming_capacity_available < u64::from(self.packet_size) {
                        return None;
                    }
                    self.incoming_capacity_reserved = self
                        .incoming_capacity_reserved
                        .saturating_add(u64::from(self.packet_size));
                    let packet = Packet::new(at, Direction::Incoming, self.packet_size).ok()?;
                    *credits_to_emit = credits_to_emit.saturating_sub(1);
                    *initial_credits_awaiting = initial_credits_awaiting.saturating_add(1);
                    return Some(packet);
                }
                Turn::Incoming { .. } => {
                    self.normalize_turn();
                    if matches!(self.turn, Turn::Incoming { .. }) {
                        return None;
                    }
                }
                Turn::Done => return None,
            }
        }
    }

    fn last_incoming_event_receiver_continuation(&self) -> Option<ReceiverContinuationDisposition> {
        self.last_receiver_continuation
    }

    fn pending_receiver_continuation(&self) -> Option<ReceiverContinuationDisposition> {
        matches!(
            self.turn,
            Turn::Incoming {
                receiver_continuation_pending: true,
                ..
            }
        )
        .then_some(ReceiverContinuationDisposition {
            cell_bytes: u64::from(self.packet_size),
            parser_ceiling_bytes: self.receiver_parser_allowance_ceiling_bytes,
        })
    }

    fn preprovision_chaff_once_to_stream_limit(&self) -> bool {
        true
    }

    fn base_chaff_requires_peer_acknowledgment(&self) -> bool {
        true
    }

    fn receiver_continuation_reserve_horizon(&self) -> usize {
        let Turn::Incoming { index, .. } = self.turn else {
            return 0;
        };
        self.molded[index..]
            .iter()
            .filter(|pair| pair.incoming > 0)
            .count()
    }

    fn max_receiver_continuation_reserve_horizon(&self) -> usize {
        self.molded.iter().filter(|pair| pair.incoming > 0).count()
    }

    fn receiver_continuation_cell_bytes(&self) -> Option<u64> {
        Some(u64::from(self.packet_size))
    }

    fn observe_capacity_adjustment(&mut self, adjustment: CapacityAdjustment) {
        self.reserved_chaff_capacity = adjustment.reserved_chaff_bytes;
    }

    fn next_event_at(&self) -> Option<Duration> {
        if self.realization_failure.is_some() {
            return None;
        }
        self.next_internal_deadline()
    }

    fn is_complete(&self) -> bool {
        self.application_complete
            && !self.application_batch_active
            && (self.realization_failure.is_some() || matches!(self.turn, Turn::Done))
    }

    fn is_outgoing_complete(&self) -> bool {
        if self.realization_failure.is_some() {
            return true;
        }
        match self.turn {
            Turn::Done => true,
            Turn::Outgoing {
                index,
                to_emit,
                awaiting,
                ..
            } => {
                to_emit == 0
                    && awaiting == 0
                    && self
                        .molded
                        .iter()
                        .skip(index.saturating_add(1))
                        .all(|pair| pair.outgoing == 0)
            }
            Turn::Incoming { index, .. } => self
                .molded
                .iter()
                .skip(index.saturating_add(1))
                .all(|pair| pair.outgoing == 0),
        }
    }

    fn can_release_chaff_send_shaping(&self) -> bool {
        self.realization_failure.is_some() || matches!(self.turn, Turn::Done)
    }

    fn can_start_application_batch(&self) -> bool {
        if self.realization_failure.is_some() {
            return false;
        }
        self.application_batches_started < self.expected_application_batches
            && !self.application_batch_active
            && !self.application_batch_assigned
            && matches!(self.turn, Turn::Outgoing { .. })
    }

    fn terminal_failure(&self) -> Option<&'static str> {
        self.realization_failure.map(|failure| match failure {
            RealizationFailure::ReceiveCreditRetired
            | RealizationFailure::IncomingSlotMissed(MissedSlotReason::ReceiveCreditRetired) => {
                "Walkie-Talkie receive credit retired before the incoming mould was realized"
            }
            RealizationFailure::IncomingSlotMissed(_) => {
                "Walkie-Talkie incoming slot failed before the mould was realized"
            }
        })
    }

    fn mode(&self) -> DefenseMode {
        DefenseMode::ChaffAndShape
    }

    fn diagnostics(&self) -> DefenseDiagnostics {
        let incoming_shortfall = self.remaining_incoming_bytes();
        let packet_size = u64::from(self.packet_size);
        let observed_incoming_cells = self.observed_incoming_bytes.div_ceil(packet_size);
        let outgoing_shortfall_cells = self
            .target_outgoing_cells
            .saturating_sub(self.observed_outgoing_cells);
        let outgoing_overflow_cells = self
            .observed_outgoing_cells
            .saturating_sub(self.target_outgoing_cells)
            .saturating_add(self.outgoing_overflow_bytes.div_ceil(packet_size));
        let incoming_shortfall_cells = incoming_shortfall.div_ceil(packet_size);
        let incoming_overflow_cells = self.incoming_overflow_bytes.div_ceil(packet_size);
        let burst_realization: Vec<_> = self
            .molded
            .iter()
            .zip(&self.observed_bursts)
            .enumerate()
            .map(|(index, (target, observed))| WalkieTalkieBurstDiagnostics {
                index,
                target_outgoing_cells: u64::from(target.outgoing),
                target_incoming_cells: u64::from(target.incoming),
                observed_outgoing_cells: observed.outgoing_cells,
                observed_incoming_cells: observed.incoming_bytes.div_ceil(packet_size),
            })
            .collect();
        let target_observed_l1 = self
            .target_outgoing_cells
            .abs_diff(self.observed_outgoing_cells)
            .saturating_add(self.target_incoming_cells.abs_diff(observed_incoming_cells));
        let target_observed_burst_l1 = burst_realization
            .iter()
            .fold(0_u64, |distance, burst| {
                distance
                    .saturating_add(
                        burst
                            .target_outgoing_cells
                            .abs_diff(burst.observed_outgoing_cells),
                    )
                    .saturating_add(
                        burst
                            .target_incoming_cells
                            .abs_diff(burst.observed_incoming_cells),
                    )
            })
            .saturating_add(self.outgoing_overflow_bytes.div_ceil(packet_size))
            .saturating_add(self.unattributed_incoming_bytes.div_ceil(packet_size));
        DefenseDiagnostics {
            retried_outgoing_events: self.retried_outgoing_events,
            walkie_talkie_target_outgoing_cells: self.target_outgoing_cells,
            walkie_talkie_target_incoming_cells: self.target_incoming_cells,
            walkie_talkie_observed_outgoing_cells: self.observed_outgoing_cells,
            walkie_talkie_observed_incoming_cells: observed_incoming_cells,
            walkie_talkie_outgoing_shortfall_cells: outgoing_shortfall_cells,
            walkie_talkie_incoming_shortfall_cells: incoming_shortfall_cells,
            walkie_talkie_outgoing_overflow_cells: outgoing_overflow_cells,
            walkie_talkie_incoming_overflow_cells: incoming_overflow_cells,
            walkie_talkie_incoming_shortfall_bytes: incoming_shortfall,
            walkie_talkie_incoming_chaff_bytes: self.incoming_chaff_bytes,
            walkie_talkie_target_observed_cell_l1: target_observed_l1,
            walkie_talkie_target_observed_burst_l1: target_observed_burst_l1,
            walkie_talkie_control_only_crossings: self.control_only_crossings,
            walkie_talkie_application_stream_crossing_bytes: self.application_stream_crossing_bytes,
            walkie_talkie_natural_outgoing_bytes: self.natural_outgoing_bytes,
            walkie_talkie_natural_incoming_bytes: self.natural_incoming_bytes,
            walkie_talkie_source_envelope_overflow_cells: self.source_envelope_overflow_cells,
            walkie_talkie_burst_realization: burst_realization,
            walkie_talkie_expected_application_batches: self.expected_application_batches,
            walkie_talkie_observed_application_batches: self.application_batches_started,
            walkie_talkie_application_batch_overflow: self
                .application_batches_started
                .saturating_sub(self.expected_application_batches),
            walkie_talkie_application_batches_completed: self.application_batches_completed,
            walkie_talkie_batch_lifecycle_errors: self.batch_lifecycle_errors,
            walkie_talkie_application_batch_active: self.application_batch_active,
            ..DefenseDiagnostics::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, time::Duration};

    use super::WalkieTalkie;
    use crate::{
        Capacity, Defense as _, DefenseMode, DefenseSignal, Direction, EventOutcome,
        MissedSlotReason, Packet, SignalKind, WalkieTalkieBurstDiagnostics, WalkieTalkieConfig,
        defense::drive,
    };

    fn config(packet_size: u16) -> WalkieTalkieConfig {
        WalkieTalkieConfig {
            molded: "test-molded.json".into(),
            workload_id: "real page".into(),
            packet_size,
        }
    }

    fn molded(bursts: &str) -> String {
        molded_pair_from_runtime(bursts)
    }

    fn parse_test_bursts(bursts: &str) -> (Vec<super::BurstPair>, Vec<usize>) {
        let mut records: Vec<serde_json::Value> =
            serde_json::from_str(bursts).expect("test bursts are valid JSON");
        let mut batch_ends = Vec::new();
        for (index, record) in records.iter_mut().enumerate() {
            let record = record.as_object_mut().expect("test burst is an object");
            let batch_end = record
                .remove("batch_end")
                .is_none_or(|value| value.as_bool().expect("boolean batch_end"));
            if batch_end {
                batch_ends.push(index);
            }
        }
        let pairs: Vec<super::BurstPair> =
            serde_json::from_value(serde_json::Value::Array(records))
                .expect("enriched test bursts are valid");
        (pairs, batch_ends)
    }

    fn molded_pair(real: &str, decoy: &str) -> String {
        molded_pair_from_sources(real, decoy)
    }

    fn molded_pair_from_runtime(bursts: &str) -> String {
        let (runtime, batch_ends) = parse_test_bursts(bursts);
        let source = runtime;
        molded_file(&source, &batch_ends, &source, &batch_ends)
    }

    fn molded_pair_from_sources(real: &str, decoy: &str) -> String {
        let (real, real_batch_ends) = parse_test_bursts(real);
        let (decoy, decoy_batch_ends) = parse_test_bursts(decoy);
        molded_file(&real, &real_batch_ends, &decoy, &decoy_batch_ends)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the strict schema-six fixture keeps all byte-exact contract strings together"
    )]
    fn molded_file(
        real: &[super::BurstPair],
        real_batch_ends: &[usize],
        decoy: &[super::BurstPair],
        decoy_batch_ends: &[usize],
    ) -> String {
        let (symmetric_mold, molded_batch_ends) =
            super::mold(real, real_batch_ends, decoy, decoy_batch_ends);
        let bursts = super::adapt_continuations(&symmetric_mold)
            .expect("adapted sender-framing and receiver continuations");
        let matching_cost_packets = super::total_packets(&bursts)
            .expect("molded test packet count")
            .checked_mul(2)
            .and_then(|value| {
                value.checked_sub(
                    super::total_packets(real).expect("real test packet count")
                        + super::total_packets(decoy).expect("decoy test packet count"),
                )
            })
            .expect("test matching cost");
        let total_scheduled_bytes = bursts.iter().fold(0_u64, |total, pair| {
            total + (u64::from(pair.outgoing) + u64::from(pair.incoming)) * 1_200
        });
        // Production parsing requires every component to provide a declared
        // staged outgoing carrier. A small set of defense-state unit tests
        // intentionally exercise zero-outgoing turns; give only those
        // cfg(test) fixtures an explicit bypass marker.
        let generated_by = if bursts.iter().any(|pair| pair.outgoing == 0) {
            "unit-test-incoming-first-fixture"
        } else {
            "test"
        };
        let real = serde_json::to_string(&real).expect("serialize real test bursts");
        let decoy = serde_json::to_string(&decoy).expect("serialize decoy test bursts");
        let bursts = serde_json::to_string(&bursts).expect("serialize molded test bursts");
        format!(
            r#"{{
                "adaptation": "qcsd-client-only",
                "burst_definition": "global-application-batch-direction-transitions",
                "cell_byte_domain": "http3-request-stream-offset.bytes",
                "schema_version": 6,
                "generated_by": "{generated_by}",
                "matching_algorithm": "minimum-base-symmetric-mold-padding-cost-one-to-one",
                "paper_equivalent": false,
                "packet_size": 1200,
                "receiver_continuation": {{
                    "allocation_policy": "single-peer-acknowledged-pristine-header-phase-controlled-chaff-stream-whole-cell",
                    "application_order": "after-symmetric-elementwise-mold",
                    "base_allocation_policy": "application-streams-before-peer-acknowledged-nonreserved-controlled-chaff-streams;exact-capacity-before-bounded-framing-claims",
                    "batch_end_release_policy": "at-molded-batch-end-after-application-batch-complete-otherwise-no-batch-gate",
                    "causal_capacity_precondition": "every-molded-component-outgoing>0;effective-configured-max-chaff-streams>=total-receiver-continuation-reserve-horizon+1;schema-two-stateful-stage-capacity-recurrence-proves-higher-priority-due-application-stream-frames-plus-cumulative-one-shot-chaff-request-stream-frames-through-fin-fit-within-each-exact-full-molded-outgoing-target-through-final-component",
                    "cells_per_nonzero_incoming_component": 1,
                    "formula": "symmetric_incoming=adapted_incoming-1-if-adapted_incoming>0-else-0",
                    "parser_allowance_ceiling_bytes": 1000,
                    "prefix_consumability_precondition": "prepared-selected-pristine-first-prior-requested-plus-raw-headroom-bytes-are-consumable",
                    "post_outgoing_loss_liveness_limitation": "loss-of-required-initial-peer-acknowledged-survivor-after-initial-request-chaff-batch-holds-base-and-continuation-allocation;no-new-chaff-request-replenishment-or-generic-post-loss-liveness-guarantee",
                    "provisioning_policy": "fill-effective-configured-max-chaff-streams-once-before-first-due-molded-outgoing-actions;never-replenish-after-initial-request-chaff-batch",
                    "raw_headroom_bytes_per_nonzero_incoming_component": 1200,
                    "sender_framing_cells_per_nonzero_outgoing_component": 1,
                    "sender_framing_formula": "symmetric_outgoing=adapted_outgoing-1-if-adapted_outgoing>0-else-0",
                    "sender_framing_policy": "one-full-cell-per-positive-symmetric-outgoing-component-reserved-for-quic-http3-stream-framing-and-mandatory-control-overhead",
                    "release_policy": "after-issued-base-events-controller-requested-and-request-signals-observed;batch-gate-open;release-when-all-base-events-issued-or-real-reported-nonreserved-capacity-is-below-one-cell;recompute-live-unconsumed-base-each-retry;retain-single-coalescible-unadvertised-positive-outstanding-at-or-below-parser-ceiling-until-max-stream-data-advertised;prefer-single-coalesced-advertised-positive-outstanding-at-or-below-parser-ceiling-on-peer-acknowledged-nonreserved-header-blocked-stream;otherwise-release-whole-cell-to-oldest-retained-peer-acknowledged-pristine-reserve-regardless-of-live-base-debt;remove-oldest-reserve-once",
                    "request_activation_policy": "zero-required-insert-count-nonblocking-qpack-chaff-header-block;positive-final-size-with-contiguous-unique-request-stream-offsets-[0,final-size)-and-fin-peer-acknowledged-under-molded-outgoing-cells",
                    "request_prefix_delivery_precondition": "before-first-incoming-component-first-base-allocation-peer-acknowledged-nonblocking-chaff-request-survivors>=total-receiver-continuation-reserve-horizon+1;initial-survivor-gate-remains-latched-across-complete-schedule",
                    "resource_precondition": "schema-two-qualified-manifest-selects-known-valid-same-origin-source-resource;derived-selected-resource-projection-dependency-free-with-effective-length>=raw-headroom-bytes-per-nonzero-incoming-component;required-chaff-streams-defines-effective-configured-max-chaff-streams",
                    "reserve_lifecycle_policy": "remove-exactly-first-reserve-once-at-corresponding-continuation-controller-allocation-even-when-positive-live-debt-releases-on-nonreserved-stream;refresh-only-from-initial-peer-acknowledged-preprovisioned-cohort-for-defense-pending-continuation-or-tagged-continuation-still-queued-for-allocation;retryable-unadvertised-continuation-allocation-rollback-or-requeue-reconstitutes-corresponding-all-future-horizon-reserve-before-further-base-allocation",
                    "reserve_policy": "reserve-deterministic-acknowledged-pristine-candidates-for-all-remaining-nonzero-incoming-components-before-first-base-allocation-and-retain-distinct-reserves-across-later-positive-outgoing-components",
                "qualified_chaff_manifest_policy": "schema-two-qualified-navigation-root-and-selected-source-resource;explicit-application-resource-id-selected-chaff-resource-id-and-required-chaff-streams;selected-source-resource-known-valid-same-origin;derived-selected-resource-projection-dependency-free;exact-lowercase-accept-accept-encoding-accept-language-projection;application-request-headers-unchanged",
                "qualified_chaff_response_policy": "three-independent-staged-qualified-parallel-chaff-streams=max-five-and-walkie-talkie-required-chaff-streams-concurrent-unshaped-production-nonblocking-qpack-qualifications-derive-selected-resource-compact-status-normalized-content-encoding-body-bytes-body-sha256;one-shot-controller-config-uses-exact-walkie-talkie-required-chaff-streams;runtime-complete-responses-must-match-derived-identity;runtime-partial-responses-have-null-identity-match-fields",
                    "staged_prefix_pack_precondition": "schema-two-every-component-staged-prefix-pack-after-peer-settings-and-drained-h3-control-qpack-warmup;each-molded-component-is-an-exact-declared-full-packet-target;opens-exact-bound-application-resources-and-cumulative-copies-of-selected-qualified-resource;active-chaff-cohort-is-nondecreasing-and-zero-delta-stages-are-allowed;all-post-cutoff-stream-transmissions-owned-by-one-of-exact-declared-stage-targets;each-stage-gate-requires-cumulative-application-requests-transmitted-contiguously-through-fin-and-required-active-chaff-requests-transmitted-contiguously-through-fin-and-peer-acknowledged-before-dependent-base-allocation;no-pending-request-causal-h3-control-or-qpack-encoder-stream-output;post-warmup-qpack-decoder-stream-output-recorded-and-excluded;zero-targetless-stream-bytes",
                "qualification_binding_policy": "schema-six-raw-sha256-per-workload-binds-schema-two-chaff-qualification-sidecar-prefix-pack-spec-and-qualified-chaff-manifest;runtime-requires-exact-current-artifact-hashes-application-resource-id-selected-chaff-resource-id-and-required-chaff-streams"
                }},
                "qualification_bindings": [
                    {{
                        "workload_id": "real page",
                        "chaff_qualification_sidecar_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "prefix_pack_spec_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "qualified_chaff_manifest_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                        "application_resource_id": 0,
                        "selected_chaff_resource_id": 0,
                        "qualified_parallel_chaff_streams": 5,
                        "walkie_talkie_required_chaff_streams": 5
                    }},
                    {{
                        "workload_id": "decoy page",
                        "chaff_qualification_sidecar_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                        "prefix_pack_spec_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                        "qualified_chaff_manifest_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                        "application_resource_id": 0,
                        "selected_chaff_resource_id": 0,
                        "qualified_parallel_chaff_streams": 5,
                        "walkie_talkie_required_chaff_streams": 5
                    }}
                ],
                "profiles": [{{
                    "real": "real page",
                    "decoy": "decoy page",
                    "matching_cost_packets": {matching_cost_packets},
                    "training_inputs": {{
                        "real": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                        "decoy": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
                    }},
                    "variation": {{
                        "real": {{
                            "visit_count": 1,
                            "varying_components": 0,
                            "maximum_component_spread": 0
                        }},
                        "decoy": {{
                            "visit_count": 1,
                            "varying_components": 0,
                            "maximum_component_spread": 0
                        }}
                    }},
                    "source_envelopes": {{"real": {real}, "decoy": {decoy}}},
                    "batch_ends": {{
                        "real": {real_batch_ends:?},
                        "decoy": {decoy_batch_ends:?}
                    }},
                    "molded_batch_ends": {molded_batch_ends:?},
                    "total_scheduled_bytes": {total_scheduled_bytes},
                    "bursts": {bursts}
                }}]
            }}"#
        )
    }

    fn resolve(defense: &mut WalkieTalkie, at_us: u64, packet: Packet, outcome: EventOutcome) {
        provide_capacity(defense, at_us, u64::MAX);
        if packet.direction() == Direction::Incoming {
            defense.observe(DefenseSignal {
                at: Duration::from_micros(at_us),
                kind: SignalKind::ReceiveCreditRequested { packet },
            });
            if matches!(outcome, EventOutcome::Missed(_)) {
                defense.observe(DefenseSignal {
                    at: Duration::from_micros(at_us),
                    kind: SignalKind::ReceiveCreditRetired {
                        bytes: u64::from(packet.length()),
                    },
                });
            }
        }
        defense.observe(DefenseSignal {
            at: Duration::from_micros(at_us),
            kind: SignalKind::Resolved { packet, outcome },
        });
    }

    fn incoming_wire(defense: &mut WalkieTalkie, at_us: u64) {
        incoming_payload(defense, at_us, 1_200, false);
    }

    fn realize_receiver_continuation(defense: &mut WalkieTalkie, at_us: u64) {
        let packet = defense
            .next_event(Duration::from_micros(at_us))
            .expect("receiver-continuation credit");
        assert_eq!(packet.direction(), Direction::Incoming);
        incoming_wire(defense, at_us);
    }

    fn realize_sender_framing_continuation(defense: &mut WalkieTalkie, at_us: u64) {
        let packet = defense
            .next_event(Duration::from_micros(at_us))
            .expect("sender-framing continuation cell");
        assert_eq!(packet.direction(), Direction::Outgoing);
        resolve(
            defense,
            at_us,
            packet,
            EventOutcome::Satisfied { observed: 1_200 },
        );
    }

    fn incoming_payload(defense: &mut WalkieTalkie, at_us: u64, bytes: u64, cover: bool) {
        let pending_length = match defense.turn {
            super::Turn::Incoming {
                initial_credits_awaiting,
                ..
            } if initial_credits_awaiting > 0 => Some(defense.packet_size),
            super::Turn::Outgoing { .. } | super::Turn::Incoming { .. } | super::Turn::Done => None,
        };
        if let Some(length) = pending_length {
            let packet = Packet::new(Duration::from_micros(at_us), Direction::Incoming, length)
                .expect("pending incoming credit");
            resolve(
                defense,
                at_us,
                packet,
                EventOutcome::Satisfied { observed: length },
            );
        }
        defense.observe(DefenseSignal {
            at: Duration::from_micros(at_us),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes,
                cover,
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(at_us),
            kind: SignalKind::ReceiveCreditConsumed { bytes },
        });
    }

    fn retire_credit(defense: &mut WalkieTalkie, at_us: u64, bytes: u64) {
        defense.observe(DefenseSignal {
            at: Duration::from_micros(at_us),
            kind: SignalKind::ReceiveCreditRetired { bytes },
        });
    }

    fn application_batch_started(defense: &mut WalkieTalkie, at_us: u64) {
        provide_capacity(defense, at_us, u64::MAX);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(at_us),
            kind: SignalKind::ApplicationBatchStarted,
        });
    }

    fn provide_capacity(defense: &mut WalkieTalkie, at_us: u64, bytes: u64) {
        defense.observe(DefenseSignal {
            at: Duration::from_micros(at_us),
            kind: SignalKind::Capacity(Capacity {
                application_incoming: bytes,
                chaff_incoming: 0,
            }),
        });
    }

    fn application_batch_completed(defense: &mut WalkieTalkie, at_us: u64) {
        defense.observe(DefenseSignal {
            at: Duration::from_micros(at_us),
            kind: SignalKind::ApplicationBatchCompleted,
        });
    }

    fn application_bytes(defense: &mut WalkieTalkie, at_us: u64, direction: Direction, bytes: u64) {
        defense.observe_application_bytes(Duration::from_micros(at_us), direction, bytes);
    }

    #[test]
    fn loader_rejects_unknown_fields_wrong_versions_and_packet_size_mismatch() {
        let unknown = molded(r#"[{"outgoing": 1, "incoming": 1}]"#).replace(
            r#""schema_version": 6,"#,
            r#""schema_version": 6, "unexpected": true,"#,
        );
        assert!(WalkieTalkie::from_json(&config(1_200), 1_200, &unknown).is_err());

        let wrong_version = molded(r#"[{"outgoing": 1, "incoming": 1}]"#)
            .replace(r#""schema_version": 6"#, r#""schema_version": 4"#);
        assert!(WalkieTalkie::from_json(&config(1_200), 1_200, &wrong_version).is_err());

        assert!(
            WalkieTalkie::from_json(
                &config(99),
                1_200,
                &molded(r#"[{"outgoing": 1, "incoming": 1}]"#)
            )
            .is_err()
        );

        let wrong_total = molded(r#"[{"outgoing": 1, "incoming": 1}]"#).replace(
            r#""total_scheduled_bytes": 4800"#,
            r#""total_scheduled_bytes": 4799"#,
        );
        assert!(WalkieTalkie::from_json(&config(1_200), 1_200, &wrong_total).is_err());

        let wrong_cost = molded(r#"[{"outgoing": 1, "incoming": 1}]"#).replace(
            r#""matching_cost_packets": 4"#,
            r#""matching_cost_packets": 3"#,
        );
        assert!(WalkieTalkie::from_json(&config(1_200), 1_200, &wrong_cost).is_err());

        let wrong_algorithm = molded(r#"[{"outgoing": 1, "incoming": 1}]"#).replace(
            "minimum-base-symmetric-mold-padding-cost-one-to-one",
            "minimum-cost-one-to-one",
        );
        assert!(WalkieTalkie::from_json(&config(1_200), 1_200, &wrong_algorithm).is_err());

        let same_label = molded(r#"[{"outgoing": 1, "incoming": 1}]"#)
            .replace(r#""decoy": "decoy page""#, r#""decoy": "real page""#);
        assert!(WalkieTalkie::from_json(&config(1_200), 1_200, &same_label).is_err());

        let mut missing = config(1_200);
        missing.workload_id = "missing workload".into();
        assert!(
            WalkieTalkie::from_json(
                &missing,
                1_200,
                &molded(r#"[{"outgoing": 1, "incoming": 1}]"#)
            )
            .is_err()
        );

        let mut unbound = config(1_200);
        unbound.workload_id.clear();
        assert!(
            WalkieTalkie::from_json(
                &unbound,
                1_200,
                &molded(r#"[{"outgoing": 1, "incoming": 1}]"#)
            )
            .is_err()
        );
    }

    #[test]
    fn schema_five_is_available_only_through_the_read_only_diagnostic_boundary() {
        let current = molded(r#"[{"outgoing": 1, "incoming": 1}]"#);
        let mut historical: serde_json::Value =
            serde_json::from_str(&current).expect("schema-six fixture");
        historical["schema_version"] = serde_json::json!(5);
        historical
            .as_object_mut()
            .expect("top object")
            .remove("qualification_bindings");
        let receiver = historical["receiver_continuation"]
            .as_object_mut()
            .expect("receiver object");
        for field in [
            "qualified_chaff_manifest_policy",
            "qualified_chaff_response_policy",
            "staged_prefix_pack_precondition",
            "qualification_binding_policy",
            "sender_framing_cells_per_nonzero_outgoing_component",
            "sender_framing_formula",
            "sender_framing_policy",
        ] {
            receiver.remove(field);
        }
        // Schema five remains a byte-for-byte historical audit format even
        // when the runnable schema-six contract advances.
        receiver.insert(
            "allocation_policy".into(),
            serde_json::json!(super::HISTORICAL_SCHEMA_FIVE_ALLOCATION_POLICY),
        );
        receiver.insert(
            "application_order".into(),
            serde_json::json!(super::HISTORICAL_SCHEMA_FIVE_APPLICATION_ORDER),
        );
        receiver.insert(
            "base_allocation_policy".into(),
            serde_json::json!(super::HISTORICAL_SCHEMA_FIVE_BASE_ALLOCATION_POLICY),
        );
        receiver.insert(
            "batch_end_release_policy".into(),
            serde_json::json!(super::HISTORICAL_SCHEMA_FIVE_BATCH_END_RELEASE_POLICY),
        );
        receiver.insert(
            "causal_capacity_precondition".into(),
            serde_json::json!(super::HISTORICAL_SCHEMA_FIVE_CAUSAL_CAPACITY_PRECONDITION),
        );
        receiver.insert(
            "post_outgoing_loss_liveness_limitation".into(),
            serde_json::json!(super::HISTORICAL_SCHEMA_FIVE_POST_OUTGOING_LOSS_LIVENESS_LIMITATION),
        );
        receiver.insert(
            "provisioning_policy".into(),
            serde_json::json!(super::HISTORICAL_SCHEMA_FIVE_PROVISIONING_POLICY),
        );
        receiver.insert(
            "formula".into(),
            serde_json::json!(super::HISTORICAL_SCHEMA_FIVE_FORMULA),
        );
        receiver.insert(
            "prefix_consumability_precondition".into(),
            serde_json::json!(super::HISTORICAL_SCHEMA_FIVE_PREFIX_CONSUMABILITY_PRECONDITION),
        );
        receiver.insert(
            "release_policy".into(),
            serde_json::json!(super::HISTORICAL_SCHEMA_FIVE_RELEASE_POLICY),
        );
        receiver.insert(
            "request_activation_policy".into(),
            serde_json::json!(super::HISTORICAL_SCHEMA_FIVE_REQUEST_ACTIVATION_POLICY),
        );
        receiver.insert(
            "request_prefix_delivery_precondition".into(),
            serde_json::json!(super::HISTORICAL_SCHEMA_FIVE_REQUEST_PREFIX_DELIVERY_PRECONDITION),
        );
        receiver.insert(
            "resource_precondition".into(),
            serde_json::json!(super::HISTORICAL_SCHEMA_FIVE_RESOURCE_PRECONDITION),
        );
        receiver.insert(
            "reserve_lifecycle_policy".into(),
            serde_json::json!(super::HISTORICAL_SCHEMA_FIVE_RESERVE_LIFECYCLE_POLICY),
        );
        receiver.insert(
            "reserve_policy".into(),
            serde_json::json!(super::HISTORICAL_SCHEMA_FIVE_RESERVE_POLICY),
        );
        historical["profiles"][0]["matching_cost_packets"] = serde_json::json!(2);
        historical["profiles"][0]["total_scheduled_bytes"] = serde_json::json!(3_600);
        historical["profiles"][0]["bursts"][0]["outgoing"] = serde_json::json!(1);
        let historical = historical.to_string();

        let diagnostic = WalkieTalkie::historical_schema_five_diagnostic(&historical)
            .expect("strict historical diagnostic");
        assert_eq!(diagnostic.packet_size, 1_200);
        assert_eq!(diagnostic.profile_count, 1);
        assert_eq!(diagnostic.workload_ids, ["real page", "decoy page"]);
        assert!(WalkieTalkie::from_json(&config(1_200), 1_200, &historical).is_err());
        assert!(WalkieTalkie::historical_schema_five_diagnostic(&current).is_err());

        let malformed = historical.replace(
            r#""schema_version":5"#,
            r#""schema_version":5,"unexpected":true"#,
        );
        assert!(WalkieTalkie::historical_schema_five_diagnostic(&malformed).is_err());
    }

    #[test]
    fn batch_aware_mold_does_not_flatten_components_across_application_batches() {
        let (real, real_batch_ends) = parse_test_bursts(
            r#"[
                {"outgoing": 1, "incoming": 1},
                {"outgoing": 2, "incoming": 2, "batch_end": false},
                {"outgoing": 3, "incoming": 3}
            ]"#,
        );
        let (decoy, decoy_batch_ends) = parse_test_bursts(
            r#"[
                {"outgoing": 4, "incoming": 4, "batch_end": false},
                {"outgoing": 5, "incoming": 5},
                {"outgoing": 6, "incoming": 6}
            ]"#,
        );

        let (batch_aware, common_batch_ends) =
            super::mold(&real, &real_batch_ends, &decoy, &decoy_batch_ends);
        let flattened: Vec<_> = real
            .iter()
            .zip(&decoy)
            .map(|(real, decoy)| super::BurstPair {
                outgoing: real.outgoing.max(decoy.outgoing),
                incoming: real.incoming.max(decoy.incoming),
            })
            .collect();

        assert_eq!(
            batch_aware,
            [
                super::BurstPair {
                    outgoing: 4,
                    incoming: 4,
                },
                super::BurstPair {
                    outgoing: 5,
                    incoming: 5,
                },
                super::BurstPair {
                    outgoing: 6,
                    incoming: 6,
                },
                super::BurstPair {
                    outgoing: 3,
                    incoming: 3,
                },
            ]
        );
        assert_eq!(common_batch_ends, [1, 3]);
        assert_ne!(batch_aware, flattened);
    }

    #[test]
    fn loader_rejects_missing_or_flattened_common_batch_boundaries() {
        let valid = molded_pair(
            r#"[
                {"outgoing": 1, "incoming": 1},
                {"outgoing": 2, "incoming": 2, "batch_end": false},
                {"outgoing": 3, "incoming": 3}
            ]"#,
            r#"[
                {"outgoing": 4, "incoming": 4, "batch_end": false},
                {"outgoing": 5, "incoming": 5},
                {"outgoing": 6, "incoming": 6}
            ]"#,
        );
        let mut missing: serde_json::Value =
            serde_json::from_str(&valid).expect("valid profile JSON");
        missing["profiles"][0]
            .as_object_mut()
            .expect("profile object")
            .remove("molded_batch_ends");
        assert!(
            WalkieTalkie::from_json(&config(1_200), 1_200, &missing.to_string()).is_err(),
            "legacy profiles without explicit common boundaries must be rejected"
        );

        let mut flattened: serde_json::Value =
            serde_json::from_str(&valid).expect("valid profile JSON");
        let profile = flattened["profiles"][0]
            .as_object_mut()
            .expect("profile object");
        profile.insert(
            "bursts".into(),
            serde_json::json!([
                {"outgoing": 4, "incoming": 4},
                {"outgoing": 5, "incoming": 5},
                {"outgoing": 6, "incoming": 6}
            ]),
        );
        profile.insert("molded_batch_ends".into(), serde_json::json!([1, 2]));
        profile.insert("matching_cost_packets".into(), serde_json::json!(18));
        profile.insert("total_scheduled_bytes".into(), serde_json::json!(3_000));
        assert!(
            WalkieTalkie::from_json(&config(1_200), 1_200, &flattened.to_string()).is_err(),
            "strict validation must recompute the batch-aware mould"
        );
    }

    #[test]
    fn either_side_of_one_symmetric_pair_selects_the_same_mold() {
        let input = molded_pair(
            r#"[
                {"outgoing": 2, "incoming": 3},
                {"outgoing": 1, "incoming": 1}
            ]"#,
            r#"[
                {"outgoing": 3, "incoming": 2, "batch_end": false},
                {"outgoing": 4, "incoming": 4},
                {"outgoing": 1, "incoming": 2}
            ]"#,
        );
        let real = WalkieTalkie::from_json(&config(1_200), 1_200, &input).expect("real binding");
        let mut decoy_config = config(1_200);
        decoy_config.workload_id = "decoy page".into();
        let decoy = WalkieTalkie::from_json(&decoy_config, 1_200, &input).expect("decoy binding");
        assert_eq!(real.molded, decoy.molded);
        assert_eq!(real.batch_ends, decoy.batch_ends);
        assert_eq!(real.batch_ends, HashSet::from([1, 2]));
        assert_eq!(real.expected_application_batches, 2);
        assert_eq!(decoy.expected_application_batches, 2);
    }

    #[test]
    fn qualification_resource_and_stream_count_bindings_are_strict() {
        let input = molded(r#"[{"outgoing": 1, "incoming": 1}]"#);
        let defense =
            WalkieTalkie::from_json(&config(1_200), 1_200, &input).expect("valid binding");
        let binding = defense.qualification_binding();
        assert_eq!(binding.application_resource_id, 0);
        assert_eq!(binding.selected_chaff_resource_id, 0);
        assert_eq!(binding.qualified_parallel_chaff_streams, 5);
        assert_eq!(binding.walkie_talkie_required_chaff_streams, 5);

        let valid: serde_json::Value = serde_json::from_str(&input).expect("valid JSON");
        for (field, mutation) in [
            ("application_resource_id", serde_json::json!(1)),
            ("selected_chaff_resource_id", serde_json::json!(-1)),
            ("qualified_parallel_chaff_streams", serde_json::json!(4)),
            (
                "walkie_talkie_required_chaff_streams",
                serde_json::json!(21),
            ),
        ] {
            let mut malformed = valid.clone();
            malformed["qualification_bindings"][0][field] = mutation;
            assert!(
                WalkieTalkie::from_json(&config(1_200), 1_200, &malformed.to_string()).is_err(),
                "invalid qualification binding {field} must fail closed"
            );
        }
        for field in [
            "application_resource_id",
            "selected_chaff_resource_id",
            "qualified_parallel_chaff_streams",
            "walkie_talkie_required_chaff_streams",
        ] {
            let mut malformed = valid.clone();
            malformed["qualification_bindings"][0]
                .as_object_mut()
                .expect("qualification binding object")
                .remove(field);
            assert!(
                WalkieTalkie::from_json(&config(1_200), 1_200, &malformed.to_string()).is_err(),
                "missing qualification binding {field} must fail closed"
            );
        }
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the overflow fixture constructs the full strict schema-six envelope"
    )]
    fn sender_and_receiver_continuation_and_scheduled_byte_overflow_are_rejected() {
        assert!(
            super::adapt_continuations(&[super::BurstPair {
                outgoing: u32::MAX,
                incoming: 0,
            }])
            .is_err()
        );
        assert!(
            super::adapt_continuations(&[super::BurstPair {
                outgoing: 0,
                incoming: u32::MAX,
            }])
            .is_err()
        );
        let bursts = vec![
            super::BurstPair {
                outgoing: u32::MAX,
                incoming: u32::MAX,
            };
            1
        ];
        let file = super::MoldedFile {
            adaptation: "qcsd-client-only".into(),
            burst_definition: "global-application-batch-direction-transitions".into(),
            cell_byte_domain: "http3-request-stream-offset.bytes".into(),
            schema_version: 6,
            generated_by: "test".into(),
            matching_algorithm: "minimum-base-symmetric-mold-padding-cost-one-to-one".into(),
            paper_equivalent: false,
            packet_size: 1_200,
            receiver_continuation: super::ReceiverContinuation {
                allocation_policy:
                    "single-peer-acknowledged-pristine-header-phase-controlled-chaff-stream-whole-cell"
                        .into(),
                application_order: "after-symmetric-elementwise-mold".into(),
                base_allocation_policy:
                    "application-streams-before-peer-acknowledged-nonreserved-controlled-chaff-streams;exact-capacity-before-bounded-framing-claims"
                        .into(),
                batch_end_release_policy:
                    "at-molded-batch-end-after-application-batch-complete-otherwise-no-batch-gate"
                        .into(),
                causal_capacity_precondition:
                    super::RECEIVER_CAUSAL_CAPACITY_PRECONDITION.into(),
                cells_per_nonzero_incoming_component: 1,
                formula: super::RECEIVER_FORMULA.into(),
                parser_allowance_ceiling_bytes: 1_000,
                prefix_consumability_precondition:
                    "prepared-selected-pristine-first-prior-requested-plus-raw-headroom-bytes-are-consumable"
                        .into(),
                post_outgoing_loss_liveness_limitation:
                    super::RECEIVER_POST_OUTGOING_LOSS_LIVENESS_LIMITATION.into(),
                provisioning_policy: super::RECEIVER_PROVISIONING_POLICY.into(),
                raw_headroom_bytes_per_nonzero_incoming_component: 1_200,
                sender_framing_cells_per_nonzero_outgoing_component:
                    super::SENDER_FRAMING_CELLS_PER_NONZERO_OUTGOING_COMPONENT,
                sender_framing_formula: super::SENDER_FRAMING_FORMULA.into(),
                sender_framing_policy: super::SENDER_FRAMING_POLICY.into(),
                release_policy: super::RECEIVER_RELEASE_POLICY.into(),
                request_activation_policy:
                    "zero-required-insert-count-nonblocking-qpack-chaff-header-block;positive-final-size-with-contiguous-unique-request-stream-offsets-[0,final-size)-and-fin-peer-acknowledged-under-molded-outgoing-cells"
                        .into(),
                request_prefix_delivery_precondition:
                    super::RECEIVER_REQUEST_PREFIX_DELIVERY_PRECONDITION.into(),
                resource_precondition: super::RECEIVER_RESOURCE_PRECONDITION.into(),
                reserve_lifecycle_policy:
                    super::RECEIVER_RESERVE_LIFECYCLE_POLICY.into(),
                reserve_policy: super::RECEIVER_RESERVE_POLICY.into(),
                qualified_chaff_manifest_policy:
                    super::RECEIVER_QUALIFIED_CHAFF_MANIFEST_POLICY.into(),
                qualified_chaff_response_policy:
                    super::RECEIVER_QUALIFIED_CHAFF_RESPONSE_POLICY.into(),
                staged_prefix_pack_precondition:
                    super::RECEIVER_STAGED_PREFIX_PACK_PRECONDITION.into(),
                qualification_binding_policy:
                    super::RECEIVER_QUALIFICATION_BINDING_POLICY.into(),
            },
            qualification_bindings: vec![
                super::WalkieTalkieQualificationBinding {
                    workload_id: "real".into(),
                    chaff_qualification_sidecar_sha256: "a".repeat(64),
                    prefix_pack_spec_sha256: "b".repeat(64),
                    qualified_chaff_manifest_sha256: "c".repeat(64),
                    application_resource_id: 0,
                    selected_chaff_resource_id: 0,
                    qualified_parallel_chaff_streams: 5,
                    walkie_talkie_required_chaff_streams: 5,
                },
                super::WalkieTalkieQualificationBinding {
                    workload_id: "decoy".into(),
                    chaff_qualification_sidecar_sha256: "d".repeat(64),
                    prefix_pack_spec_sha256: "e".repeat(64),
                    qualified_chaff_manifest_sha256: "f".repeat(64),
                    application_resource_id: 0,
                    selected_chaff_resource_id: 0,
                    qualified_parallel_chaff_streams: 5,
                    walkie_talkie_required_chaff_streams: 5,
                },
            ],
            profiles: vec![super::MoldedProfile {
                real: "real".into(),
                decoy: "decoy".into(),
                matching_cost_packets: 0,
                training_inputs: super::PairTrainingInputs {
                    real: vec!["a".repeat(64)],
                    decoy: vec!["b".repeat(64)],
                },
                variation: super::PairVariation {
                    real: super::ProfileVariation {
                        visit_count: 1,
                        varying_components: 0,
                        maximum_component_spread: 0,
                    },
                    decoy: super::ProfileVariation {
                        visit_count: 1,
                        varying_components: 0,
                        maximum_component_spread: 0,
                    },
                },
                source_envelopes: super::SourceEnvelopes {
                    real: bursts.clone(),
                    decoy: bursts.clone(),
                },
                batch_ends: super::PairBatchEnds {
                    real: vec![bursts.len() - 1],
                    decoy: vec![bursts.len() - 1],
                },
                molded_batch_ends: vec![bursts.len() - 1],
                total_scheduled_bytes: 0,
                bursts,
            }],
        };

        assert!(file.select_profile(1_200, 1_000, "real").is_err());
        assert!(super::checked_scheduled_bytes(u64::MAX, 1_200).is_err());
    }

    #[test]
    fn schema_six_adapts_every_positive_outgoing_and_incoming_component_exactly_once() {
        let input = molded_pair_from_sources(
            r#"[
                {"outgoing": 2, "incoming": 0, "batch_end": false},
                {"outgoing": 1, "incoming": 3, "batch_end": false},
                {"outgoing": 0, "incoming": 4}
            ]"#,
            r#"[
                {"outgoing": 1, "incoming": 0, "batch_end": false},
                {"outgoing": 3, "incoming": 2, "batch_end": false},
                {"outgoing": 0, "incoming": 5}
            ]"#,
        );
        let defense = WalkieTalkie::from_json(&config(1_200), 1_200, &input)
            .expect("strict schema-six adapted mould");

        assert_eq!(
            defense.molded,
            [
                super::BurstPair {
                    outgoing: 3,
                    incoming: 0,
                },
                super::BurstPair {
                    outgoing: 4,
                    incoming: 4,
                },
                super::BurstPair {
                    outgoing: 0,
                    incoming: 6,
                },
            ]
        );
        assert_eq!(defense.batch_ends, HashSet::from([2]));
    }

    #[test]
    fn schema_six_rejects_unadapted_or_overadapted_bursts() {
        let input = molded_pair_from_sources(
            r#"[{"outgoing": 1, "incoming": 0, "batch_end": false},
                {"outgoing": 0, "incoming": 2}]"#,
            r#"[{"outgoing": 2, "incoming": 0, "batch_end": false},
                {"outgoing": 0, "incoming": 1}]"#,
        );
        let valid: serde_json::Value = serde_json::from_str(&input).expect("valid JSON");
        for bursts in [
            serde_json::json!([
                {"outgoing": 2, "incoming": 0},
                {"outgoing": 0, "incoming": 3}
            ]),
            serde_json::json!([
                {"outgoing": 4, "incoming": 0},
                {"outgoing": 0, "incoming": 3}
            ]),
            serde_json::json!([
                {"outgoing": 3, "incoming": 0},
                {"outgoing": 0, "incoming": 2}
            ]),
            serde_json::json!([
                {"outgoing": 3, "incoming": 0},
                {"outgoing": 0, "incoming": 4}
            ]),
        ] {
            let mut malformed = valid.clone();
            malformed["profiles"][0]["bursts"] = bursts;
            assert!(
                WalkieTalkie::from_json(&config(1_200), 1_200, &malformed.to_string()).is_err()
            );
        }
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "all exact schema-six continuation fields are tested fail closed together"
    )]
    fn receiver_continuation_metadata_and_runtime_allowance_are_fail_closed() {
        let input = molded_pair_from_sources(
            r#"[{"outgoing": 1, "incoming": 1}]"#,
            r#"[{"outgoing": 1, "incoming": 1}]"#,
        );
        for allowance in [0, 999, 1_000] {
            WalkieTalkie::from_json_with_max_stream_data_excess(
                &config(1_200),
                1_200,
                allowance,
                &input,
            )
            .expect("runtime allowance safely dominated by the artifact ceiling");
        }
        assert!(
            WalkieTalkie::from_json_with_max_stream_data_excess(
                &config(1_200),
                1_200,
                1_001,
                &input,
            )
            .is_err()
        );

        let valid: serde_json::Value = serde_json::from_str(&input).expect("valid JSON");
        for (field, mutation) in [
            (
                "allocation_policy",
                serde_json::json!("fragment-across-any-stream"),
            ),
            ("application_order", serde_json::json!("before-mold")),
            (
                "base_allocation_policy",
                serde_json::json!("unacknowledged-chaff-first"),
            ),
            (
                "batch_end_release_policy",
                serde_json::json!("before-application-batch-complete"),
            ),
            (
                "causal_capacity_precondition",
                serde_json::json!("max_chaff_streams>=horizon"),
            ),
            ("cells_per_nonzero_incoming_component", serde_json::json!(2)),
            ("formula", serde_json::json!("different")),
            ("parser_allowance_ceiling_bytes", serde_json::json!(999)),
            (
                "prefix_consumability_precondition",
                serde_json::json!("not-prepared"),
            ),
            (
                "post_outgoing_loss_liveness_limitation",
                serde_json::json!("loss-is-always-live"),
            ),
            ("provisioning_policy", serde_json::json!("lazy")),
            (
                "raw_headroom_bytes_per_nonzero_incoming_component",
                serde_json::json!(1_201),
            ),
            (
                "sender_framing_cells_per_nonzero_outgoing_component",
                serde_json::json!(2),
            ),
            ("sender_framing_formula", serde_json::json!("different")),
            ("sender_framing_policy", serde_json::json!("none")),
            ("release_policy", serde_json::json!("eager")),
            ("request_activation_policy", serde_json::json!("any-byte")),
            (
                "request_prefix_delivery_precondition",
                serde_json::json!("one-reserve-only"),
            ),
            (
                "resource_precondition",
                serde_json::json!("optional-manifest"),
            ),
            (
                "reserve_lifecycle_policy",
                serde_json::json!("leak-reserve"),
            ),
            ("reserve_policy", serde_json::json!("none")),
            (
                "qualified_chaff_manifest_policy",
                serde_json::json!("optional-qualified-manifest"),
            ),
            (
                "qualified_chaff_response_policy",
                serde_json::json!("single-qualification"),
            ),
            (
                "staged_prefix_pack_precondition",
                serde_json::json!("first-cell-only"),
            ),
            (
                "qualification_binding_policy",
                serde_json::json!("hashes-only"),
            ),
        ] {
            let mut malformed = valid.clone();
            malformed["receiver_continuation"][field] = mutation;
            assert!(
                WalkieTalkie::from_json(&config(1_200), 1_200, &malformed.to_string()).is_err(),
                "mutated {field} must be rejected"
            );
        }

        for field in [
            "allocation_policy",
            "application_order",
            "base_allocation_policy",
            "batch_end_release_policy",
            "causal_capacity_precondition",
            "cells_per_nonzero_incoming_component",
            "formula",
            "parser_allowance_ceiling_bytes",
            "prefix_consumability_precondition",
            "post_outgoing_loss_liveness_limitation",
            "provisioning_policy",
            "raw_headroom_bytes_per_nonzero_incoming_component",
            "sender_framing_cells_per_nonzero_outgoing_component",
            "sender_framing_formula",
            "sender_framing_policy",
            "release_policy",
            "request_activation_policy",
            "request_prefix_delivery_precondition",
            "resource_precondition",
            "reserve_lifecycle_policy",
            "reserve_policy",
            "qualified_chaff_manifest_policy",
            "qualified_chaff_response_policy",
            "staged_prefix_pack_precondition",
            "qualification_binding_policy",
        ] {
            let mut malformed = valid.clone();
            malformed["receiver_continuation"]
                .as_object_mut()
                .expect("receiver continuation object")
                .remove(field);
            assert!(
                WalkieTalkie::from_json(&config(1_200), 1_200, &malformed.to_string()).is_err(),
                "missing {field} must be rejected"
            );
        }

        let mut missing = valid.clone();
        missing
            .as_object_mut()
            .expect("top-level object")
            .remove("receiver_continuation");
        assert!(WalkieTalkie::from_json(&config(1_200), 1_200, &missing.to_string()).is_err());

        let mut stale_prefix_key = valid.clone();
        let receiver = stale_prefix_key["receiver_continuation"]
            .as_object_mut()
            .expect("receiver continuation object");
        let staged = receiver
            .remove("staged_prefix_pack_precondition")
            .expect("current staged prefix field");
        receiver.insert("first_cell_prefix_pack_precondition".into(), staged);
        assert!(
            WalkieTalkie::from_json(&config(1_200), 1_200, &stale_prefix_key.to_string()).is_err(),
            "the stale first-cell schema key must fail closed"
        );

        let mut unknown = valid;
        unknown["receiver_continuation"]
            .as_object_mut()
            .expect("receiver continuation object")
            .insert("unexpected".into(), serde_json::json!(true));
        assert!(WalkieTalkie::from_json(&config(1_200), 1_200, &unknown.to_string()).is_err());

        let mut incoming_first: serde_json::Value =
            serde_json::from_str(&molded(r#"[{"outgoing": 0, "incoming": 1}]"#))
                .expect("incoming-first unit fixture");
        incoming_first["generated_by"] = serde_json::json!("external-generator");
        assert!(
            WalkieTalkie::from_json(&config(1_200), 1_200, &incoming_first.to_string()).is_err(),
            "production artifacts must begin with an outgoing carrier component"
        );

        let mut later_zero: serde_json::Value = serde_json::from_str(&molded(
            r#"[
                {"outgoing": 1, "incoming": 1, "batch_end": false},
                {"outgoing": 0, "incoming": 1}
            ]"#,
        ))
        .expect("later-zero unit fixture");
        later_zero["generated_by"] = serde_json::json!("external-generator");
        assert!(
            WalkieTalkie::from_json(&config(1_200), 1_200, &later_zero.to_string()).is_err(),
            "every production component must own an exact staged outgoing carrier"
        );
    }

    #[test]
    fn receiver_continuation_waits_for_base_request_and_batch_end_not_global_debt() {
        let mut before_start = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 0, "incoming": 1}]"#),
        )
        .expect("molded sequence");
        provide_capacity(&mut before_start, 0, u64::MAX);
        let base = before_start.next_event(Duration::ZERO).expect("base cell");
        resolve(
            &mut before_start,
            0,
            base,
            EventOutcome::Satisfied { observed: 1_200 },
        );
        before_start.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::ReceiveCreditConsumed { bytes: 200 },
        });
        assert_eq!(before_start.next_event(Duration::ZERO), None);
        assert_eq!(before_start.next_event_at(), None);

        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 0, "incoming": 1}]"#),
        )
        .expect("molded sequence");
        application_batch_started(&mut defense, 0);

        let first = defense.next_event(Duration::ZERO).expect("base cell");
        assert_eq!(defense.next_event(Duration::ZERO), None);
        assert_eq!(defense.next_event_at(), None);

        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::ReceiveCreditRequested { packet: first },
        });
        // The requested base cell remains wholly in flight: 1,200 bytes is
        // deliberately above the 1,000-byte coalescing ceiling. Only the
        // application batch gate still blocks the distinct continuation.
        assert_eq!(defense.next_event(Duration::from_micros(1)), None);
        application_batch_completed(&mut defense, 2);
        assert_eq!(defense.next_event_at(), Some(Duration::from_micros(2)));
        let continuation = defense
            .next_event(Duration::from_micros(2))
            .expect("distinct continuation despite high live base debt");
        assert_eq!(continuation.direction(), Direction::Incoming);
        assert_eq!(
            defense.last_incoming_event_receiver_continuation(),
            Some(super::ReceiverContinuationDisposition {
                cell_bytes: 1_200,
                parser_ceiling_bytes: 1_000,
            })
        );
    }

    #[test]
    fn receiver_reserve_horizon_counts_all_future_incoming_components() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 1, "incoming": 1, "batch_end": false},
                    {"outgoing": 2, "incoming": 1, "batch_end": false},
                    {"outgoing": 1, "incoming": 1}
                ]"#,
            ),
        )
        .expect("three-component molded sequence");
        assert_eq!(defense.max_receiver_continuation_reserve_horizon(), 3);

        application_batch_started(&mut defense, 0);
        let outgoing = defense.next_event(Duration::ZERO).expect("first outgoing");
        resolve(
            &mut defense,
            1,
            outgoing,
            EventOutcome::Satisfied { observed: 1_200 },
        );
        realize_sender_framing_continuation(&mut defense, 2);
        assert_eq!(
            defense.receiver_continuation_reserve_horizon(),
            3,
            "later positive outgoing components must not shorten the initial reserve horizon"
        );
    }

    #[test]
    fn cloudflare_sized_component_holds_cell_47_as_the_receiver_continuation() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 0, "incoming": 46}]"#),
        )
        .expect("47-cell adapted incoming component");
        application_batch_started(&mut defense, 0);

        let mut base = Vec::new();
        for _ in 0..46 {
            let packet = defense.next_event(Duration::ZERO).expect("base cell");
            assert_eq!(packet.direction(), Direction::Incoming);
            assert_eq!(defense.last_incoming_event_receiver_continuation(), None);
            base.push(packet);
        }
        assert_eq!(defense.next_event(Duration::ZERO), None);

        for packet in base {
            defense.observe(DefenseSignal {
                at: Duration::from_micros(1),
                kind: SignalKind::ReceiveCreditRequested { packet },
            });
            defense.observe(DefenseSignal {
                at: Duration::from_micros(1),
                kind: SignalKind::PayloadBytes {
                    direction: Direction::Incoming,
                    bytes: 1_200,
                    cover: true,
                },
            });
            defense.observe(DefenseSignal {
                at: Duration::from_micros(1),
                kind: SignalKind::ReceiveCreditConsumed { bytes: 1_200 },
            });
        }
        assert_eq!(defense.next_event(Duration::from_micros(1)), None);
        application_batch_completed(&mut defense, 2);
        let held = defense
            .next_event(Duration::from_micros(2))
            .expect("cell 47 is released only as the continuation");
        assert_eq!(held.direction(), Direction::Incoming);
        assert_eq!(held.length(), 1_200);
        assert_eq!(
            defense.last_incoming_event_receiver_continuation(),
            Some(super::ReceiverContinuationDisposition {
                cell_bytes: 1_200,
                parser_ceiling_bytes: 1_000,
            })
        );
    }

    #[test]
    fn subcell_reported_capacity_releases_continuation_before_remaining_base() {
        const CELL: u64 = 1_200;
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 0, "incoming": 46}]"#),
        )
        .expect("47-cell adapted incoming component");
        application_batch_started(&mut defense, 0);
        application_bytes(&mut defense, 0, Direction::Outgoing, 1);
        provide_capacity(&mut defense, 0, 45 * CELL + 1);

        let base: Vec<_> = std::iter::repeat_with(|| {
            let packet = defense.next_event(Duration::ZERO).expect("base cell");
            assert_eq!(defense.last_incoming_event_receiver_continuation(), None);
            packet
        })
        .take(45)
        .collect();
        assert_eq!(defense.incoming_capacity_available(), 1);
        assert_eq!(defense.next_event(Duration::ZERO), None);
        assert_eq!(
            defense.next_event_at(),
            None,
            "the batch gate remains closed"
        );

        for packet in base {
            defense.observe(DefenseSignal {
                at: Duration::from_micros(1),
                kind: SignalKind::ReceiveCreditRequested { packet },
            });
        }
        application_bytes(&mut defense, 1, Direction::Incoming, 1);
        application_batch_completed(&mut defense, 2);
        assert_eq!(defense.next_event_at(), Some(Duration::from_micros(2)));
        let continuation = defense
            .next_event(Duration::from_micros(2))
            .expect("early receiver continuation");
        assert_eq!(continuation.direction(), Direction::Incoming);
        assert!(
            defense
                .last_incoming_event_receiver_continuation()
                .is_some()
        );
        assert!(matches!(
            defense.turn,
            super::Turn::Incoming {
                credits_to_emit: 1,
                receiver_continuation_pending: false,
                ..
            }
        ));
        assert_eq!(defense.next_event(Duration::from_micros(2)), None);

        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::ReceiveCreditRequested {
                packet: continuation,
            },
        });
        // The controller's reserve discharge exposes at least one fresh cell
        // in its next authoritative capacity snapshot.
        provide_capacity(&mut defense, 3, CELL);
        let final_base = defense
            .next_event(Duration::from_micros(3))
            .expect("remaining base cell after reserve discharge");
        assert_eq!(final_base.direction(), Direction::Incoming);
        assert_eq!(defense.last_incoming_event_receiver_continuation(), None);
    }

    #[test]
    fn one_cell_reported_capacity_keeps_final_base_before_continuation() {
        const CELL: u64 = 1_200;
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 0, "incoming": 46}]"#),
        )
        .expect("47-cell adapted incoming component");
        application_batch_started(&mut defense, 0);
        application_bytes(&mut defense, 0, Direction::Outgoing, 1);
        provide_capacity(&mut defense, 0, 46 * CELL);

        let base: Vec<_> =
            std::iter::repeat_with(|| defense.next_event(Duration::ZERO).expect("base cell"))
                .take(45)
                .collect();
        for packet in base {
            defense.observe(DefenseSignal {
                at: Duration::from_micros(1),
                kind: SignalKind::ReceiveCreditRequested { packet },
            });
        }
        application_bytes(&mut defense, 1, Direction::Incoming, 1);
        application_batch_completed(&mut defense, 2);

        let final_base = defense
            .next_event(Duration::from_micros(2))
            .expect("one full reported cell keeps base priority");
        assert_eq!(defense.last_incoming_event_receiver_continuation(), None);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::ReceiveCreditRequested { packet: final_base },
        });
        let continuation = defense
            .next_event(Duration::from_micros(2))
            .expect("continuation follows the requested final base");
        assert_eq!(continuation.direction(), Direction::Incoming);
        assert!(
            defense
                .last_incoming_event_receiver_continuation()
                .is_some()
        );
    }

    #[test]
    fn incoming_turn_never_emits_an_outgoing_defense_event() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 2, "incoming": 2},
                    {"outgoing": 1, "incoming": 1}
                ]"#,
            ),
        )
        .expect("molded sequence");
        application_batch_started(&mut defense, 0);

        let first = defense.next_event(Duration::ZERO).expect("outgoing one");
        let second = defense.next_event(Duration::ZERO).expect("outgoing two");
        assert_eq!(first.direction(), Direction::Outgoing);
        assert_eq!(second.direction(), Direction::Outgoing);
        realize_sender_framing_continuation(&mut defense, 0);
        assert_eq!(defense.next_event(Duration::ZERO), None);

        resolve(
            &mut defense,
            1,
            first,
            EventOutcome::Satisfied { observed: 100 },
        );
        resolve(
            &mut defense,
            2,
            second,
            EventOutcome::Satisfied { observed: 100 },
        );

        let incoming_one = defense
            .next_event(Duration::from_micros(2))
            .expect("incoming credit one");
        let incoming_two = defense
            .next_event(Duration::from_micros(2))
            .expect("incoming credit two");
        assert_eq!(incoming_one.direction(), Direction::Incoming);
        assert_eq!(incoming_two.direction(), Direction::Incoming);
        assert_eq!(defense.next_event(Duration::from_micros(2)), None);

        incoming_wire(&mut defense, 3);
        assert_eq!(defense.next_event(Duration::from_micros(3)), None);
        incoming_wire(&mut defense, 4);
        application_batch_completed(&mut defense, 5);
        realize_receiver_continuation(&mut defense, 5);
        assert!(defense.can_start_application_batch());
        application_batch_started(&mut defense, 6);
        assert_eq!(
            defense
                .next_event(Duration::from_micros(6))
                .map(Packet::direction),
            Some(Direction::Outgoing)
        );
        assert_eq!(defense.mode(), DefenseMode::ChaffAndShape);
    }

    #[test]
    fn outgoing_wire_during_an_incoming_turn_is_a_control_only_crossing() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 0, "incoming": 1}]"#),
        )
        .expect("molded sequence");
        provide_capacity(&mut defense, 0, u64::MAX);
        assert_eq!(
            defense.next_event(Duration::ZERO).map(Packet::direction),
            Some(Direction::Incoming)
        );
        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::Wire {
                direction: Direction::Outgoing,
                length: 77,
            },
        });
        assert_eq!(
            defense.diagnostics().walkie_talkie_control_only_crossings,
            1
        );
    }

    #[test]
    fn application_stream_bytes_during_incoming_turn_are_integrity_failures() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 0, "incoming": 1}]"#),
        )
        .expect("molded sequence");
        provide_capacity(&mut defense, 0, u64::MAX);
        assert_eq!(
            defense.next_event(Duration::ZERO).map(Packet::direction),
            Some(Direction::Incoming)
        );

        defense.observe(DefenseSignal {
            at: Duration::from_micros(1),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Outgoing,
                bytes: 17,
                cover: false,
            },
        });
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Outgoing,
                bytes: 23,
                cover: true,
            },
        });

        assert_eq!(
            defense
                .diagnostics()
                .walkie_talkie_application_stream_crossing_bytes,
            17
        );
    }

    #[test]
    fn missed_outgoing_events_are_retried_before_the_turn_advances() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 1, "incoming": 1}]"#),
        )
        .expect("molded sequence");
        let first = defense.next_event(Duration::ZERO).expect("outgoing");

        resolve(
            &mut defense,
            1,
            first,
            EventOutcome::Missed(MissedSlotReason::NoEndpoint),
        );
        let retry = defense.next_event(Duration::from_micros(1)).expect("retry");
        assert_eq!(retry.direction(), Direction::Outgoing);
        assert_eq!(defense.diagnostics().retried_outgoing_events, 1);
        realize_sender_framing_continuation(&mut defense, 1);
        assert_eq!(defense.next_event(Duration::from_micros(1)), None);

        resolve(
            &mut defense,
            2,
            retry,
            EventOutcome::Satisfied { observed: 100 },
        );
        assert_eq!(
            defense
                .next_event(Duration::from_micros(2))
                .map(Packet::direction),
            Some(Direction::Incoming)
        );
    }

    #[test]
    fn incoming_shortage_never_advances_on_elapsed_time() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 0, "incoming": 2},
                    {"outgoing": 1, "incoming": 1}
                ]"#,
            ),
        )
        .expect("molded sequence");
        application_batch_started(&mut defense, 0);
        provide_capacity(&mut defense, 0, u64::MAX);
        assert_eq!(
            defense.next_event(Duration::ZERO).map(Packet::direction),
            Some(Direction::Incoming)
        );
        assert_eq!(
            defense.next_event(Duration::ZERO).map(Packet::direction),
            Some(Direction::Incoming)
        );
        incoming_wire(&mut defense, 10);
        incoming_wire(&mut defense, 11);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(12),
            kind: SignalKind::ApplicationComplete,
        });

        assert_eq!(defense.next_event(Duration::from_micros(109)), None);
        assert_eq!(defense.next_event(Duration::from_micros(999)), None);
        assert_eq!(defense.next_event(Duration::from_secs(60)), None);
        assert!(!defense.is_complete());
        assert_eq!(
            defense.diagnostics().walkie_talkie_incoming_shortfall_bytes,
            3_600
        );
        application_batch_completed(&mut defense, 60_000_001);
        realize_receiver_continuation(&mut defense, 60_000_001);
        assert!(defense.can_start_application_batch());
        application_batch_started(&mut defense, 60_000_002);
        assert_eq!(
            defense
                .next_event(Duration::from_micros(60_000_002))
                .map(Packet::direction),
            Some(Direction::Outgoing)
        );
    }

    #[test]
    fn incoming_turn_waits_for_both_payload_budget_and_application_batch() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 1, "incoming": 1},
                    {"outgoing": 1, "incoming": 1}
                ]"#,
            ),
        )
        .expect("molded sequence");

        assert!(defense.can_start_application_batch());
        application_batch_started(&mut defense, 0);
        application_bytes(&mut defense, 0, Direction::Outgoing, 100);
        assert!(!defense.can_start_application_batch());

        let outgoing = defense.next_event(Duration::ZERO).expect("outgoing");
        resolve(
            &mut defense,
            1,
            outgoing,
            EventOutcome::Satisfied { observed: 100 },
        );
        realize_sender_framing_continuation(&mut defense, 1);
        assert_eq!(
            defense
                .next_event(Duration::from_micros(1))
                .map(Packet::direction),
            Some(Direction::Incoming)
        );
        incoming_wire(&mut defense, 2);
        application_bytes(&mut defense, 2, Direction::Incoming, 100);

        defense.observe(DefenseSignal {
            at: Duration::from_secs(60),
            kind: SignalKind::ApplicationComplete,
        });
        assert_eq!(
            defense
                .next_event(Duration::from_secs(60))
                .map(Packet::direction),
            None
        );
        assert!(!defense.can_start_application_batch());

        application_batch_completed(&mut defense, 60_000_001);
        realize_receiver_continuation(&mut defense, 60_000_001);
        assert!(defense.can_start_application_batch());
        assert_eq!(defense.next_event(Duration::from_micros(60_000_001)), None);

        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.walkie_talkie_expected_application_batches, 2);
        assert_eq!(diagnostics.walkie_talkie_observed_application_batches, 1);
        assert_eq!(diagnostics.walkie_talkie_application_batch_overflow, 0);
        assert_eq!(diagnostics.walkie_talkie_application_batches_completed, 1);
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 0);
        assert!(!diagnostics.walkie_talkie_application_batch_active);

        application_batch_started(&mut defense, 60_000_002);
        assert_eq!(
            defense
                .next_event(Duration::from_micros(60_000_002))
                .map(Packet::direction),
            Some(Direction::Outgoing)
        );
    }

    #[test]
    fn incoming_events_wait_without_a_busy_deadline_when_capacity_is_absent() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 0, "incoming": 2}]"#),
        )
        .expect("incoming-only molded sequence");

        for at_us in 0..=10_000 {
            assert_eq!(defense.next_event(Duration::from_micros(at_us)), None);
            assert_eq!(defense.next_event_at(), None);
        }
        assert_eq!(defense.incoming_capacity_reserved, 0);
        assert_eq!(defense.incoming_capacity_committed, 0);
    }

    #[test]
    fn repeated_and_partially_growing_capacity_never_double_allocates() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 0, "incoming": 2}]"#),
        )
        .expect("incoming-only molded sequence");

        provide_capacity(&mut defense, 0, 1_250);
        let first = defense.next_event(Duration::ZERO).expect("first cell");
        assert_eq!(first.length(), 1_200);
        assert_eq!(defense.incoming_capacity_reserved, 1_200);
        assert_eq!(defense.next_event(Duration::ZERO), None);

        provide_capacity(&mut defense, 1, 1_250);
        assert_eq!(defense.next_event(Duration::from_micros(1)), None);
        provide_capacity(&mut defense, 2, 1_275);
        assert_eq!(defense.next_event(Duration::from_micros(2)), None);

        defense.observe(DefenseSignal {
            at: Duration::from_micros(3),
            kind: SignalKind::ReceiveCreditRequested { packet: first },
        });
        assert_eq!(defense.incoming_capacity_reserved, 0);
        assert_eq!(defense.incoming_capacity_committed, 1_200);
        provide_capacity(&mut defense, 3, 1_275);
        assert_eq!(defense.next_event(Duration::from_micros(3)), None);

        // Changed values are authoritative remaining-capacity snapshots after
        // the controller has incorporated the accepted first reservation.
        provide_capacity(&mut defense, 4, 50);
        assert_eq!(defense.next_event(Duration::from_micros(4)), None);
        provide_capacity(&mut defense, 5, 75);
        assert_eq!(defense.next_event(Duration::from_micros(5)), None);
        provide_capacity(&mut defense, 6, 1_200);
        let second = defense
            .next_event(Duration::from_micros(6))
            .expect("second cell after full capacity becomes available");
        assert_eq!(second.length(), 1_200);
        assert_eq!(defense.next_event(Duration::from_micros(6)), None);
        assert_eq!(defense.incoming_capacity_reserved, 1_200);
    }

    #[test]
    fn retired_credit_is_a_terminal_bounded_realization_failure() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 1, "incoming": 2}]"#),
        )
        .expect("single-batch molded sequence");
        application_batch_started(&mut defense, 0);
        application_bytes(&mut defense, 0, Direction::Outgoing, 100);
        let outgoing = defense.next_event(Duration::ZERO).expect("outgoing cell");
        resolve(
            &mut defense,
            1,
            outgoing,
            EventOutcome::Satisfied { observed: 100 },
        );
        realize_sender_framing_continuation(&mut defense, 1);
        let credits: Vec<_> = std::iter::repeat_with(|| {
            defense
                .next_event(Duration::from_micros(1))
                .expect("initial incoming credit")
        })
        .take(2)
        .collect();
        for credit in credits {
            resolve(
                &mut defense,
                2,
                credit,
                EventOutcome::Satisfied { observed: 100 },
            );
        }
        incoming_payload(&mut defense, 3, 150, false);
        application_bytes(&mut defense, 3, Direction::Incoming, 150);
        retire_credit(&mut defense, 4, 50);

        assert_eq!(
            defense.realization_failure,
            Some(super::RealizationFailure::ReceiveCreditRetired)
        );
        for at_us in 4..=10_000 {
            assert_eq!(defense.next_event(Duration::from_micros(at_us)), None);
        }
        assert_eq!(defense.next_event_at(), None);
        assert!(defense.can_release_chaff_send_shaping());

        application_batch_completed(&mut defense, 10_001);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(10_002),
            kind: SignalKind::ApplicationComplete,
        });
        assert!(defense.is_complete());
        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.walkie_talkie_target_incoming_cells, 3);
        assert_eq!(diagnostics.walkie_talkie_observed_incoming_cells, 1);
        assert_eq!(diagnostics.walkie_talkie_incoming_shortfall_bytes, 3_450);
        assert_eq!(diagnostics.walkie_talkie_incoming_overflow_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_target_observed_burst_l1, 2);
        assert_eq!(diagnostics.walkie_talkie_expected_application_batches, 1);
        assert_eq!(diagnostics.walkie_talkie_application_batches_completed, 1);
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 0);
        assert_eq!(diagnostics.walkie_talkie_source_envelope_overflow_cells, 0);
    }

    #[test]
    fn retired_credit_aborts_before_a_later_application_batch_can_start() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 1, "incoming": 1},
                    {"outgoing": 1, "incoming": 1}
                ]"#,
            ),
        )
        .expect("two-batch molded sequence");
        application_batch_started(&mut defense, 0);
        let outgoing = defense
            .next_event(Duration::ZERO)
            .expect("first outgoing cell");
        resolve(
            &mut defense,
            1,
            outgoing,
            EventOutcome::Satisfied { observed: 100 },
        );
        realize_sender_framing_continuation(&mut defense, 1);
        let credit = defense
            .next_event(Duration::from_micros(1))
            .expect("first incoming credit");
        resolve(
            &mut defense,
            2,
            credit,
            EventOutcome::Satisfied { observed: 100 },
        );
        retire_credit(&mut defense, 3, 100);

        assert_eq!(
            defense.realization_failure,
            Some(super::RealizationFailure::ReceiveCreditRetired)
        );
        assert_eq!(
            defense.terminal_failure(),
            Some("Walkie-Talkie receive credit retired before the incoming mould was realized")
        );
        assert!(!defense.can_start_application_batch());
        assert_eq!(defense.next_event(Duration::from_micros(3)), None);
        assert_eq!(defense.next_event_at(), None);

        application_batch_completed(&mut defense, 4);
        assert!(!defense.can_start_application_batch());
        assert_eq!(defense.next_event(Duration::from_secs(120)), None);
        assert_eq!(defense.next_event_at(), None);
        assert_eq!(defense.diagnostics().retried_outgoing_events, 0);
        assert_eq!(
            defense
                .diagnostics()
                .walkie_talkie_observed_application_batches,
            1
        );
    }

    #[test]
    fn batch_completion_releases_one_continuation_while_base_credit_is_in_flight() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 0, "incoming": 2}]"#),
        )
        .expect("single-batch molded sequence");
        application_batch_started(&mut defense, 0);
        application_bytes(&mut defense, 0, Direction::Outgoing, 50);

        let credits: Vec<_> = std::iter::repeat_with(|| {
            defense
                .next_event(Duration::ZERO)
                .expect("initial incoming credit")
        })
        .take(2)
        .collect();
        for credit in credits {
            resolve(
                &mut defense,
                1,
                credit,
                EventOutcome::Satisfied { observed: 100 },
            );
        }
        incoming_payload(&mut defense, 2, 50, false);
        application_bytes(&mut defense, 2, Direction::Incoming, 50);
        application_batch_completed(&mut defense, 3);

        // The two requested base cells still have 2,350 bytes outstanding.
        // The held cell is a distinct prefix, so high/split global debt no
        // longer suppresses it. It remains one-shot.
        let continuation = defense
            .next_event(Duration::from_micros(3))
            .expect("one distinct continuation while base remains in flight");
        assert_eq!(continuation.direction(), Direction::Incoming);
        assert!(
            defense
                .last_incoming_event_receiver_continuation()
                .is_some()
        );
        assert_eq!(defense.next_event(Duration::from_micros(3)), None);
        retire_credit(&mut defense, 4, 50);
        assert_eq!(
            defense.realization_failure,
            Some(super::RealizationFailure::ReceiveCreditRetired)
        );
        assert_eq!(defense.next_event(Duration::from_micros(4)), None);
        assert_eq!(defense.next_event_at(), None);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(5),
            kind: SignalKind::ApplicationComplete,
        });

        let diagnostics = defense.diagnostics();
        assert!(defense.is_complete());
        assert_eq!(diagnostics.walkie_talkie_observed_incoming_cells, 1);
        assert_eq!(diagnostics.walkie_talkie_incoming_shortfall_bytes, 3_550);
        assert_eq!(diagnostics.walkie_talkie_incoming_overflow_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_target_observed_burst_l1, 2);
    }

    #[test]
    fn initial_allowance_does_not_retire_scheduled_credit_early() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 0, "incoming": 1}]"#),
        )
        .expect("single incoming cell");
        application_batch_started(&mut defense, 0);
        provide_capacity(&mut defense, 0, 1_200);
        let credit = defense.next_event(Duration::ZERO).expect("incoming credit");
        resolve(
            &mut defense,
            1,
            credit,
            EventOutcome::Satisfied { observed: 1_200 },
        );
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::PayloadBytes {
                direction: Direction::Incoming,
                bytes: 1_200,
                cover: true,
            },
        });
        // Raw offsets 0..16 came from the initial transport allowance. Only
        // 1,184 bytes intersect the scheduled [16, 1,216) range.
        defense.observe(DefenseSignal {
            at: Duration::from_micros(2),
            kind: SignalKind::ReceiveCreditConsumed { bytes: 1_184 },
        });
        application_batch_completed(&mut defense, 2);
        let continuation = defense
            .next_event(Duration::from_micros(2))
            .expect("receiver-continuation credit");
        resolve(
            &mut defense,
            2,
            continuation,
            EventOutcome::Satisfied { observed: 1_200 },
        );
        incoming_payload(&mut defense, 3, 1_200, false);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(4),
            kind: SignalKind::ApplicationComplete,
        });

        assert!(!defense.is_complete());
        assert_eq!(defense.next_event(Duration::from_secs(60)), None);

        retire_credit(&mut defense, 60_000_001, 16);
        assert!(defense.is_complete());
        assert_eq!(
            defense.diagnostics().walkie_talkie_incoming_shortfall_bytes,
            0
        );
    }

    #[test]
    fn impossible_incoming_slot_fails_once_without_a_retry_loop() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 1, "incoming": 1}]"#),
        )
        .expect("single-batch molded sequence");
        application_batch_started(&mut defense, 0);
        application_bytes(&mut defense, 0, Direction::Outgoing, 100);
        let outgoing = defense.next_event(Duration::ZERO).expect("outgoing cell");
        resolve(
            &mut defense,
            1,
            outgoing,
            EventOutcome::Satisfied { observed: 100 },
        );
        realize_sender_framing_continuation(&mut defense, 1);
        let initial = defense
            .next_event(Duration::from_micros(1))
            .expect("initial incoming credit");
        resolve(
            &mut defense,
            2,
            initial,
            EventOutcome::Missed(MissedSlotReason::InsufficientIncomingCapacity),
        );
        assert_eq!(
            defense.realization_failure,
            Some(super::RealizationFailure::IncomingSlotMissed(
                MissedSlotReason::InsufficientIncomingCapacity
            ))
        );
        for at in 2..=24_000 {
            assert_eq!(defense.next_event(Duration::from_micros(at)), None);
        }
        assert_eq!(defense.next_event_at(), None);
        provide_capacity(&mut defense, 24_001, 100);
        provide_capacity(&mut defense, 24_002, 200);
        assert_eq!(defense.next_event(Duration::from_micros(24_002)), None);
        assert_eq!(
            defense.diagnostics().walkie_talkie_incoming_shortfall_bytes,
            2_400
        );
        application_batch_completed(&mut defense, 24_003);
        defense.observe(DefenseSignal {
            at: Duration::from_micros(24_004),
            kind: SignalKind::ApplicationComplete,
        });
        assert!(defense.is_complete());
    }

    #[test]
    fn direction_transitions_inside_one_batch_do_not_open_a_new_batch() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 1, "incoming": 1, "batch_end": false},
                    {"outgoing": 1, "incoming": 1, "batch_end": true}
                ]"#,
            ),
        )
        .expect("valid multi-burst application batch");
        application_batch_started(&mut defense, 0);

        let first_outgoing = defense
            .next_event(Duration::ZERO)
            .expect("first outgoing cell");
        resolve(
            &mut defense,
            0,
            first_outgoing,
            EventOutcome::Satisfied { observed: 100 },
        );
        realize_sender_framing_continuation(&mut defense, 0);
        assert_eq!(
            defense.next_event(Duration::ZERO),
            Packet::new(Duration::ZERO, Direction::Incoming, 1_200).ok()
        );
        incoming_wire(&mut defense, 0);
        realize_receiver_continuation(&mut defense, 0);

        assert!(!defense.can_start_application_batch());
        let second_outgoing = defense
            .next_event(Duration::ZERO)
            .expect("same batch's second outgoing burst");
        resolve(
            &mut defense,
            0,
            second_outgoing,
            EventOutcome::Satisfied { observed: 100 },
        );
        realize_sender_framing_continuation(&mut defense, 0);
        assert_eq!(
            defense.next_event(Duration::ZERO),
            Packet::new(Duration::ZERO, Direction::Incoming, 1_200).ok()
        );
        incoming_wire(&mut defense, 0);
        assert_eq!(defense.next_event(Duration::ZERO), None);
        assert!(!matches!(defense.turn, super::Turn::Done));

        application_batch_completed(&mut defense, 0);
        realize_receiver_continuation(&mut defense, 0);
        assert!(matches!(defense.turn, super::Turn::Done));
    }

    #[test]
    fn longer_decoy_suffix_is_chaff_only_and_batch_overflow_is_diagnostic() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded_pair(
                r#"[{"outgoing": 1, "incoming": 1}]"#,
                r#"[
                    {"outgoing": 1, "incoming": 1},
                    {"outgoing": 2, "incoming": 1}
                ]"#,
            ),
        )
        .expect("asymmetric molded sequence");

        assert_eq!(defense.source_batch_ends, [0]);
        assert_eq!(defense.batch_ends.len(), 2);
        assert!(defense.batch_ends.contains(&0));
        assert!(defense.batch_ends.contains(&1));
        application_batch_started(&mut defense, 0);
        application_bytes(&mut defense, 0, Direction::Outgoing, 100);
        let first = defense.next_event(Duration::ZERO).expect("source outgoing");
        resolve(
            &mut defense,
            1,
            first,
            EventOutcome::Satisfied { observed: 100 },
        );
        realize_sender_framing_continuation(&mut defense, 1);
        assert_eq!(
            defense
                .next_event(Duration::from_micros(1))
                .map(Packet::direction),
            Some(Direction::Incoming)
        );
        incoming_wire(&mut defense, 2);
        application_bytes(&mut defense, 2, Direction::Incoming, 100);
        application_batch_completed(&mut defense, 3);
        realize_receiver_continuation(&mut defense, 3);

        assert!(!defense.can_start_application_batch());
        for at_us in [3, 4, 5] {
            let suffix = defense
                .next_event(Duration::from_micros(at_us))
                .expect("decoy-only outgoing suffix");
            assert_eq!(suffix.direction(), Direction::Outgoing);
            resolve(
                &mut defense,
                at_us,
                suffix,
                EventOutcome::Satisfied { observed: 100 },
            );
        }
        assert_eq!(
            defense
                .next_event(Duration::from_micros(5))
                .map(Packet::direction),
            Some(Direction::Incoming)
        );
        incoming_wire(&mut defense, 6);
        realize_receiver_continuation(&mut defense, 6);
        assert!(matches!(defense.turn, super::Turn::Done));
        assert!(!defense.can_start_application_batch());

        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.walkie_talkie_expected_application_batches, 1);
        assert_eq!(diagnostics.walkie_talkie_observed_application_batches, 1);
        assert_eq!(diagnostics.walkie_talkie_application_batch_overflow, 0);
        assert_eq!(diagnostics.walkie_talkie_application_batches_completed, 1);
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 0);

        application_batch_started(&mut defense, 6);
        let overflow = defense.diagnostics();
        assert_eq!(overflow.walkie_talkie_observed_application_batches, 2);
        assert_eq!(overflow.walkie_talkie_application_batch_overflow, 1);
        assert_eq!(overflow.walkie_talkie_batch_lifecycle_errors, 1);
    }

    #[test]
    fn shorter_selected_batch_finishes_its_common_chaff_suffix_before_the_next_batch() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded_pair(
                r#"[
                    {"outgoing": 1, "incoming": 1},
                    {"outgoing": 1, "incoming": 1}
                ]"#,
                r#"[
                    {"outgoing": 1, "incoming": 1, "batch_end": false},
                    {"outgoing": 1, "incoming": 1},
                    {"outgoing": 1, "incoming": 1}
                ]"#,
            ),
        )
        .expect("asymmetric batch-aware mould");
        assert_eq!(defense.source_batch_ends, [0, 1]);
        assert_eq!(defense.batch_ends, HashSet::from([1, 2]));

        application_batch_started(&mut defense, 0);
        application_bytes(&mut defense, 0, Direction::Outgoing, 100);
        let application_outgoing = defense
            .next_event(Duration::ZERO)
            .expect("selected component outgoing cell");
        resolve(
            &mut defense,
            1,
            application_outgoing,
            EventOutcome::Satisfied { observed: 100 },
        );
        realize_sender_framing_continuation(&mut defense, 1);
        assert_eq!(
            defense
                .next_event(Duration::from_micros(1))
                .map(Packet::direction),
            Some(Direction::Incoming)
        );
        incoming_wire(&mut defense, 2);
        realize_receiver_continuation(&mut defense, 2);
        application_bytes(&mut defense, 2, Direction::Incoming, 100);
        application_batch_completed(&mut defense, 3);

        assert!(!defense.can_start_application_batch());
        let suffix_outgoing = defense
            .next_event(Duration::from_micros(3))
            .expect("common first-batch chaff suffix");
        assert_eq!(suffix_outgoing.direction(), Direction::Outgoing);
        resolve(
            &mut defense,
            4,
            suffix_outgoing,
            EventOutcome::Satisfied { observed: 100 },
        );
        realize_sender_framing_continuation(&mut defense, 4);
        assert_eq!(
            defense
                .next_event(Duration::from_micros(4))
                .map(Packet::direction),
            Some(Direction::Incoming)
        );
        incoming_wire(&mut defense, 5);
        realize_receiver_continuation(&mut defense, 5);

        assert!(defense.can_start_application_batch());
        assert_eq!(defense.next_event(Duration::from_micros(5)), None);
        assert_eq!(
            defense
                .diagnostics()
                .walkie_talkie_observed_application_batches,
            1
        );
    }

    #[test]
    fn natural_ingress_outside_an_incoming_turn_is_a_lifecycle_failure() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 1, "incoming": 1}]"#),
        )
        .expect("moulded sequence");
        application_batch_started(&mut defense, 0);

        application_bytes(&mut defense, 1, Direction::Incoming, 37);

        let diagnostics = defense.diagnostics();
        assert_eq!(
            diagnostics.walkie_talkie_application_stream_crossing_bytes,
            37
        );
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 1);
        assert_eq!(diagnostics.walkie_talkie_natural_incoming_bytes, 37);
    }

    #[test]
    fn evaluation_over_source_envelope_is_diagnostic_even_when_pair_mould_is_exact() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded_pair(
                r#"[{"outgoing": 1, "incoming": 1}]"#,
                r#"[{"outgoing": 3, "incoming": 3}]"#,
            ),
        )
        .expect("asymmetric molded sequence");

        application_batch_started(&mut defense, 0);
        application_bytes(&mut defense, 0, Direction::Outgoing, 2_400);
        for at_us in 1..=4 {
            let outgoing = defense
                .next_event(Duration::from_micros(at_us))
                .expect("molded outgoing cell");
            assert_eq!(outgoing.direction(), Direction::Outgoing);
            resolve(
                &mut defense,
                at_us,
                outgoing,
                EventOutcome::Satisfied { observed: 100 },
            );
        }
        application_bytes(&mut defense, 4, Direction::Incoming, 2_400);
        for at_us in 4..=6 {
            let incoming = defense
                .next_event(Duration::from_micros(at_us))
                .expect("molded incoming cell");
            assert_eq!(incoming.direction(), Direction::Incoming);
            incoming_wire(&mut defense, at_us);
        }
        assert_eq!(defense.next_event(Duration::from_micros(7)), None);
        application_batch_completed(&mut defense, 7);
        realize_receiver_continuation(&mut defense, 7);

        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.walkie_talkie_target_outgoing_cells, 4);
        assert_eq!(diagnostics.walkie_talkie_target_incoming_cells, 4);
        assert_eq!(diagnostics.walkie_talkie_observed_outgoing_cells, 4);
        assert_eq!(diagnostics.walkie_talkie_observed_incoming_cells, 4);
        assert_eq!(diagnostics.walkie_talkie_target_observed_burst_l1, 0);
        assert_eq!(diagnostics.walkie_talkie_natural_outgoing_bytes, 2_400);
        assert_eq!(diagnostics.walkie_talkie_natural_incoming_bytes, 2_400);
        assert_eq!(diagnostics.walkie_talkie_source_envelope_overflow_cells, 2);
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 0);
    }

    #[test]
    fn completed_batch_still_waits_for_incoming_payload_budget() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 1, "incoming": 1},
                    {"outgoing": 1, "incoming": 1}
                ]"#,
            ),
        )
        .expect("molded sequence");

        application_batch_started(&mut defense, 0);
        application_batch_completed(&mut defense, 1);
        assert!(!defense.can_start_application_batch());
        let outgoing = defense
            .next_event(Duration::from_micros(1))
            .expect("outgoing");
        resolve(
            &mut defense,
            2,
            outgoing,
            EventOutcome::Satisfied { observed: 100 },
        );
        realize_sender_framing_continuation(&mut defense, 2);
        assert_eq!(
            defense
                .next_event(Duration::from_micros(2))
                .map(Packet::direction),
            Some(Direction::Incoming)
        );

        assert_eq!(defense.next_event(Duration::from_secs(60)), None);
        assert!(!defense.can_start_application_batch());
        incoming_wire(&mut defense, 60_000_001);
        assert!(!defense.can_start_application_batch());
        assert_eq!(
            defense
                .next_event(Duration::from_micros(60_000_001))
                .map(Packet::direction),
            Some(Direction::Incoming)
        );
        incoming_wire(&mut defense, 60_000_002);
        assert!(defense.can_start_application_batch());
        assert_eq!(defense.next_event(Duration::from_micros(60_000_002)), None);
        application_batch_started(&mut defense, 60_000_003);
        assert_eq!(
            defense
                .next_event(Duration::from_micros(60_000_003))
                .map(Packet::direction),
            Some(Direction::Outgoing)
        );
    }

    #[test]
    fn malformed_application_batch_lifecycle_is_diagnostic() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 1, "incoming": 1}]"#),
        )
        .expect("molded sequence");

        application_batch_completed(&mut defense, 0);
        application_batch_started(&mut defense, 1);
        application_batch_started(&mut defense, 2);
        application_bytes(&mut defense, 2, Direction::Outgoing, 100);
        application_bytes(&mut defense, 2, Direction::Incoming, 100);
        application_batch_completed(&mut defense, 3);
        application_batch_completed(&mut defense, 4);

        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.walkie_talkie_expected_application_batches, 1);
        assert_eq!(diagnostics.walkie_talkie_observed_application_batches, 2);
        assert_eq!(diagnostics.walkie_talkie_application_batch_overflow, 1);
        assert_eq!(diagnostics.walkie_talkie_application_batches_completed, 1);
        assert_eq!(diagnostics.walkie_talkie_batch_lifecycle_errors, 4);
        assert!(!diagnostics.walkie_talkie_application_batch_active);
    }

    #[test]
    fn incoming_payload_satisfies_the_turn() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 0, "incoming": 1},
                    {"outgoing": 1, "incoming": 0}
                ]"#,
            ),
        )
        .expect("molded sequence");
        application_batch_started(&mut defense, 0);
        provide_capacity(&mut defense, 0, u64::MAX);
        assert_eq!(
            defense.next_event(Duration::ZERO).map(Packet::direction),
            Some(Direction::Incoming)
        );

        incoming_wire(&mut defense, 1_000);
        application_batch_completed(&mut defense, 1_000);
        realize_receiver_continuation(&mut defense, 1_000);
        assert!(defense.can_start_application_batch());
        application_batch_started(&mut defense, 1_001);

        assert_eq!(
            defense
                .next_event(Duration::from_micros(1_001))
                .map(Packet::direction),
            Some(Direction::Outgoing)
        );
    }

    #[test]
    fn diagnostics_preserve_each_burst_instead_of_cancelling_counts() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 0, "incoming": 1},
                    {"outgoing": 0, "incoming": 1}
                ]"#,
            ),
        )
        .expect("molded sequence");
        application_batch_started(&mut defense, 0);
        provide_capacity(&mut defense, 0, u64::MAX);
        assert!(defense.next_event(Duration::ZERO).is_some());
        incoming_payload(&mut defense, 1, 2_400, false);
        application_batch_completed(&mut defense, 1);
        assert!(defense.next_event(Duration::from_micros(1)).is_some());

        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.walkie_talkie_target_observed_cell_l1, 2);
        assert_eq!(diagnostics.walkie_talkie_target_observed_burst_l1, 2);
        assert_eq!(
            diagnostics.walkie_talkie_burst_realization,
            [
                WalkieTalkieBurstDiagnostics {
                    index: 0,
                    target_outgoing_cells: 0,
                    target_incoming_cells: 2,
                    observed_outgoing_cells: 0,
                    observed_incoming_cells: 2,
                },
                WalkieTalkieBurstDiagnostics {
                    index: 1,
                    target_outgoing_cells: 0,
                    target_incoming_cells: 2,
                    observed_outgoing_cells: 0,
                    observed_incoming_cells: 0,
                },
            ]
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "the controller must deliver Walkie-Talkie timestamps monotonically")]
    fn non_monotonic_timestamps_violate_the_controller_contract() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 1, "incoming": 0}]"#),
        )
        .expect("molded sequence");
        assert!(defense.next_event(Duration::from_micros(10)).is_some());
        assert!(defense.next_event(Duration::from_micros(9)).is_none());
    }

    #[test]
    fn incoming_only_suffix_keeps_chaff_stream_data_gated_until_done() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 0, "incoming": 2}]"#),
        )
        .expect("molded sequence");
        application_batch_started(&mut defense, 0);
        provide_capacity(&mut defense, 0, u64::MAX);

        assert!(defense.is_outgoing_complete());
        assert!(!defense.can_release_chaff_send_shaping());
        assert_eq!(
            defense.next_event(Duration::ZERO).map(Packet::direction),
            Some(Direction::Incoming)
        );
        assert_eq!(
            defense.next_event(Duration::ZERO).map(Packet::direction),
            Some(Direction::Incoming)
        );
        assert_eq!(defense.next_event(Duration::ZERO), None);
        incoming_wire(&mut defense, 10);
        assert_eq!(defense.next_event(Duration::from_micros(109)), None);
        assert_eq!(defense.next_event(Duration::from_micros(999)), None);
        assert!(!defense.can_release_chaff_send_shaping());
        assert_eq!(defense.next_event(Duration::from_millis(1)), None);
        assert_eq!(
            defense.diagnostics().walkie_talkie_incoming_shortfall_bytes,
            2_400
        );
        incoming_wire(&mut defense, 1_001);
        application_batch_completed(&mut defense, 1_002);
        realize_receiver_continuation(&mut defense, 1_002);
        assert!(defense.can_release_chaff_send_shaping());
    }

    #[test]
    fn incoming_turn_requires_observed_payload_for_liveness() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(
                r#"[
                    {"outgoing": 0, "incoming": 1},
                    {"outgoing": 1, "incoming": 1}
                ]"#,
            ),
        )
        .expect("molded sequence");
        application_batch_started(&mut defense, 0);
        provide_capacity(&mut defense, 0, u64::MAX);
        assert_eq!(
            defense.next_event(Duration::ZERO).map(Packet::direction),
            Some(Direction::Incoming)
        );

        assert_eq!(defense.next_event(Duration::from_secs(60)), None);
        incoming_wire(&mut defense, 60_000_001);
        assert_eq!(defense.next_event(Duration::from_micros(60_000_001)), None);
        application_batch_completed(&mut defense, 60_000_002);
        realize_receiver_continuation(&mut defense, 60_000_002);
        assert!(defense.can_start_application_batch());
        application_batch_started(&mut defense, 60_000_003);
        assert_eq!(
            defense
                .next_event(Duration::from_micros(60_000_003))
                .map(Packet::direction),
            Some(Direction::Outgoing)
        );
    }

    #[test]
    fn completion_requires_both_application_and_molded_sequence() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            &molded(r#"[{"outgoing": 1, "incoming": 0}]"#),
        )
        .expect("molded sequence");
        application_batch_started(&mut defense, 0);
        defense.observe(DefenseSignal {
            at: Duration::ZERO,
            kind: SignalKind::ApplicationComplete,
        });
        assert!(!defense.is_complete());

        let outgoing = defense.next_event(Duration::ZERO).expect("outgoing");
        resolve(
            &mut defense,
            1,
            outgoing,
            EventOutcome::Satisfied { observed: 100 },
        );
        realize_sender_framing_continuation(&mut defense, 1);
        application_batch_completed(&mut defense, 1);

        assert!(defense.is_complete());
        assert!(defense.is_outgoing_complete());
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the deterministic golden keeps every terminal credit and payload signal explicit"
    )]
    fn full_molded_sequence_has_a_golden_schedule() {
        let mut defense = WalkieTalkie::from_json(
            &config(1_200),
            1_200,
            include_str!("../../tests/data/walkie-talkie-golden.json"),
        )
        .expect("molded sequence");
        let outgoing = |at_us| {
            Packet::new(Duration::from_micros(at_us), Direction::Outgoing, 1_200)
                .expect("golden outgoing packet")
        };
        let incoming = |at_us| {
            Packet::new(Duration::from_micros(at_us), Direction::Incoming, 1_200)
                .expect("golden incoming packet")
        };
        let mut script = vec![
            (
                Duration::ZERO,
                SignalKind::Capacity(Capacity {
                    application_incoming: u64::MAX,
                    chaff_incoming: 0,
                }),
            ),
            (Duration::ZERO, SignalKind::ApplicationBatchStarted),
            (
                Duration::from_micros(10),
                SignalKind::Resolved {
                    packet: outgoing(0),
                    outcome: EventOutcome::Satisfied { observed: 1_200 },
                },
            ),
            (
                Duration::from_micros(20),
                SignalKind::Resolved {
                    packet: outgoing(0),
                    outcome: EventOutcome::Satisfied { observed: 1_200 },
                },
            ),
            (
                Duration::from_micros(25),
                SignalKind::Resolved {
                    packet: outgoing(0),
                    outcome: EventOutcome::Satisfied { observed: 1_200 },
                },
            ),
        ];
        for at_us in [30, 40, 45] {
            script.extend([
                (
                    Duration::from_micros(at_us),
                    SignalKind::ReceiveCreditRequested {
                        packet: incoming(25),
                    },
                ),
                (
                    Duration::from_micros(at_us),
                    SignalKind::PayloadBytes {
                        direction: Direction::Incoming,
                        bytes: 1_200,
                        cover: false,
                    },
                ),
                (
                    Duration::from_micros(at_us),
                    SignalKind::ReceiveCreditConsumed { bytes: 1_200 },
                ),
            ]);
        }
        script.push((
            Duration::from_micros(40),
            SignalKind::ApplicationBatchCompleted,
        ));
        for at_us in [50, 55] {
            script.push((
                Duration::from_micros(at_us),
                SignalKind::Resolved {
                    packet: outgoing(40),
                    outcome: EventOutcome::Satisfied { observed: 1_200 },
                },
            ));
        }
        script.push((
            Duration::from_micros(45),
            SignalKind::ApplicationBatchStarted,
        ));
        for at_us in [60, 70] {
            script.extend([
                (
                    Duration::from_micros(at_us),
                    SignalKind::ReceiveCreditRequested {
                        packet: incoming(55),
                    },
                ),
                (
                    Duration::from_micros(at_us),
                    SignalKind::PayloadBytes {
                        direction: Direction::Incoming,
                        bytes: 1_200,
                        cover: true,
                    },
                ),
                (
                    Duration::from_micros(at_us),
                    SignalKind::ReceiveCreditConsumed { bytes: 1_200 },
                ),
            ]);
        }
        script.push((
            Duration::from_micros(60),
            SignalKind::ApplicationBatchCompleted,
        ));
        script.push((Duration::from_micros(70), SignalKind::ApplicationComplete));
        let actual: Vec<_> = drive(&mut defense, &script, Duration::from_micros(70))
            .into_iter()
            .map(|packet| (packet.timestamp_us(), packet.direction(), packet.length()))
            .collect();
        assert_eq!(
            actual,
            [
                (0, Direction::Outgoing, 1_200),
                (0, Direction::Outgoing, 1_200),
                (0, Direction::Outgoing, 1_200),
                (25, Direction::Incoming, 1_200),
                (25, Direction::Incoming, 1_200),
                (40, Direction::Incoming, 1_200),
                (45, Direction::Outgoing, 1_200),
                (45, Direction::Outgoing, 1_200),
                (55, Direction::Incoming, 1_200),
                (60, Direction::Incoming, 1_200),
            ]
        );
        assert!(defense.is_complete());
        assert_eq!(
            defense.diagnostics().walkie_talkie_incoming_shortfall_bytes,
            0
        );
        let diagnostics = defense.diagnostics();
        assert_eq!(diagnostics.walkie_talkie_target_outgoing_cells, 5);
        assert_eq!(diagnostics.walkie_talkie_target_incoming_cells, 5);
        assert_eq!(diagnostics.walkie_talkie_observed_outgoing_cells, 5);
        assert_eq!(diagnostics.walkie_talkie_observed_incoming_cells, 5);
        assert_eq!(diagnostics.walkie_talkie_outgoing_shortfall_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_incoming_shortfall_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_outgoing_overflow_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_incoming_overflow_cells, 0);
        assert_eq!(diagnostics.walkie_talkie_incoming_chaff_bytes, 2_400);
        assert_eq!(diagnostics.walkie_talkie_target_observed_cell_l1, 0);
        assert_eq!(diagnostics.walkie_talkie_target_observed_burst_l1, 0);
        assert_eq!(diagnostics.walkie_talkie_control_only_crossings, 0);
    }
}
