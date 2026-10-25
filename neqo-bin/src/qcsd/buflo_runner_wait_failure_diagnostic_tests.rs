// Native152 diagnostic-only connected controls; no physical-credit assertion.
use super::*;

fn clocks(monotonic: Option<u64>, tai: Option<u64>, cpu: Option<u64>) -> BufloRunnerWaitClocks {
    BufloRunnerWaitClocks {
        monotonic_before_ns: monotonic,
        tai_before_ns: tai,
        thread_cpu_ns: cpu,
        tai_after_ns: tai,
        monotonic_after_ns: monotonic,
    }
}

fn failure_json(diagnostic: &mut BufloPreSelectionDiagnostic, slot: u64) -> serde_json::Value {
    let mut output = None;
    diagnostic.finish_protected_check_with(
        Some(slot), || Some(1), || Some(1), |raw| output = Some(raw.to_owned()),
    );
    serde_json::from_str(&output.expect("one failure-only emission")).expect("failure JSON")
}

#[test]
fn buflo_runner_wait_diagnostic_separates_monotonic_elapsed_from_tai_movement_without_authority() {
    let start = now();
    for (monotonic_gap, instant_gap) in [(50_293_084, 50_293_084), (1_000_000, 1_000_000)] {
        let mut sample = BufloRunnerWaitSample::begin_with(
            start + Duration::from_nanos(21_330_394),
            RunnerWaitPolicy::KernelBufloAdmission { admission_tai_ns: 1_021_330_394 },
            true, start, clocks(Some(2_000_000_000), Some(1_000_000_000), Some(100)),
        );
        sample.finish_with(
            start + Duration::from_nanos(instant_gap),
            clocks(Some(2_000_000_000 + monotonic_gap), Some(1_050_293_084), Some(125_434)),
            &Ok(Some(ActivityWake::Timer)),
        );
        let mut diagnostic = BufloPreSelectionDiagnostic::new();
        diagnostic.record_runner_wait(sample);
        // A successful protected check never emits or samples failure clocks.
        diagnostic.finish_protected_check_with(None,
            || panic!("not a failure"), || panic!("not a failure"), |_| panic!("not a failure"));
        let value = failure_json(&mut diagnostic, 6_110);
        let row = &value["runner_wait_observations"][0];
        assert_eq!(row["after"]["monotonic_before_ns"].as_u64().unwrap()
            - row["before"]["monotonic_before_ns"].as_u64().unwrap(), monotonic_gap);
        assert_eq!(row["after"]["tai_before_ns"].as_u64().unwrap()
            - row["before"]["tai_before_ns"].as_u64().unwrap(), 50_293_084);
        assert_eq!(row["std_instant_elapsed_ns"], instant_gap);
        assert_eq!(row["selected_wakeup_offset_ns"], 21_330_394);
        assert_eq!(row["admission_tai_ns"], 1_021_330_394);
        assert_eq!(row["returned"], "timer");
        assert_eq!(value["phase_or_deadline_authority"], false);
        assert_eq!(value["selected_wakeup_is_actual_timer_arm"], false);
    }
}

#[test]
fn buflo_runner_wait_diagnostic_saved_red_and_zero_expiry_reasons_remain_strict() {
    for (slot, tick, admission, selection, release, deadline, entered) in [
        (6_110, 3_055, 1_792_897_539_252_111_830, 1_792_897_539_257_111_830,
         1_792_897_539_262_111_830, 1_792_897_539_266_111_830, 1_792_897_539_281_294_188),
        (6_128, 3_064, 1_792_897_539_249_854_509, 1_792_897_539_254_854_509,
         1_792_897_539_259_854_509, 1_792_897_539_263_854_509, 1_792_897_539_291_713_457),
    ] {
        let identity = BufloKernelProtectedSelectionIdentity {
            slot, tick, tick_zero: false, admission_tai_ns: admission,
            selection_tai_ns: selection, release_tai_ns: release,
            preparation_deadline_tai_ns: Some(deadline),
        };
        let step = buflo_kernel_protected_selection_wait_with_clock(&identity, || Ok(entered));
        let BufloKernelProtectedSelectionStep::Failed { entry, error } = step else {
            panic!("actual saved expired TAI must still fail");
        };
        assert_eq!(entry.clock_read_attempts, 1);
        assert_eq!(entry.confirmation_attempts, 0);
        assert_eq!(entry.wait_duration_ns, 0);
        assert!(entry.dispatch_confirmed_tai_ns.is_none());
        assert_eq!(entry.failure.as_ref().unwrap().kind, "selection-expired");
        assert_eq!(error.to_string(), format!(
            "client defence execution failed: BuFLO kernel slot {slot} selection expired in CLOCK_TAI before dispatch"));
        let mut diagnostic = BufloPreSelectionDiagnostic::new();
        let value = failure_json(&mut diagnostic, slot);
        assert_eq!(value["slot"], slot);
        assert_eq!(value["phase_or_deadline_authority"], false);
        assert!(value["runner_wait_observations"].as_array().unwrap().is_empty());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn buflo_runner_wait_diagnostic_connects_real_future_and_expired_timer_returns() {
    for offset in [Some(Duration::from_millis(1)), None] {
        let wakeup = offset.map_or_else(|| now() - Duration::from_millis(1), |d| now() + d);
        let mut sample = BufloRunnerWaitSample::begin(wakeup, RunnerWaitPolicy::Ordinary, true);
        let result = wait_for_runner_activity_until(&[], wakeup, true, RunnerWaitPolicy::Ordinary).await;
        sample.finish(&result);
        assert_eq!(result.expect("original timer result"), Some(ActivityWake::Timer));
        assert_eq!(sample.returned, "timer");
        assert_eq!(sample.wait_policy, "ordinary");
        assert!(sample.admission_tai_ns.is_none());
        if offset.is_none() {
            assert!(sample.selected_wakeup_offset_ns.unwrap() < 0);
        }
        assert!(sample.std_instant_elapsed_ns.is_some());
        assert!(sample.before.monotonic_before_ns.is_some());
        assert!(sample.after.unwrap().monotonic_after_ns.is_some());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn buflo_runner_wait_diagnostic_never_consumes_original_decision_clock_or_admits_expired_hint() {
    let _decision_clock = TestBufloDecisionTaiOverride::sequence([999, 1_000]);
    let policy = RunnerWaitPolicy::KernelBufloAdmission { admission_tai_ns: 1_000 };
    let wakeup = now() - Duration::from_millis(1);
    let mut first = BufloRunnerWaitSample::begin(wakeup, policy, true);
    let result = wait_for_runner_activity_until(&[], wakeup, true, policy).await;
    first.finish(&result);
    assert_eq!(result.expect("not yet admitted"), Some(ActivityWake::Timer));
    let mut second = BufloRunnerWaitSample::begin(wakeup, policy, true);
    let result = wait_for_runner_activity_until(&[], wakeup, true, policy).await;
    second.finish(&result);
    assert_eq!(result.expect("original due admission reentry"), None);
    assert_eq!(first.returned, "timer");
    assert_eq!(second.returned, "no-wake");
    assert_eq!(second.admission_tai_ns, Some(1_000));
}

#[test]
fn buflo_runner_wait_diagnostic_fixed_two_nullable_records_and_existing_json_cap() {
    let start = now();
    let mut diagnostic = BufloPreSelectionDiagnostic::new();
    for index in 0..5 {
        let observed = if index == 3 { Some(u64::MAX) } else { None };
        let mut sample = BufloRunnerWaitSample::begin_with(start, RunnerWaitPolicy::Ordinary,
            false, start, clocks(observed, observed, observed));
        sample.finish_with(start + Duration::from_nanos(index), clocks(observed, observed, observed),
            &Err(Error::SlotInvariant("synthetic result only".into())));
        diagnostic.record_runner_wait(sample);
    }
    for _ in 0..15 {
        diagnostic.record_with("bounded-existing-phase", || Some(u64::MAX), || Some(u64::MAX));
    }
    let value = failure_json(&mut diagnostic, u64::MAX);
    assert_eq!(value["runner_wait_observations_truncated"], true);
    let rows = value["runner_wait_observations"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["std_instant_elapsed_ns"], 3);
    assert_eq!(rows[1]["std_instant_elapsed_ns"], 4);
    assert_eq!(rows[1]["returned"], "error");
    assert_eq!(rows[0]["before"]["monotonic_before_ns"], u64::MAX);
    assert!(rows[1]["before"]["monotonic_before_ns"].is_null());
    assert!(rows[1]["after"]["tai_after_ns"].is_null());
    assert!(serde_json::to_string(&value).unwrap().len() <= BUFLO_POST_SELECTION_MAX_JSON_BYTES);
    diagnostic.finish_protected_check_with(Some(1), || panic!("once"), || panic!("once"), |_| panic!("once"));
}
