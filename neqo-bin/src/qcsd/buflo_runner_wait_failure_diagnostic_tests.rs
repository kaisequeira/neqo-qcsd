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

// Native153: meaningful single-poll/cancellation controls. These do not assert
// a realized kernel timer arm, domain result or physical packet deadline.
struct Native153ScriptedTimer<'a> {
    polls: std::rc::Rc<std::cell::Cell<u64>>,
    drops: std::rc::Rc<std::cell::Cell<u64>>,
    pending_before_ready: u64,
    expected_waker: &'a std::task::Waker,
    _pinned: std::marker::PhantomPinned,
}

impl std::future::Future for Native153ScriptedTimer<'_> {
    type Output = u64;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>)
        -> std::task::Poll<Self::Output> {
        let this = self.as_ref().get_ref();
        assert!(std::ptr::eq(cx.waker(), this.expected_waker));
        let polled = this.polls.get();
        this.polls.set(polled + 1);
        if polled < this.pending_before_ready {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(37)
        }
    }
}

impl Drop for Native153ScriptedTimer<'_> {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

fn native153_scripted_timer<'a>(pending_before_ready: u64, waker: &'a std::task::Waker)
    -> (Native153ScriptedTimer<'a>, std::rc::Rc<std::cell::Cell<u64>>,
        std::rc::Rc<std::cell::Cell<u64>>) {
    let polls = std::rc::Rc::new(std::cell::Cell::new(0));
    let drops = std::rc::Rc::new(std::cell::Cell::new(0));
    (Native153ScriptedTimer { polls: polls.clone(), drops: drops.clone(),
        pending_before_ready, expected_waker: waker,
        _pinned: std::marker::PhantomPinned }, polls, drops)
}

#[test]
fn buflo_runner_wait_diagnostic_153_single_delegate_preserves_pending_ready_and_context() {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    let (inner, polls, drops) = native153_scripted_timer(2, waker);
    let mut observed = BufloRunnerTimerPollObservation::constructed_with([Some(10); 5]);
    observed.before_await_with([Some(11); 5]);
    let mut clock = 100;
    let mut future = Box::pin(observe_exact_runner_timer_with_clock(inner, Some(&mut observed), || {
        let current = clock;
        clock += 1;
        [Some(current); 5]
    }));
    assert!(std::future::Future::poll(future.as_mut(), &mut cx).is_pending());
    assert_eq!(polls.get(), 1);
    assert!(std::future::Future::poll(future.as_mut(), &mut cx).is_pending());
    assert_eq!(polls.get(), 2);
    assert_eq!(std::future::Future::poll(future.as_mut(), &mut cx), std::task::Poll::Ready(37));
    assert_eq!(polls.get(), 3);
    drop(future);
    assert_eq!(drops.get(), 1);
    assert_eq!(clock, 106);
    assert_eq!(observed.poll_count, 3);
    assert_eq!(observed.pending_poll_count, 2);
    assert_eq!(observed.first_poll_before, Some([Some(100); 5]));
    assert_eq!(observed.first_poll_after, Some([Some(101); 5]));
    assert_eq!(observed.last_pending_after, Some([Some(103); 5]));
    assert_eq!(observed.ready_poll_before, Some([Some(104); 5]));
    assert_eq!(observed.ready_poll_after, Some([Some(105); 5]));
    assert!(!observed.actual_kernel_arm_observed);
}

#[test]
fn buflo_runner_wait_diagnostic_153_already_ready_first_poll_has_no_invented_pending() {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    let (inner, polls, drops) = native153_scripted_timer(0, waker);
    let mut observed = BufloRunnerTimerPollObservation::constructed_with([None; 5]);
    let mut future = Box::pin(observe_exact_runner_timer_with_clock(inner,
        Some(&mut observed), || [None; 5]));
    assert_eq!(std::future::Future::poll(future.as_mut(), &mut cx), std::task::Poll::Ready(37));
    drop(future);
    assert_eq!(polls.get(), 1);
    assert_eq!(drops.get(), 1);
    assert_eq!(observed.poll_count, 1);
    assert_eq!(observed.pending_poll_count, 0);
    assert_eq!(observed.first_poll_before, Some([None; 5]));
    assert_eq!(observed.first_poll_after, Some([None; 5]));
    assert_eq!(observed.ready_poll_before, Some([None; 5]));
    assert_eq!(observed.ready_poll_after, Some([None; 5]));
    assert!(observed.last_pending_after.is_none());
    assert!(!observed.actual_kernel_arm_observed);
}

#[test]
fn buflo_runner_wait_diagnostic_153_original_select_socket_winner_can_leave_timer_unpolled() {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    let (inner, polls, drops) = native153_scripted_timer(2, waker);
    let mut observed = BufloRunnerTimerPollObservation::constructed_with([Some(1); 5]);
    observed.before_await_with([Some(2); 5]);
    let timer = Box::pin(observe_exact_runner_timer_with_clock(inner, Some(&mut observed),
        || panic!("the unchanged left-ready select must not poll its timer loser")));
    let sockets_ready = Box::pin(std::future::ready(17_u64));
    let mut selected = Box::pin(select(sockets_ready, timer));
    let loser = match std::future::Future::poll(selected.as_mut(), &mut cx) {
        std::task::Poll::Ready(futures::future::Either::Left((17, loser))) => loser,
        _ => panic!("same original first readiness operand must win"),
    };
    drop(loser);
    drop(selected);
    assert_eq!(polls.get(), 0);
    assert_eq!(drops.get(), 1);
    assert_eq!(observed.poll_count, 0);
    assert!(observed.timer_constructed.is_some());
    assert!(observed.first_poll_before.is_none());
    assert!(observed.last_pending_after.is_none());
    assert!(observed.ready_poll_before.is_none());
    assert!(!observed.actual_kernel_arm_observed);
}

#[test]
fn buflo_runner_wait_diagnostic_153_none_observer_never_reads_clocks_or_adds_polls() {
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    let (inner, polls, drops) = native153_scripted_timer(0, waker);
    let mut future = Box::pin(observe_exact_runner_timer_with_clock(inner, None,
        || panic!("no observer must mean no clock reads")));
    assert_eq!(std::future::Future::poll(future.as_mut(), &mut cx), std::task::Poll::Ready(37));
    drop(future);
    assert_eq!(polls.get(), 1);
    assert_eq!(drops.get(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn buflo_runner_wait_diagnostic_153_real_timer_and_socket_paths_keep_original_returns() {
    let wakeup = now() + Duration::from_millis(1);
    let mut timer_sample = BufloRunnerWaitSample::begin(wakeup, RunnerWaitPolicy::Ordinary, true);
    let result = wait_for_runner_activity_until_observed(&[], wakeup, true,
        RunnerWaitPolicy::Ordinary, Some(&mut timer_sample)).await;
    timer_sample.finish(&result);
    assert_eq!(result.expect("same actual timer return"), Some(ActivityWake::Timer));
    if let Some(timer) = timer_sample.timer_poll {
        assert!(timer.timer_constructed.is_some());
        assert!(timer.before_await_expression.is_some());
        assert!(timer.first_poll_before.is_some());
        assert!(timer.ready_poll_after.is_some());
        assert!(!timer.actual_kernel_arm_observed);
    } else {
        // An actual pre-first-poll pause may pass the selected hint. The
        // unchanged runner then intentionally uses its relative1us fallback.
        assert!(now() >= wakeup);
    }
    // A real original Tokio Sleep always exercises the same wrapper, whether
    // its first poll is Pending or the timer is already Ready after a pause.
    let timer = tokio::time::sleep_until(tokio::time::Instant::from_std(
        now() + Duration::from_millis(1)));
    let mut direct = BufloRunnerTimerPollObservation::constructed_with(
        buflo_runner_timer_poll_clocks());
    direct.before_await_with(buflo_runner_timer_poll_clocks());
    observe_exact_runner_timer(timer, Some(&mut direct)).await;
    assert!(direct.first_poll_before.is_some());
    assert!(direct.ready_poll_after.is_some());
    assert!(!direct.actual_kernel_arm_observed);

    let socket = Socket::bind("127.0.0.1:0").expect("receiver socket");
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender socket");
    sender.send_to(&[1], socket.local_addr().expect("receiver address")).expect("queue datagram");
    let wakeup = now() + Duration::from_secs(60);
    let mut sample = BufloRunnerWaitSample::begin(wakeup, RunnerWaitPolicy::Ordinary, false);
    let result = tokio::time::timeout(Duration::from_secs(1),
        wait_for_activity_until_with_policy_observed([&socket], wakeup,
            RunnerWaitPolicy::Ordinary, Some(&mut sample)))
        .await.expect("original socket readiness still wins");
    sample.finish(&result);
    assert_eq!(result.expect("same actual socket return"), Some(ActivityWake::SocketReady));
    let timer = sample.timer_poll.expect("Sleep construction is distinct from polling");
    assert!(timer.timer_constructed.is_some());
    assert!(timer.ready_poll_after.is_none());
    assert_eq!(timer.poll_count, timer.pending_poll_count);
    assert!(!timer.actual_kernel_arm_observed);
}

#[test]
fn buflo_runner_wait_diagnostic_153_full_two_records_max_width_stay_under_original_8KiB() {
    let start = now();
    let full = [Some(u64::MAX); 5];
    let mut diagnostic = BufloPreSelectionDiagnostic::new();
    for _ in 0..3 {
        let mut sample = BufloRunnerWaitSample::begin_with(start,
            RunnerWaitPolicy::KernelBufloAdmission { admission_tai_ns: u64::MAX },
            true, start, clocks(Some(u64::MAX), Some(u64::MAX), Some(u64::MAX)));
        sample.selected_wakeup_offset_ns = Some(i64::MIN);
        sample.std_instant_elapsed_ns = Some(u64::MAX);
        sample.returned = "socket-ready";
        sample.after = Some(clocks(Some(u64::MAX), Some(u64::MAX), Some(u64::MAX)));
        sample.timer_poll = Some(BufloRunnerTimerPollObservation {
            timer_constructed: Some(full), before_await_expression: Some(full),
            first_poll_before: Some(full), first_poll_after: Some(full),
            last_pending_after: Some(full), ready_poll_before: Some(full),
            ready_poll_after: Some(full), poll_count: u64::MAX,
            pending_poll_count: u64::MAX, actual_kernel_arm_observed: false,
        });
        diagnostic.record_runner_wait(sample);
    }
    for _ in 0..15 {
        diagnostic.record_with("after-control-rolling-reconciliation",
            || Some(u64::MAX), || Some(u64::MAX));
    }
    let value = failure_json(&mut diagnostic, u64::MAX);
    assert_eq!(value["runner_wait_observation_schema_version"], 2);
    assert_eq!(value["runner_wait_observations"].as_array().unwrap().len(), 2);
    assert_eq!(value["runner_wait_observations_truncated"], true);
    assert_eq!(value["selected_wakeup_is_actual_timer_arm"], false);
    assert!(serde_json::to_vec(&value).unwrap().len() <= BUFLO_POST_SELECTION_MAX_JSON_BYTES);
}

#[test]
fn buflo_runner_wait_diagnostic_153_enqueue_gap_two_thread_clocks_are_separate_and_bounded() {
    let mut runner = timed_egress::BufloEnqueueGapDiagnostic::runner(4136);
    runner.bind_job(2068);
    runner.record_with("runner-confirm-return", [Some(1); 5]);
    runner.record_with("runner-before-exact-main", [Some(2); 5]);
    runner.record_with("runner-main-result-error", [Some(3); 5]);
    runner.emit_failure_with(false, |_| panic!("success has no failure log"));
    let mut a = None;
    runner.emit_failure_with(true, |raw| a = Some(serde_json::from_str::<serde_json::Value>(raw).unwrap()));
    runner.emit_failure_with(true, |_| panic!("emit at most once"));
    let a = a.unwrap();
    let mut helper = timed_egress::BufloEnqueueGapDiagnostic::helper(2068, 0, 101, 100, [Some(4); 5]);
    helper.record_with("helper-command-received", [Some(5); 5]);
    helper.record_with("helper-before-compound-job", [Some(6); 5]);
    helper.record_with("helper-compound-result", [Some(7); 5]);
    let mut b = None;
    helper.emit_failure_with(true, |raw| b = Some(serde_json::from_str::<serde_json::Value>(raw).unwrap()));
    let b = b.unwrap();
    assert_eq!(a["job_id"], b["job_id"]);
    assert_eq!(a["side"], "runner");
    assert_eq!(b["side"], "helper");
    assert_eq!(b["runner_submit_clocks"], serde_json::json!([4, 4, 4, 4, 4]));
    assert_eq!(b["samples"][0]["clocks"], serde_json::json!([5, 5, 5, 5, 5]));
    for v in [&a, &b] {
        assert_eq!(v["phase_or_deadline_authority"], false);
        assert_eq!(v["actual_kernel_enqueue_or_wake_observed"], false);
        assert_eq!(v["cross_thread_CPU_values_are_not_subtractable"], true);
        assert!(serde_json::to_vec(v).unwrap().len() <= 4096);
    }
}

#[test]
fn buflo_runner_wait_diagnostic_153_enqueue_gap_max_width_nullable_and_overflow_do_not_waive() {
    for clocks in [[None; 5], [Some(u64::MAX); 5]] {
        let mut helper = timed_egress::BufloEnqueueGapDiagnostic::helper(
            u64::MAX, usize::MAX, u64::MAX, u64::MAX, clocks);
        for _ in 0..6 {
            helper.record_with("helper-before-compound-job", clocks);
        }
        let mut emitted = None;
        helper.emit_failure_with(true, |raw| emitted = Some(raw.to_owned()));
        let raw = emitted.expect("bounded independent failure JSON");
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(raw.len() <= 4096);
        assert_eq!(value["samples"].as_array().unwrap().len(), 4);
        assert_eq!(value["truncated"], true);
        assert_eq!(value["operation_failed"], true);
        assert_eq!(value["phase_or_deadline_authority"], false);
    }
}
