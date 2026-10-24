// The subject is the real ReceiverFlowControl primitive, not a cloned model.
// encoded() simulates its frame_sent boundary; no QUIC-wire/Raw proof is issued.
use super::*;
fn state(fc:&ReceiverFlowControl<StreamId>)->(StreamId,u64,u64,u64,u64,Option<u64>,Option<Instant>){
    (fc.subject,fc.max_active,fc.max_allowed,fc.consumed,fc.retired,fc.manual_limit,fc.last_update)
}
fn encoded(fc:&mut ReceiverFlowControl<StreamId>)->u64{
    assert!(fc.frame_needed());let limit=fc.next_limit();fc.frame_sent(limit);
    assert!(!fc.frame_needed());limit
}
fn manual(limit:u64)->ReceiverFlowControl<StreamId>{
    let mut fc=ReceiverFlowControl::new(StreamId::new(8),16);
    assert_eq!(fc.set_manual_limit(16),Ok(QcsdReceiveLimitOutcome::Applied));
    assert!(!fc.frame_needed());fc.set_manual_limit(limit).unwrap();
    assert_eq!(encoded(&mut fc),limit);assert_eq!(fc.set_consumed(16),Ok(16));
    fc.add_retired(16);assert!(!fc.frame_needed());fc
}
#[test]
fn manual_stale_blocked_actual_694_421_509_same_ceiling_only(){
    for limit in [694,421,509]{
        let mut fc=manual(limit);let initial=state(&fc);
        for _ in 0..2{
            fc.peer_blocked(16);assert_eq!(fc.frame_needed(),EXPECT_RECOVERY);
            assert_eq!(fc.next_limit(),limit);assert_eq!(state(&fc),initial);
            if EXPECT_RECOVERY{assert_eq!(encoded(&mut fc),limit);}
            assert_eq!(state(&fc),initial);
        }
    }
}
#[test]
fn manual_stale_blocked_equal_newer_and_initial_do_not_grow(){
    for limit in [694,421,509]{for blocked in [limit,limit+1,u64::MAX]{
        let mut fc=manual(limit);let initial=state(&fc);fc.peer_blocked(blocked);
        assert!(!fc.frame_needed());assert_eq!(state(&fc),initial);assert_eq!(fc.next_limit(),limit);
    }}
    let mut fc=ReceiverFlowControl::new(StreamId::new(8),16);fc.set_manual_limit(16).unwrap();let initial=state(&fc);
    fc.peer_blocked(16);assert!(!fc.frame_needed());assert_eq!(state(&fc),initial);
    fc.peer_blocked(0);assert_eq!(fc.frame_needed(),EXPECT_RECOVERY);
    if EXPECT_RECOVERY{assert_eq!(encoded(&mut fc),16);}assert_eq!(state(&fc),initial);
}
#[test]
fn manual_stale_blocked_pending_higher_limit_unchanged(){
    for limit in [694,421,509]{
        let mut attacked=manual(limit);let mut control=manual(limit);
        attacked.set_manual_limit(limit+1200).unwrap();control.set_manual_limit(limit+1200).unwrap();
        let initial=state(&attacked);assert!(attacked.frame_needed());attacked.peer_blocked(16);
        assert_eq!(state(&attacked),initial);assert_eq!(attacked.frame_needed(),control.frame_needed());
        assert_eq!(attacked.next_limit(),control.next_limit());assert_eq!(encoded(&mut attacked),encoded(&mut control));
        assert_eq!(state(&attacked),state(&control));
    }
}
#[test]
fn manual_stale_blocked_loss_already_pending_duplicate_idempotent(){
    for limit in [694,421,509]{
        let mut fc=manual(limit);let initial=state(&fc);fc.frame_lost(limit);assert!(fc.frame_needed());
        fc.peer_blocked(16);fc.peer_blocked(16);assert!(fc.frame_needed());assert_eq!(state(&fc),initial);
        assert_eq!(encoded(&mut fc),limit);assert_eq!(state(&fc),initial);
        fc.frame_lost(limit-1);assert!(!fc.frame_needed());fc.peer_blocked(16);
        assert_eq!(fc.frame_needed(),EXPECT_RECOVERY);if EXPECT_RECOVERY{assert_eq!(encoded(&mut fc),limit);}
        assert_eq!(state(&fc),initial);
    }
}
#[test]
fn manual_stale_blocked_consumption_retirement_never_grants_credit(){
    for limit in [694,421,509]{
        let mut fc=manual(limit);assert_eq!(fc.set_consumed(limit),Ok(limit-16));fc.add_retired(limit-16);
        fc.retire(limit);fc.send_flowc_update();assert!(!fc.frame_needed());let initial=state(&fc);
        fc.peer_blocked(16);assert_eq!(fc.frame_needed(),EXPECT_RECOVERY);assert_eq!(state(&fc),initial);
        assert_eq!(fc.next_limit(),limit);if EXPECT_RECOVERY{assert_eq!(encoded(&mut fc),limit);}
        assert_eq!(state(&fc),initial);assert_eq!(fc.set_consumed(limit+1),Err(Error::FlowControl));assert_eq!(state(&fc),initial);
    }
}
#[test]
fn manual_stale_blocked_original_automatic_mode_unchanged(){
    let mut fc=ReceiverFlowControl::new(StreamId::new(8),16);fc.peer_blocked(16);assert!(!fc.frame_needed());
    fc.set_max_active(1_048_576);assert_eq!(encoded(&mut fc),1_048_576);let initial=state(&fc);
    fc.peer_blocked(16);assert!(fc.frame_needed());assert_eq!(state(&fc),initial);assert_eq!(encoded(&mut fc),1_048_576);
    fc.peer_blocked(1_048_576);assert!(!fc.frame_needed());fc.frame_lost(1_048_576);
    assert_eq!(encoded(&mut fc),1_048_576);assert_eq!(state(&fc),initial);
}
