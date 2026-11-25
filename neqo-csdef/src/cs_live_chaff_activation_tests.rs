// Method-only Native config activation vectors; no files, sockets or receipt authority.
use super::*;
use crate::CsBufloConfig;

fn selected() -> QcsdConfig {
    QcsdConfig {
        max_udp_payload_size: 1_200,
        cs_live_chaff_header_progress: true,
        defense: DefenseConfig::CsBuflo(CsBufloConfig {
            parameters: "method-fixture-only.json".into(),
        }),
        ..QcsdConfig::default()
    }
}

#[test]
fn ali_cs_activation_default_is_false_and_old_serialized_shape_is_preserved() {
    let old = QcsdConfig::default();
    assert!(!old.cs_live_chaff_header_progress);
    assert!(old.validate().is_ok());
    let encoded = serde_json::to_value(&old).unwrap();
    assert!(encoded.get("cs_live_chaff_header_progress").is_none());
    let decoded: QcsdConfig = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded, old);
}

#[test]
fn ali_cs_activation_exact_cs_config_records_true_in_resolved_config() {
    let config = selected();
    assert!(config.validate().is_ok());
    let encoded = serde_json::to_value(&config).unwrap();
    assert_eq!(encoded["cs_live_chaff_header_progress"], true);
    let decoded: QcsdConfig = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded, config);
}

#[test]
fn ali_cs_activation_true_refuses_other_modes_without_changing_default() {
    let mut config = QcsdConfig::default();
    config.cs_live_chaff_header_progress = true;
    assert!(config.validate().is_err());
    config.cs_live_chaff_header_progress = false;
    assert!(config.validate().is_ok());
}

#[test]
fn ali_cs_activation_exact_common_receive_and_timing_settings_are_required() {
    for case in 0..7 {
        let mut config = selected();
        match case {
            0 => config.control_interval_us = 5_001,
            1 => config.initial_max_stream_data = 17,
            2 => config.max_stream_data_excess = 1_001,
            3 => config.max_udp_payload_size = 1_450,
            4 => config.max_chaff_streams = 6,
            5 => config.use_empty_resources = true,
            _ => config.drop_unsatisfied_events = true,
        }
        assert!(
            config.validate().is_err(),
            "case{case} changes new explicit policy"
        );
    }
}

#[test]
fn ali_cs_activation_non_boolean_and_unknown_policy_fields_refuse() {
    for wrong in [
        serde_json::json!(1),
        serde_json::json!("true"),
        serde_json::Value::Null,
    ] {
        let mut encoded = serde_json::to_value(selected()).unwrap();
        encoded["cs_live_chaff_header_progress"] = wrong;
        assert!(serde_json::from_value::<QcsdConfig>(encoded).is_err());
    }
    let mut encoded = serde_json::to_value(selected()).unwrap();
    encoded["inferred_header_success"] = serde_json::json!(true);
    assert!(serde_json::from_value::<QcsdConfig>(encoded).is_err());
}
