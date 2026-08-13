//! Offline command-line oracle for the production defense-parameter parsers.

use std::{env, error::Error, io, path::Path};

use neqo_csdef::{
    TrafficMorphing, TrafficMorphingConfig, WalkieTalkie, WalkieTalkieConfig, WtfPad, WtfPadConfig,
};

const UDP_PAYLOAD_CEILING: u16 = 1_200;

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn validate_traffic_morphing(path: &Path, workloads: &[String]) -> Result<(), Box<dyn Error>> {
    if workloads.is_empty() {
        return Err(invalid_input("Traffic Morphing validation requires workload IDs").into());
    }
    let matrix = path.to_string_lossy().into_owned();
    for workload_id in workloads {
        let config = TrafficMorphingConfig {
            matrix: matrix.clone(),
            workload_id: workload_id.clone(),
            ingress_packet_size: UDP_PAYLOAD_CEILING,
            max_ingress_deficit_bytes: 8_000,
        };
        TrafficMorphing::new(&config, 0, UDP_PAYLOAD_CEILING)?;
    }
    Ok(())
}

fn validate_wtf_pad(path: &Path) -> Result<(), Box<dyn Error>> {
    let config = WtfPadConfig {
        histograms: path.to_string_lossy().into_owned(),
        packet_size: UDP_PAYLOAD_CEILING,
        max_padding_events: 100_000,
    };
    WtfPad::from_file(&config, 0, UDP_PAYLOAD_CEILING, path)?;
    Ok(())
}

fn validate_walkie_talkie(path: &Path, workloads: &[String]) -> Result<(), Box<dyn Error>> {
    if workloads.is_empty() {
        return Err(invalid_input("Walkie-Talkie validation requires workload IDs").into());
    }
    let molded = path.to_string_lossy().into_owned();
    for workload_id in workloads {
        let config = WalkieTalkieConfig {
            molded: molded.clone(),
            workload_id: workload_id.clone(),
            packet_size: UDP_PAYLOAD_CEILING,
        };
        WalkieTalkie::from_file(&config, UDP_PAYLOAD_CEILING, 1_000, path)?;
    }
    Ok(())
}

fn validate_one(kind: &str, path: &Path, workloads: &[String]) -> Result<(), Box<dyn Error>> {
    match kind {
        "traffic_morphing" => validate_traffic_morphing(path, workloads),
        "wtf_pad" => validate_wtf_pad(path),
        "walkie_talkie" => validate_walkie_talkie(path, workloads),
        _ => Err(invalid_input(format!("unsupported parameter kind: {kind}")).into()),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let kind = arguments
        .next()
        .ok_or_else(|| invalid_input("usage: qcsd-validate-parameters KIND PATH [WORKLOAD ...]"))?
        .into_string()
        .map_err(|_| invalid_input("parameter kind is not UTF-8"))?;
    let path = arguments
        .next()
        .ok_or_else(|| invalid_input("usage: qcsd-validate-parameters KIND PATH [WORKLOAD ...]"))?;
    let workloads = arguments
        .map(|value| {
            value
                .into_string()
                .map_err(|_| invalid_input("workload ID is not UTF-8"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let path = Path::new(&path);

    if kind == "bundle" {
        validate_traffic_morphing(&path.join("traffic-morphing.json"), &workloads)?;
        validate_wtf_pad(&path.join("wtf-pad.json"))?;
        validate_walkie_talkie(&path.join("walkie-talkie.json"), &workloads)?;
        return Ok(());
    }
    validate_one(&kind, path, &workloads)
}
