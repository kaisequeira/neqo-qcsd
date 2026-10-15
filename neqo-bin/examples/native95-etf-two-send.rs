// Licensed under the Apache License, Version 2.0 or the MIT license.
//! Two real owned sends on an operator-prepared veth/ETF route, without HTTP.
//!
//! Run only in a disposable, single-threaded privileged process with the exact
//! veth/ETF fixture and a listening UDP peer already prepared by the operator:
//! `native95-etf-two-send SOURCE_SOCKET DEST_SOCKET UID GID HELPER_CPU`.
//! Set `QCSD_NATIVE95_ETF_INTERFACE` to that fixture's veth interface. This
//! engineering regression installs no qdisc and issues no capture credit.

#[cfg(all(target_os = "linux", feature = "qcsd", not(test)))]
#[path = "../src/qcsd/timed_egress.rs"]
mod timed_egress;

#[cfg(all(target_os = "linux", feature = "qcsd", not(test)))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        net::{SocketAddr, UdpSocket},
        num::NonZeroUsize,
        time::Duration,
    };

    use neqo_common::{Tos, datagram};
    use timed_egress::*;

    let args: Vec<_> = std::env::args().collect();
    if args.len() != 6 {
        return Err("SOURCE_SOCKET DEST_SOCKET UID GID HELPER_CPU required".into());
    }
    let source: SocketAddr = args[1].parse()?;
    let destination: SocketAddr = args[2].parse()?;
    if !source.is_ipv4()
        || !destination.is_ipv4()
        || source.ip().is_loopback()
        || source.ip().is_unspecified()
        || destination.ip().is_loopback()
        || destination.ip().is_unspecified()
        || destination.port() == 0
    {
        return Err(
            "two-send regression requires explicit non-loopback IPv4 veth endpoints".into(),
        );
    }
    let interface = std::env::var("QCSD_NATIVE95_ETF_INTERFACE")?;
    if interface.is_empty()
        || !interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err("canonical veth interface name required".into());
    }
    let sysfs = std::path::Path::new("/sys/class/net").join(&interface);
    let ifindex: u32 = std::fs::read_to_string(sysfs.join("ifindex"))?
        .trim()
        .parse()?;
    let iflink: u32 = std::fs::read_to_string(sysfs.join("iflink"))?
        .trim()
        .parse()?;
    if ifindex == 0 || iflink == 0 {
        return Err("fixture requires positive interface and peer indices".into());
    }
    // Interface indices belong to their respective network namespaces. A
    // genuine veth peer can have the same numeric index in another namespace.
    let inspected = std::process::Command::new("/usr/sbin/ip")
        .args(["-details", "-json", "link", "show", "dev", &interface])
        .output()?;
    if !inspected.status.success() {
        return Err("cannot inspect the operator-owned veth interface".into());
    }
    let links: Vec<serde_json::Value> = serde_json::from_slice(&inspected.stdout)?;
    let [link] = links.as_slice() else {
        return Err("exactly one inspected veth interface required".into());
    };
    if link["ifname"].as_str() != Some(interface.as_str())
        || link["ifindex"].as_u64() != Some(u64::from(ifindex))
        || link["linkinfo"]["info_kind"].as_str() != Some("veth")
    {
        return Err("inspected interface must match the actual sysfs veth identity".into());
    }
    let sender = UdpSocket::bind(source)?;
    sender.set_nonblocking(true)?;
    let source = sender.local_addr()?;
    let prepared = PreparedTimedEgressSocket::configure(&sender, EtfContract::STRICT)?;
    let scheduling = libc::sched_param { sched_priority: 1 };
    let status = unsafe {
        // SAFETY: pid zero selects only this single-threaded process; scheduling
        // points to a live sched_param for the documented SCHED_RR operation.
        libc::sched_setscheduler(0, libc::SCHED_RR, &scheduling)
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let privilege = drop_process_privileges_permanently(PrivilegeDropTarget {
        uid: args[3].parse()?,
        gid: args[4].parse()?,
    })?;
    let mut active = prepared.activate_after_privilege_drop()?;
    active.enable_layered_timestamp_feedback()?;
    let contract =
        HelperThreadContract::portable_etf_helper("native95-etf-two-send-v1", args[5].parse()?);
    let mut helper = TimedEgressHelper::spawn_after_privilege_drop(
        vec![active],
        contract,
        PostMainInventoryContract {
            expected_endpoint_sockets: 1,
            credit_owner_capacity: 1,
            max_datagrams_per_owner: 1,
            max_post_main_datagrams: 1,
        },
    )?;
    let mut jobs = Vec::new();
    let exercise = (|| -> Result<(), Box<dyn std::error::Error>> {
        for job_id in 0..2 {
            let clock_before = sample_kernel_clock_bracket()?;
            let release = clock_tai_ns()?
                .checked_add(100_000_000)
                .ok_or("release overflow")?;
            let batch = datagram::Batch::new(
                source,
                destination,
                Tos::default(),
                NonZeroUsize::new(1_200).ok_or("payload size")?,
                vec![0x95; 1_200],
            );
            let txtime = release.checked_add(10_000_000).ok_or("txtime overflow")?;
            let deadline = release.checked_add(5_000_000).ok_or("deadline overflow")?;
            let result = helper.transmit_main(
                job_id,
                0,
                batch,
                txtime,
                deadline,
                Duration::from_millis(500),
            )?;
            let close = helper.finish_job(job_id)?;
            let clock_after = sample_kernel_clock_bracket()?;
            let offset = |sample: &TaiBracketedClockSample| -> Result<(u64, u64), Box<dyn std::error::Error>> {
                Ok((sample.tai_before_ns.checked_sub(sample.clock_ns).ok_or("TAI offset underflow")?,
                    sample.tai_after_ns.checked_sub(sample.clock_ns).ok_or("TAI offset underflow")?))
            };
            let (before_lower, before_upper) = offset(&clock_before.realtime)?;
            let (after_lower, after_upper) = offset(&clock_after.realtime)?;
            let lower_offset = before_lower.max(after_lower);
            let upper_offset = before_upper.min(after_upper);
            let physical_lower = result
                .outcome
                .tx_software_realtime_ns
                .checked_add(lower_offset)
                .ok_or("physical time overflow")?;
            let physical_upper = result
                .outcome
                .tx_software_realtime_ns
                .checked_add(upper_offset)
                .ok_or("physical time overflow")?;
            let physical_window_valid = lower_offset <= upper_offset
                && physical_lower >= release
                && physical_upper < deadline;
            jobs.push(serde_json::json!({"job_id":job_id,"release_tai_ns":release,
                "clock_before":clock_before,"clock_after":clock_after,
                "physical_lower_tai_ns":physical_lower,"physical_upper_tai_ns":physical_upper,
                "physical_window_valid":physical_window_valid,"result":result,"close":close}));
            if !physical_window_valid {
                return Err("original half-open five-millisecond physical window refused".into());
            }
            // Make later virtual-layer feedback available at the next owned
            // enqueue/shutdown boundary, without changing any transmit time.
            std::thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    })();
    let error = exercise.as_ref().err().map(|error| error.to_string());
    let shutdown = helper.shutdown();
    let passed = exercise.is_ok()
        && jobs.len() == 2
        && shutdown.shutdown_complete
        && shutdown.worker_joined
        && shutdown.clean_socket_state
        && shutdown.errors.is_empty()
        && shutdown.socket_state.as_ref().is_some_and(|state| {
            state.schema_version == 2
                && state.clean
                && state.timestamp_inventories.len() == 1
                && state.timestamp_inventories[0].completed_transmissions == 2
        });
    println!(
        "{}",
        serde_json::json!({"record_type":"qcsd-native95-etf-two-send-regression-v1",
        "passed":passed,"interface":interface,"ifindex":ifindex,"iflink":iflink,
        "source":source,"destination":destination,"privilege":privilege,
        "jobs":jobs,"shutdown":shutdown,"error":error,"qdisc_installed":false,
        "HTTP_performed":false,"scientific_credit_added":0})
    );
    exercise?;
    if !passed {
        return Err("two-send owned closure or timestamp inventory refused".into());
    }
    Ok(())
}

#[cfg(any(not(target_os = "linux"), not(feature = "qcsd"), test))]
fn main() {
    eprintln!("requires Linux, --features qcsd and the explicit operator-owned veth/ETF fixture");
    std::process::exit(2);
}
