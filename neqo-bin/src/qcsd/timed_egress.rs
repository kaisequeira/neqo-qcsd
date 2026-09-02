// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Fail-closed Linux kernel-timed UDP egress for QCSD.
//!
//! The module never installs or weakens an ETF qdisc. Its contract requires
//! `CLOCK_TAI`, non-deadline mode, and socket checks. Socket setup and runtime
//! activation are separate types: all sockets are configured first, then the
//! process permanently drops privilege, and only then can a sender activate.

#![expect(
    dead_code,
    reason = "This primitive is staged and tested before scheduler integration."
)]

use std::{
    fs, io,
    mem::{self, MaybeUninit},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    os::fd::{AsFd, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd},
    ptr,
    sync::{
        Arc, Mutex,
        mpsc::{self, SyncSender},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use neqo_common::datagram;
use serde::Serialize;
use thiserror::Error;

const SCM_PRIORITY: libc::c_int = libc::SO_PRIORITY;
const SO_EE_ORIGIN_TXTIME: u8 = 6;
const SO_EE_CODE_TXTIME_INVALID_PARAM: u8 = 1;
const SO_EE_CODE_TXTIME_MISSED: u8 = 2;
const SCM_TSTAMP_SND: u32 = 0;
const SCM_TSTAMP_SCHED: u32 = 1;
const REPORT_FLAGS: libc::c_int = (libc::SOF_TIMESTAMPING_SOFTWARE
    | libc::SOF_TIMESTAMPING_OPT_ID
    | libc::SOF_TIMESTAMPING_OPT_TSONLY)
    .cast_signed();
const REQUEST_FLAGS: libc::c_int =
    (libc::SOF_TIMESTAMPING_TX_SCHED | libc::SOF_TIMESTAMPING_TX_SOFTWARE).cast_signed();
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;
const SEND_CONTROL_WORDS: usize = 32;
const SEND_CONTROL_CAPACITY_BYTES: usize = SEND_CONTROL_WORDS * size_of::<usize>();
const _: () = {
    assert!(size_of::<u64>() == 8);
    assert!(size_of::<libc::c_int>() == 4);
    assert!(size_of::<libc::in6_pktinfo>() == 20);
};
const MAX_SEND_CONTROL_BYTES: usize = unsafe {
    // SAFETY: the compile-time size assertions bind these ABI-sized literals.
    libc::CMSG_SPACE(8_u32) as usize
        + libc::CMSG_SPACE(4_u32) as usize
        + libc::CMSG_SPACE(4_u32) as usize
        + libc::CMSG_SPACE(4_u32) as usize
        + libc::CMSG_SPACE(20_u32) as usize
};
const _: () = assert!(SEND_CONTROL_CAPACITY_BYTES >= MAX_SEND_CONTROL_BYTES);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct EtfContract {
    pub clock_id: libc::clockid_t,
    pub deadline_mode: bool,
    pub skip_socket_check: bool,
    pub timed_priority: libc::c_int,
}

impl EtfContract {
    pub const STRICT: Self = Self {
        clock_id: libc::CLOCK_TAI,
        deadline_mode: false,
        skip_socket_check: false,
        timed_priority: 6,
    };

    const fn validate(self) -> Result<(), TimedEgressError> {
        if self.clock_id != libc::CLOCK_TAI {
            return Err(TimedEgressError::InvalidContract(
                "ETF and SO_TXTIME must use CLOCK_TAI",
            ));
        }
        if self.deadline_mode {
            return Err(TimedEgressError::InvalidContract(
                "ETF deadline mode is forbidden",
            ));
        }
        if self.skip_socket_check {
            return Err(TimedEgressError::InvalidContract(
                "ETF skip_sock_check is forbidden",
            ));
        }
        if self.timed_priority != 6 {
            return Err(TimedEgressError::InvalidContract(
                "timed datagrams must use SCM_PRIORITY=6",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SocketFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimedPriorityMethod {
    PerDatagramScmPriority,
    SerializedSocketSoPriority,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the setup receipt records independently auditable kernel contract checks"
)]
pub struct TimedEgressSetupReceipt {
    pub schema_version: u32,
    pub family: SocketFamily,
    pub local_address: SocketAddr,
    pub duplicated_fd_cloexec: bool,
    pub nonblocking: bool,
    pub socket_type: libc::c_int,
    pub txtime_clock_id: libc::clockid_t,
    pub txtime_flags: u32,
    pub timestamping_report_flags: libc::c_int,
    pub timed_priority: libc::c_int,
    pub priority_before_probe: libc::c_int,
    pub priority_after_probe: libc::c_int,
    pub corresponding_error_queue_enabled: bool,
    pub etf_deadline_mode: bool,
    pub etf_skip_socket_check: bool,
    pub priority_method: TimedPriorityMethod,
    pub scm_priority_supported: bool,
    pub scm_priority_probe_family: SocketFamily,
    pub scm_priority_probe_errno: Option<libc::c_int>,
    pub exclusive_socket_sender_required: bool,
    pub per_datagram_timestamp_requests: bool,
}

pub struct PreparedTimedEgressSocket {
    fd: OwnedFd,
    family: SocketFamily,
    local_address: SocketAddr,
    contract: EtfContract,
    receipt: TimedEgressSetupReceipt,
}

impl PreparedTimedEgressSocket {
    #[expect(
        clippy::too_many_lines,
        reason = "one setup transaction reads back and receipts every kernel socket contract"
    )]
    pub fn configure<S: AsFd>(socket: &S, contract: EtfContract) -> Result<Self, TimedEgressError> {
        contract.validate()?;
        let fd = duplicate_cloexec(socket.as_fd())?;
        let raw_fd = fd.as_raw_fd();

        let socket_type: libc::c_int = getsockopt(
            raw_fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            "getsockopt(SO_TYPE)",
        )?;
        if socket_type != libc::SOCK_DGRAM {
            return Err(TimedEgressError::UnsupportedSocket(format!(
                "SO_TYPE was {socket_type}, expected SOCK_DGRAM"
            )));
        }
        let status = unsafe {
            // SAFETY: raw_fd is a live descriptor owned by fd.
            libc::fcntl(raw_fd, libc::F_GETFL)
        };
        if status < 0 {
            return Err(last_io_error("fcntl(F_GETFL)"));
        }
        let nonblocking = status & libc::O_NONBLOCK != 0;
        if !nonblocking {
            return Err(TimedEgressError::UnsupportedSocket(
                "timed egress requires O_NONBLOCK".into(),
            ));
        }
        let descriptor_flags = unsafe {
            // SAFETY: raw_fd is a live descriptor owned by fd.
            libc::fcntl(raw_fd, libc::F_GETFD)
        };
        if descriptor_flags < 0 {
            return Err(last_io_error("fcntl(F_GETFD)"));
        }
        let duplicated_fd_cloexec = descriptor_flags & libc::FD_CLOEXEC != 0;
        if !duplicated_fd_cloexec {
            return Err(TimedEgressError::CapabilityMismatch(
                "duplicated descriptor lacks FD_CLOEXEC".into(),
            ));
        }

        let (family, local_address) = socket_identity(raw_fd)?;
        let txtime = libc::sock_txtime {
            clockid: libc::CLOCK_TAI,
            flags: libc::SOF_TXTIME_REPORT_ERRORS,
        };
        setsockopt(
            raw_fd,
            libc::SOL_SOCKET,
            libc::SO_TXTIME,
            &txtime,
            "setsockopt(SO_TXTIME)",
        )?;
        let observed_txtime: libc::sock_txtime = getsockopt(
            raw_fd,
            libc::SOL_SOCKET,
            libc::SO_TXTIME,
            "getsockopt(SO_TXTIME)",
        )?;
        if observed_txtime.clockid != libc::CLOCK_TAI
            || observed_txtime.flags != libc::SOF_TXTIME_REPORT_ERRORS
        {
            return Err(TimedEgressError::CapabilityMismatch(format!(
                "SO_TXTIME readback clock={} flags={:#x}",
                observed_txtime.clockid, observed_txtime.flags
            )));
        }

        // Only reporting/identification flags are global. TX generation is
        // requested per exact datagram via a SO_TIMESTAMPING control message.
        setsockopt(
            raw_fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPING,
            &REPORT_FLAGS,
            "setsockopt(SO_TIMESTAMPING reporting)",
        )?;
        let observed_report_flags: libc::c_int = getsockopt(
            raw_fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPING,
            "getsockopt(SO_TIMESTAMPING)",
        )?;
        if observed_report_flags != REPORT_FLAGS {
            return Err(TimedEgressError::CapabilityMismatch(format!(
                "SO_TIMESTAMPING readback {observed_report_flags:#x}, expected {REPORT_FLAGS:#x}"
            )));
        }

        let enabled: libc::c_int = 1;
        let corresponding_error_queue_enabled = match family {
            SocketFamily::Ipv4 => {
                setsockopt(
                    raw_fd,
                    libc::SOL_IP,
                    libc::IP_RECVERR,
                    &enabled,
                    "setsockopt(IP_RECVERR)",
                )?;
                getsockopt::<libc::c_int>(
                    raw_fd,
                    libc::SOL_IP,
                    libc::IP_RECVERR,
                    "getsockopt(IP_RECVERR)",
                )? == enabled
            }
            SocketFamily::Ipv6 => {
                setsockopt(
                    raw_fd,
                    libc::SOL_IPV6,
                    libc::IPV6_RECVERR,
                    &enabled,
                    "setsockopt(IPV6_RECVERR)",
                )?;
                getsockopt::<libc::c_int>(
                    raw_fd,
                    libc::SOL_IPV6,
                    libc::IPV6_RECVERR,
                    "getsockopt(IPV6_RECVERR)",
                )? == enabled
            }
        };
        if !corresponding_error_queue_enabled {
            return Err(TimedEgressError::CapabilityMismatch(
                "IP error queue readback was disabled".into(),
            ));
        }

        // Probe priority permission during setup, then restore it. Production
        // prefers SCM_PRIORITY; an explicitly receipted fallback performs a
        // serialized set/send/restore while the helper has exclusive ownership.
        let (priority_before_probe, priority_after_probe) =
            probe_socket_so_priority(raw_fd, contract.timed_priority)?;
        if priority_before_probe != 0 {
            return Err(TimedEgressError::CapabilityMismatch(format!(
                "serialized priority requires default SO_PRIORITY=0, observed \
                 {priority_before_probe}"
            )));
        }
        let scm_priority_probe = probe_scm_priority(family)?;
        let priority_method = if scm_priority_probe.supported {
            TimedPriorityMethod::PerDatagramScmPriority
        } else {
            TimedPriorityMethod::SerializedSocketSoPriority
        };

        let receipt = TimedEgressSetupReceipt {
            schema_version: 1,
            family,
            local_address,
            duplicated_fd_cloexec,
            nonblocking,
            socket_type,
            txtime_clock_id: observed_txtime.clockid,
            txtime_flags: observed_txtime.flags,
            timestamping_report_flags: observed_report_flags,
            timed_priority: contract.timed_priority,
            priority_before_probe,
            priority_after_probe,
            corresponding_error_queue_enabled,
            etf_deadline_mode: contract.deadline_mode,
            etf_skip_socket_check: contract.skip_socket_check,
            priority_method,
            scm_priority_supported: scm_priority_probe.supported,
            scm_priority_probe_family: scm_priority_probe.family,
            scm_priority_probe_errno: scm_priority_probe.errno,
            exclusive_socket_sender_required: true,
            per_datagram_timestamp_requests: true,
        };
        Ok(Self {
            fd,
            family,
            local_address,
            contract,
            receipt,
        })
    }

    pub const fn receipt(&self) -> &TimedEgressSetupReceipt {
        &self.receipt
    }

    pub fn activate_after_privilege_drop(
        self,
    ) -> Result<ActiveTimedEgressSocket, TimedEgressError> {
        let privilege = PrivilegeDropReceipt::capture()?;
        privilege.validate_permanent_drop()?;
        Ok(ActiveTimedEgressSocket {
            fd: self.fd,
            family: self.family,
            local_address: self.local_address,
            contract: self.contract,
            setup_receipt: self.receipt,
            privilege_receipt: privilege,
            pending: None,
            poison: None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct PrivilegeDropTarget {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PrivilegeDropReceipt {
    pub schema_version: u32,
    pub uid: [u32; 4],
    pub gid: [u32; 4],
    pub supplementary_groups: Vec<u32>,
    pub cap_inheritable: String,
    pub cap_permitted: String,
    pub cap_effective: String,
    pub cap_bounding: String,
    pub cap_ambient: String,
    pub no_new_privileges: bool,
}

impl PrivilegeDropReceipt {
    fn capture() -> Result<Self, TimedEgressError> {
        let status = fs::read_to_string("/proc/self/status")
            .map_err(|source| TimedEgressError::Io("read /proc/self/status", source))?;
        Self::parse_proc_status(&status)
    }

    fn parse_proc_status(status: &str) -> Result<Self, TimedEgressError> {
        let field = |name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .map(str::trim)
                .ok_or_else(|| {
                    TimedEgressError::PrivilegeState(format!("/proc/self/status is missing {name}"))
                })
        };
        let parse_ids = |name: &str| -> Result<[u32; 4], TimedEgressError> {
            let values = field(name)?
                .split_ascii_whitespace()
                .map(str::parse::<u32>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| {
                    TimedEgressError::PrivilegeState(format!("invalid {name}: {source}"))
                })?;
            values.try_into().map_err(|values: Vec<u32>| {
                TimedEgressError::PrivilegeState(format!(
                    "{name} had {} values, expected four",
                    values.len()
                ))
            })
        };
        let parse_caps = |name: &str| -> Result<String, TimedEgressError> {
            let value = field(name)?;
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(TimedEgressError::PrivilegeState(format!(
                    "invalid hexadecimal {name}"
                )));
            }
            Ok(value.to_ascii_lowercase())
        };
        let supplementary_groups = field("Groups:")?
            .split_ascii_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| {
                TimedEgressError::PrivilegeState(format!("invalid Groups: {source}"))
            })?;
        let no_new_privileges = match field("NoNewPrivs:")? {
            "0" => false,
            "1" => true,
            other => {
                return Err(TimedEgressError::PrivilegeState(format!(
                    "invalid NoNewPrivs value {other}"
                )));
            }
        };
        Ok(Self {
            schema_version: 1,
            uid: parse_ids("Uid:")?,
            gid: parse_ids("Gid:")?,
            supplementary_groups,
            cap_inheritable: parse_caps("CapInh:")?,
            cap_permitted: parse_caps("CapPrm:")?,
            cap_effective: parse_caps("CapEff:")?,
            cap_bounding: parse_caps("CapBnd:")?,
            cap_ambient: parse_caps("CapAmb:")?,
            no_new_privileges,
        })
    }

    fn validate_permanent_drop(&self) -> Result<(), TimedEgressError> {
        if self.uid[0] == 0 || !self.uid.iter().all(|value| *value == self.uid[0]) {
            return Err(TimedEgressError::PrivilegeState(format!(
                "UID quartet is not one non-root UID: {:?}",
                self.uid
            )));
        }
        if self.gid[0] == 0 || !self.gid.iter().all(|value| *value == self.gid[0]) {
            return Err(TimedEgressError::PrivilegeState(format!(
                "GID quartet is not one non-root GID: {:?}",
                self.gid
            )));
        }
        if !self.supplementary_groups.is_empty() {
            return Err(TimedEgressError::PrivilegeState(format!(
                "supplementary groups were not empty: {:?}",
                self.supplementary_groups
            )));
        }
        for (name, value) in [
            ("CapInh", &self.cap_inheritable),
            ("CapPrm", &self.cap_permitted),
            ("CapEff", &self.cap_effective),
            ("CapBnd", &self.cap_bounding),
            ("CapAmb", &self.cap_ambient),
        ] {
            if value.bytes().any(|byte| byte != b'0') {
                return Err(TimedEgressError::PrivilegeState(format!(
                    "{name} was not empty: {value}"
                )));
            }
        }
        if !self.no_new_privileges {
            return Err(TimedEgressError::PrivilegeState(
                "NoNewPrivs was not set".into(),
            ));
        }
        Ok(())
    }
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[expect(
    clippy::too_many_lines,
    reason = "credential, bounding, usable, ambient, and no-new-privilege changes are one transaction"
)]
pub fn drop_process_privileges_permanently(
    target: PrivilegeDropTarget,
) -> Result<PrivilegeDropReceipt, TimedEgressError> {
    if target.uid == 0 || target.gid == 0 {
        return Err(TimedEgressError::PrivilegeState(
            "permanent-drop target must be non-root".into(),
        ));
    }
    let tasks = fs::read_dir("/proc/self/task")
        .map_err(|source| TimedEgressError::Io("read /proc/self/task", source))?
        .count();
    if tasks != 1 {
        return Err(TimedEgressError::PrivilegeState(format!(
            "privilege drop requires one process thread; observed {tasks}"
        )));
    }
    let initial_privilege = PrivilegeDropReceipt::capture()?;
    let effective_uid = unsafe {
        // SAFETY: credential getter has no preconditions.
        libc::geteuid()
    };
    if effective_uid != 0 && !initial_privilege.supplementary_groups.is_empty() {
        return Err(TimedEgressError::PrivilegeState(format!(
            "unprivileged setup cannot clear supplementary groups {:?}",
            initial_privilege.supplementary_groups
        )));
    }
    let result = unsafe {
        // SAFETY: documented integer-only PR_CAP_AMBIENT_CLEAR_ALL operation.
        libc::prctl(
            PR_CAP_AMBIENT,
            PR_CAP_AMBIENT_CLEAR_ALL,
            0_u64,
            0_u64,
            0_u64,
        )
    };
    if result != 0 {
        return Err(last_io_error("prctl(PR_CAP_AMBIENT_CLEAR_ALL)"));
    }

    // CAP_SETPCAP must still be effective while every capability, including
    // CAP_NET_ADMIN and CAP_SETPCAP itself, is removed from the bounding set.
    // Removing a bit from the bounding set does not remove it from the current
    // effective set, so the complete loop is valid.
    let cap_last = fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .map_err(|source| TimedEgressError::Io("read /proc/sys/kernel/cap_last_cap", source))?
        .trim()
        .parse::<libc::c_ulong>()
        .map_err(|source| {
            TimedEgressError::PrivilegeState(format!("invalid kernel cap_last_cap: {source}"))
        })?;
    for capability in 0..=cap_last {
        let result = unsafe {
            // SAFETY: capability is within the kernel-reported range and
            // PR_CAPBSET_DROP is an integer-only prctl operation.
            libc::prctl(libc::PR_CAPBSET_DROP, capability, 0_u64, 0_u64, 0_u64)
        };
        if result != 0 {
            return Err(last_io_error("prctl(PR_CAPBSET_DROP)"));
        }
    }

    if effective_uid == 0 {
        let result = unsafe {
            // SAFETY: zero group count permits a null group pointer.
            libc::setgroups(0, ptr::null())
        };
        if result != 0 {
            return Err(last_io_error("setgroups(clear)"));
        }
        let result = unsafe {
            // SAFETY: scalar IDs are supplied to the documented syscall.
            libc::setresgid(target.gid, target.gid, target.gid)
        };
        if result != 0 {
            return Err(last_io_error("setresgid"));
        }
        let result = unsafe {
            // SAFETY: scalar IDs are supplied to the documented syscall.
            libc::setresuid(target.uid, target.uid, target.uid)
        };
        if result != 0 {
            return Err(last_io_error("setresuid"));
        }
    } else {
        let ids_match = unsafe {
            // SAFETY: credential getter syscalls have no preconditions.
            libc::getuid() == target.uid
                && libc::geteuid() == target.uid
                && libc::getgid() == target.gid
                && libc::getegid() == target.gid
        };
        if !ids_match {
            return Err(TimedEgressError::PrivilegeState(
                "unprivileged caller cannot change to a different UID/GID".into(),
            ));
        }
    }

    let mut header = CapabilityHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        CapabilityData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapabilityData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    let result = unsafe {
        // SAFETY: header and two-element data array match capability ABI v3.
        libc::syscall(libc::SYS_capset, ptr::from_mut(&mut header), data.as_ptr())
    };
    if result != 0 {
        return Err(last_io_error("capset(clear capability sets)"));
    }
    let result = unsafe {
        // SAFETY: documented integer-only PR_SET_NO_NEW_PRIVS operation.
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1_u64, 0_u64, 0_u64, 0_u64)
    };
    if result != 0 {
        return Err(last_io_error("prctl(PR_SET_NO_NEW_PRIVS)"));
    }
    let receipt = PrivilegeDropReceipt::capture()?;
    receipt.validate_permanent_drop()?;
    Ok(receipt)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TimedEnqueueReceipt {
    pub schema_version: u32,
    pub requested_txtime_tai_ns: u64,
    pub latest_enqueue_tai_ns: u64,
    pub enqueue_before_tai_ns: u64,
    pub enqueue_after_tai_ns: u64,
    pub enqueue_monotonic_ns: u64,
    pub payload_bytes: usize,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub tos: u8,
    pub per_message_priority: Option<libc::c_int>,
    pub effective_socket_priority: libc::c_int,
    pub priority_method: TimedPriorityMethod,
    pub per_message_timestamp_flags: libc::c_int,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TimedTxOutcome {
    pub schema_version: u32,
    pub requested_txtime_tai_ns: u64,
    pub kernel_timestamp_id: u32,
    pub tx_sched_realtime_ns: u64,
    pub tx_software_realtime_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ImmediateTxOutcome {
    pub schema_version: u32,
    pub latest_enqueue_tai_ns: u64,
    pub enqueue_before_tai_ns: u64,
    pub enqueue_after_tai_ns: u64,
    pub enqueue_monotonic_ns: u64,
    pub payload_bytes: usize,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub tos: u8,
    pub kernel_timestamp_id: u32,
    pub tx_sched_realtime_ns: u64,
    pub tx_software_realtime_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ImmediateEnqueueReceipt {
    pub schema_version: u32,
    pub latest_enqueue_tai_ns: u64,
    pub enqueue_before_tai_ns: u64,
    pub enqueue_after_tai_ns: u64,
    pub enqueue_monotonic_ns: u64,
    pub payload_bytes: usize,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub tos: u8,
    pub per_message_timestamp_flags: libc::c_int,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SendAttemptKind {
    TimedMain,
    ImmediatePostMain,
}

/// Incremental evidence retained from the instant `sendmsg` is invoked.
///
/// Later clock reads, priority restoration, size validation, and error-queue
/// processing can all fail. Nullable samples make those failures explicit
/// without erasing proof that the syscall was attempted (and may have sent).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SendAttemptReceipt {
    pub schema_version: u32,
    pub kind: SendAttemptKind,
    pub requested_txtime_tai_ns: Option<u64>,
    pub latest_enqueue_tai_ns: u64,
    pub enqueue_before_tai_ns: u64,
    pub enqueue_monotonic_ns: Option<u64>,
    pub enqueue_after_tai_ns: Option<u64>,
    pub sendmsg_result: libc::ssize_t,
    pub send_errno: Option<libc::c_int>,
    pub payload_bytes: usize,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub tos: u8,
    pub priority_method: Option<TimedPriorityMethod>,
}

#[derive(Debug)]
struct RawSendAttempt {
    enqueue_before_tai_ns: u64,
    enqueue_monotonic_ns: Option<u64>,
    sendmsg_result: libc::ssize_t,
    send_errno: Option<libc::c_int>,
    post_send_error: Option<TimedEgressError>,
}

/// One raw Linux clock read bracketed by `CLOCK_TAI` reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct TaiBracketedClockSample {
    pub schema_version: u32,
    pub clock_id: libc::clockid_t,
    pub tai_before_ns: u64,
    pub clock_ns: u64,
    pub tai_after_ns: u64,
}

/// Raw samples needed to map both helper enqueue and kernel TX timestamps.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct KernelClockBracket {
    pub schema_version: u32,
    pub monotonic: TaiBracketedClockSample,
    pub realtime: TaiBracketedClockSample,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingTransmission {
    requested_txtime_tai_ns: u64,
    kernel_timestamp_id: Option<u32>,
    tx_sched_realtime_ns: Option<u64>,
    tx_software_realtime_ns: Option<u64>,
}

pub struct ActiveTimedEgressSocket {
    fd: OwnedFd,
    family: SocketFamily,
    local_address: SocketAddr,
    contract: EtfContract,
    setup_receipt: TimedEgressSetupReceipt,
    privilege_receipt: PrivilegeDropReceipt,
    pending: Option<PendingTransmission>,
    poison: Option<String>,
}

impl ActiveTimedEgressSocket {
    pub const fn setup_receipt(&self) -> &TimedEgressSetupReceipt {
        &self.setup_receipt
    }

    pub const fn privilege_receipt(&self) -> &PrivilegeDropReceipt {
        &self.privilege_receipt
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one exact enqueue binds constructed bytes, deadline, ancillary data, and receipt"
    )]
    pub fn enqueue_exact(
        &mut self,
        batch: &datagram::Batch,
        txtime_tai_ns: u64,
        latest_enqueue_tai_ns: u64,
    ) -> Result<TimedEnqueueReceipt, TimedEgressError> {
        self.ensure_usable()?;
        if self.pending.is_some() {
            return self.fail(TimedEgressError::Protocol(
                "a timed transmission is already pending".into(),
            ));
        }
        if let Some(stale) = receive_error_queue_event(self.fd.as_raw_fd())? {
            return self.fail(TimedEgressError::StaleErrorQueue(format!("{stale:?}")));
        }
        validate_exact_batch(batch, self.family, self.local_address)?;

        if latest_enqueue_tai_ns >= txtime_tai_ns {
            return self.fail(TimedEgressError::Protocol(format!(
                "latest enqueue {latest_enqueue_tai_ns} was not before txtime {txtime_tai_ns}"
            )));
        }

        let mut control = build_timed_send_control(
            batch,
            txtime_tai_ns,
            self.setup_receipt.priority_method,
            self.contract.timed_priority,
        )?;

        let mut destination = SocketAddress::new(batch.destination());
        let mut iov = libc::iovec {
            iov_base: batch.data().as_ptr().cast_mut().cast(),
            iov_len: batch.data().len(),
        };
        let mut message: libc::msghdr = unsafe {
            // SAFETY: all-zero is a valid initial msghdr state.
            mem::zeroed()
        };
        message.msg_name = destination.as_mut_ptr();
        message.msg_namelen = destination.len();
        message.msg_iov = ptr::from_mut(&mut iov);
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len();
        let send_result = match self.setup_receipt.priority_method {
            TimedPriorityMethod::PerDatagramScmPriority => {
                // All construction is complete; this is the final userspace
                // operation before the native sendmsg.
                let enqueue_before_tai_ns = clock_tai_ns().and_then(|observed| {
                    validate_enqueue_deadline(txtime_tai_ns, latest_enqueue_tai_ns, observed)?;
                    Ok(observed)
                });
                let enqueue_before_tai_ns = match enqueue_before_tai_ns {
                    Ok(observed) => observed,
                    Err(error) => return self.fail(error),
                };
                let sent = unsafe {
                    // SAFETY: all msghdr pointers reference live storage for
                    // this call and SCM_PRIORITY was preflighted successfully.
                    libc::sendmsg(
                        self.fd.as_raw_fd(),
                        &raw const message,
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                };
                let send_error = (sent < 0).then(io::Error::last_os_error);
                let send_errno = send_error.as_ref().and_then(io::Error::raw_os_error);
                let monotonic_result = clock_monotonic_ns();
                let enqueue_monotonic_ns = monotonic_result.as_ref().ok().copied();
                let post_send_error = send_error.map_or_else(
                    || monotonic_result.err(),
                    |source| Some(TimedEgressError::Io("sendmsg(SCM_TXTIME)", source)),
                );
                Ok(RawSendAttempt {
                    enqueue_before_tai_ns,
                    enqueue_monotonic_ns,
                    sendmsg_result: sent,
                    send_errno,
                    post_send_error,
                })
            }
            TimedPriorityMethod::SerializedSocketSoPriority => sendmsg_with_serialized_priority(
                self.fd.as_raw_fd(),
                &message,
                self.contract.timed_priority,
                txtime_tai_ns,
                latest_enqueue_tai_ns,
            ),
        };
        let mut raw = match send_result {
            Ok(result) => result,
            Err(error) => return self.fail(error),
        };
        if raw.sendmsg_result >= 0 {
            self.pending = Some(PendingTransmission {
                requested_txtime_tai_ns: txtime_tai_ns,
                kernel_timestamp_id: None,
                tx_sched_realtime_ns: None,
                tx_software_realtime_ns: None,
            });
        }
        if let Some(source) = raw.post_send_error.take() {
            let attempt = send_attempt_receipt(
                batch,
                SendAttemptKind::TimedMain,
                Some(txtime_tai_ns),
                latest_enqueue_tai_ns,
                &raw,
                None,
                Some(self.setup_receipt.priority_method),
            );
            return self.fail(TimedEgressError::SendAttemptFailed {
                attempt: Box::new(attempt),
                source: Box::new(source),
            });
        }
        let sent = match usize::try_from(raw.sendmsg_result) {
            Ok(sent) => sent,
            Err(source) => {
                let attempt = send_attempt_receipt(
                    batch,
                    SendAttemptKind::TimedMain,
                    Some(txtime_tai_ns),
                    latest_enqueue_tai_ns,
                    &raw,
                    None,
                    Some(self.setup_receipt.priority_method),
                );
                return self.fail(TimedEgressError::SendAttemptFailed {
                    attempt: Box::new(attempt),
                    source: Box::new(TimedEgressError::Protocol(format!(
                        "nonnegative sendmsg result conversion: {source}"
                    ))),
                });
            }
        };
        if sent != batch.data().len() {
            let attempt = send_attempt_receipt(
                batch,
                SendAttemptKind::TimedMain,
                Some(txtime_tai_ns),
                latest_enqueue_tai_ns,
                &raw,
                None,
                Some(self.setup_receipt.priority_method),
            );
            return self.fail(TimedEgressError::SendAttemptFailed {
                attempt: Box::new(attempt),
                source: Box::new(TimedEgressError::ShortSend {
                    expected: batch.data().len(),
                    observed: sent,
                }),
            });
        }
        let enqueue_after_tai_ns = match clock_tai_ns() {
            Ok(value) => value,
            Err(source) => {
                let attempt = send_attempt_receipt(
                    batch,
                    SendAttemptKind::TimedMain,
                    Some(txtime_tai_ns),
                    latest_enqueue_tai_ns,
                    &raw,
                    None,
                    Some(self.setup_receipt.priority_method),
                );
                return self.fail(TimedEgressError::SendAttemptFailed {
                    attempt: Box::new(attempt),
                    source: Box::new(source),
                });
            }
        };
        let Some(enqueue_monotonic_ns) = raw.enqueue_monotonic_ns else {
            let attempt = send_attempt_receipt(
                batch,
                SendAttemptKind::TimedMain,
                Some(txtime_tai_ns),
                latest_enqueue_tai_ns,
                &raw,
                Some(enqueue_after_tai_ns),
                Some(self.setup_receipt.priority_method),
            );
            return self.fail(TimedEgressError::SendAttemptFailed {
                attempt: Box::new(attempt),
                source: Box::new(TimedEgressError::Protocol(
                    "send attempt omitted its CLOCK_MONOTONIC sample".into(),
                )),
            });
        };
        Ok(TimedEnqueueReceipt {
            schema_version: 1,
            requested_txtime_tai_ns: txtime_tai_ns,
            latest_enqueue_tai_ns,
            enqueue_before_tai_ns: raw.enqueue_before_tai_ns,
            enqueue_after_tai_ns,
            enqueue_monotonic_ns,
            payload_bytes: batch.data().len(),
            source: batch.source(),
            destination: batch.destination(),
            tos: u8::from(batch.tos()),
            per_message_priority: matches!(
                self.setup_receipt.priority_method,
                TimedPriorityMethod::PerDatagramScmPriority
            )
            .then_some(self.contract.timed_priority),
            effective_socket_priority: if matches!(
                self.setup_receipt.priority_method,
                TimedPriorityMethod::SerializedSocketSoPriority
            ) {
                self.contract.timed_priority
            } else {
                0
            },
            priority_method: self.setup_receipt.priority_method,
            per_message_timestamp_flags: REQUEST_FLAGS,
        })
    }

    pub fn wait_for_outcome(
        &mut self,
        timeout: Duration,
    ) -> Result<TimedTxOutcome, TimedEgressError> {
        self.ensure_usable()?;
        if self.pending.is_none() {
            return self.fail(TimedEgressError::Protocol(
                "wait_for_outcome called without a pending send".into(),
            ));
        }
        let deadline_monotonic_ns = monotonic_deadline(timeout)?;
        loop {
            while let Some(event) = receive_error_queue_event(self.fd.as_raw_fd())? {
                if let Some(outcome) = self.observe_event(event)? {
                    self.pending = None;
                    return Ok(outcome);
                }
            }
            let now_monotonic_ns = clock_monotonic_ns()?;
            if now_monotonic_ns >= deadline_monotonic_ns {
                let Some(pending) = self.pending else {
                    return self.fail(TimedEgressError::Protocol(
                        "pending transmission disappeared while waiting for an outcome".into(),
                    ));
                };
                return self.fail(TimedEgressError::ReportTimeout {
                    requested: pending.requested_txtime_tai_ns,
                    saw_sched: pending.tx_sched_realtime_ns.is_some(),
                    saw_software: pending.tx_software_realtime_ns.is_some(),
                });
            }
            poll_error_queue(
                self.fd.as_raw_fd(),
                Duration::from_nanos(deadline_monotonic_ns - now_monotonic_ns),
            )?;
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one synchronous immediate send binds enqueue and both kernel timestamps"
    )]
    fn send_immediate_after_proven_main(
        &mut self,
        batch: &datagram::Batch,
        latest_enqueue_tai_ns: u64,
        report_timeout: Duration,
    ) -> Result<ImmediateTxOutcome, TimedEgressError> {
        self.ensure_usable()?;
        if self.pending.is_some() {
            return self.fail(TimedEgressError::Protocol(
                "post-main send found a pending transmission".into(),
            ));
        }
        if let Some(stale) = receive_error_queue_event(self.fd.as_raw_fd())? {
            return self.fail(TimedEgressError::StaleErrorQueue(format!("{stale:?}")));
        }
        validate_exact_batch(batch, self.family, self.local_address)?;
        let priority: libc::c_int = getsockopt(
            self.fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PRIORITY,
            "getsockopt(SO_PRIORITY before post-main send)",
        )?;
        if priority != 0 {
            return self.fail(TimedEgressError::CapabilityMismatch(format!(
                "post-main send observed SO_PRIORITY={priority}, expected 0"
            )));
        }

        let mut control = ControlBuffer::<SEND_CONTROL_WORDS>::new();
        control.push(libc::SOL_SOCKET, libc::SO_TIMESTAMPING, REQUEST_FLAGS)?;
        append_ip_control_messages(&mut control, batch)?;
        let mut destination = SocketAddress::new(batch.destination());
        let mut iov = libc::iovec {
            iov_base: batch.data().as_ptr().cast_mut().cast(),
            iov_len: batch.data().len(),
        };
        let mut message: libc::msghdr = unsafe {
            // SAFETY: all-zero is a valid initial msghdr state.
            mem::zeroed()
        };
        message.msg_name = destination.as_mut_ptr();
        message.msg_namelen = destination.len();
        message.msg_iov = ptr::from_mut(&mut iov);
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len();
        // This is the final userspace operation before sendmsg. Refuse the
        // syscall itself once the caller's strict realization cutoff arrives;
        // discovering lateness after an skb was queued would permit catch-up.
        let enqueue_before_tai_ns = match clock_tai_ns().and_then(|observed| {
            validate_immediate_enqueue_deadline(latest_enqueue_tai_ns, observed)?;
            Ok(observed)
        }) {
            Ok(observed) => observed,
            Err(error) => return self.fail(error),
        };
        let sent = unsafe {
            // SAFETY: all msghdr pointers reference live storage for this call.
            libc::sendmsg(
                self.fd.as_raw_fd(),
                &raw const message,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        let send_error = (sent < 0).then(io::Error::last_os_error);
        let send_errno = send_error.as_ref().and_then(io::Error::raw_os_error);
        // This is intentionally sampled in the helper immediately after the
        // actual sendmsg, not reconstructed later by the caller.
        let monotonic_result = clock_monotonic_ns();
        let enqueue_monotonic_ns = monotonic_result.as_ref().ok().copied();
        let post_send_error = send_error.map_or_else(
            || monotonic_result.err(),
            |source| {
                Some(TimedEgressError::Io(
                    "sendmsg(post-main timestamped)",
                    source,
                ))
            },
        );
        let mut raw = RawSendAttempt {
            enqueue_before_tai_ns,
            enqueue_monotonic_ns,
            sendmsg_result: sent,
            send_errno,
            post_send_error,
        };
        if raw.sendmsg_result >= 0 {
            // Zero is internal only. This send carries no SCM_TXTIME, so any
            // TXTIME-origin error is necessarily a fail-closed mismatch.
            self.pending = Some(PendingTransmission {
                requested_txtime_tai_ns: 0,
                kernel_timestamp_id: None,
                tx_sched_realtime_ns: None,
                tx_software_realtime_ns: None,
            });
        }
        if let Some(source) = raw.post_send_error.take() {
            let attempt = send_attempt_receipt(
                batch,
                SendAttemptKind::ImmediatePostMain,
                None,
                latest_enqueue_tai_ns,
                &raw,
                None,
                None,
            );
            return self.fail(TimedEgressError::SendAttemptFailed {
                attempt: Box::new(attempt),
                source: Box::new(source),
            });
        }
        let sent = match usize::try_from(raw.sendmsg_result) {
            Ok(sent) => sent,
            Err(source) => {
                let attempt = send_attempt_receipt(
                    batch,
                    SendAttemptKind::ImmediatePostMain,
                    None,
                    latest_enqueue_tai_ns,
                    &raw,
                    None,
                    None,
                );
                return self.fail(TimedEgressError::SendAttemptFailed {
                    attempt: Box::new(attempt),
                    source: Box::new(TimedEgressError::Protocol(format!(
                        "nonnegative sendmsg result conversion: {source}"
                    ))),
                });
            }
        };
        if sent != batch.data().len() {
            let attempt = send_attempt_receipt(
                batch,
                SendAttemptKind::ImmediatePostMain,
                None,
                latest_enqueue_tai_ns,
                &raw,
                None,
                None,
            );
            return self.fail(TimedEgressError::SendAttemptFailed {
                attempt: Box::new(attempt),
                source: Box::new(TimedEgressError::ShortSend {
                    expected: batch.data().len(),
                    observed: sent,
                }),
            });
        }
        let enqueue_after_tai_ns = match clock_tai_ns() {
            Ok(value) => value,
            Err(source) => {
                let attempt = send_attempt_receipt(
                    batch,
                    SendAttemptKind::ImmediatePostMain,
                    None,
                    latest_enqueue_tai_ns,
                    &raw,
                    None,
                    None,
                );
                return self.fail(TimedEgressError::SendAttemptFailed {
                    attempt: Box::new(attempt),
                    source: Box::new(source),
                });
            }
        };
        let Some(enqueue_monotonic_ns) = raw.enqueue_monotonic_ns else {
            let attempt = send_attempt_receipt(
                batch,
                SendAttemptKind::ImmediatePostMain,
                None,
                latest_enqueue_tai_ns,
                &raw,
                Some(enqueue_after_tai_ns),
                None,
            );
            return self.fail(TimedEgressError::SendAttemptFailed {
                attempt: Box::new(attempt),
                source: Box::new(TimedEgressError::Protocol(
                    "send attempt omitted its CLOCK_MONOTONIC sample".into(),
                )),
            });
        };
        let enqueue = ImmediateEnqueueReceipt {
            schema_version: 1,
            latest_enqueue_tai_ns,
            enqueue_before_tai_ns,
            enqueue_after_tai_ns,
            enqueue_monotonic_ns,
            payload_bytes: batch.data().len(),
            source: batch.source(),
            destination: batch.destination(),
            tos: u8::from(batch.tos()),
            per_message_timestamp_flags: REQUEST_FLAGS,
        };
        if enqueue_after_tai_ns >= latest_enqueue_tai_ns {
            let source = TimedEgressError::EnqueueDeadline {
                latest: latest_enqueue_tai_ns,
                observed: enqueue_after_tai_ns,
            };
            return self.fail(TimedEgressError::ImmediateEnqueueFailed {
                enqueue: Box::new(enqueue),
                socket_timestamp_id: None,
                tx_sched_realtime_ns: None,
                tx_software_realtime_ns: None,
                source: Box::new(source),
            });
        }
        let timestamps = match self.wait_for_outcome(report_timeout) {
            Ok(timestamps) => timestamps,
            Err(source) => {
                let pending = self.pending;
                let socket_timestamp_id = pending.and_then(|value| value.kernel_timestamp_id);
                return Err(TimedEgressError::ImmediateEnqueueFailed {
                    enqueue: Box::new(enqueue),
                    socket_timestamp_id,
                    tx_sched_realtime_ns: pending.and_then(|value| value.tx_sched_realtime_ns),
                    tx_software_realtime_ns: pending
                        .and_then(|value| value.tx_software_realtime_ns),
                    source: Box::new(source),
                });
            }
        };
        Ok(ImmediateTxOutcome {
            schema_version: 1,
            latest_enqueue_tai_ns: enqueue.latest_enqueue_tai_ns,
            enqueue_before_tai_ns: enqueue.enqueue_before_tai_ns,
            enqueue_after_tai_ns: enqueue.enqueue_after_tai_ns,
            enqueue_monotonic_ns: enqueue.enqueue_monotonic_ns,
            payload_bytes: enqueue.payload_bytes,
            source: enqueue.source,
            destination: enqueue.destination,
            tos: enqueue.tos,
            kernel_timestamp_id: timestamps.kernel_timestamp_id,
            tx_sched_realtime_ns: timestamps.tx_sched_realtime_ns,
            tx_software_realtime_ns: timestamps.tx_software_realtime_ns,
        })
    }

    fn observe_event(
        &mut self,
        event: KernelTxEvent,
    ) -> Result<Option<TimedTxOutcome>, TimedEgressError> {
        let Some(mut pending) = self.pending else {
            return self.fail(TimedEgressError::Protocol(
                "observe_event called without a pending transmission".into(),
            ));
        };
        match event {
            KernelTxEvent::Timestamp {
                kind,
                kernel_id,
                realtime_ns,
            } => {
                if let Some(expected) = pending.kernel_timestamp_id
                    && expected != kernel_id
                {
                    return self.fail(TimedEgressError::KernelIdMismatch {
                        expected,
                        observed: kernel_id,
                    });
                }
                pending.kernel_timestamp_id = Some(kernel_id);
                let slot = match kind {
                    TimestampKind::Scheduled => &mut pending.tx_sched_realtime_ns,
                    TimestampKind::Software => &mut pending.tx_software_realtime_ns,
                };
                if slot.replace(realtime_ns).is_some() {
                    return self.fail(TimedEgressError::DuplicateTimestamp { kind, kernel_id });
                }
            }
            KernelTxEvent::TxtimeDrop(diagnostic) => {
                if diagnostic.requested_txtime_tai_ns != pending.requested_txtime_tai_ns {
                    return self.fail(TimedEgressError::TxtimeDropMismatch {
                        expected: pending.requested_txtime_tai_ns,
                        observed: diagnostic.requested_txtime_tai_ns,
                        diagnostic,
                    });
                }
                return self.fail(TimedEgressError::TxtimeDrop(diagnostic));
            }
            KernelTxEvent::NetworkError(diagnostic) => {
                return self.fail(TimedEgressError::NetworkError(diagnostic));
            }
        }
        self.pending = Some(pending);
        let Some(kernel_timestamp_id) = pending.kernel_timestamp_id else {
            return Ok(None);
        };
        let (Some(tx_sched_realtime_ns), Some(tx_software_realtime_ns)) = (
            pending.tx_sched_realtime_ns,
            pending.tx_software_realtime_ns,
        ) else {
            return Ok(None);
        };
        if tx_software_realtime_ns < tx_sched_realtime_ns {
            return self.fail(TimedEgressError::TimestampOrder {
                scheduled: tx_sched_realtime_ns,
                software: tx_software_realtime_ns,
            });
        }
        Ok(Some(TimedTxOutcome {
            schema_version: 1,
            requested_txtime_tai_ns: pending.requested_txtime_tai_ns,
            kernel_timestamp_id,
            tx_sched_realtime_ns,
            tx_software_realtime_ns,
        }))
    }

    fn ensure_usable(&self) -> Result<(), TimedEgressError> {
        if let Some(detail) = &self.poison {
            return Err(TimedEgressError::Poisoned(detail.clone()));
        }
        Ok(())
    }

    fn fail<T>(&mut self, error: TimedEgressError) -> Result<T, TimedEgressError> {
        self.poison = Some(error.to_string());
        Err(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct HelperThreadContract {
    pub name: &'static str,
    pub target_cpu: usize,
    pub expected_scheduler_policy: libc::c_int,
    pub expected_scheduler_priority: libc::c_int,
}

impl HelperThreadContract {
    pub const RR1_CPU11_V1: Self = Self {
        name: "qcsd-client-rr1-cpu10-etf-helper-cpu11-v1",
        target_cpu: 11,
        expected_scheduler_policy: libc::SCHED_RR,
        expected_scheduler_priority: 1,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct PostMainInventoryContract {
    pub expected_endpoint_sockets: usize,
    pub credit_owner_capacity: usize,
    pub max_datagrams_per_owner: usize,
    pub max_post_main_datagrams: usize,
}

impl PostMainInventoryContract {
    fn validate(self, observed_endpoint_sockets: usize) -> Result<(), TimedEgressError> {
        if self.expected_endpoint_sockets != observed_endpoint_sockets {
            return Err(TimedEgressError::HelperContract(format!(
                "endpoint socket inventory was {observed_endpoint_sockets}, expected {}",
                self.expected_endpoint_sockets
            )));
        }
        if self.credit_owner_capacity != self.expected_endpoint_sockets {
            return Err(TimedEgressError::HelperContract(format!(
                "credit-owner inventory was {}, expected one owner for each of {} endpoint \
                 sockets",
                self.credit_owner_capacity, self.expected_endpoint_sockets
            )));
        }
        let inventory_capacity = self
            .credit_owner_capacity
            .checked_mul(self.max_datagrams_per_owner)
            .ok_or_else(|| {
                TimedEgressError::HelperContract(
                    "post-main action inventory capacity overflowed".into(),
                )
            })?;
        if self.max_post_main_datagrams > inventory_capacity {
            return Err(TimedEgressError::HelperContract(format!(
                "post-main bound {} exceeds action inventory capacity {inventory_capacity} \
                 ({} owners x {} datagrams)",
                self.max_post_main_datagrams,
                self.credit_owner_capacity,
                self.max_datagrams_per_owner
            )));
        }
        Ok(())
    }
}

fn validate_post_main_owner(
    inventory: PostMainInventoryContract,
    owner_index: usize,
    sent_by_owner: &[usize],
    remaining_post_main_datagrams: usize,
) -> Result<(), TimedEgressError> {
    if remaining_post_main_datagrams == 0 {
        return Err(TimedEgressError::Protocol(
            "immediate send exhausted its receipted post-main inventory".into(),
        ));
    }
    let sent = sent_by_owner.get(owner_index).ok_or_else(|| {
        TimedEgressError::Protocol(format!(
            "post-main credit owner index {owner_index} was outside the receipted inventory of {}",
            inventory.credit_owner_capacity
        ))
    })?;
    if *sent >= inventory.max_datagrams_per_owner {
        return Err(TimedEgressError::Protocol(format!(
            "post-main credit owner {owner_index} exhausted its receipted per-owner bound of {} \
             datagrams",
            inventory.max_datagrams_per_owner
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HelperThreadReceipt {
    pub schema_version: u32,
    pub contract_name: String,
    pub target_cpu: usize,
    pub observed_affinity: Vec<usize>,
    pub scheduler_policy: libc::c_int,
    pub scheduler_policy_name: String,
    pub scheduler_priority: libc::c_int,
    pub thread_id: libc::pid_t,
    pub privilege: PrivilegeDropReceipt,
    pub endpoint_socket_count: usize,
    pub credit_owner_capacity: usize,
    pub max_datagrams_per_owner: usize,
    pub max_post_main_datagrams: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HelperLifecycleReceipt {
    pub schema_version: u32,
    pub globally_poisoned: bool,
    pub poison_reason: Option<String>,
    pub completed_main_jobs: u64,
    pub completed_immediate_datagrams: u64,
    pub aborted_jobs: u64,
    pub failed_commands: u64,
    pub causal_main_proven: bool,
    pub active_job_id: Option<u64>,
    pub last_main_job_id: Option<u64>,
    pub remaining_post_main_datagrams: usize,
}

impl HelperLifecycleReceipt {
    const fn initial() -> Self {
        Self {
            schema_version: 1,
            globally_poisoned: false,
            poison_reason: None,
            completed_main_jobs: 0,
            completed_immediate_datagrams: 0,
            aborted_jobs: 0,
            failed_commands: 0,
            causal_main_proven: false,
            active_job_id: None,
            last_main_job_id: None,
            remaining_post_main_datagrams: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HelperJobCloseReceipt {
    pub schema_version: u32,
    pub job_id: u64,
    pub unused_post_main_datagrams: usize,
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HelperJobAbortReceipt {
    pub schema_version: u32,
    pub job_id: u64,
    pub reason: String,
    pub unused_post_main_datagrams: usize,
    pub complete: bool,
    pub aborted: bool,
    pub global_poisoned: bool,
    pub failed_commands: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "shutdown receipt records independent command, join, and socket-cleanliness gates"
)]
pub struct HelperShutdownReceipt {
    pub schema_version: u32,
    pub shutdown_command_sent: bool,
    pub shutdown_received: bool,
    pub worker_joined: bool,
    pub shutdown_complete: bool,
    pub clean_socket_state: bool,
    pub global_poisoned: bool,
    pub failed_commands: Option<u64>,
    pub remaining_post_main_datagrams: Option<usize>,
    pub socket_state: Option<HelperSocketShutdownReceipt>,
    pub lifecycle: Option<HelperLifecycleReceipt>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HelperSocketShutdownReceipt {
    pub schema_version: u32,
    pub socket_count: usize,
    pub active_job_id: Option<u64>,
    pub pending_socket_count: usize,
    pub stale_error_queue_socket_count: usize,
    pub nonzero_priority_socket_count: usize,
    pub inspection_errors: Vec<String>,
    pub clean: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TimedEgressJobResult {
    pub enqueue: TimedEnqueueReceipt,
    pub outcome: TimedTxOutcome,
    pub post_main: Vec<ImmediateTxOutcome>,
}

#[derive(Clone, Debug)]
pub struct PostMainDatagram {
    pub socket_index: usize,
    pub batch: datagram::Batch,
    pub latest_enqueue_tai_ns: u64,
}

enum HelperCommand {
    TransmitMain {
        job_id: u64,
        socket_index: usize,
        batch: datagram::Batch,
        txtime_tai_ns: u64,
        latest_enqueue_tai_ns: u64,
        report_timeout: Duration,
        response: SyncSender<Result<TimedEgressJobResult, TimedEgressError>>,
    },
    TransmitImmediate {
        job_id: u64,
        socket_index: usize,
        batch: datagram::Batch,
        latest_enqueue_tai_ns: u64,
        report_timeout: Duration,
        response: SyncSender<Result<ImmediateTxOutcome, TimedEgressError>>,
    },
    FinishJob {
        job_id: u64,
        response: SyncSender<Result<HelperJobCloseReceipt, TimedEgressError>>,
    },
    AbortJob {
        job_id: u64,
        reason: String,
        response: SyncSender<Result<HelperJobAbortReceipt, TimedEgressError>>,
    },
    Shutdown {
        response: SyncSender<HelperSocketShutdownReceipt>,
    },
}

pub struct TimedEgressHelper {
    sender: SyncSender<HelperCommand>,
    thread: Option<JoinHandle<()>>,
    receipt: HelperThreadReceipt,
    inventory: PostMainInventoryContract,
    lifecycle: Arc<Mutex<HelperLifecycleReceipt>>,
}

impl TimedEgressHelper {
    #[expect(
        clippy::too_many_lines,
        reason = "spawn atomically establishes readiness, global poison, and two-phase command state"
    )]
    #[expect(
        clippy::option_if_let_else,
        reason = "explicit job-state branches keep fail-closed transition diagnostics readable"
    )]
    pub fn spawn_after_privilege_drop(
        sockets: Vec<ActiveTimedEgressSocket>,
        contract: HelperThreadContract,
        inventory: PostMainInventoryContract,
    ) -> Result<Self, TimedEgressError> {
        if sockets.is_empty() {
            return Err(TimedEgressError::Protocol(
                "timed-egress helper requires at least one socket".into(),
            ));
        }
        inventory.validate(sockets.len())?;
        let caller_privilege = PrivilegeDropReceipt::capture()?;
        caller_privilege.validate_permanent_drop()?;
        let (sender, receiver) = mpsc::sync_channel::<HelperCommand>(1);
        let (ready_sender, ready_receiver) =
            mpsc::sync_channel::<Result<HelperThreadReceipt, TimedEgressError>>(1);
        let lifecycle = Arc::new(Mutex::new(HelperLifecycleReceipt::initial()));
        let worker_lifecycle = Arc::clone(&lifecycle);
        let thread = thread::Builder::new()
            .name("qcsd-etf-helper".into())
            .spawn(move || {
                let receipt = initialise_helper_thread(contract, inventory);
                match receipt {
                    Ok(receipt) => {
                        if ready_sender.send(Ok(receipt)).is_err() {
                            return;
                        }
                    }
                    Err(error) => {
                        drop(ready_sender.send(Err(error)));
                        return;
                    }
                }
                let mut sockets = sockets;
                let mut global_poison = None::<String>;
                let mut active_job_id = None::<u64>;
                let mut last_main_job_id = None::<u64>;
                let mut remaining_post_main_datagrams = 0_usize;
                let mut post_main_datagrams_by_owner =
                    vec![0_usize; inventory.credit_owner_capacity];
                while let Ok(command) = receiver.recv() {
                    match command {
                        HelperCommand::TransmitMain {
                            job_id,
                            socket_index,
                            batch,
                            txtime_tai_ns,
                            latest_enqueue_tai_ns,
                            report_timeout,
                            response,
                        } => {
                            let result = global_poison.as_ref().map_or_else(
                                || {
                                    if let Some(active) = active_job_id {
                                        Err(TimedEgressError::Protocol(format!(
                                            "main job {job_id} arrived before active job {active} \
                                             was finished"
                                        )))
                                    } else if last_main_job_id.is_some_and(|last| job_id <= last) {
                                        Err(TimedEgressError::Protocol(format!(
                                            "main job id {job_id} was not greater than prior id {}",
                                            last_main_job_id.unwrap_or_default()
                                        )))
                                    } else {
                                        execute_compound_job(
                                            &mut sockets,
                                            socket_index,
                                            &batch,
                                            txtime_tai_ns,
                                            latest_enqueue_tai_ns,
                                            report_timeout,
                                            &[],
                                            inventory.max_post_main_datagrams,
                                        )
                                    }
                                },
                                |reason| Err(TimedEgressError::Poisoned(reason.clone())),
                            );
                            match &result {
                                Ok(_) => {
                                    active_job_id = Some(job_id);
                                    last_main_job_id = Some(job_id);
                                    remaining_post_main_datagrams =
                                        inventory.max_post_main_datagrams;
                                    post_main_datagrams_by_owner.fill(0);
                                    update_helper_lifecycle(&worker_lifecycle, |receipt| {
                                        receipt.completed_main_jobs += 1;
                                        receipt.causal_main_proven = true;
                                        receipt.active_job_id = Some(job_id);
                                        receipt.last_main_job_id = Some(job_id);
                                        receipt.remaining_post_main_datagrams =
                                            remaining_post_main_datagrams;
                                    });
                                }
                                Err(error) => {
                                    poison_helper_lifecycle(
                                        &worker_lifecycle,
                                        &mut global_poison,
                                        error.to_string(),
                                    );
                                }
                            }
                            if response.send(result).is_err() {
                                poison_helper_lifecycle(
                                    &worker_lifecycle,
                                    &mut global_poison,
                                    "main response channel disconnected".into(),
                                );
                                break;
                            }
                        }
                        HelperCommand::TransmitImmediate {
                            job_id,
                            socket_index,
                            batch,
                            latest_enqueue_tai_ns,
                            report_timeout,
                            response,
                        } => {
                            let result = global_poison.as_ref().map_or_else(
                                || {
                                    if active_job_id != Some(job_id) {
                                        Err(TimedEgressError::Protocol(format!(
                                            "immediate job {job_id} did not match active job \
                                                 {active_job_id:?}"
                                        )))
                                    } else if let Err(error) = validate_post_main_owner(
                                        inventory,
                                        socket_index,
                                        &post_main_datagrams_by_owner,
                                        remaining_post_main_datagrams,
                                    ) {
                                        Err(error)
                                    } else {
                                        execute_immediate_job(
                                            &mut sockets,
                                            socket_index,
                                            &batch,
                                            latest_enqueue_tai_ns,
                                            report_timeout,
                                        )
                                    }
                                },
                                |reason| Err(TimedEgressError::Poisoned(reason.clone())),
                            );
                            match &result {
                                Ok(_) => {
                                    remaining_post_main_datagrams -= 1;
                                    post_main_datagrams_by_owner[socket_index] += 1;
                                    update_helper_lifecycle(&worker_lifecycle, |receipt| {
                                        receipt.completed_immediate_datagrams += 1;
                                        receipt.remaining_post_main_datagrams =
                                            remaining_post_main_datagrams;
                                    });
                                }
                                Err(error) => {
                                    poison_helper_lifecycle(
                                        &worker_lifecycle,
                                        &mut global_poison,
                                        error.to_string(),
                                    );
                                }
                            }
                            if response.send(result).is_err() {
                                poison_helper_lifecycle(
                                    &worker_lifecycle,
                                    &mut global_poison,
                                    "immediate response channel disconnected".into(),
                                );
                                break;
                            }
                        }
                        HelperCommand::FinishJob { job_id, response } => {
                            let result = global_poison.as_ref().map_or_else(
                                || {
                                    if active_job_id != Some(job_id) {
                                        Err(TimedEgressError::Protocol(format!(
                                            "finish job {job_id} did not match active job \
                                             {active_job_id:?}"
                                        )))
                                    } else if sockets.iter().any(|socket| socket.pending.is_some())
                                    {
                                        Err(TimedEgressError::Protocol(format!(
                                            "finish job {job_id} found a pending socket send"
                                        )))
                                    } else {
                                        Ok(HelperJobCloseReceipt {
                                            schema_version: 1,
                                            job_id,
                                            unused_post_main_datagrams:
                                                remaining_post_main_datagrams,
                                            complete: true,
                                        })
                                    }
                                },
                                |reason| Err(TimedEgressError::Poisoned(reason.clone())),
                            );
                            match &result {
                                Ok(_) => {
                                    active_job_id = None;
                                    remaining_post_main_datagrams = 0;
                                    post_main_datagrams_by_owner.fill(0);
                                    update_helper_lifecycle(&worker_lifecycle, |receipt| {
                                        receipt.causal_main_proven = false;
                                        receipt.active_job_id = None;
                                        receipt.remaining_post_main_datagrams = 0;
                                    });
                                }
                                Err(error) => poison_helper_lifecycle(
                                    &worker_lifecycle,
                                    &mut global_poison,
                                    error.to_string(),
                                ),
                            }
                            if response.send(result).is_err() {
                                poison_helper_lifecycle(
                                    &worker_lifecycle,
                                    &mut global_poison,
                                    "finish-job response channel disconnected".into(),
                                );
                                break;
                            }
                        }
                        HelperCommand::AbortJob {
                            job_id,
                            reason,
                            response,
                        } => {
                            let result = abort_active_helper_job(
                                &mut active_job_id,
                                &mut remaining_post_main_datagrams,
                                &mut global_poison,
                                &worker_lifecycle,
                                job_id,
                                reason,
                            );
                            if result.is_ok() {
                                post_main_datagrams_by_owner.fill(0);
                            }
                            if let Err(error) = &result {
                                poison_helper_lifecycle(
                                    &worker_lifecycle,
                                    &mut global_poison,
                                    error.to_string(),
                                );
                            }
                            if response.send(result).is_err() {
                                poison_helper_lifecycle(
                                    &worker_lifecycle,
                                    &mut global_poison,
                                    "abort-job response channel disconnected".into(),
                                );
                                break;
                            }
                        }
                        HelperCommand::Shutdown { response } => {
                            if global_poison.is_none()
                                && let Some(active) = active_job_id
                            {
                                poison_helper_lifecycle(
                                    &worker_lifecycle,
                                    &mut global_poison,
                                    format!(
                                        "shutdown arrived before active job {active} was finished"
                                    ),
                                );
                            }
                            let socket_state =
                                inspect_socket_shutdown_state(&mut sockets, active_job_id);
                            if !socket_state.clean && global_poison.is_none() {
                                poison_helper_lifecycle(
                                    &worker_lifecycle,
                                    &mut global_poison,
                                    "shutdown socket-state inspection was not clean".into(),
                                );
                            }
                            drop(response.send(socket_state));
                            break;
                        }
                    }
                }
            })
            .map_err(|source| TimedEgressError::Io("spawn ETF helper", source))?;
        let ready = ready_receiver
            .recv()
            .map_err(|source| TimedEgressError::Channel(source.to_string()));
        let receipt = match ready {
            Ok(Ok(receipt)) => receipt,
            Ok(Err(error)) | Err(error) => {
                if thread.join().is_err() {
                    return Err(TimedEgressError::ThreadPanic);
                }
                return Err(error);
            }
        };
        Ok(Self {
            sender,
            thread: Some(thread),
            receipt,
            inventory,
            lifecycle,
        })
    }

    pub const fn receipt(&self) -> &HelperThreadReceipt {
        &self.receipt
    }

    pub const fn inventory_contract(&self) -> PostMainInventoryContract {
        self.inventory
    }

    pub const fn max_post_main_datagrams(&self) -> usize {
        self.inventory.max_post_main_datagrams
    }

    pub fn lifecycle_receipt(&self) -> Result<HelperLifecycleReceipt, TimedEgressError> {
        self.lifecycle
            .lock()
            .map(|receipt| receipt.clone())
            .map_err(|_| {
                TimedEgressError::Poisoned("helper lifecycle receipt mutex was poisoned".into())
            })
    }

    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "exclusive mutable command access prevents concurrent caller interleaving"
    )]
    pub fn transmit_main(
        &mut self,
        job_id: u64,
        socket_index: usize,
        batch: datagram::Batch,
        txtime_tai_ns: u64,
        latest_enqueue_tai_ns: u64,
        report_timeout: Duration,
    ) -> Result<TimedEgressJobResult, TimedEgressError> {
        let (response, result) = mpsc::sync_channel(1);
        self.sender
            .send(HelperCommand::TransmitMain {
                job_id,
                socket_index,
                batch,
                txtime_tai_ns,
                latest_enqueue_tai_ns,
                report_timeout,
                response,
            })
            .map_err(|source| TimedEgressError::Channel(source.to_string()))?;
        result
            .recv()
            .map_err(|source| TimedEgressError::Channel(source.to_string()))?
    }

    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "exclusive mutable command access prevents concurrent caller interleaving"
    )]
    pub fn transmit_immediate(
        &mut self,
        job_id: u64,
        socket_index: usize,
        batch: datagram::Batch,
        latest_enqueue_tai_ns: u64,
        report_timeout: Duration,
    ) -> Result<ImmediateTxOutcome, TimedEgressError> {
        let (response, result) = mpsc::sync_channel(1);
        self.sender
            .send(HelperCommand::TransmitImmediate {
                job_id,
                socket_index,
                batch,
                latest_enqueue_tai_ns,
                report_timeout,
                response,
            })
            .map_err(|source| TimedEgressError::Channel(source.to_string()))?;
        result
            .recv()
            .map_err(|source| TimedEgressError::Channel(source.to_string()))?
    }

    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "exclusive mutable command access closes the job causality permit"
    )]
    pub fn finish_job(&mut self, job_id: u64) -> Result<HelperJobCloseReceipt, TimedEgressError> {
        let (response, result) = mpsc::sync_channel(1);
        self.sender
            .send(HelperCommand::FinishJob { job_id, response })
            .map_err(|source| TimedEgressError::Channel(source.to_string()))?;
        result
            .recv()
            .map_err(|source| TimedEgressError::Channel(source.to_string()))?
    }

    /// Close a proven-main job after a controller-side terminal failure.
    ///
    /// A successful abort closes the causal permit but permanently poisons the
    /// helper so no later traffic can be sent. It is deliberately distinct
    /// from `finish_job`, and therefore never claims successful completion.
    #[expect(
        clippy::needless_pass_by_ref_mut,
        reason = "exclusive mutable command access closes the job causality permit"
    )]
    pub fn abort_job<S: Into<String>>(
        &mut self,
        job_id: u64,
        reason: S,
    ) -> Result<HelperJobAbortReceipt, TimedEgressError> {
        let (response, result) = mpsc::sync_channel(1);
        self.sender
            .send(HelperCommand::AbortJob {
                job_id,
                reason: reason.into(),
                response,
            })
            .map_err(|source| TimedEgressError::Channel(source.to_string()))?;
        result
            .recv()
            .map_err(|source| TimedEgressError::Channel(source.to_string()))?
    }

    /// Shut the helper down and retain every independently obtainable result.
    ///
    /// This is intentionally a total receipt, rather than a `Result`: a
    /// channel error, worker panic, or poisoned lifecycle mutex must not erase
    /// socket inspection or any other evidence that was still available.
    pub fn shutdown(mut self) -> HelperShutdownReceipt {
        let (response, result) = mpsc::sync_channel(1);
        let mut errors = Vec::new();
        let shutdown_command_sent = match self.sender.send(HelperCommand::Shutdown { response }) {
            Ok(()) => true,
            Err(source) => {
                errors.push(format!("shutdown command send failed: {source}"));
                false
            }
        };
        let socket_state = if shutdown_command_sent {
            match result.recv() {
                Ok(receipt) => Some(receipt),
                Err(source) => {
                    errors.push(format!("shutdown response receive failed: {source}"));
                    None
                }
            }
        } else {
            None
        };
        let worker_joined = self.thread.take().is_none_or(|thread| {
            if thread.join().is_ok() {
                true
            } else {
                errors.push("timed-egress helper thread panicked".into());
                false
            }
        });
        let lifecycle = match self.lifecycle_receipt() {
            Ok(receipt) => Some(receipt),
            Err(error) => {
                errors.push(format!("helper lifecycle receipt unavailable: {error}"));
                None
            }
        };
        assemble_helper_shutdown_receipt(
            shutdown_command_sent,
            worker_joined,
            socket_state,
            lifecycle,
            errors,
        )
    }
}

impl Drop for TimedEgressHelper {
    fn drop(&mut self) {
        let (response, result) = mpsc::sync_channel(1);
        drop(self.sender.send(HelperCommand::Shutdown { response }));
        drop(result);
        if let Some(thread) = self.thread.take() {
            drop(thread.join());
        }
    }
}

fn update_helper_lifecycle(
    lifecycle: &Mutex<HelperLifecycleReceipt>,
    update: impl FnOnce(&mut HelperLifecycleReceipt),
) {
    if let Ok(mut receipt) = lifecycle.lock() {
        update(&mut receipt);
    }
}

fn assemble_helper_shutdown_receipt(
    shutdown_command_sent: bool,
    worker_joined: bool,
    socket_state: Option<HelperSocketShutdownReceipt>,
    lifecycle: Option<HelperLifecycleReceipt>,
    errors: Vec<String>,
) -> HelperShutdownReceipt {
    let shutdown_received = socket_state.is_some();
    let clean_socket_state = socket_state.as_ref().is_some_and(|state| state.clean);
    // Unknown lifecycle state is conservatively treated as poisoned. The
    // nullable detailed fields distinguish unknown from a measured value.
    let global_poisoned = lifecycle
        .as_ref()
        .is_none_or(|receipt| receipt.globally_poisoned);
    let failed_commands = lifecycle.as_ref().map(|receipt| receipt.failed_commands);
    let remaining_post_main_datagrams = lifecycle
        .as_ref()
        .map(|receipt| receipt.remaining_post_main_datagrams);
    HelperShutdownReceipt {
        schema_version: 1,
        shutdown_command_sent,
        shutdown_received,
        worker_joined,
        shutdown_complete: shutdown_command_sent && shutdown_received && worker_joined,
        clean_socket_state,
        global_poisoned,
        failed_commands,
        remaining_post_main_datagrams,
        socket_state,
        lifecycle,
        errors,
    }
}

fn poison_helper_lifecycle(
    lifecycle: &Mutex<HelperLifecycleReceipt>,
    global_poison: &mut Option<String>,
    reason: String,
) {
    if global_poison.is_none() {
        global_poison.clone_from(&Some(reason.clone()));
    }
    update_helper_lifecycle(lifecycle, |receipt| {
        receipt.globally_poisoned = true;
        if receipt.poison_reason.is_none() {
            receipt.poison_reason = Some(reason);
        }
        receipt.failed_commands += 1;
    });
}

fn abort_active_helper_job(
    active_job_id: &mut Option<u64>,
    remaining_post_main_datagrams: &mut usize,
    global_poison: &mut Option<String>,
    lifecycle: &Mutex<HelperLifecycleReceipt>,
    job_id: u64,
    reason: String,
) -> Result<HelperJobAbortReceipt, TimedEgressError> {
    if reason.trim().is_empty() {
        return Err(TimedEgressError::Protocol(
            "abort-job reason must not be empty".into(),
        ));
    }
    if *active_job_id != Some(job_id) {
        return Err(TimedEgressError::Protocol(format!(
            "abort job {job_id} did not match active job {active_job_id:?}"
        )));
    }
    let mut lifecycle = lifecycle.lock().map_err(|_| {
        TimedEgressError::Poisoned("helper lifecycle receipt mutex was poisoned".into())
    })?;
    let unused_post_main_datagrams = *remaining_post_main_datagrams;
    *active_job_id = None;
    *remaining_post_main_datagrams = 0;
    let poison_reason = format!("active timed-egress job {job_id} was aborted: {reason}");
    if global_poison.is_none() {
        *global_poison = Some(poison_reason.clone());
    }
    lifecycle.globally_poisoned = true;
    if lifecycle.poison_reason.is_none() {
        lifecycle.poison_reason = Some(poison_reason);
    }
    lifecycle.aborted_jobs += 1;
    lifecycle.causal_main_proven = false;
    lifecycle.active_job_id = None;
    lifecycle.remaining_post_main_datagrams = 0;
    Ok(HelperJobAbortReceipt {
        schema_version: 1,
        job_id,
        reason,
        unused_post_main_datagrams,
        complete: false,
        aborted: true,
        global_poisoned: true,
        failed_commands: lifecycle.failed_commands,
    })
}

fn inspect_socket_shutdown_state(
    sockets: &mut [ActiveTimedEgressSocket],
    active_job_id: Option<u64>,
) -> HelperSocketShutdownReceipt {
    let mut pending_socket_count = 0;
    let mut stale_error_queue_socket_count = 0;
    let mut nonzero_priority_socket_count = 0;
    let mut inspection_errors = Vec::new();
    for (index, socket) in sockets.iter_mut().enumerate() {
        pending_socket_count += usize::from(socket.pending.is_some());
        match getsockopt::<libc::c_int>(
            socket.fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PRIORITY,
            "getsockopt(SO_PRIORITY at helper shutdown)",
        ) {
            Ok(0) => {}
            Ok(priority) => {
                nonzero_priority_socket_count += 1;
                inspection_errors.push(format!("socket {index} retained SO_PRIORITY={priority}"));
            }
            Err(error) => inspection_errors.push(format!(
                "socket {index} priority inspection failed: {error}"
            )),
        }
        match receive_error_queue_event(socket.fd.as_raw_fd()) {
            Ok(None) => {}
            Ok(Some(event)) => {
                stale_error_queue_socket_count += 1;
                inspection_errors.push(format!(
                    "socket {index} retained error-queue event {event:?}"
                ));
            }
            Err(error) => inspection_errors.push(format!(
                "socket {index} error-queue inspection failed: {error}"
            )),
        }
    }
    let clean = active_job_id.is_none()
        && pending_socket_count == 0
        && stale_error_queue_socket_count == 0
        && nonzero_priority_socket_count == 0
        && inspection_errors.is_empty();
    HelperSocketShutdownReceipt {
        schema_version: 1,
        socket_count: sockets.len(),
        active_job_id,
        pending_socket_count,
        stale_error_queue_socket_count,
        nonzero_priority_socket_count,
        inspection_errors,
        clean,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "isolated test primitive retains the full timed-main and optional dependent contract"
)]
fn execute_compound_job(
    sockets: &mut [ActiveTimedEgressSocket],
    main_socket_index: usize,
    main_batch: &datagram::Batch,
    txtime_tai_ns: u64,
    latest_enqueue_tai_ns: u64,
    report_timeout: Duration,
    post_main: &[PostMainDatagram],
    max_post_main_datagrams: usize,
) -> Result<TimedEgressJobResult, TimedEgressError> {
    if post_main.len() > max_post_main_datagrams {
        return Err(TimedEgressError::Protocol(format!(
            "post-main datagram count {} exceeds receipted inventory bound \
             {max_post_main_datagrams}",
            post_main.len(),
        )));
    }
    let main_socket = sockets.get(main_socket_index).ok_or_else(|| {
        TimedEgressError::Protocol(format!(
            "timed-egress main socket index {main_socket_index} out of range"
        ))
    })?;
    validate_exact_batch(main_batch, main_socket.family, main_socket.local_address)?;
    // Validate every dependent datagram before the main cell is enqueued.
    // No malformed post-main job can therefore send the main cell and fail
    // only during later structural validation.
    for dependent in post_main {
        let socket = sockets.get(dependent.socket_index).ok_or_else(|| {
            TimedEgressError::Protocol(format!(
                "post-main socket index {} out of range",
                dependent.socket_index
            ))
        })?;
        validate_exact_batch(&dependent.batch, socket.family, socket.local_address)?;
    }

    let deadline_monotonic_ns = monotonic_deadline(report_timeout)?;
    let main_socket = &mut sockets[main_socket_index];
    let enqueue = main_socket.enqueue_exact(main_batch, txtime_tai_ns, latest_enqueue_tai_ns)?;
    let outcome_timeout = match remaining_until(deadline_monotonic_ns) {
        Ok(timeout) => timeout,
        Err(source) => {
            return Err(TimedEgressError::TimedEnqueueFailed {
                enqueue: Box::new(enqueue),
                socket_timestamp_id: None,
                tx_sched_realtime_ns: None,
                tx_software_realtime_ns: None,
                source: Box::new(source),
            });
        }
    };
    let outcome = match main_socket.wait_for_outcome(outcome_timeout) {
        Ok(outcome) => outcome,
        Err(source) => {
            let pending = main_socket.pending;
            let socket_timestamp_id = pending.and_then(|value| value.kernel_timestamp_id);
            return Err(TimedEgressError::TimedEnqueueFailed {
                enqueue: Box::new(enqueue),
                socket_timestamp_id,
                tx_sched_realtime_ns: pending.and_then(|value| value.tx_sched_realtime_ns),
                tx_software_realtime_ns: pending.and_then(|value| value.tx_software_realtime_ns),
                source: Box::new(source),
            });
        }
    };

    // This loop is reached only after TX_SOFTWARE proves the exact main cell
    // crossed the software transmit boundary. A TXTIME drop or missing receipt
    // returns above, so dependent incoming-credit traffic cannot leak.
    let mut post_main_outcomes = Vec::with_capacity(post_main.len());
    for dependent in post_main {
        post_main_outcomes.push(
            sockets[dependent.socket_index].send_immediate_after_proven_main(
                &dependent.batch,
                dependent.latest_enqueue_tai_ns,
                remaining_until(deadline_monotonic_ns)?,
            )?,
        );
    }
    Ok(TimedEgressJobResult {
        enqueue,
        outcome,
        post_main: post_main_outcomes,
    })
}

fn execute_immediate_job(
    sockets: &mut [ActiveTimedEgressSocket],
    socket_index: usize,
    batch: &datagram::Batch,
    latest_enqueue_tai_ns: u64,
    report_timeout: Duration,
) -> Result<ImmediateTxOutcome, TimedEgressError> {
    // Commands are serialized, but inspect every endpoint explicitly so the
    // two-phase API can never overlap a pending main send on another socket.
    for socket in &mut *sockets {
        socket.ensure_usable()?;
        if socket.pending.is_some() {
            return Err(TimedEgressError::Protocol(
                "immediate send found a pending main transmission".into(),
            ));
        }
    }
    sockets
        .get_mut(socket_index)
        .ok_or_else(|| {
            TimedEgressError::Protocol(format!(
                "immediate socket index {socket_index} out of range"
            ))
        })?
        .send_immediate_after_proven_main(batch, latest_enqueue_tai_ns, report_timeout)
}

fn monotonic_deadline(timeout: Duration) -> Result<u64, TimedEgressError> {
    let timeout_ns = u64::try_from(timeout.as_nanos())
        .map_err(|source| TimedEgressError::Protocol(format!("timeout overflow: {source}")))?;
    clock_monotonic_ns()?
        .checked_add(timeout_ns)
        .ok_or_else(|| TimedEgressError::Protocol("monotonic deadline overflow".into()))
}

fn remaining_until(deadline_monotonic_ns: u64) -> Result<Duration, TimedEgressError> {
    let now_monotonic_ns = clock_monotonic_ns()?;
    deadline_monotonic_ns
        .checked_sub(now_monotonic_ns)
        .filter(|remaining_ns| *remaining_ns != 0)
        .map(Duration::from_nanos)
        .ok_or(TimedEgressError::ReportTimeout {
            requested: 0,
            saw_sched: false,
            saw_software: false,
        })
}

fn initialise_helper_thread(
    contract: HelperThreadContract,
    inventory: PostMainInventoryContract,
) -> Result<HelperThreadReceipt, TimedEgressError> {
    if contract.target_cpu >= libc::CPU_SETSIZE as usize {
        return Err(TimedEgressError::HelperContract(format!(
            "target CPU {} exceeds CPU_SETSIZE",
            contract.target_cpu
        )));
    }
    let privilege = PrivilegeDropReceipt::capture()?;
    privilege.validate_permanent_drop()?;
    let mut affinity: libc::cpu_set_t = unsafe {
        // SAFETY: all-zero is a valid empty cpu_set_t.
        mem::zeroed()
    };
    unsafe {
        // SAFETY: affinity is live and target_cpu is within CPU_SETSIZE.
        libc::CPU_ZERO(&mut affinity);
        libc::CPU_SET(contract.target_cpu, &mut affinity);
    }
    let result = unsafe {
        // SAFETY: affinity points to a fully initialized cpu_set_t.
        libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &raw const affinity)
    };
    if result != 0 {
        return Err(last_io_error("sched_setaffinity(ETF helper)"));
    }
    let observed_affinity = current_affinity()?;
    if observed_affinity != [contract.target_cpu] {
        return Err(TimedEgressError::HelperContract(format!(
            "helper affinity was {observed_affinity:?}, expected [{}]",
            contract.target_cpu
        )));
    }
    let scheduler_policy = unsafe {
        // SAFETY: scheduler getter has no preconditions.
        libc::sched_getscheduler(0)
    };
    if scheduler_policy < 0 {
        return Err(last_io_error("sched_getscheduler(ETF helper)"));
    }
    let mut scheduler_parameters = libc::sched_param { sched_priority: 0 };
    let result = unsafe {
        // SAFETY: scheduler_parameters is live writable storage.
        libc::sched_getparam(0, &raw mut scheduler_parameters)
    };
    if result != 0 {
        return Err(last_io_error("sched_getparam(ETF helper)"));
    }
    if scheduler_policy != contract.expected_scheduler_policy
        || scheduler_parameters.sched_priority != contract.expected_scheduler_priority
    {
        return Err(TimedEgressError::HelperContract(format!(
            "helper scheduler was policy={scheduler_policy} priority={}, expected \
             policy={} priority={}",
            scheduler_parameters.sched_priority,
            contract.expected_scheduler_policy,
            contract.expected_scheduler_priority
        )));
    }
    let thread_id = unsafe {
        // SAFETY: gettid has no preconditions.
        libc::syscall(libc::SYS_gettid)
    };
    let thread_id = libc::pid_t::try_from(thread_id)
        .map_err(|source| TimedEgressError::HelperContract(source.to_string()))?;
    Ok(HelperThreadReceipt {
        schema_version: 1,
        contract_name: contract.name.into(),
        target_cpu: contract.target_cpu,
        observed_affinity,
        scheduler_policy,
        scheduler_policy_name: scheduler_policy_name(scheduler_policy).into(),
        scheduler_priority: scheduler_parameters.sched_priority,
        thread_id,
        privilege,
        endpoint_socket_count: inventory.expected_endpoint_sockets,
        credit_owner_capacity: inventory.credit_owner_capacity,
        max_datagrams_per_owner: inventory.max_datagrams_per_owner,
        max_post_main_datagrams: inventory.max_post_main_datagrams,
    })
}

fn current_affinity() -> Result<Vec<usize>, TimedEgressError> {
    let mut affinity: libc::cpu_set_t = unsafe {
        // SAFETY: all-zero is a valid empty cpu_set_t.
        mem::zeroed()
    };
    let result = unsafe {
        // SAFETY: affinity points to writable cpu_set_t storage.
        libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &raw mut affinity)
    };
    if result != 0 {
        return Err(last_io_error("sched_getaffinity(ETF helper)"));
    }
    Ok((0..libc::CPU_SETSIZE as usize)
        .filter(|cpu| unsafe {
            // SAFETY: cpu is within CPU_SETSIZE and affinity is initialized.
            libc::CPU_ISSET(*cpu, &affinity)
        })
        .collect())
}

const fn scheduler_policy_name(policy: libc::c_int) -> &'static str {
    match policy {
        libc::SCHED_OTHER => "SCHED_OTHER",
        libc::SCHED_FIFO => "SCHED_FIFO",
        libc::SCHED_RR => "SCHED_RR",
        libc::SCHED_BATCH => "SCHED_BATCH",
        libc::SCHED_IDLE => "SCHED_IDLE",
        _ => "UNKNOWN",
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampKind {
    Scheduled,
    Software,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TxtimeDropKind {
    InvalidParameter,
    Missed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TxtimeDropDiagnostic {
    pub family: SocketFamily,
    pub errno: u32,
    pub kind: TxtimeDropKind,
    pub requested_txtime_tai_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NetworkErrorDiagnostic {
    pub family: SocketFamily,
    pub errno: u32,
    pub origin: u8,
    pub error_type: u8,
    pub code: u8,
    pub info: u32,
    pub data: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TimedEgressFailureReceipt {
    pub schema_version: u32,
    pub terminal_error: String,
    pub terminal_error_detail: String,
    pub socket_timestamp_id: Option<u32>,
    pub tx_sched_realtime_ns: Option<u64>,
    pub tx_software_realtime_ns: Option<u64>,
    pub timed_enqueue: Option<TimedEnqueueReceipt>,
    pub immediate_enqueue: Option<ImmediateEnqueueReceipt>,
    pub send_attempt: Option<SendAttemptReceipt>,
    pub txtime_error: Option<TxtimeDropDiagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum KernelTxEvent {
    Timestamp {
        kind: TimestampKind,
        kernel_id: u32,
        realtime_ns: u64,
    },
    TxtimeDrop(TxtimeDropDiagnostic),
    NetworkError(NetworkErrorDiagnostic),
}

#[derive(Debug, Error)]
pub enum TimedEgressError {
    #[error("invalid ETF contract: {0}")]
    InvalidContract(&'static str),
    #[error("unsupported socket: {0}")]
    UnsupportedSocket(String),
    #[error("kernel capability mismatch: {0}")]
    CapabilityMismatch(String),
    #[error("privilege state is not permanently dropped: {0}")]
    PrivilegeState(String),
    #[error("{0}: {1}")]
    Io(&'static str, #[source] io::Error),
    #[error("timed-egress protocol failure: {0}")]
    Protocol(String),
    #[error("timed-egress socket is poisoned: {0}")]
    Poisoned(String),
    #[error("stale error-queue entry before timed enqueue: {0}")]
    StaleErrorQueue(String),
    #[error("requested CLOCK_TAI txtime {requested} was not after observed time {observed}")]
    PastTxtime { requested: u64, observed: u64 },
    #[error("enqueue cutoff {latest} was reached at CLOCK_TAI {observed} before sendmsg")]
    EnqueueDeadline { latest: u64, observed: u64 },
    #[error("sendmsg reported {observed} bytes, expected {expected}")]
    ShortSend { expected: usize, observed: usize },
    #[error("kernel timestamp id mismatch: expected {expected}, observed {observed}")]
    KernelIdMismatch { expected: u32, observed: u32 },
    #[error("duplicate {kind:?} timestamp for kernel id {kernel_id}")]
    DuplicateTimestamp { kind: TimestampKind, kernel_id: u32 },
    #[error("TX_SOFTWARE {software} preceded TX_SCHED {scheduled}")]
    TimestampOrder { scheduled: u64, software: u64 },
    #[error(
        "report timeout for txtime {requested}; tx_sched={saw_sched}, \
         tx_software={saw_software}"
    )]
    ReportTimeout {
        requested: u64,
        saw_sched: bool,
        saw_software: bool,
    },
    #[error("kernel TXTIME drop: {0:?}")]
    TxtimeDrop(TxtimeDropDiagnostic),
    #[error("TXTIME drop referred to {observed}, expected {expected}: {diagnostic:?}")]
    TxtimeDropMismatch {
        expected: u64,
        observed: u64,
        diagnostic: TxtimeDropDiagnostic,
    },
    #[error("kernel network error: {0:?}")]
    NetworkError(NetworkErrorDiagnostic),
    #[error("ancillary buffer needed {required} bytes, capacity {capacity}")]
    AncillaryOverflow { required: usize, capacity: usize },
    #[error("malformed error-queue ancillary data: {0}")]
    MalformedAncillary(String),
    #[error("timed-egress helper contract failure: {0}")]
    HelperContract(String),
    #[error("timed-egress helper channel failure: {0}")]
    Channel(String),
    #[error("timed-egress helper thread panicked")]
    ThreadPanic,
    #[error("timed transmission failed after enqueue: {source}")]
    TimedEnqueueFailed {
        enqueue: Box<TimedEnqueueReceipt>,
        socket_timestamp_id: Option<u32>,
        tx_sched_realtime_ns: Option<u64>,
        tx_software_realtime_ns: Option<u64>,
        #[source]
        source: Box<Self>,
    },
    #[error("immediate transmission failed after enqueue: {source}")]
    ImmediateEnqueueFailed {
        enqueue: Box<ImmediateEnqueueReceipt>,
        socket_timestamp_id: Option<u32>,
        tx_sched_realtime_ns: Option<u64>,
        tx_software_realtime_ns: Option<u64>,
        #[source]
        source: Box<Self>,
    },
    #[error("transmission failed after sendmsg was invoked: {source}")]
    SendAttemptFailed {
        attempt: Box<SendAttemptReceipt>,
        #[source]
        source: Box<Self>,
    },
}

impl TimedEgressError {
    pub fn failure_receipt(&self) -> TimedEgressFailureReceipt {
        let (
            socket_timestamp_id,
            tx_sched_realtime_ns,
            tx_software_realtime_ns,
            timed_enqueue,
            immediate_enqueue,
            send_attempt,
            source,
        ) = match self {
            Self::TimedEnqueueFailed {
                enqueue,
                socket_timestamp_id,
                tx_sched_realtime_ns,
                tx_software_realtime_ns,
                source,
            } => (
                *socket_timestamp_id,
                *tx_sched_realtime_ns,
                *tx_software_realtime_ns,
                Some((**enqueue).clone()),
                None,
                None,
                source.as_ref(),
            ),
            Self::ImmediateEnqueueFailed {
                enqueue,
                socket_timestamp_id,
                tx_sched_realtime_ns,
                tx_software_realtime_ns,
                source,
            } => (
                *socket_timestamp_id,
                *tx_sched_realtime_ns,
                *tx_software_realtime_ns,
                None,
                Some((**enqueue).clone()),
                None,
                source.as_ref(),
            ),
            Self::SendAttemptFailed { attempt, source } => (
                None,
                None,
                None,
                None,
                None,
                Some((**attempt).clone()),
                source.as_ref(),
            ),
            _ => (None, None, None, None, None, None, self),
        };
        TimedEgressFailureReceipt {
            schema_version: 1,
            terminal_error: source.terminal_error_code().into(),
            terminal_error_detail: source.to_string(),
            socket_timestamp_id,
            tx_sched_realtime_ns,
            tx_software_realtime_ns,
            timed_enqueue,
            immediate_enqueue,
            send_attempt,
            txtime_error: source.txtime_drop_diagnostic().cloned(),
        }
    }

    pub const fn terminal_error_code(&self) -> &'static str {
        match self {
            Self::InvalidContract(_) => "invalid_contract",
            Self::UnsupportedSocket(_) => "unsupported_socket",
            Self::CapabilityMismatch(_) => "capability_mismatch",
            Self::PrivilegeState(_) => "privilege_state",
            Self::Io(_, _) => "io_error",
            Self::Protocol(_) => "protocol_failure",
            Self::Poisoned(_) => "globally_poisoned",
            Self::StaleErrorQueue(_) => "stale_error_queue",
            Self::PastTxtime { .. } => "past_txtime",
            Self::EnqueueDeadline { .. } => "enqueue_deadline",
            Self::ShortSend { .. } => "short_send",
            Self::KernelIdMismatch { .. } => "kernel_id_mismatch",
            Self::DuplicateTimestamp { .. } => "duplicate_timestamp",
            Self::TimestampOrder { .. } => "timestamp_order",
            Self::ReportTimeout { .. } => "report_timeout",
            Self::TxtimeDrop(diagnostic) => match diagnostic.kind {
                TxtimeDropKind::InvalidParameter => "txtime_invalid_parameter",
                TxtimeDropKind::Missed => "txtime_missed",
            },
            Self::TxtimeDropMismatch { .. } => "txtime_drop_mismatch",
            Self::NetworkError(_) => "network_error",
            Self::AncillaryOverflow { .. } => "ancillary_overflow",
            Self::MalformedAncillary(_) => "malformed_ancillary",
            Self::HelperContract(_) => "helper_contract",
            Self::Channel(_) => "channel_failure",
            Self::ThreadPanic => "thread_panic",
            Self::TimedEnqueueFailed { source, .. }
            | Self::ImmediateEnqueueFailed { source, .. }
            | Self::SendAttemptFailed { source, .. } => source.terminal_error_code(),
        }
    }

    pub const fn txtime_drop_diagnostic(&self) -> Option<&TxtimeDropDiagnostic> {
        match self {
            Self::TxtimeDrop(diagnostic) | Self::TxtimeDropMismatch { diagnostic, .. } => {
                Some(diagnostic)
            }
            Self::TimedEnqueueFailed { source, .. }
            | Self::ImmediateEnqueueFailed { source, .. }
            | Self::SendAttemptFailed { source, .. } => source.txtime_drop_diagnostic(),
            _ => None,
        }
    }
}

fn validate_exact_batch(
    batch: &datagram::Batch,
    family: SocketFamily,
    local_address: SocketAddr,
) -> Result<(), TimedEgressError> {
    if batch.num_datagrams() != 1 || batch.data().len() != batch.datagram_size().get() {
        return Err(TimedEgressError::Protocol(format!(
            "timed egress requires one non-GSO datagram; segments={} data={} segment={}",
            batch.num_datagrams(),
            batch.data().len(),
            batch.datagram_size()
        )));
    }
    let source = batch.source();
    let destination = batch.destination();
    let family_matches = match family {
        SocketFamily::Ipv4 => source.is_ipv4() && destination.is_ipv4(),
        SocketFamily::Ipv6 => source.is_ipv6() && destination.is_ipv6(),
    };
    if !family_matches {
        return Err(TimedEgressError::Protocol(format!(
            "batch {source}->{destination} does not match {family:?} socket"
        )));
    }
    if source.port() != local_address.port() {
        return Err(TimedEgressError::Protocol(format!(
            "source port {} did not match socket port {}",
            source.port(),
            local_address.port()
        )));
    }
    if !local_address.ip().is_unspecified() && source.ip() != local_address.ip() {
        return Err(TimedEgressError::Protocol(format!(
            "source IP {} did not match bound IP {}",
            source.ip(),
            local_address.ip()
        )));
    }
    Ok(())
}

fn send_attempt_receipt(
    batch: &datagram::Batch,
    kind: SendAttemptKind,
    requested_txtime_tai_ns: Option<u64>,
    latest_enqueue_tai_ns: u64,
    raw: &RawSendAttempt,
    enqueue_after_tai_ns: Option<u64>,
    priority_method: Option<TimedPriorityMethod>,
) -> SendAttemptReceipt {
    SendAttemptReceipt {
        schema_version: 1,
        kind,
        requested_txtime_tai_ns,
        latest_enqueue_tai_ns,
        enqueue_before_tai_ns: raw.enqueue_before_tai_ns,
        enqueue_monotonic_ns: raw.enqueue_monotonic_ns,
        enqueue_after_tai_ns,
        sendmsg_result: raw.sendmsg_result,
        send_errno: raw.send_errno,
        payload_bytes: batch.data().len(),
        source: batch.source(),
        destination: batch.destination(),
        tos: u8::from(batch.tos()),
        priority_method,
    }
}

const fn validate_enqueue_deadline(
    txtime_tai_ns: u64,
    latest_enqueue_tai_ns: u64,
    observed_tai_ns: u64,
) -> Result<(), TimedEgressError> {
    if observed_tai_ns >= latest_enqueue_tai_ns {
        return Err(TimedEgressError::EnqueueDeadline {
            latest: latest_enqueue_tai_ns,
            observed: observed_tai_ns,
        });
    }
    if txtime_tai_ns <= observed_tai_ns {
        return Err(TimedEgressError::PastTxtime {
            requested: txtime_tai_ns,
            observed: observed_tai_ns,
        });
    }
    Ok(())
}

const fn validate_immediate_enqueue_deadline(
    latest_enqueue_tai_ns: u64,
    observed_tai_ns: u64,
) -> Result<(), TimedEgressError> {
    if observed_tai_ns >= latest_enqueue_tai_ns {
        return Err(TimedEgressError::EnqueueDeadline {
            latest: latest_enqueue_tai_ns,
            observed: observed_tai_ns,
        });
    }
    Ok(())
}

fn build_timed_send_control(
    batch: &datagram::Batch,
    txtime_tai_ns: u64,
    priority_method: TimedPriorityMethod,
    timed_priority: libc::c_int,
) -> Result<ControlBuffer<SEND_CONTROL_WORDS>, TimedEgressError> {
    let mut control = ControlBuffer::<SEND_CONTROL_WORDS>::new();
    control.push(libc::SOL_SOCKET, libc::SCM_TXTIME, txtime_tai_ns)?;
    if matches!(priority_method, TimedPriorityMethod::PerDatagramScmPriority) {
        // Exactly one per-datagram priority cmsg is part of the native path.
        control.push(libc::SOL_SOCKET, SCM_PRIORITY, timed_priority)?;
    }
    control.push(libc::SOL_SOCKET, libc::SO_TIMESTAMPING, REQUEST_FLAGS)?;
    append_ip_control_messages(&mut control, batch)?;
    Ok(control)
}

fn append_ip_control_messages<const WORDS: usize>(
    control: &mut ControlBuffer<WORDS>,
    batch: &datagram::Batch,
) -> Result<(), TimedEgressError> {
    let tos = libc::c_int::from(u8::from(batch.tos()));
    match (batch.source().ip(), batch.destination().ip()) {
        (IpAddr::V4(source), IpAddr::V4(_)) => {
            control.push(libc::SOL_IP, libc::IP_TOS, tos)?;
            if !source.is_unspecified() {
                control.push(
                    libc::SOL_IP,
                    libc::IP_PKTINFO,
                    libc::in_pktinfo {
                        ipi_ifindex: 0,
                        ipi_spec_dst: libc::in_addr {
                            s_addr: u32::from(source).to_be(),
                        },
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    },
                )?;
            }
        }
        (IpAddr::V6(source), IpAddr::V6(_)) => {
            control.push(libc::SOL_IPV6, libc::IPV6_TCLASS, tos)?;
            if !source.is_unspecified() {
                control.push(
                    libc::SOL_IPV6,
                    libc::IPV6_PKTINFO,
                    libc::in6_pktinfo {
                        ipi6_addr: libc::in6_addr {
                            s6_addr: source.octets(),
                        },
                        ipi6_ifindex: 0,
                    },
                )?;
            }
        }
        _ => {
            return Err(TimedEgressError::Protocol(
                "source and destination families differ".into(),
            ));
        }
    }
    Ok(())
}

struct ControlBuffer<const WORDS: usize> {
    words: [usize; WORDS],
    len: usize,
}

impl<const WORDS: usize> ControlBuffer<WORDS> {
    const fn new() -> Self {
        Self {
            words: [0; WORDS],
            len: 0,
        }
    }

    fn push<T: Copy>(
        &mut self,
        level: libc::c_int,
        kind: libc::c_int,
        value: T,
    ) -> Result<(), TimedEgressError> {
        let data_len = u32::try_from(size_of::<T>())
            .map_err(|source| TimedEgressError::Protocol(source.to_string()))?;
        let space = unsafe {
            // SAFETY: data_len is the representable size of T.
            libc::CMSG_SPACE(data_len)
        } as usize;
        let capacity = size_of_val(&self.words);
        let required = self
            .len
            .checked_add(space)
            .ok_or(TimedEgressError::AncillaryOverflow {
                required: usize::MAX,
                capacity,
            })?;
        if required > capacity {
            return Err(TimedEgressError::AncillaryOverflow { required, capacity });
        }
        if !self.len.is_multiple_of(size_of::<usize>()) {
            return Err(TimedEgressError::Protocol(format!(
                "ancillary offset {} was not word aligned",
                self.len
            )));
        }
        let header = unsafe {
            // SAFETY: required is within the usize-aligned control buffer and
            // CMSG_SPACE preserves alignment between messages.
            self.words
                .as_mut_ptr()
                .add(self.len / size_of::<usize>())
                .cast::<libc::cmsghdr>()
        };
        unsafe {
            // SAFETY: header points to sufficient live storage for header and T.
            (*header).cmsg_level = level;
            (*header).cmsg_type = kind;
            (*header).cmsg_len = libc::CMSG_LEN(data_len) as usize;
            ptr::copy_nonoverlapping(
                ptr::from_ref(&value).cast::<u8>(),
                libc::CMSG_DATA(header),
                size_of::<T>(),
            );
        }
        self.len = required;
        Ok(())
    }

    const fn as_mut_ptr(&mut self) -> *mut usize {
        self.words.as_mut_ptr()
    }

    const fn len(&self) -> usize {
        self.len
    }
}

enum SocketAddress {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
}

impl SocketAddress {
    fn new(address: SocketAddr) -> Self {
        match address {
            SocketAddr::V4(address) => Self::V4(libc::sockaddr_in {
                sin_family: libc::sa_family_t::try_from(libc::AF_INET)
                    .expect("AF_INET fits sa_family_t"),
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(*address.ip()).to_be(),
                },
                sin_zero: [0; 8],
            }),
            SocketAddr::V6(address) => Self::V6(libc::sockaddr_in6 {
                sin6_family: libc::sa_family_t::try_from(libc::AF_INET6)
                    .expect("AF_INET6 fits sa_family_t"),
                sin6_port: address.port().to_be(),
                sin6_flowinfo: address.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: address.ip().octets(),
                },
                sin6_scope_id: address.scope_id(),
            }),
        }
    }

    const fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        match self {
            Self::V4(address) => ptr::from_mut(address).cast(),
            Self::V6(address) => ptr::from_mut(address).cast(),
        }
    }

    fn len(&self) -> libc::socklen_t {
        let len = match self {
            Self::V4(_) => size_of::<libc::sockaddr_in>(),
            Self::V6(_) => size_of::<libc::sockaddr_in6>(),
        };
        libc::socklen_t::try_from(len).expect("sockaddr size fits socklen_t")
    }
}

struct SocketPriorityRestoreGuard {
    fd: RawFd,
    restore_priority: libc::c_int,
    armed: bool,
}

impl SocketPriorityRestoreGuard {
    const fn new(fd: RawFd, restore_priority: libc::c_int) -> Self {
        Self {
            fd,
            restore_priority,
            armed: true,
        }
    }

    fn restore_verified(
        mut self,
        set_operation: &'static str,
        read_operation: &'static str,
    ) -> Result<libc::c_int, TimedEgressError> {
        // Evaluate both operations even if the set fails, so diagnostics never
        // skip the final observable priority state.
        let set_result = setsockopt(
            self.fd,
            libc::SOL_SOCKET,
            libc::SO_PRIORITY,
            &self.restore_priority,
            set_operation,
        );
        let observed_result =
            getsockopt::<libc::c_int>(self.fd, libc::SOL_SOCKET, libc::SO_PRIORITY, read_operation);
        set_result?;
        let observed = observed_result?;
        if observed != self.restore_priority {
            return Err(TimedEgressError::CapabilityMismatch(format!(
                "SO_PRIORITY restoration read {observed}, expected {}",
                self.restore_priority
            )));
        }
        self.armed = false;
        Ok(observed)
    }
}

impl Drop for SocketPriorityRestoreGuard {
    fn drop(&mut self) {
        if self.armed {
            let length = libc::socklen_t::try_from(size_of::<libc::c_int>())
                .expect("SO_PRIORITY size fits socklen_t");
            unsafe {
                // SAFETY: this is a last-resort unwind/error-path reset on the
                // live descriptor. The checked path above supplies evidence.
                libc::setsockopt(
                    self.fd,
                    libc::SOL_SOCKET,
                    libc::SO_PRIORITY,
                    ptr::from_ref(&self.restore_priority).cast(),
                    length,
                );
            }
        }
    }
}

fn probe_socket_so_priority(
    fd: RawFd,
    priority: libc::c_int,
) -> Result<(libc::c_int, libc::c_int), TimedEgressError> {
    let before: libc::c_int = getsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_PRIORITY,
        "getsockopt(SO_PRIORITY before setup probe)",
    )?;
    if before != 0 {
        return Err(TimedEgressError::CapabilityMismatch(format!(
            "timed egress requires default SO_PRIORITY=0, observed {before}"
        )));
    }
    setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_PRIORITY,
        &priority,
        "setsockopt(SO_PRIORITY setup probe)",
    )?;
    let restore = SocketPriorityRestoreGuard::new(fd, before);
    let probe_result = getsockopt::<libc::c_int>(
        fd,
        libc::SOL_SOCKET,
        libc::SO_PRIORITY,
        "getsockopt(SO_PRIORITY during setup probe)",
    )
    .and_then(|observed| {
        if observed == priority {
            Ok(observed)
        } else {
            Err(TimedEgressError::CapabilityMismatch(format!(
                "SO_PRIORITY setup probe read {observed}, expected {priority}"
            )))
        }
    });
    let restore_result = restore.restore_verified(
        "setsockopt(SO_PRIORITY after setup probe)",
        "getsockopt(SO_PRIORITY after setup probe)",
    );
    // A restoration failure dominates the probe result: it means the shared
    // socket state is not safe for any later ordinary send.
    let after = restore_result?;
    probe_result?;
    Ok((before, after))
}

fn sendmsg_with_serialized_priority(
    fd: RawFd,
    message: &libc::msghdr,
    priority: libc::c_int,
    txtime_tai_ns: u64,
    latest_enqueue_tai_ns: u64,
) -> Result<RawSendAttempt, TimedEgressError> {
    let before: libc::c_int = getsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_PRIORITY,
        "getsockopt(SO_PRIORITY before serialized send)",
    )?;
    if before != 0 {
        return Err(TimedEgressError::CapabilityMismatch(format!(
            "serialized send began with SO_PRIORITY={before}, expected 0"
        )));
    }
    setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_PRIORITY,
        &priority,
        "setsockopt(SO_PRIORITY=6 serialized send)",
    )?;
    let restore = SocketPriorityRestoreGuard::new(fd, 0);
    let operation_result = (|| {
        let armed: libc::c_int = getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PRIORITY,
            "getsockopt(SO_PRIORITY armed)",
        )?;
        if armed != priority {
            return Err(TimedEgressError::CapabilityMismatch(format!(
                "serialized send armed SO_PRIORITY={armed}, expected {priority}"
            )));
        }
        // The serialized fallback must arm/read priority first; this TAI read
        // is therefore its final userspace operation before sendmsg.
        let enqueue_before_tai_ns = clock_tai_ns()?;
        validate_enqueue_deadline(txtime_tai_ns, latest_enqueue_tai_ns, enqueue_before_tai_ns)?;
        let sent = unsafe {
            // SAFETY: caller guarantees all pointers in message remain live.
            libc::sendmsg(fd, message, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL)
        };
        let send_error = (sent < 0).then(io::Error::last_os_error);
        let send_errno = send_error.as_ref().and_then(io::Error::raw_os_error);
        let monotonic_result = clock_monotonic_ns();
        let enqueue_monotonic_ns = monotonic_result.as_ref().ok().copied();
        let post_send_error = send_error.map_or_else(
            || monotonic_result.err(),
            |source| {
                Some(TimedEgressError::Io(
                    "sendmsg(SCM_TXTIME, serialized SO_PRIORITY)",
                    source,
                ))
            },
        );
        Ok(RawSendAttempt {
            enqueue_before_tai_ns,
            enqueue_monotonic_ns,
            sendmsg_result: sent,
            send_errno,
            post_send_error,
        })
    })();
    let restore_result = restore.restore_verified(
        "setsockopt(SO_PRIORITY=0 after serialized send)",
        "getsockopt(SO_PRIORITY=0 after serialized send)",
    );
    match operation_result {
        Err(error) => {
            // No sendmsg was reached. Restoration still dominates because
            // leaked socket priority would corrupt future ordinary sends.
            restore_result?;
            Err(error)
        }
        Ok(mut attempt) => {
            // Once sendmsg ran, never erase that fact. A restoration failure
            // dominates the terminal reason but travels with the attempt.
            if let Err(error) = restore_result {
                attempt.post_send_error = Some(error);
            }
            Ok(attempt)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScmPriorityProbe {
    family: SocketFamily,
    supported: bool,
    errno: Option<libc::c_int>,
}

fn probe_scm_priority(family: SocketFamily) -> Result<ScmPriorityProbe, TimedEgressError> {
    // Never inject probe traffic into, or read from, a real QUIC endpoint.
    // Disposable same-family loopback sockets isolate this ABI preflight.
    let bind_address = match family {
        SocketFamily::Ipv4 => SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        SocketFamily::Ipv6 => SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
    };
    let sender = UdpSocket::bind(bind_address)
        .map_err(|source| TimedEgressError::Io("bind SCM_PRIORITY probe sender", source))?;
    let receiver = UdpSocket::bind(bind_address)
        .map_err(|source| TimedEgressError::Io("bind SCM_PRIORITY probe receiver", source))?;
    sender
        .set_nonblocking(true)
        .map_err(|source| TimedEgressError::Io("set probe sender nonblocking", source))?;
    receiver
        .set_nonblocking(true)
        .map_err(|source| TimedEgressError::Io("set probe receiver nonblocking", source))?;
    let mut destination = SocketAddress::new(
        receiver
            .local_addr()
            .map_err(|source| TimedEgressError::Io("probe receiver local_addr", source))?,
    );
    let mut byte = 0xa5_u8;
    let mut iov = libc::iovec {
        iov_base: ptr::from_mut(&mut byte).cast(),
        iov_len: 1,
    };
    let mut control = ControlBuffer::<4>::new();
    control.push(libc::SOL_SOCKET, SCM_PRIORITY, 6_i32)?;
    let mut message: libc::msghdr = unsafe {
        // SAFETY: all-zero is a valid initial msghdr state.
        mem::zeroed()
    };
    message.msg_name = destination.as_mut_ptr();
    message.msg_namelen = destination.len();
    message.msg_iov = ptr::from_mut(&mut iov);
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    let sent = unsafe {
        // SAFETY: all pointers reference live storage for this sendmsg call.
        libc::sendmsg(
            sender.as_raw_fd(),
            &raw const message,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if sent < 0 {
        let source = io::Error::last_os_error();
        if source.raw_os_error() == Some(libc::EINVAL) {
            return Ok(ScmPriorityProbe {
                family,
                supported: false,
                errno: Some(libc::EINVAL),
            });
        }
        return Err(TimedEgressError::Io(
            "sendmsg(SCM_PRIORITY capability probe)",
            source,
        ));
    }
    if sent != 1 {
        return Err(TimedEgressError::ShortSend {
            expected: 1,
            observed: usize::try_from(sent).unwrap_or(0),
        });
    }
    let mut probe_payload = [0_u8; 1];
    let mut attempts = 0;
    loop {
        let result = unsafe {
            // SAFETY: probe_payload is live and receiver is disposable.
            libc::recv(
                receiver.as_raw_fd(),
                probe_payload.as_mut_ptr().cast(),
                probe_payload.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if result == 1 {
            break;
        }
        if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
            attempts += 1;
            if attempts < 100 {
                thread::yield_now();
                continue;
            }
        }
        return Err(TimedEgressError::CapabilityMismatch(format!(
            "SCM_PRIORITY probe sent one byte but drain returned {result}"
        )));
    }
    if probe_payload != [0xa5] {
        return Err(TimedEgressError::CapabilityMismatch(
            "SCM_PRIORITY probe payload did not round trip".into(),
        ));
    }
    Ok(ScmPriorityProbe {
        family,
        supported: true,
        errno: None,
    })
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ScmTimestamping {
    ts: [libc::timespec; 3],
}

fn receive_error_queue_event(fd: RawFd) -> Result<Option<KernelTxEvent>, TimedEgressError> {
    let mut payload = [0_u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut name = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut control = [0_usize; 64];
    let mut message: libc::msghdr = unsafe {
        // SAFETY: all-zero is a valid initial msghdr state.
        mem::zeroed()
    };
    message.msg_name = name.as_mut_ptr().cast();
    message.msg_namelen = libc::socklen_t::try_from(size_of::<libc::sockaddr_storage>())
        .map_err(|source| TimedEgressError::Protocol(source.to_string()))?;
    message.msg_iov = ptr::from_mut(&mut iov);
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size_of_val(&control);
    let received = unsafe {
        // SAFETY: all msghdr pointers reference writable live storage.
        libc::recvmsg(
            fd,
            &raw mut message,
            libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT,
        )
    };
    if received < 0 {
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(TimedEgressError::Io("recvmsg(MSG_ERRQUEUE)", source));
    }
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(TimedEgressError::MalformedAncillary(
            "recvmsg reported MSG_CTRUNC".into(),
        ));
    }
    decode_error_queue_message(&message).map(Some)
}

#[expect(
    clippy::too_many_lines,
    reason = "one decoder validates the coupled timestamp and extended-error ancillary record"
)]
fn decode_error_queue_message(message: &libc::msghdr) -> Result<KernelTxEvent, TimedEgressError> {
    let mut timestamp = None;
    let mut extended_error = None;
    let mut current = unsafe {
        // SAFETY: message is backed by the live recvmsg control buffer.
        libc::CMSG_FIRSTHDR(message)
    };
    while !current.is_null() {
        let header = unsafe {
            // SAFETY: current was returned by CMSG_FIRSTHDR or CMSG_NXTHDR.
            &*current
        };
        let base_len = unsafe {
            // SAFETY: zero is valid ancillary payload length.
            libc::CMSG_LEN(0)
        } as usize;
        if header.cmsg_len < base_len || header.cmsg_len > message.msg_controllen {
            return Err(TimedEgressError::MalformedAncillary(format!(
                "invalid cmsg_len {}",
                header.cmsg_len
            )));
        }
        let data_len = header.cmsg_len - base_len;
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_TIMESTAMPING {
            if timestamp.is_some() {
                return Err(TimedEgressError::MalformedAncillary(
                    "duplicate SCM_TIMESTAMPING".into(),
                ));
            }
            timestamp = Some(read_cmsg::<ScmTimestamping>(current, data_len)?);
        } else if (header.cmsg_level == libc::SOL_IP && header.cmsg_type == libc::IP_RECVERR)
            || (header.cmsg_level == libc::SOL_IPV6 && header.cmsg_type == libc::IPV6_RECVERR)
        {
            if extended_error.is_some() {
                return Err(TimedEgressError::MalformedAncillary(
                    "duplicate IP error cmsg".into(),
                ));
            }
            let family = if header.cmsg_level == libc::SOL_IP {
                SocketFamily::Ipv4
            } else {
                SocketFamily::Ipv6
            };
            extended_error = Some((
                family,
                read_cmsg::<libc::sock_extended_err>(current, data_len)?,
            ));
        } else {
            return Err(TimedEgressError::MalformedAncillary(format!(
                "unexpected cmsg level={} type={}",
                header.cmsg_level, header.cmsg_type
            )));
        }
        current = unsafe {
            // SAFETY: current belongs to message and the buffer remains live.
            libc::CMSG_NXTHDR(message, current)
        };
    }
    let (family, error) = extended_error.ok_or_else(|| {
        TimedEgressError::MalformedAncillary("error queue lacked IP_RECVERR or IPV6_RECVERR".into())
    })?;
    if error.ee_origin == libc::SO_EE_ORIGIN_TIMESTAMPING {
        if error.ee_errno != libc::ENOMSG as u32 {
            return Err(TimedEgressError::MalformedAncillary(format!(
                "timestamp errno {} was not ENOMSG",
                error.ee_errno
            )));
        }
        let timestamp = timestamp.ok_or_else(|| {
            TimedEgressError::MalformedAncillary("timestamp event lacked SCM_TIMESTAMPING".into())
        })?;
        let kind = match error.ee_info {
            SCM_TSTAMP_SND => TimestampKind::Software,
            SCM_TSTAMP_SCHED => TimestampKind::Scheduled,
            other => {
                return Err(TimedEgressError::MalformedAncillary(format!(
                    "unexpected timestamp ee_info={other}"
                )));
            }
        };
        return Ok(KernelTxEvent::Timestamp {
            kind,
            kernel_id: error.ee_data,
            realtime_ns: timespec_ns(timestamp.ts[0])?,
        });
    }
    if error.ee_origin == SO_EE_ORIGIN_TXTIME {
        if timestamp.is_some() {
            return Err(TimedEgressError::MalformedAncillary(
                "TXTIME drop unexpectedly carried timestamp data".into(),
            ));
        }
        let kind = match error.ee_code {
            SO_EE_CODE_TXTIME_INVALID_PARAM => TxtimeDropKind::InvalidParameter,
            SO_EE_CODE_TXTIME_MISSED => TxtimeDropKind::Missed,
            other => {
                return Err(TimedEgressError::MalformedAncillary(format!(
                    "unknown TXTIME ee_code={other}"
                )));
            }
        };
        return Ok(KernelTxEvent::TxtimeDrop(TxtimeDropDiagnostic {
            family,
            errno: error.ee_errno,
            kind,
            // Linux encodes the low word in ee_info and high word in ee_data.
            // No SO_TIMESTAMPING OPT_ID is available for this origin.
            requested_txtime_tai_ns: (u64::from(error.ee_data) << 32) | u64::from(error.ee_info),
        }));
    }
    if timestamp.is_some() {
        return Err(TimedEgressError::MalformedAncillary(format!(
            "origin {} unexpectedly carried timestamp data",
            error.ee_origin
        )));
    }
    Ok(KernelTxEvent::NetworkError(NetworkErrorDiagnostic {
        family,
        errno: error.ee_errno,
        origin: error.ee_origin,
        error_type: error.ee_type,
        code: error.ee_code,
        info: error.ee_info,
        data: error.ee_data,
    }))
}

fn read_cmsg<T: Copy>(cmsg: *const libc::cmsghdr, data_len: usize) -> Result<T, TimedEgressError> {
    if data_len < size_of::<T>() {
        return Err(TimedEgressError::MalformedAncillary(format!(
            "cmsg length {data_len} shorter than {}",
            size_of::<T>()
        )));
    }
    Ok(unsafe {
        // SAFETY: length proves T bytes exist; unaligned read avoids assuming
        // anything beyond the CMSG ABI guarantee.
        ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<T>())
    })
}

fn timespec_ns(value: libc::timespec) -> Result<u64, TimedEgressError> {
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err(TimedEgressError::MalformedAncillary(format!(
            "invalid timespec sec={} nsec={}",
            value.tv_sec, value.tv_nsec
        )));
    }
    let seconds = u64::try_from(value.tv_sec)
        .map_err(|source| TimedEgressError::MalformedAncillary(source.to_string()))?;
    let nanos = u64::try_from(value.tv_nsec)
        .map_err(|source| TimedEgressError::MalformedAncillary(source.to_string()))?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or_else(|| TimedEgressError::MalformedAncillary("timespec overflow".into()))
}

fn poll_error_queue(fd: RawFd, remaining: Duration) -> Result<(), TimedEgressError> {
    let nanos_remainder = remaining.subsec_nanos() % 1_000_000;
    let timeout_ms = libc::c_int::try_from(
        remaining
            .as_millis()
            .saturating_add(u128::from(nanos_remainder != 0))
            .min(libc::c_int::MAX as u128),
    )
    .map_err(|source| TimedEgressError::Protocol(source.to_string()))?;
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLERR,
        revents: 0,
    };
    let result = unsafe {
        // SAFETY: descriptor is a live one-element pollfd array.
        libc::poll(ptr::from_mut(&mut descriptor), 1, timeout_ms)
    };
    if result < 0 {
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::Interrupted {
            return Ok(());
        }
        return Err(TimedEgressError::Io("poll(POLLERR)", source));
    }
    if result > 0 && descriptor.revents & libc::POLLNVAL != 0 {
        return Err(TimedEgressError::Protocol("poll reported POLLNVAL".into()));
    }
    Ok(())
}

pub fn clock_tai_ns() -> Result<u64, TimedEgressError> {
    clock_ns(libc::CLOCK_TAI, "clock_gettime(CLOCK_TAI)")
}

pub fn clock_monotonic_ns() -> Result<u64, TimedEgressError> {
    clock_ns(libc::CLOCK_MONOTONIC, "clock_gettime(CLOCK_MONOTONIC)")
}

pub fn clock_realtime_ns() -> Result<u64, TimedEgressError> {
    clock_ns(libc::CLOCK_REALTIME, "clock_gettime(CLOCK_REALTIME)")
}

pub fn sample_kernel_clock_bracket() -> Result<KernelClockBracket, TimedEgressError> {
    let monotonic = sample_tai_bracketed_clock(libc::CLOCK_MONOTONIC)?;
    let realtime = sample_tai_bracketed_clock(libc::CLOCK_REALTIME)?;
    Ok(KernelClockBracket {
        schema_version: 1,
        monotonic,
        realtime,
    })
}

pub fn sample_tai_bracketed_clock(
    clock_id: libc::clockid_t,
) -> Result<TaiBracketedClockSample, TimedEgressError> {
    let clock_operation = match clock_id {
        libc::CLOCK_MONOTONIC => "clock_gettime(CLOCK_MONOTONIC)",
        libc::CLOCK_REALTIME => "clock_gettime(CLOCK_REALTIME)",
        _ => {
            return Err(TimedEgressError::Protocol(format!(
                "TAI bracket does not support clock id {clock_id}"
            )));
        }
    };
    let tai_before_ns = clock_tai_ns()?;
    let clock_ns = clock_ns(clock_id, clock_operation)?;
    let tai_after_ns = clock_tai_ns()?;
    Ok(TaiBracketedClockSample {
        schema_version: 1,
        clock_id,
        tai_before_ns,
        clock_ns,
        tai_after_ns,
    })
}

fn clock_ns(clock_id: libc::clockid_t, operation: &'static str) -> Result<u64, TimedEgressError> {
    let mut value = MaybeUninit::<libc::timespec>::uninit();
    let result = unsafe {
        // SAFETY: value points to writable timespec storage.
        libc::clock_gettime(clock_id, value.as_mut_ptr())
    };
    if result != 0 {
        return Err(last_io_error(operation));
    }
    let value = unsafe {
        // SAFETY: successful clock_gettime initialized value.
        value.assume_init()
    };
    timespec_ns(value)
}

fn duplicate_cloexec(fd: BorrowedFd<'_>) -> Result<OwnedFd, TimedEgressError> {
    let duplicate = unsafe {
        // SAFETY: fd is live and F_DUPFD_CLOEXEC creates a new descriptor.
        libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0)
    };
    if duplicate < 0 {
        return Err(last_io_error("fcntl(F_DUPFD_CLOEXEC)"));
    }
    Ok(unsafe {
        // SAFETY: ownership of the fresh descriptor transfers exactly once.
        OwnedFd::from_raw_fd(duplicate)
    })
}

fn setsockopt<T>(
    fd: RawFd,
    level: libc::c_int,
    option: libc::c_int,
    value: &T,
    operation: &'static str,
) -> Result<(), TimedEgressError> {
    let length = libc::socklen_t::try_from(size_of::<T>())
        .map_err(|source| TimedEgressError::Protocol(source.to_string()))?;
    let result = unsafe {
        // SAFETY: value is live for length bytes and fd is a live socket.
        libc::setsockopt(fd, level, option, ptr::from_ref(value).cast(), length)
    };
    if result != 0 {
        return Err(last_io_error(operation));
    }
    Ok(())
}

fn getsockopt<T: Copy>(
    fd: RawFd,
    level: libc::c_int,
    option: libc::c_int,
    operation: &'static str,
) -> Result<T, TimedEgressError> {
    let mut value = MaybeUninit::<T>::zeroed();
    let mut length = libc::socklen_t::try_from(size_of::<T>())
        .map_err(|source| TimedEgressError::Protocol(source.to_string()))?;
    let result = unsafe {
        // SAFETY: value and length are writable and fd is a live socket.
        libc::getsockopt(
            fd,
            level,
            option,
            value.as_mut_ptr().cast(),
            ptr::from_mut(&mut length),
        )
    };
    if result != 0 {
        return Err(last_io_error(operation));
    }
    if length as usize != size_of::<T>() {
        return Err(TimedEgressError::CapabilityMismatch(format!(
            "{operation} returned {length} bytes, expected {}",
            size_of::<T>()
        )));
    }
    Ok(unsafe {
        // SAFETY: successful getsockopt wrote exactly size_of::<T>() bytes.
        value.assume_init()
    })
}

fn socket_identity(fd: RawFd) -> Result<(SocketFamily, SocketAddr), TimedEgressError> {
    let mut storage = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut length = libc::socklen_t::try_from(size_of::<libc::sockaddr_storage>())
        .map_err(|source| TimedEgressError::Protocol(source.to_string()))?;
    let result = unsafe {
        // SAFETY: storage and length are writable and fd is a live socket.
        libc::getsockname(fd, storage.as_mut_ptr().cast(), ptr::from_mut(&mut length))
    };
    if result != 0 {
        return Err(last_io_error("getsockname"));
    }
    let storage = unsafe {
        // SAFETY: successful getsockname initialized the address prefix.
        storage.assume_init()
    };
    match libc::c_int::from(storage.ss_family) {
        libc::AF_INET if length as usize >= size_of::<libc::sockaddr_in>() => {
            let address = unsafe {
                // SAFETY: family and length establish sockaddr_in layout.
                ptr::read_unaligned(ptr::from_ref(&storage).cast::<libc::sockaddr_in>())
            };
            Ok((
                SocketFamily::Ipv4,
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr))),
                    u16::from_be(address.sin_port),
                ),
            ))
        }
        libc::AF_INET6 if length as usize >= size_of::<libc::sockaddr_in6>() => {
            let address = unsafe {
                // SAFETY: family and length establish sockaddr_in6 layout.
                ptr::read_unaligned(ptr::from_ref(&storage).cast::<libc::sockaddr_in6>())
            };
            Ok((
                SocketFamily::Ipv6,
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)),
                    u16::from_be(address.sin6_port),
                ),
            ))
        }
        other => Err(TimedEgressError::UnsupportedSocket(format!(
            "getsockname returned family={other} length={length}"
        ))),
    }
}

fn last_io_error(operation: &'static str) -> TimedEgressError {
    TimedEgressError::Io(operation, io::Error::last_os_error())
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, os::fd::AsRawFd as _};

    use neqo_common::{Ecn, Tos};

    use super::*;

    fn dropped_status() -> &'static str {
        "Uid:\t1000\t1000\t1000\t1000\n\
         Gid:\t1000\t1000\t1000\t1000\n\
         Groups:\t\n\
         CapInh:\t0000000000000000\n\
         CapPrm:\t0000000000000000\n\
         CapEff:\t0000000000000000\n\
         CapBnd:\t0000000000000000\n\
         CapAmb:\t0000000000000000\n\
         NoNewPrivs:\t1\n"
    }

    fn pending_socket() -> ActiveTimedEgressSocket {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        socket.set_nonblocking(true).expect("nonblocking");
        let address = socket.local_addr().expect("address");
        ActiveTimedEgressSocket {
            fd: duplicate_cloexec(socket.as_fd()).expect("duplicate"),
            family: SocketFamily::Ipv4,
            local_address: address,
            contract: EtfContract::STRICT,
            setup_receipt: TimedEgressSetupReceipt {
                schema_version: 1,
                family: SocketFamily::Ipv4,
                local_address: address,
                duplicated_fd_cloexec: true,
                nonblocking: true,
                socket_type: libc::SOCK_DGRAM,
                txtime_clock_id: libc::CLOCK_TAI,
                txtime_flags: libc::SOF_TXTIME_REPORT_ERRORS,
                timestamping_report_flags: REPORT_FLAGS,
                timed_priority: 6,
                priority_before_probe: 0,
                priority_after_probe: 0,
                corresponding_error_queue_enabled: true,
                etf_deadline_mode: false,
                etf_skip_socket_check: false,
                priority_method: TimedPriorityMethod::SerializedSocketSoPriority,
                scm_priority_supported: false,
                scm_priority_probe_family: SocketFamily::Ipv4,
                scm_priority_probe_errno: Some(libc::EINVAL),
                exclusive_socket_sender_required: true,
                per_datagram_timestamp_requests: true,
            },
            privilege_receipt: PrivilegeDropReceipt::parse_proc_status(dropped_status())
                .expect("parse"),
            pending: Some(PendingTransmission {
                requested_txtime_tai_ns: 123,
                kernel_timestamp_id: None,
                tx_sched_realtime_ns: None,
                tx_software_realtime_ns: None,
            }),
            poison: None,
        }
    }

    fn timestamp_event(kind: TimestampKind, kernel_id: u32, realtime_ns: u64) -> KernelTxEvent {
        KernelTxEvent::Timestamp {
            kind,
            kernel_id,
            realtime_ns,
        }
    }

    fn decode_control(control: &mut ControlBuffer<32>) -> Result<KernelTxEvent, TimedEgressError> {
        let mut message: libc::msghdr = unsafe {
            // SAFETY: all-zero is a valid initial msghdr state.
            mem::zeroed()
        };
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len();
        decode_error_queue_message(&message)
    }

    fn count_control_messages<const WORDS: usize>(
        control: &mut ControlBuffer<WORDS>,
        level: libc::c_int,
        kind: libc::c_int,
    ) -> usize {
        let mut message: libc::msghdr = unsafe {
            // SAFETY: all-zero is a valid initial msghdr state.
            mem::zeroed()
        };
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len();
        let mut count = 0;
        let mut current = unsafe {
            // SAFETY: message points at the live test control buffer.
            libc::CMSG_FIRSTHDR(&raw const message)
        };
        while !current.is_null() {
            let header = unsafe {
                // SAFETY: current is returned by the CMSG traversal API.
                &*current
            };
            if header.cmsg_level == level && header.cmsg_type == kind {
                count += 1;
            }
            current = unsafe {
                // SAFETY: current and message refer to the same live buffer.
                libc::CMSG_NXTHDR(&raw const message, current)
            };
        }
        count
    }

    #[test]
    fn linux_abi_bits_are_bound_explicitly() {
        assert_eq!(libc::SOF_TXTIME_DEADLINE_MODE, 1 << 0);
        assert_eq!(libc::SOF_TXTIME_REPORT_ERRORS, 1 << 1);
        assert_eq!(libc::SOF_TIMESTAMPING_TX_SCHED, 1 << 8);
        assert_eq!(
            EtfContract::STRICT,
            EtfContract {
                clock_id: libc::CLOCK_TAI,
                deadline_mode: false,
                skip_socket_check: false,
                timed_priority: 6,
            }
        );
    }

    #[test]
    fn strict_contract_rejects_every_semantic_deviation() {
        EtfContract::STRICT.validate().expect("strict");
        for invalid in [
            EtfContract {
                clock_id: libc::CLOCK_MONOTONIC,
                ..EtfContract::STRICT
            },
            EtfContract {
                deadline_mode: true,
                ..EtfContract::STRICT
            },
            EtfContract {
                skip_socket_check: true,
                ..EtfContract::STRICT
            },
            EtfContract {
                timed_priority: 5,
                ..EtfContract::STRICT
            },
        ] {
            assert!(matches!(
                invalid.validate(),
                Err(TimedEgressError::InvalidContract(_))
            ));
        }
    }

    #[test]
    fn enqueue_cutoff_is_strict_and_checked_before_txtime() {
        assert!(validate_enqueue_deadline(120, 100, 99).is_ok());
        assert!(matches!(
            validate_enqueue_deadline(120, 100, 100),
            Err(TimedEgressError::EnqueueDeadline {
                latest: 100,
                observed: 100
            })
        ));
        assert!(matches!(
            validate_enqueue_deadline(120, 200, 120),
            Err(TimedEgressError::PastTxtime {
                requested: 120,
                observed: 120
            })
        ));
    }

    #[test]
    fn expired_main_cutoff_refuses_sendmsg_and_restores_default_priority() {
        let mut socket = pending_socket();
        socket.pending = None;
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("receiver");
        receiver
            .set_nonblocking(true)
            .expect("nonblocking receiver");
        let batch = datagram::Batch::new(
            socket.local_address,
            receiver.local_addr().expect("receiver address"),
            Tos::default(),
            NonZeroUsize::new(1).expect("nonzero"),
            vec![0x51],
        );
        let error = socket
            .enqueue_exact(&batch, u64::MAX, 0)
            .expect_err("zero cutoff must reject before sendmsg");
        assert!(matches!(
            error,
            TimedEgressError::EnqueueDeadline {
                latest: 0,
                observed: 1..
            }
        ));
        let mut payload = [0_u8; 1];
        assert!(matches!(
            receiver.recv(&mut payload),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        assert_eq!(
            getsockopt::<libc::c_int>(
                socket.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PRIORITY,
                "test priority after main cutoff"
            )
            .expect("priority"),
            0
        );
        assert!(socket.pending.is_none());
        assert!(matches!(
            socket.ensure_usable(),
            Err(TimedEgressError::Poisoned(_))
        ));
    }

    #[test]
    fn expired_immediate_cutoff_refuses_sendmsg() {
        let mut socket = pending_socket();
        socket.pending = None;
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("receiver");
        receiver
            .set_nonblocking(true)
            .expect("nonblocking receiver");
        let batch = datagram::Batch::new(
            socket.local_address,
            receiver.local_addr().expect("receiver address"),
            Tos::default(),
            NonZeroUsize::new(1).expect("nonzero"),
            vec![0x52],
        );
        let error = socket
            .send_immediate_after_proven_main(&batch, 0, Duration::from_millis(1))
            .expect_err("zero cutoff must reject before sendmsg");
        assert!(matches!(
            error,
            TimedEgressError::EnqueueDeadline {
                latest: 0,
                observed: 1..
            }
        ));
        let mut payload = [0_u8; 1];
        assert!(matches!(
            receiver.recv(&mut payload),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        assert!(socket.pending.is_none());
        assert!(matches!(
            socket.ensure_usable(),
            Err(TimedEgressError::Poisoned(_))
        ));
    }

    #[test]
    fn raw_clocks_are_independently_tai_bracketed() {
        let bracket = sample_kernel_clock_bracket().expect("clock bracket");
        assert_eq!(bracket.schema_version, 1);
        assert_eq!(bracket.monotonic.clock_id, libc::CLOCK_MONOTONIC);
        assert_eq!(bracket.realtime.clock_id, libc::CLOCK_REALTIME);
        for sample in [bracket.monotonic, bracket.realtime] {
            assert_eq!(sample.schema_version, 1);
            assert!(sample.tai_before_ns <= sample.tai_after_ns);
            assert!(sample.clock_ns > 0);
        }
        assert!(
            bracket.monotonic.tai_after_ns <= bracket.realtime.tai_before_ns,
            "the two phase samples must retain acquisition order"
        );
        assert!(clock_tai_ns().expect("TAI") > 0);
        assert!(clock_monotonic_ns().expect("monotonic") > 0);
        assert!(clock_realtime_ns().expect("realtime") > 0);
    }

    #[test]
    fn privilege_receipt_requires_empty_bounding_and_usable_sets() {
        let valid = PrivilegeDropReceipt::parse_proc_status(dropped_status()).expect("parse valid");
        valid.validate_permanent_drop().expect("valid drop");
        for invalid in [
            dropped_status().replace("Uid:\t1000\t1000\t1000\t1000", "Uid:\t1000\t0\t1000\t1000"),
            dropped_status().replace("CapEff:\t0000000000000000", "CapEff:\t0000000000001000"),
            dropped_status().replace("CapBnd:\t0000000000000000", "CapBnd:\t0000000000000100"),
            dropped_status().replace("Groups:\t", "Groups:\t27"),
            dropped_status().replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
        ] {
            let receipt = PrivilegeDropReceipt::parse_proc_status(&invalid).expect("parse invalid");
            assert!(matches!(
                receipt.validate_permanent_drop(),
                Err(TimedEgressError::PrivilegeState(_))
            ));
        }
    }

    #[test]
    fn duplicated_descriptor_is_owned_and_cloexec() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let address = socket.local_addr().expect("address");
        let duplicate = duplicate_cloexec(socket.as_fd()).expect("duplicate");
        let duplicate_raw = duplicate.as_raw_fd();
        assert_ne!(duplicate_raw, socket.as_raw_fd());
        drop(socket);
        let flags = unsafe {
            // SAFETY: duplicate remains owned after the source socket is gone.
            libc::fcntl(duplicate_raw, libc::F_GETFD)
        };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        assert_eq!(socket_identity(duplicate_raw).expect("identity").1, address);
    }

    #[test]
    fn setup_rejects_blocking_socket() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        assert!(matches!(
            PreparedTimedEgressSocket::configure(&socket, EtfContract::STRICT),
            Err(TimedEgressError::UnsupportedSocket(_))
        ));
    }

    #[test]
    fn setup_reads_back_minimum_global_options_and_selects_one_priority_method() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        socket.set_nonblocking(true).expect("nonblocking");
        let prepared =
            PreparedTimedEgressSocket::configure(&socket, EtfContract::STRICT).expect("setup");
        let receipt = prepared.receipt();
        let mut untouched = [0_u8; 1];
        assert!(matches!(
            socket.recv(&mut untouched),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        assert_eq!(receipt.txtime_clock_id, libc::CLOCK_TAI);
        assert_eq!(receipt.txtime_flags, 1 << 1);
        assert_eq!(receipt.timestamping_report_flags, REPORT_FLAGS);
        assert_eq!(
            receipt.timestamping_report_flags & REQUEST_FLAGS,
            0,
            "ordinary sends must not request TX timestamps globally"
        );
        assert_eq!(receipt.priority_before_probe, 0);
        assert_eq!(receipt.priority_after_probe, 0);
        assert_eq!(
            receipt.scm_priority_supported,
            matches!(
                receipt.priority_method,
                TimedPriorityMethod::PerDatagramScmPriority
            )
        );
        assert_eq!(receipt.scm_priority_probe_family, SocketFamily::Ipv4);
        assert_eq!(
            receipt.scm_priority_probe_errno,
            (!receipt.scm_priority_supported).then_some(libc::EINVAL)
        );
        assert!(receipt.exclusive_socket_sender_required);
        assert!(!receipt.etf_skip_socket_check);
    }

    #[test]
    fn ordinary_send_generates_no_tx_error_queue_receipt() {
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("sender");
        sender.set_nonblocking(true).expect("nonblocking");
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("receiver");
        receiver.set_nonblocking(true).expect("nonblocking");
        let prepared =
            PreparedTimedEgressSocket::configure(&sender, EtfContract::STRICT).expect("setup");
        sender
            .send_to(&[0x42], receiver.local_addr().expect("receiver address"))
            .expect("ordinary send");
        let mut payload = [0_u8; 1];
        for _ in 0..100 {
            match receiver.recv(&mut payload) {
                Ok(1) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::yield_now(),
                other => panic!("unexpected receive result: {other:?}"),
            }
        }
        thread::sleep(Duration::from_millis(2));
        assert_eq!(payload, [0x42]);
        assert!(
            receive_error_queue_event(prepared.fd.as_raw_fd())
                .expect("error queue")
                .is_none()
        );
    }

    #[test]
    fn ancillary_capacity_covers_worst_case_and_overflow_is_exact() {
        let mut control = ControlBuffer::<SEND_CONTROL_WORDS>::new();
        control
            .push(libc::SOL_SOCKET, libc::SCM_TXTIME, 1_u64)
            .expect("txtime");
        control
            .push(libc::SOL_SOCKET, libc::SO_TIMESTAMPING, REQUEST_FLAGS)
            .expect("timestamp");
        control
            .push(libc::SOL_SOCKET, SCM_PRIORITY, 6_i32)
            .expect("priority");
        control
            .push(libc::SOL_IPV6, libc::IPV6_TCLASS, 0_i32)
            .expect("tclass");
        control
            .push(
                libc::SOL_IPV6,
                libc::IPV6_PKTINFO,
                libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr { s6_addr: [0; 16] },
                    ipi6_ifindex: 0,
                },
            )
            .expect("pktinfo");
        assert_eq!(control.len(), MAX_SEND_CONTROL_BYTES);
        assert!(control.len() <= SEND_CONTROL_CAPACITY_BYTES);

        let mut tiny = ControlBuffer::<1>::new();
        assert!(matches!(
            tiny.push(libc::SOL_SOCKET, libc::SCM_TXTIME, 1_u64),
            Err(TimedEgressError::AncillaryOverflow {
                required,
                capacity
            }) if required == unsafe {
                // SAFETY: concrete u64 ancillary length is representable.
                libc::CMSG_SPACE(8_u32)
            } as usize && capacity == size_of::<usize>()
        ));
    }

    #[test]
    fn native_timed_control_contains_exactly_one_priority_message() {
        let source = SocketAddr::from((Ipv6Addr::LOCALHOST, 12_000));
        let destination = SocketAddr::from((Ipv6Addr::LOCALHOST, 12_001));
        let batch = datagram::Batch::new(
            source,
            destination,
            Tos::default(),
            NonZeroUsize::new(4).expect("nonzero"),
            vec![1; 4],
        );
        let mut native =
            build_timed_send_control(&batch, 123, TimedPriorityMethod::PerDatagramScmPriority, 6)
                .expect("native control");
        assert_eq!(
            count_control_messages(&mut native, libc::SOL_SOCKET, SCM_PRIORITY),
            1
        );
        assert_eq!(
            count_control_messages(&mut native, libc::SOL_SOCKET, libc::SCM_TXTIME),
            1
        );
        assert_eq!(
            count_control_messages(&mut native, libc::SOL_SOCKET, libc::SO_TIMESTAMPING),
            1
        );

        let mut fallback = build_timed_send_control(
            &batch,
            123,
            TimedPriorityMethod::SerializedSocketSoPriority,
            6,
        )
        .expect("fallback control");
        assert_eq!(
            count_control_messages(&mut fallback, libc::SOL_SOCKET, SCM_PRIORITY),
            0
        );
    }

    #[test]
    fn serialized_priority_restores_zero_when_send_fails() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        socket.set_nonblocking(true).expect("nonblocking");
        let mut byte = 1_u8;
        let mut iov = libc::iovec {
            iov_base: ptr::from_mut(&mut byte).cast(),
            iov_len: 1,
        };
        let mut message: libc::msghdr = unsafe {
            // SAFETY: all-zero is a valid initial msghdr state.
            mem::zeroed()
        };
        message.msg_iov = ptr::from_mut(&mut iov);
        message.msg_iovlen = 1;
        let now = clock_tai_ns().expect("TAI");
        let attempt = sendmsg_with_serialized_priority(
            socket.as_raw_fd(),
            &message,
            6,
            now + 2_000_000_000,
            now + 1_000_000_000,
        )
        .expect("sendmsg attempt is retained");
        assert!(matches!(
            attempt.post_send_error,
            Some(TimedEgressError::Io(_, _))
        ));
        assert_eq!(
            getsockopt::<libc::c_int>(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PRIORITY,
                "test readback"
            )
            .expect("priority"),
            0
        );
    }

    #[test]
    fn serialized_enqueue_failure_poison_is_terminal() {
        let mut socket = pending_socket();
        socket.pending = None;
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("receiver");
        let batch = datagram::Batch::new(
            socket.local_address,
            receiver.local_addr().expect("receiver address"),
            Tos::default(),
            NonZeroUsize::new(1).expect("nonzero"),
            vec![1],
        );
        let txtime = clock_tai_ns()
            .expect("TAI")
            .checked_add(1_000_000_000)
            .expect("future txtime");
        assert!(
            socket
                .enqueue_exact(&batch, txtime, txtime - 500_000_000)
                .is_err()
        );
        assert!(matches!(
            socket.ensure_usable(),
            Err(TimedEgressError::Poisoned(_))
        ));
        assert_eq!(
            getsockopt::<libc::c_int>(
                socket.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PRIORITY,
                "test priority after failed enqueue"
            )
            .expect("priority"),
            0
        );
    }

    #[test]
    fn exact_batch_validation_rejects_gso_and_wrong_port() {
        let source = SocketAddr::from((Ipv4Addr::LOCALHOST, 12000));
        let destination = SocketAddr::from((Ipv4Addr::LOCALHOST, 12001));
        let gso = datagram::Batch::new(
            source,
            destination,
            Tos::from(Ecn::Ect0),
            NonZeroUsize::new(4).expect("nonzero"),
            vec![1; 8],
        );
        assert!(matches!(
            validate_exact_batch(&gso, SocketFamily::Ipv4, source),
            Err(TimedEgressError::Protocol(_))
        ));
        let exact = datagram::Batch::new(
            source,
            destination,
            Tos::default(),
            NonZeroUsize::new(4).expect("nonzero"),
            vec![1; 4],
        );
        assert!(matches!(
            validate_exact_batch(
                &exact,
                SocketFamily::Ipv4,
                SocketAddr::from((Ipv4Addr::LOCALHOST, 9999))
            ),
            Err(TimedEgressError::Protocol(_))
        ));
    }

    #[test]
    fn decodes_ipv4_sched_and_ipv6_software_timestamp_events() {
        for (level, kind, info) in [
            (libc::SOL_IP, TimestampKind::Scheduled, SCM_TSTAMP_SCHED),
            (libc::SOL_IPV6, TimestampKind::Software, SCM_TSTAMP_SND),
        ] {
            let timestamping = ScmTimestamping {
                ts: [
                    libc::timespec {
                        tv_sec: 12,
                        tv_nsec: 34,
                    },
                    libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    },
                    libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    },
                ],
            };
            let error = libc::sock_extended_err {
                ee_errno: libc::ENOMSG as u32,
                ee_origin: libc::SO_EE_ORIGIN_TIMESTAMPING,
                ee_type: 0,
                ee_code: 0,
                ee_pad: 0,
                ee_info: info,
                ee_data: 7,
            };
            let mut control = ControlBuffer::<32>::new();
            control
                .push(libc::SOL_SOCKET, libc::SCM_TIMESTAMPING, timestamping)
                .expect("timestamp");
            control
                .push(
                    level,
                    if level == libc::SOL_IP {
                        libc::IP_RECVERR
                    } else {
                        libc::IPV6_RECVERR
                    },
                    error,
                )
                .expect("extended error");
            assert_eq!(
                decode_control(&mut control).expect("decode"),
                timestamp_event(kind, 7, 12_000_000_034)
            );
        }
    }

    #[test]
    fn decodes_txtime_missed_and_invalid_parameter_drops() {
        for (level, code, kind) in [
            (
                libc::SOL_IP,
                SO_EE_CODE_TXTIME_MISSED,
                TxtimeDropKind::Missed,
            ),
            (
                libc::SOL_IPV6,
                SO_EE_CODE_TXTIME_INVALID_PARAM,
                TxtimeDropKind::InvalidParameter,
            ),
        ] {
            let error = libc::sock_extended_err {
                ee_errno: libc::ECANCELED as u32,
                ee_origin: SO_EE_ORIGIN_TXTIME,
                ee_type: 0,
                ee_code: code,
                ee_pad: 0,
                ee_info: 0x1234_5678,
                ee_data: 0x90ab_cdef,
            };
            let mut control = ControlBuffer::<32>::new();
            control
                .push(
                    level,
                    if level == libc::SOL_IP {
                        libc::IP_RECVERR
                    } else {
                        libc::IPV6_RECVERR
                    },
                    error,
                )
                .expect("extended error");
            assert_eq!(
                decode_control(&mut control).expect("decode"),
                KernelTxEvent::TxtimeDrop(TxtimeDropDiagnostic {
                    family: if level == libc::SOL_IP {
                        SocketFamily::Ipv4
                    } else {
                        SocketFamily::Ipv6
                    },
                    errno: libc::ECANCELED as u32,
                    kind,
                    requested_txtime_tai_ns: 0x90ab_cdef_1234_5678,
                })
            );
        }
    }

    #[test]
    fn report_aggregation_is_matching_and_fail_closed() {
        let mut socket = pending_socket();
        assert!(
            socket
                .observe_event(timestamp_event(TimestampKind::Scheduled, 7, 1_000))
                .expect("scheduled")
                .is_none()
        );
        let outcome = socket
            .observe_event(timestamp_event(TimestampKind::Software, 7, 1_100))
            .expect("software")
            .expect("outcome");
        assert_eq!(outcome.kernel_timestamp_id, 7);
        assert_eq!(outcome.tx_sched_realtime_ns, 1_000);
        assert_eq!(outcome.tx_software_realtime_ns, 1_100);

        let mut mismatch = pending_socket();
        mismatch
            .observe_event(timestamp_event(TimestampKind::Scheduled, 7, 1_000))
            .expect("scheduled");
        assert!(matches!(
            mismatch.observe_event(timestamp_event(TimestampKind::Software, 8, 1_100)),
            Err(TimedEgressError::KernelIdMismatch {
                expected: 7,
                observed: 8
            })
        ));
        assert!(matches!(
            mismatch.ensure_usable(),
            Err(TimedEgressError::Poisoned(_))
        ));
    }

    #[test]
    fn missing_pending_state_is_typed_and_fail_closed() {
        let mut wait_socket = pending_socket();
        wait_socket.pending = None;
        assert!(matches!(
            wait_socket.wait_for_outcome(Duration::ZERO),
            Err(TimedEgressError::Protocol(detail))
                if detail == "wait_for_outcome called without a pending send"
        ));
        assert!(matches!(
            wait_socket.ensure_usable(),
            Err(TimedEgressError::Poisoned(detail))
                if detail.contains("wait_for_outcome called without a pending send")
        ));

        let mut observe_socket = pending_socket();
        observe_socket.pending = None;
        assert!(matches!(
            observe_socket.observe_event(timestamp_event(
                TimestampKind::Scheduled,
                7,
                1_000,
            )),
            Err(TimedEgressError::Protocol(detail))
                if detail == "observe_event called without a pending transmission"
        ));
        assert!(matches!(
            observe_socket.ensure_usable(),
            Err(TimedEgressError::Poisoned(detail))
                if detail.contains("observe_event called without a pending transmission")
        ));
    }

    #[test]
    fn helper_contract_binds_cpu_scheduler_and_name() {
        let contract = HelperThreadContract::RR1_CPU11_V1;
        assert_eq!(contract.target_cpu, 11);
        assert_eq!(contract.expected_scheduler_policy, libc::SCHED_RR);
        assert_eq!(contract.expected_scheduler_priority, 1);
        assert_eq!(contract.name, "qcsd-client-rr1-cpu10-etf-helper-cpu11-v1");
        assert_eq!(scheduler_policy_name(libc::SCHED_RR), "SCHED_RR");
        let inventory = PostMainInventoryContract {
            expected_endpoint_sockets: 73,
            credit_owner_capacity: 73,
            max_datagrams_per_owner: 4,
            max_post_main_datagrams: 256,
        };
        inventory.validate(73).expect("matching inventory");
        assert!(matches!(
            inventory.validate(72),
            Err(TimedEgressError::HelperContract(_))
        ));
        assert!(matches!(
            PostMainInventoryContract {
                expected_endpoint_sockets: 73,
                credit_owner_capacity: 73,
                max_datagrams_per_owner: 4,
                max_post_main_datagrams: 293,
            }
            .validate(73),
            Err(TimedEgressError::HelperContract(_))
        ));
    }

    #[test]
    fn post_main_inventory_is_bounded_per_owner_and_in_total() {
        let inventory = PostMainInventoryContract {
            expected_endpoint_sockets: 3,
            credit_owner_capacity: 3,
            max_datagrams_per_owner: 1,
            max_post_main_datagrams: 3,
        };
        inventory.validate(3).expect("valid owner inventory");
        validate_post_main_owner(inventory, 0, &[0, 0, 0], 3).expect("unused owner");
        assert!(matches!(
            validate_post_main_owner(inventory, 0, &[1, 0, 0], 2),
            Err(TimedEgressError::Protocol(detail))
                if detail.contains("per-owner bound")
        ));
        assert!(matches!(
            validate_post_main_owner(inventory, 3, &[0, 0, 0], 3),
            Err(TimedEgressError::Protocol(detail))
                if detail.contains("outside the receipted inventory")
        ));
        assert!(matches!(
            validate_post_main_owner(inventory, 1, &[0, 0, 0], 0),
            Err(TimedEgressError::Protocol(detail))
                if detail.contains("exhausted its receipted post-main inventory")
        ));

        assert!(matches!(
            PostMainInventoryContract {
                expected_endpoint_sockets: 3,
                credit_owner_capacity: 2,
                max_datagrams_per_owner: 1,
                max_post_main_datagrams: 2,
            }
            .validate(3),
            Err(TimedEgressError::HelperContract(detail))
                if detail.contains("one owner for each")
        ));
        assert!(matches!(
            PostMainInventoryContract {
                expected_endpoint_sockets: usize::MAX,
                credit_owner_capacity: usize::MAX,
                max_datagrams_per_owner: 2,
                max_post_main_datagrams: 0,
            }
            .validate(usize::MAX),
            Err(TimedEgressError::HelperContract(detail))
                if detail.contains("overflowed")
        ));
    }

    #[test]
    fn helper_poison_is_global_and_receipted() {
        let lifecycle = Mutex::new(HelperLifecycleReceipt::initial());
        let mut poison = None;
        poison_helper_lifecycle(&lifecycle, &mut poison, "socket 3 restore failed".into());
        poison_helper_lifecycle(&lifecycle, &mut poison, "socket 7 was attempted".into());
        assert_eq!(poison.as_deref(), Some("socket 3 restore failed"));
        let receipt = lifecycle.lock().expect("lifecycle").clone();
        assert!(receipt.globally_poisoned);
        assert_eq!(
            receipt.poison_reason.as_deref(),
            Some("socket 3 restore failed")
        );
        assert_eq!(receipt.failed_commands, 2);
    }

    #[test]
    fn immediate_enqueue_deadline_is_strict() {
        validate_immediate_enqueue_deadline(101, 100).expect("before cutoff");
        assert!(matches!(
            validate_immediate_enqueue_deadline(100, 100),
            Err(TimedEgressError::EnqueueDeadline {
                latest: 100,
                observed: 100
            })
        ));
        assert!(matches!(
            validate_immediate_enqueue_deadline(100, 101),
            Err(TimedEgressError::EnqueueDeadline {
                latest: 100,
                observed: 101
            })
        ));
    }

    #[test]
    fn abort_closes_job_without_claiming_completion_and_poisons_globally() {
        let lifecycle = Mutex::new(HelperLifecycleReceipt {
            causal_main_proven: true,
            active_job_id: Some(41),
            last_main_job_id: Some(41),
            remaining_post_main_datagrams: 3,
            ..HelperLifecycleReceipt::initial()
        });
        let mut active_job_id = Some(41);
        let mut remaining = 3;
        let mut poison = None;
        let receipt = abort_active_helper_job(
            &mut active_job_id,
            &mut remaining,
            &mut poison,
            &lifecycle,
            41,
            "controller finalisation failed".into(),
        )
        .expect("abort receipt");
        assert_eq!(active_job_id, None);
        assert_eq!(remaining, 0);
        assert!(!receipt.complete);
        assert!(receipt.aborted);
        assert!(receipt.global_poisoned);
        assert_eq!(receipt.unused_post_main_datagrams, 3);
        assert_eq!(receipt.failed_commands, 0);
        assert!(
            poison
                .as_deref()
                .is_some_and(|reason| reason.contains("41"))
        );
        let lifecycle = lifecycle.lock().expect("lifecycle");
        assert!(lifecycle.globally_poisoned);
        assert_eq!(lifecycle.aborted_jobs, 1);
        assert!(!lifecycle.causal_main_proven);
        assert_eq!(lifecycle.active_job_id, None);
        drop(lifecycle);
    }

    #[test]
    fn total_shutdown_receipt_retains_independent_partial_evidence() {
        let socket_state = HelperSocketShutdownReceipt {
            schema_version: 1,
            socket_count: 2,
            active_job_id: None,
            pending_socket_count: 0,
            stale_error_queue_socket_count: 0,
            nonzero_priority_socket_count: 0,
            inspection_errors: Vec::new(),
            clean: true,
        };
        let receipt = assemble_helper_shutdown_receipt(
            true,
            false,
            Some(socket_state.clone()),
            Some(HelperLifecycleReceipt::initial()),
            vec!["worker join failed".into()],
        );
        assert!(receipt.shutdown_command_sent);
        assert!(receipt.shutdown_received);
        assert!(!receipt.worker_joined);
        assert!(!receipt.shutdown_complete);
        assert!(receipt.clean_socket_state);
        assert_eq!(receipt.socket_state, Some(socket_state.clone()));
        assert!(receipt.lifecycle.is_some());
        assert_eq!(receipt.errors, ["worker join failed"]);

        let unknown = assemble_helper_shutdown_receipt(
            false,
            true,
            None,
            None,
            vec!["channel disconnected".into()],
        );
        assert!(!unknown.shutdown_received);
        assert!(unknown.global_poisoned);
        assert_eq!(unknown.failed_commands, None);
        assert_eq!(unknown.remaining_post_main_datagrams, None);

        let complete = assemble_helper_shutdown_receipt(
            true,
            true,
            Some(socket_state),
            Some(HelperLifecycleReceipt::initial()),
            Vec::new(),
        );
        assert!(complete.shutdown_command_sent);
        assert!(complete.shutdown_received);
        assert!(complete.worker_joined);
        assert!(complete.shutdown_complete);
        assert!(complete.clean_socket_state);
        assert!(!complete.global_poisoned);
        assert_eq!(complete.failed_commands, Some(0));
        assert_eq!(complete.remaining_post_main_datagrams, Some(0));
        assert!(complete.errors.is_empty());
    }

    #[test]
    fn failure_receipt_retains_partial_kernel_timestamps_and_send_attempt() {
        let enqueue = ImmediateEnqueueReceipt {
            schema_version: 1,
            latest_enqueue_tai_ns: 200,
            enqueue_before_tai_ns: 100,
            enqueue_after_tai_ns: 110,
            enqueue_monotonic_ns: 90,
            payload_bytes: 4,
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 12000)),
            destination: SocketAddr::from((Ipv4Addr::LOCALHOST, 12001)),
            tos: 0,
            per_message_timestamp_flags: REQUEST_FLAGS,
        };
        let error = TimedEgressError::ImmediateEnqueueFailed {
            enqueue: Box::new(enqueue),
            socket_timestamp_id: Some(9),
            tx_sched_realtime_ns: Some(123),
            tx_software_realtime_ns: None,
            source: Box::new(TimedEgressError::ReportTimeout {
                requested: 0,
                saw_sched: true,
                saw_software: false,
            }),
        };
        let receipt = error.failure_receipt();
        assert_eq!(receipt.socket_timestamp_id, Some(9));
        assert_eq!(receipt.tx_sched_realtime_ns, Some(123));
        assert_eq!(receipt.tx_software_realtime_ns, None);
        assert!(receipt.immediate_enqueue.is_some());

        let timed_enqueue = TimedEnqueueReceipt {
            schema_version: 1,
            requested_txtime_tai_ns: 500,
            latest_enqueue_tai_ns: 400,
            enqueue_before_tai_ns: 300,
            enqueue_after_tai_ns: 310,
            enqueue_monotonic_ns: 290,
            payload_bytes: 4,
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 12000)),
            destination: SocketAddr::from((Ipv4Addr::LOCALHOST, 12001)),
            tos: 0,
            per_message_priority: None,
            effective_socket_priority: 6,
            priority_method: TimedPriorityMethod::SerializedSocketSoPriority,
            per_message_timestamp_flags: REQUEST_FLAGS,
        };
        let error = TimedEgressError::TimedEnqueueFailed {
            enqueue: Box::new(timed_enqueue.clone()),
            socket_timestamp_id: Some(10),
            tx_sched_realtime_ns: Some(456),
            tx_software_realtime_ns: None,
            source: Box::new(TimedEgressError::ReportTimeout {
                requested: 500,
                saw_sched: true,
                saw_software: false,
            }),
        };
        let receipt = error.failure_receipt();
        assert_eq!(receipt.terminal_error, "report_timeout");
        assert_eq!(receipt.socket_timestamp_id, Some(10));
        assert_eq!(receipt.tx_sched_realtime_ns, Some(456));
        assert_eq!(receipt.tx_software_realtime_ns, None);
        assert_eq!(receipt.timed_enqueue, Some(timed_enqueue));
        assert!(receipt.immediate_enqueue.is_none());
        assert!(receipt.send_attempt.is_none());

        let attempt = SendAttemptReceipt {
            schema_version: 1,
            kind: SendAttemptKind::TimedMain,
            requested_txtime_tai_ns: Some(500),
            latest_enqueue_tai_ns: 400,
            enqueue_before_tai_ns: 300,
            enqueue_monotonic_ns: None,
            enqueue_after_tai_ns: None,
            sendmsg_result: 4,
            send_errno: None,
            payload_bytes: 4,
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 12000)),
            destination: SocketAddr::from((Ipv4Addr::LOCALHOST, 12001)),
            tos: 0,
            priority_method: Some(TimedPriorityMethod::SerializedSocketSoPriority),
        };
        let error = TimedEgressError::SendAttemptFailed {
            attempt: Box::new(attempt.clone()),
            source: Box::new(TimedEgressError::Io(
                "clock_gettime(CLOCK_MONOTONIC)",
                io::Error::from_raw_os_error(libc::EIO),
            )),
        };
        let receipt = error.failure_receipt();
        assert_eq!(receipt.terminal_error, "io_error");
        assert_eq!(receipt.send_attempt, Some(attempt));
        assert!(receipt.timed_enqueue.is_none());
        assert!(receipt.immediate_enqueue.is_none());
        assert_eq!(receipt.socket_timestamp_id, None);
        assert_eq!(receipt.tx_sched_realtime_ns, None);
        assert_eq!(receipt.tx_software_realtime_ns, None);
    }

    #[test]
    fn shutdown_inspection_requires_closed_job_empty_queue_and_priority_zero() {
        let mut clean = pending_socket();
        clean.pending = None;
        let clean_receipt = inspect_socket_shutdown_state(std::slice::from_mut(&mut clean), None);
        assert!(clean_receipt.clean);
        assert_eq!(clean_receipt.pending_socket_count, 0);
        assert_eq!(clean_receipt.nonzero_priority_socket_count, 0);

        let mut pending = pending_socket();
        let pending_receipt =
            inspect_socket_shutdown_state(std::slice::from_mut(&mut pending), Some(7));
        assert!(!pending_receipt.clean);
        assert_eq!(pending_receipt.active_job_id, Some(7));
        assert_eq!(pending_receipt.pending_socket_count, 1);
    }
}
