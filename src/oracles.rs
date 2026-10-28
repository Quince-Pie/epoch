//! Plane 4.3: Multi-Signal Health Oracles (`PROBING` phase)
//!
//! Implements the three orthogonal health oracles required before any node in a wave
//! can transition `PROBING -> BARRIER_WAIT`:
//! 1. **Oracle 1 (Systemd D-Bus / Unit Convergence)**: Verifies required systemd units are
//!    `active` (`running`) and zero units entered `failed`.
//! 2. **Oracle 2 (Kernel `/dev/kmsg` & Cgroup OOM Oracle)**: Scans kernel ring buffer lines
//!    for forbidden fault patterns (`Oops:`, `BUG:`, `Kernel panic`, `Out of memory: Killed process`)
//!    and checks `/sys/fs/cgroup/system.slice/memory.events` for `oom_kill > baseline`.
//! 3. **Oracle 3 (Synthetic Data-Plane & Cohort Peer Mesh Probes)**: Executes TCP/HTTP probes
//!    and verifies reachability to at least `peer_mesh_quorum` cohort peers in the wave.

use crate::schema::HealthOracleSpec;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleEvaluationResult {
    pub healthy: bool,
    pub diagnostic: String,
}

impl OracleEvaluationResult {
    pub fn ok() -> Self {
        Self {
            healthy: true,
            diagnostic: "AllOraclesPassed".into(),
        }
    }

    pub fn fail(reason: impl Into<String>) -> Self {
        Self {
            healthy: false,
            diagnostic: reason.into(),
        }
    }
}

/// Runtime probe environment allowing both real host inspection (`/run/dbus/system_bus_socket`,
/// `/dev/kmsg`, `/sys/fs/cgroup`, TCP/HTTP sockets) and deterministic fault injection.
#[derive(Debug, Clone, Default)]
pub struct ProbeEnvironment {
    /// Simulated or overridden systemd unit states (`unit_name -> "active" | "failed" | "activating"`).
    /// When empty, queries `systemctl is-active <unit>` on the host.
    pub unit_states: BTreeMap<String, String>,
    /// Simulated or captured `/dev/kmsg` lines since `ACTIVATING` entry.
    /// When `None`, reads non-blocking from `/dev/kmsg` if readable.
    pub kmsg_lines: Option<Vec<String>>,
    /// Baseline `oom_kill` count recorded at `ACTIVATING` entry.
    pub oom_kill_baseline: u64,
    /// Current `oom_kill` count (or read from `/sys/fs/cgroup/system.slice/memory.events`).
    pub oom_kill_current: Option<u64>,
    /// Number of reachable cohort peers over the data-plane QUIC mesh (including self).
    pub reachable_cohort_peers: u16,
    /// Optional simulated HTTP endpoint status overrides (`url -> status_code`).
    pub simulated_http_status: BTreeMap<String, u16>,
    /// Optional simulated TCP endpoint reachability overrides (`addr -> reachable`).
    pub simulated_tcp_status: BTreeMap<String, bool>,
}

/// Read `oom_kill` counter from a `memory.events` file content or `/sys/fs/cgroup/system.slice/memory.events`.
pub fn parse_cgroup_oom_kill(content: &str) -> u64 {
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some("oom_kill")
            && let Some(val_str) = parts.next()
            && let Ok(v) = val_str.parse::<u64>()
        {
            return v;
        }
    }
    0
}

pub fn read_host_oom_kill(cgroup_events_path: &Path) -> u64 {
    fs::read_to_string(cgroup_events_path)
        .map(|s| parse_cgroup_oom_kill(&s))
        .unwrap_or(0)
}

/// Evaluate all three multi-signal health oracles against `spec` and `env`.
pub fn evaluate_health_oracles(
    spec: &HealthOracleSpec,
    env: &ProbeEnvironment,
) -> OracleEvaluationResult {
    // 1. Oracle 1: Systemd Unit Convergence
    for unit in &spec.required_systemd_units {
        let state = if let Some(sim_state) = env.unit_states.get(unit) {
            sim_state.clone()
        } else {
            query_host_systemd_unit(unit)
        };
        if state != "active" {
            return OracleEvaluationResult::fail(format!("UnitFailed: {unit} (state={state})"));
        }
    }
    for (unit, state) in &env.unit_states {
        if state == "failed" {
            return OracleEvaluationResult::fail(format!("UnitFailed: {unit}"));
        }
    }

    // 2. Oracle 2: Kernel `/dev/kmsg` & Cgroup OOM check
    let kmsg_lines: Vec<String> = match &env.kmsg_lines {
        Some(lines) => lines.clone(),
        None => read_nonblocking_kmsg(),
    };
    for line in &kmsg_lines {
        for forbidden in &spec.forbid_kmsg_patterns {
            if !forbidden.is_empty() && line.contains(forbidden) {
                return OracleEvaluationResult::fail(format!(
                    "KernelKmsgFault: matched forbidden pattern '{forbidden}' in '{line}'"
                ));
            }
        }
    }

    let current_oom = env.oom_kill_current.unwrap_or_else(|| {
        read_host_oom_kill(Path::new("/sys/fs/cgroup/system.slice/memory.events"))
    });
    if current_oom > env.oom_kill_baseline {
        return OracleEvaluationResult::fail(format!(
            "CgroupOomKillDetected: oom_kill increased from {} to {}",
            env.oom_kill_baseline, current_oom
        ));
    }

    // 3. Oracle 3a: Cohort Peer Mesh Quorum Reachability
    if spec.peer_mesh_quorum > 0 && env.reachable_cohort_peers < spec.peer_mesh_quorum {
        return OracleEvaluationResult::fail(format!(
            "DataPlaneMeshIsolated: reachable_peers={} < peer_mesh_quorum={}",
            env.reachable_cohort_peers, spec.peer_mesh_quorum
        ));
    }

    // 3. Oracle 3b: Synthetic TCP Endpoints
    for ep in &spec.tcp_endpoints {
        if let Some(&ok) = env.simulated_tcp_status.get(ep) {
            if !ok {
                return OracleEvaluationResult::fail(format!("TcpProbeFailed: {ep}"));
            }
        } else if !probe_tcp_endpoint(ep, Duration::from_millis(500)) {
            return OracleEvaluationResult::fail(format!("TcpProbeFailed: {ep}"));
        }
    }

    // 3. Oracle 3c: Synthetic HTTP Health Checks
    for (url, expected_status) in &spec.http_checks {
        if let Some(&status) = env.simulated_http_status.get(url) {
            if status != *expected_status {
                return OracleEvaluationResult::fail(format!(
                    "HttpProbeFailed: {url} returned {status}, expected {expected_status}"
                ));
            }
        } else {
            match probe_http_get_status(url, Duration::from_millis(500)) {
                Some(status) if status == *expected_status => {}
                Some(status) => {
                    return OracleEvaluationResult::fail(format!(
                        "HttpProbeFailed: {url} returned {status}, expected {expected_status}"
                    ));
                }
                None => {
                    return OracleEvaluationResult::fail(format!(
                        "HttpProbeFailed: {url} unreachable"
                    ));
                }
            }
        }
    }

    OracleEvaluationResult::ok()
}

fn query_host_systemd_unit(unit: &str) -> String {
    Command::new("systemctl")
        .arg("is-active")
        .arg(unit)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|| "unknown".into())
}

fn read_nonblocking_kmsg() -> Vec<String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut lines = Vec::new();
    if let Ok(mut f) = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/kmsg")
    {
        let mut buf = [0u8; 4096];
        let mut total_read = 0usize;
        while total_read < 65536 {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    total_read += n;
                    let s = String::from_utf8_lossy(&buf[..n]).into_owned();
                    for l in s.lines() {
                        lines.push(l.to_owned());
                    }
                }
                Err(_) => break,
            }
        }
    }
    lines
}

fn probe_tcp_endpoint(addr_str: &str, timeout: Duration) -> bool {
    if let Ok(sock_addr) = addr_str.parse::<SocketAddr>() {
        TcpStream::connect_timeout(&sock_addr, timeout).is_ok()
    } else {
        false
    }
}

fn probe_http_get_status(url: &str, timeout: Duration) -> Option<u16> {
    let rest = url.strip_prefix("http://")?;
    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (rest, "/".to_owned()),
    };
    let sock_addr: SocketAddr = host_port.parse().ok()?;
    let mut stream = TcpStream::connect_timeout(&sock_addr, timeout).ok()?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;
    let mut resp = [0u8; 256];
    let n = stream.read(&mut resp).ok()?;
    let line = std::str::from_utf8(&resp[..n]).ok()?.lines().next()?;
    let status_str = line.split_whitespace().nth(1)?;
    status_str.parse::<u16>().ok()
}
