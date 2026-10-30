//! Machine and process metrics for the local admin page: CPU, memory, this process's I/O and
//! the machine's network traffic, sampled every few seconds into a short history held in
//! memory only. Aggregates of the whole machine or process: nothing per account, nothing
//! written to disk.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use sysinfo::{
    MemoryRefreshKind, Networks, Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System,
};

/// Time between samples.
pub const INTERVAL: Duration = Duration::from_secs(5);
/// Samples kept (15 minutes).
const HISTORY: usize = 180;

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Sample {
    /// Seconds since the server started.
    pub t: u64,
    /// Whole machine, 0-100.
    pub cpu: f32,
    /// This process, as a share of the whole machine (0-100).
    pub cpu_self: f32,
    pub mem_used: u64,
    pub mem_self: u64,
    /// Bytes per second read and written by this process (on Windows this counts all of the
    /// process's I/O, network included).
    pub io_read: u64,
    pub io_write: u64,
    /// Bytes per second over all non-loopback interfaces.
    pub net_rx: u64,
    pub net_tx: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Snapshot {
    pub cpus: usize,
    pub mem_total: u64,
    /// Totals since the server started.
    pub io_read_total: u64,
    pub io_write_total: u64,
    pub history: Vec<Sample>,
}

#[derive(Default)]
pub struct Metrics {
    state: Mutex<Snapshot>,
}

impl Metrics {
    pub fn snapshot(&self) -> Snapshot {
        self.state.lock().unwrap().clone()
    }

    /// Sample until the runtime shuts down.
    pub fn start(self: &Arc<Self>, started: Instant) {
        let metrics = self.clone();
        tokio::spawn(async move {
            let sampler = Arc::new(Mutex::new(Sampler::new()));
            let mut tick = tokio::time::interval(INTERVAL);
            tick.tick().await;
            loop {
                tick.tick().await;
                let (s, m) = (sampler.clone(), metrics.clone());
                let _ = tokio::task::spawn_blocking(move || {
                    s.lock().unwrap().sample(&m, started);
                })
                .await;
            }
        });
    }
}

struct Sampler {
    sys: System,
    nets: Networks,
    pid: Option<Pid>,
    last: Instant,
}

impl Sampler {
    fn new() -> Self {
        let mut sys = System::new_with_specifics(
            RefreshKind::nothing()
                .with_cpu(sysinfo::CpuRefreshKind::nothing().with_cpu_usage())
                .with_memory(MemoryRefreshKind::nothing().with_ram()),
        );
        let pid = sysinfo::get_current_pid().ok();
        if let Some(pid) = pid {
            sys.refresh_processes_specifics(ProcessesToUpdate::Some(&[pid]), true, process_kind());
        }
        Sampler {
            sys,
            nets: Networks::new_with_refreshed_list(),
            pid,
            last: Instant::now(),
        }
    }

    fn sample(&mut self, metrics: &Metrics, started: Instant) {
        let secs = self.last.elapsed().as_secs_f64().max(0.001);
        self.last = Instant::now();
        let per_sec = |bytes: u64| (bytes as f64 / secs) as u64;
        self.sys.refresh_cpu_usage();
        self.sys
            .refresh_memory_specifics(MemoryRefreshKind::nothing().with_ram());
        self.nets.refresh(true);
        let cpus = self.sys.cpus().len().max(1);
        let mut sample = Sample {
            t: started.elapsed().as_secs(),
            cpu: self.sys.global_cpu_usage(),
            mem_used: self.sys.used_memory(),
            ..Default::default()
        };
        let (mut rx, mut tx) = (0, 0);
        for (name, net) in &self.nets {
            if name != "lo" && !name.starts_with("Loopback") {
                rx += net.received();
                tx += net.transmitted();
            }
        }
        sample.net_rx = per_sec(rx);
        sample.net_tx = per_sec(tx);
        let mut totals = (0, 0);
        if let Some(pid) = self.pid {
            self.sys.refresh_processes_specifics(
                ProcessesToUpdate::Some(&[pid]),
                true,
                process_kind(),
            );
            if let Some(p) = self.sys.process(pid) {
                let io = p.disk_usage();
                sample.cpu_self = p.cpu_usage() / cpus as f32;
                sample.mem_self = p.memory();
                sample.io_read = per_sec(io.read_bytes);
                sample.io_write = per_sec(io.written_bytes);
                totals = (io.total_read_bytes, io.total_written_bytes);
            }
        }
        let mut state = metrics.state.lock().unwrap();
        state.cpus = cpus;
        state.mem_total = self.sys.total_memory();
        (state.io_read_total, state.io_write_total) = totals;
        // 180 samples: shifting a Vec is cheap, and it serialises as-is.
        if state.history.len() >= HISTORY {
            state.history.remove(0);
        }
        state.history.push(sample);
    }
}

fn process_kind() -> ProcessRefreshKind {
    ProcessRefreshKind::nothing()
        .with_cpu()
        .with_memory()
        .with_disk_usage()
}
