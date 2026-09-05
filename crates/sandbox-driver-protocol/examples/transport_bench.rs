//! Explicit transport benchmark. Not an ordinary CI capacity gate.
use std::error::Error as StdError;
use std::path::PathBuf;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use std::{env, process};

use async_trait::async_trait;
use clap::{Parser, ValueEnum};
use sandbox_driver::{
    Capabilities, DirEntry, Error, EventContext, Exec, ExecControls, ExecResult, ExecSpec,
    ExecStreamingResult, FileMetadata, Filesystem, HealthStatus, Isolation, OutputStream,
    PlatformInfo, ProviderHealth, ProviderKind, Result, Sandbox, SandboxFilter, SandboxId,
    SandboxProvider, SandboxSource, SandboxSpec, SandboxState, SandboxStatus, Termination,
};
use sandbox_driver_protocol::{PluginProvider, TransportDiagnostics, TransportLimits, serve_stdio};
use serde_json::json;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::task::{JoinSet, yield_now};
use tokio::time;
use tokio_util::sync::CancellationToken;

struct GeneratedProvider {
    kind:         ProviderKind,
    capabilities: Capabilities,
    next_id:      AtomicU64,
}

impl GeneratedProvider {
    fn new() -> Self {
        Self {
            kind:         ProviderKind::try_new("transport-bench").expect("static provider kind"),
            capabilities: Capabilities::minimal(Isolation::None),
            next_id:      AtomicU64::new(1),
        }
    }

    fn sandbox(&self, id: SandboxId) -> Arc<dyn Sandbox> {
        Arc::new(GeneratedSandbox {
            id,
            capabilities: self.capabilities.clone(),
        })
    }
}

struct GeneratedSandbox {
    id:           SandboxId,
    capabilities: Capabilities,
}

#[async_trait]
impl SandboxProvider for GeneratedProvider {
    fn kind(&self) -> &ProviderKind {
        &self.kind
    }
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
    async fn create(&self, _: &SandboxSpec, _: Option<EventContext>) -> Result<Arc<dyn Sandbox>> {
        Ok(self.sandbox(
            SandboxId::try_new(format!(
                "bench-{}",
                self.next_id.fetch_add(1, Ordering::Relaxed)
            ))
            .expect("generated sandbox ID"),
        ))
    }
    async fn attach(&self, id: &SandboxId, _: Option<EventContext>) -> Result<Arc<dyn Sandbox>> {
        Ok(self.sandbox(id.clone()))
    }
    async fn list(&self, _: &SandboxFilter) -> Result<Vec<SandboxStatus>> {
        Ok(Vec::new())
    }
    async fn health(&self) -> Result<ProviderHealth> {
        Ok(ProviderHealth::new(HealthStatus::Ok))
    }
}
#[async_trait]
impl Sandbox for GeneratedSandbox {
    fn id(&self) -> &SandboxId {
        &self.id
    }
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
    fn working_directory(&self) -> &'static str {
        "/"
    }
    async fn describe(&self) -> Result<SandboxStatus> {
        Ok(SandboxStatus::new(self.id.clone(), SandboxState::Running))
    }
    async fn platform_info(&self) -> Result<PlatformInfo> {
        Err(Error::invalid_spec("benchmark", "no sandbox compute"))
    }
    async fn start(&self) -> Result<()> {
        Ok(())
    }
    async fn stop(&self) -> Result<()> {
        Ok(())
    }
    async fn delete(&self) -> Result<()> {
        Ok(())
    }
    fn exec(&self) -> &dyn Exec {
        self
    }
    fn fs(&self) -> &dyn Filesystem {
        self
    }
}
#[async_trait]
impl Filesystem for GeneratedSandbox {
    async fn read(&self, _: &str) -> Result<Vec<u8>> {
        no_filesystem()
    }
    async fn write(&self, _: &str, _: &[u8]) -> Result<()> {
        no_filesystem()
    }
    async fn delete(&self, _: &str, _: bool) -> Result<()> {
        no_filesystem()
    }
    async fn exists(&self, _: &str) -> Result<bool> {
        no_filesystem()
    }
    async fn metadata(&self, _: &str) -> Result<FileMetadata> {
        no_filesystem()
    }
    async fn list_dir(&self, _: &str, _: usize) -> Result<Vec<DirEntry>> {
        no_filesystem()
    }
    async fn create_dir(&self, _: &str) -> Result<()> {
        no_filesystem()
    }
    async fn rename(&self, _: &str, _: &str) -> Result<()> {
        no_filesystem()
    }
}

fn no_filesystem<T>() -> Result<T> {
    Err(Error::invalid_spec("benchmark", "no sandbox filesystem"))
}
#[async_trait]
impl Exec for GeneratedSandbox {
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult> {
        self.run_streaming(spec, ExecControls::buffered())
            .await?
            .into_complete()
    }
    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        let started = Instant::now();
        let tiny = spec.program == "tiny";
        let bulk = spec.program == "bulk";
        let mut interval = time::interval(Duration::from_millis(10));
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = controls.stop_requested() => break,
                () = async { if bulk || tiny { yield_now().await; } else { interval.tick().await; } } => {
                    if let Some(sink) = &controls.sink {
                        sink(OutputStream::Stdout, vec![b'x'; if bulk { 65536 } else { 1024 }]).await?;
                    }
                    if tiny { break; }
                }
            }
        }
        let mut result = ExecStreamingResult::new(ExecResult::from_shell_status(
            if tiny {
                Termination::Exited
            } else {
                Termination::Killed
            },
            if tiny { Some(0) } else { None },
            started.elapsed(),
        ));
        result.live_streaming = true;
        result.streams_separated = true;
        Ok(result)
    }
}

fn distribution(samples: &mut [u64]) -> serde_json::Value {
    if samples.is_empty() {
        return json!({"samples": 0});
    }
    samples.sort_unstable();
    let percentile =
        |percent: usize| samples[(samples.len() * percent / 100).min(samples.len() - 1)];
    json!({"samples": samples.len(), "p50_us": percentile(50), "p95_us": percentile(95), "p99_us": percentile(99)})
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Rate,
    Bulk,
    Tiny,
    Cycles,
    Burst,
}

#[derive(Parser)]
struct Options {
    #[arg(long, hide = true)]
    plugin:     bool,
    #[arg(long, default_value_t = 1000)]
    operations: usize,
    #[arg(long, default_value_t = 30)]
    seconds:    u64,
    #[arg(long, value_enum, default_value = "rate")]
    mode:       Mode,
    #[arg(long, default_value_t = 10000)]
    cycles:     usize,
    #[arg(long)]
    telemetry:  Option<PathBuf>,
}

type BenchResult<T> = StdResult<T, Box<dyn StdError>>;

async fn telemetry(
    file: &mut Option<File>,
    provider: &PluginProvider,
    phase: &str,
    started: Instant,
) -> BenchResult<TransportDiagnostics> {
    let diagnostics = provider.transport_diagnostics().await?;
    if let Some(file) = file {
        let record = json!({"elapsed_seconds": started.elapsed().as_secs_f64(), "phase": phase,
            "client_pid": process::id(), "plugin_pid": provider.process_id(), "diagnostics": diagnostics});
        file.write_all(format!("{record}\n").as_bytes()).await?;
        file.flush().await?;
    }
    Ok(diagnostics)
}

async fn settled(provider: &PluginProvider, handles: usize) -> BenchResult<TransportDiagnostics> {
    Ok(time::timeout(Duration::from_secs(10), async {
        loop {
            let stats = provider.transport_diagnostics().await?;
            let client = &stats.client;
            let server = &stats.server;
            if client.active_io == 0
                && client.pending_opens == 0
                && client.handshakes == 0
                && client.cleanup_tasks == 0
                && client.failed_cleanups == 0
                && client.event_routes == 0
                && client.event_contexts == 0
                && server.active_io == 0
                && server.pending_opens == 0
                && server.execs == 0
                && server.stdios == 0
                && server.ptys == 0
                && server.streams == 0
                && server.background_tasks == 0
                && server.cached_handles == handles
            {
                return Ok::<_, Error>(stats);
            }
            time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??)
}

#[tokio::main]
#[expect(
    clippy::print_stdout,
    reason = "benchmark emits its measured JSON report"
)]
async fn main() -> BenchResult<()> {
    let args = Options::parse();
    if args.plugin {
        return Ok(serve_stdio(Arc::new(GeneratedProvider::new())).await?);
    }
    if args.operations == 0
        || args.operations > 1000
        || args.seconds == 0
        || args.seconds > 86400
        || args.cycles == 0
        || args.cycles > 1_000_000
    {
        return Err("operations must be 1..1000, seconds 1..86400, and cycles 1..1000000".into());
    }
    let mut trace = match &args.telemetry {
        Some(path) => Some(File::create(path).await?),
        None => None,
    };
    let mut command = Command::new(env::current_exe()?);
    command.arg("--plugin");
    let cold = Instant::now();
    let mut limits = TransportLimits::default();
    if matches!(args.mode, Mode::Burst) {
        limits.active_io = args.operations;
    }
    let provider = PluginProvider::spawn_with_limits(command, limits.clone()).await?;
    let startup = cold.elapsed();
    let baseline = telemetry(&mut trace, &provider, "baseline", cold).await?;
    time::sleep(Duration::from_secs(2)).await;
    let mut controls = Vec::new();
    let mut first_byte = Vec::new();
    let mut setup = Vec::new();
    let mut completed = 0usize;
    let mut rejected = 0usize;
    let mut termination_confirmed = 0usize;
    let mut abandoned_output = 0usize;
    let mut last_sample = Instant::now();
    let bytes = Arc::new(AtomicU64::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let measured = Instant::now();
    let mut stop_us = 0u128;
    let mut active_transfer = None;
    if matches!(args.mode, Mode::Cycles) {
        for _ in 0..args.cycles {
            let sandbox = provider
                .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
                .await?;
            let attached = provider.attach(sandbox.id(), None).await?;
            let start = Instant::now();
            let first = Arc::new(AtomicU64::new(0));
            let first_sample = Arc::clone(&first);
            let transferred = Arc::clone(&bytes);
            attached
                .exec()
                .run_streaming(&ExecSpec::new("tiny"), ExecControls {
                    sink: Some(Arc::new(move |_, chunk| {
                        transferred.fetch_add(chunk.len() as u64, Ordering::Relaxed);
                        let _ = first_sample.compare_exchange(
                            0,
                            u64::try_from(start.elapsed().as_micros())
                                .unwrap_or(u64::MAX)
                                .max(1),
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        );
                        Box::pin(async { Ok(()) })
                    })),
                    ..ExecControls::default()
                })
                .await?;
            first_byte.push(first.load(Ordering::Relaxed));
            sandbox.delete().await?;
            drop(attached);
            drop(sandbox);
            settled(&provider, 0).await?;
            setup.extend(provider.take_channel_setup_samples_us());
            completed += 1;
            let start = Instant::now();
            provider.health().await?;
            controls.push(u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX));
            if last_sample.elapsed() >= Duration::from_secs(1) {
                telemetry(&mut trace, &provider, "cycles", cold).await?;
                last_sample = Instant::now();
            }
        }
    } else {
        let sandbox = provider
            .create(&SandboxSpec::new(SandboxSource::HostDirectory), None)
            .await?;
        let kill = CancellationToken::new();
        let tiny = matches!(args.mode, Mode::Tiny);
        let total = if tiny { args.cycles } else { args.operations };
        let batch = args.operations.min(32);
        let (ready, mut readiness) = mpsc::channel(batch);
        let mut tasks = JoinSet::new();
        for index in 0..total {
            let sandbox = Arc::clone(&sandbox);
            let bytes = Arc::clone(&bytes);
            let active = Arc::clone(&active);
            let kill = kill.clone();
            let ready = ready.clone();
            let mode = if tiny {
                "tiny"
            } else if matches!(args.mode, Mode::Bulk) {
                "bulk"
            } else {
                "rate"
            };
            tasks.spawn(async move {
                let started = Instant::now();
                let first = Arc::new(AtomicUsize::new(0));
                sandbox
                    .exec()
                    .run_streaming(&ExecSpec::new(mode), ExecControls {
                        kill: Some(kill),
                        sink: Some(Arc::new(move |_, chunk| {
                            bytes.fetch_add(chunk.len() as u64, Ordering::Relaxed);
                            if first.fetch_add(1, Ordering::Relaxed) == 0 {
                                active.fetch_add(1, Ordering::Relaxed);
                                let _ = ready.try_send(
                                    u64::try_from(started.elapsed().as_micros())
                                        .unwrap_or(u64::MAX),
                                );
                            }
                            Box::pin(async { Ok(()) })
                        })),
                        ..ExecControls::default()
                    })
                    .await
            });
            if (index + 1) % batch == 0 || index + 1 == total {
                time::timeout(Duration::from_secs(30), async {
                    while first_byte.len() <= index {
                        first_byte.push(readiness.recv().await.ok_or("operation did not start")?);
                    }
                    Ok::<_, Box<dyn StdError>>(())
                })
                .await??;
                if tiny {
                    while let Some(result) = tasks.join_next().await {
                        result??;
                        completed += 1;
                    }
                    let start = Instant::now();
                    provider.health().await?;
                    controls.push(u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX));
                }
                setup.extend(provider.take_channel_setup_samples_us());
                if last_sample.elapsed() >= Duration::from_secs(1) {
                    telemetry(&mut trace, &provider, "ramp", cold).await?;
                    last_sample = Instant::now();
                }
            }
        }
        drop(ready);
        if matches!(args.mode, Mode::Burst) {
            let mut attempts = JoinSet::new();
            for _ in 0..10000 {
                let sandbox = Arc::clone(&sandbox);
                attempts.spawn(async move { sandbox.exec().run(&ExecSpec::new("tiny")).await });
            }
            while !attempts.is_empty() {
                let start = Instant::now();
                time::timeout(Duration::from_secs(5), provider.health()).await??;
                controls.push(u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX));
                let result = attempts.join_next().await.ok_or("missing burst result")?;
                match result? {
                    Err(Error::Overloaded { .. }) => rejected += 1,
                    _ => return Err("excess operation was not rejected before dispatch".into()),
                }
            }
        }
        if !tiny {
            let starting_bytes = bytes.load(Ordering::Relaxed);
            let duration = Instant::now();
            while duration.elapsed() < Duration::from_secs(args.seconds) {
                let start = Instant::now();
                time::timeout(Duration::from_secs(5), provider.health()).await??;
                controls.push(u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX));
                if last_sample.elapsed() >= Duration::from_secs(1) {
                    telemetry(&mut trace, &provider, "active", cold).await?;
                    last_sample = Instant::now();
                }
                time::sleep(Duration::from_millis(10)).await;
            }
            let active_bytes = bytes.load(Ordering::Relaxed) - starting_bytes;
            active_transfer = Some(json!({"seconds": duration.elapsed().as_secs_f64(),
                "bytes": active_bytes, "bytes_per_second": active_bytes as f64 / duration.elapsed().as_secs_f64()}));
            let stop = Instant::now();
            kill.cancel();
            while let Some(result) = tasks.join_next().await {
                let result = result??;
                termination_confirmed +=
                    usize::from(result.result.termination == Termination::Killed);
                abandoned_output +=
                    usize::from(result.stdout_capture.truncated || result.stderr_capture.truncated);
                completed += 1;
            }
            stop_us = stop.elapsed().as_micros();
        }
        settled(&provider, 1).await?;
        telemetry(&mut trace, &provider, "after_stop", cold).await?;
        sandbox.delete().await?;
        drop(sandbox);
    }
    let elapsed = measured.elapsed();
    let final_state = settled(&provider, 0).await?;
    telemetry(&mut trace, &provider, "after_delete", cold).await?;
    setup.extend(provider.take_channel_setup_samples_us());
    if final_state.client.runtime_tasks > baseline.client.runtime_tasks
        || final_state.server.runtime_tasks > baseline.server.runtime_tasks
    {
        return Err("live runtime tasks did not return to baseline".into());
    }
    // Leave a quiet sampling window while both processes are still alive.
    time::sleep(Duration::from_secs(2)).await;
    telemetry(&mut trace, &provider, "settled", cold).await?;
    provider.shutdown().await?;
    let transferred = bytes.load(Ordering::Relaxed);
    println!(
        "{}",
        json!({
            "os": env::consts::OS, "arch": env::consts::ARCH, "mode": format!("{:?}", args.mode),
            "operations": args.operations, "completed_operations": completed, "rejected_attempts": rejected,
            "setup_batch_size": args.operations.min(32), "duration_seconds": elapsed.as_secs_f64(),
            "offered_bytes_per_second_per_operation": if matches!(args.mode, Mode::Rate | Mode::Burst) { Some(102_400) } else { None },
            "sink": "immediate byte counter; no capture", "cold_start_us": startup.as_micros(),
            "authenticated_setup": distribution(&mut setup), "first_byte": distribution(&mut first_byte),
            "control": distribution(&mut controls), "active_transfer": active_transfer, "bytes": transferred, "bytes_per_second": transferred as f64 / elapsed.as_secs_f64(),
            "stop_to_local_completion_us": stop_us, "termination_confirmed": termination_confirmed, "abandoned_output": abandoned_output,
            "baseline": baseline, "after_cleanup": final_state, "limits": limits, "reference_capacity_validated": false
        })
    );
    Ok(())
}
