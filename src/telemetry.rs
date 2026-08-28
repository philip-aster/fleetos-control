//! OpenTelemetry observability: metrics, traces, and logs pushed via OTLP.
//!
//! FleetOS is a dark overlay — control nodes never expose inbound scrape
//! endpoints. All telemetry is PUSHED outbound to an OTLP collector, which is
//! consistent with the no-open-ports rule. Prometheus (or any backend) sits
//! behind the collector via remote-write / OTLP ingest.
//!
//! Three signals:
//! - Metrics: control-plane health (Raft term/leadership, replicated version,
//!   watch-stream subscriber counts, uptime).
//! - Traces: existing `tracing` spans bridged via `tracing-opentelemetry`.
//! - Logs: existing `tracing` events bridged via `opentelemetry-appender-tracing`.
//!
//! NOTE: the OTel Rust SDK API is version-sensitive. The builders below target
//! the 0.27 line; reconcile against the pinned versions if they drift.

use std::sync::Arc;
use std::time::Duration;

use opentelemetry::KeyValue;
use opentelemetry::metrics::MeterProvider;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;

use crate::config::ControlConfig;
use crate::raft::FleetosRaftConfig;
use crate::storage::version::VersionedState;
use crate::watch::broadcast::BroadcastHub;

/// Live OTel providers. Held for the lifetime of the process; flushed on shutdown.
pub struct TelemetryProviders {
    pub meter_provider: SdkMeterProvider,
    pub tracer_provider: SdkTracerProvider,
    pub logger_provider: SdkLoggerProvider,
}

/// Initialize OTel providers from config. Returns `None` if telemetry is disabled.
///
/// Exporter connections are lazy (tonic connects on first export), so this
/// succeeds even if the collector is temporarily unreachable.
pub fn init_providers(
    config: &ControlConfig,
) -> Result<Option<TelemetryProviders>, Box<dyn std::error::Error>> {
    let tele = &config.telemetry;
    if !tele.enabled || tele.otlp_endpoint.is_empty() {
        return Ok(None);
    }

    // Resource construction in 0.32+ uses the builder pattern.
    let resource = Resource::builder()
        .with_service_name("fleetos-control")
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .with_attribute(KeyValue::new("node.name", config.node.name.clone()))
        .build();

    // Traces.
    let span_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(tele.otlp_endpoint.clone())
        .build()?;
    let tracer_provider = SdkTracerProvider::builder()
        .with_batch_exporter(span_exporter)
        .with_resource(resource.clone())
        .build();

    // Metrics.
    let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(tele.otlp_endpoint.clone())
        .build()?;

    // In 0.32+, PeriodicReader takes only the exporter. The runtime is inferred
    // from the `rt-tokio` feature, and the interval is configured via the builder.
    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(metric_exporter)
        .with_interval(Duration::from_secs(tele.push_interval_secs))
        .build();

    let meter_provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource.clone())
        .build();

    // Logs.
    let log_exporter = opentelemetry_otlp::LogExporter::builder()
        .with_tonic()
        .with_endpoint(tele.otlp_endpoint.clone())
        .build()?;
    let logger_provider = SdkLoggerProvider::builder()
        .with_batch_exporter(log_exporter)
        .with_resource(resource)
        .build();

    Ok(Some(TelemetryProviders {
        meter_provider,
        tracer_provider,
        logger_provider,
    }))
}

/// A named tracer for the tracing-opentelemetry bridge.
pub fn tracer(providers: &TelemetryProviders) -> opentelemetry_sdk::trace::Tracer {
    providers.tracer_provider.tracer("fleetos-control")
}

/// Register the control-plane metric set as observable gauges.
///
/// Call once, after the Raft handle exists. Each gauge reads live state at
/// observation time, so values are always current.
pub fn register_metrics(
    meter_provider: &SdkMeterProvider,
    versioned_state: VersionedState,
    broadcast_hub: Arc<BroadcastHub>,
    raft: Arc<openraft::Raft<FleetosRaftConfig>>,
) {
    let meter = meter_provider.meter("fleetos-control");

    // Raft node ID.
    let raft_id = raft.clone();
    meter
        .f64_observable_gauge("fleetos.node.id")
        .with_description("Raft node ID of this control node")
        .with_callback(move |observer| {
            let id = raft_id.metrics().borrow().id as f64;
            observer.observe(id, &[]);
        })
        .build();

    // Raft current term.
    let raft_term = raft.clone();
    meter
        .f64_observable_gauge("fleetos.raft.current_term")
        .with_description("Current Raft term")
        .with_callback(move |observer| {
            let term = raft_term.metrics().borrow().current_term;
            observer.observe(term as f64, &[]);
        })
        .build();

    // Raft leadership (1 = leader).
    let raft_leader = raft.clone();
    meter
        .f64_observable_gauge("fleetos.raft.is_leader")
        .with_description("1 if this node is the Raft leader")
        .with_callback(move |observer| {
            let is_leader = raft_leader.metrics().borrow().state == openraft::ServerState::Leader;
            observer.observe(if is_leader { 1.0 } else { 0.0 }, &[]);
        })
        .build();

    // Raft last-applied log index.
    let raft_applied = raft.clone();
    meter
        .f64_observable_gauge("fleetos.raft.last_applied_index")
        .with_description("Log index of last applied entry (-1 = none)")
        .with_callback(move |observer| {
            let idx = raft_applied
                .metrics()
                .borrow()
                .last_applied
                .map(|l| l.index as f64)
                .unwrap_or(-1.0);
            observer.observe(idx, &[]);
        })
        .build();

    // Replicated MonotonicVersion — the heartbeat of the state machine.
    meter
        .f64_observable_gauge("fleetos.version.current")
        .with_description("Current MonotonicVersion of replicated state")
        .with_callback(move |observer| {
            observer.observe(versioned_state.current_version().get() as f64, &[]);
        })
        .build();

    // Watch-stream subscriber counts (one series per stream).
    meter
        .f64_observable_gauge("fleetos.watch.subscribers")
        .with_description("Subscribers per watch stream")
        .with_callback(move |observer| {
            let (watch, sag, schedule, routes) = broadcast_hub.subscriber_counts();
            observer.observe(watch as f64, &[KeyValue::new("stream", "watch")]);
            observer.observe(sag as f64, &[KeyValue::new("stream", "sag")]);
            observer.observe(schedule as f64, &[KeyValue::new("stream", "schedule")]);
            observer.observe(routes as f64, &[KeyValue::new("stream", "routes")]);
        })
        .build();

    // Uptime.
    let start = std::time::Instant::now();
    meter
        .f64_observable_gauge("fleetos.uptime.seconds")
        .with_description("Seconds since process start")
        .with_callback(move |observer| {
            observer.observe(start.elapsed().as_secs_f64(), &[]);
        })
        .build();
}

/// Flush and shut down all providers. Call once at process shutdown.
pub fn shutdown(providers: &TelemetryProviders) {
    if let Err(e) = providers.tracer_provider.shutdown() {
        eprintln!("trace provider shutdown error: {}", e);
    }
    if let Err(e) = providers.meter_provider.shutdown() {
        eprintln!("meter provider shutdown error: {}", e);
    }
    if let Err(e) = providers.logger_provider.shutdown() {
        eprintln!("logger provider shutdown error: {}", e);
    }
}
