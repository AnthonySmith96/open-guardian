use tracing_appender::rolling;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub fn init_logger() {
    let base_dir = if let Ok(exe_path) = std::env::current_exe() {
        exe_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
    } else {
        std::env::current_dir().unwrap_or_default()
    };

    let log_dir = base_dir.join("logs");
    let file_appender = rolling::daily(log_dir, "open-guardian.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // Filter from environment or default to INFO
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // We only log to the file.
    // Console output is handled exclusively by banner.rs for a clean user experience.
    tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_target(true),
        )
        .init();

    tracing::info!(
        "Open-Guardian Logger v{} initialized. Rolling daily logs in logs/. Non-blocking I/O enabled.",
        env!("CARGO_PKG_VERSION")
    );

    // leaked guard is intentional to keep logging alive for the process duration
    std::mem::forget(_guard);
}
