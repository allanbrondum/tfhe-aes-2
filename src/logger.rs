use tracing::{metadata::LevelFilter, Subscriber};
use tracing_subscriber::{
    prelude::__tracing_subscriber_SubscriberExt, registry::LookupSpan, util::SubscriberInitExt,
    EnvFilter, Layer,
};

pub fn init(default_level: LevelFilter) {
    let subscriber = tracing_subscriber::registry();
    let stdout_log = stdout_layer(default_level);
    subscriber.with(stdout_log).init();
}

fn stdout_layer<S>(default_level: LevelFilter) -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_level.to_string()));

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_ansi(true)
        .with_target(true);

    stdout_layer.and_then(env_filter)
}

#[cfg(test)]
pub fn test_init(default_level: LevelFilter) {
    use std::sync::OnceLock;
    static INITIALIZED: OnceLock<()> = OnceLock::new();

    INITIALIZED.get_or_init(|| {
        init(default_level);
    });
}
