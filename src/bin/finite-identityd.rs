use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use finite_identity::authority::{
    AuthorityConfig, AuthorityState, DevMailer, IdentityStore, SystemClock, router,
};

#[tokio::main]
async fn main() {
    if let Err(message) = run(std::env::args().skip(1).collect()).await {
        eprintln!("finite-identityd: {message}");
        std::process::exit(2);
    }
}

async fn run(args: Vec<String>) -> Result<(), String> {
    if args.first().map(String::as_str) != Some("serve") {
        return Err(usage());
    }
    let data = flag_value(&args, "--data").ok_or_else(usage)?;
    let listen = flag_value(&args, "--listen").unwrap_or_else(|| "127.0.0.1:8790".to_owned());
    let external_base_url =
        flag_value(&args, "--external-base-url").ok_or("--external-base-url URL is required")?;
    if flag_value(&args, "--dev-print-email-tokens").as_deref() != Some("yes") {
        return Err(
            "--dev-print-email-tokens yes is required until a production Mailer Adapter is configured"
                .to_owned(),
        );
    }
    let finite_vip_domain =
        flag_value(&args, "--finite-vip-domain").unwrap_or_else(|| "finite.vip".to_owned());
    let operator_token = flag_value(&args, "--operator-token");
    let address: SocketAddr = listen
        .parse()
        .map_err(|error| format!("invalid --listen address: {error}"))?;
    let data_dir = PathBuf::from(data);
    let store = IdentityStore::open(data_dir.join("identity.db"))
        .map_err(|error| format!("cannot open identity store: {error}"))?;
    let state = AuthorityState::new(
        store,
        Arc::new(DevMailer),
        SystemClock,
        AuthorityConfig {
            external_base_url,
            finite_vip_domain,
            email_challenge_ttl_seconds: 15 * 60,
            operator_token,
        },
    );
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|error| format!("cannot bind {address}: {error}"))?;
    axum::serve(listener, router(state))
        .await
        .map_err(|error| format!("server error: {error}"))
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find_map(|window| (window[0] == name).then(|| window[1].clone()))
}

fn usage() -> String {
    "usage: finite-identityd serve --data DIR --external-base-url URL --dev-print-email-tokens yes [--listen 127.0.0.1:8790] [--finite-vip-domain finite.vip] [--operator-token TOKEN]".to_owned()
}
