//! Vedette CLI — fast, multi-threaded HTTP prober.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use futures::StreamExt;
use tokio::io::{AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use vedette::input::{self, Source};
use vedette::probe::{probe, ProbeOptions};

/// Fast, multi-threaded HTTP prober. Reads hosts from a file, stdin, or a Redis
/// queue, probes them concurrently, and writes one JSON record per host.
#[derive(Parser, Debug)]
#[command(name = "vedette", version, about)]
struct Args {
    /// Input file with one host per line.
    #[arg(short = 'l', long = "list", value_name = "FILE")]
    list: Option<PathBuf>,

    /// Read hosts from a Redis list via BRPOP (streaming). Value is the Redis URL,
    /// e.g. redis://127.0.0.1:6379.
    #[arg(long, value_name = "URL")]
    redis: Option<String>,

    /// Redis list/queue key to pop hosts from.
    #[arg(long, default_value = "vedette:hosts")]
    queue: String,

    /// Output file for JSONL results (default: stdout).
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Number of concurrent probes.
    #[arg(short = 'c', long, default_value_t = 50)]
    concurrency: usize,

    /// Per-request timeout in seconds.
    #[arg(short = 't', long, default_value_t = 10)]
    timeout: u64,

    /// Retries per scheme after the first attempt.
    #[arg(long, default_value_t = 1)]
    retries: u32,

    /// Stop reading each body after this many bytes (0 = unlimited).
    #[arg(long, default_value_t = 512 * 1024)]
    max_body: usize,

    /// Only probe https.
    #[arg(long, conflicts_with = "http_only")]
    https_only: bool,

    /// Only probe http.
    #[arg(long)]
    http_only: bool,

    /// Suppress the stderr summary.
    #[arg(long)]
    silent: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let schemes = if args.https_only {
        vec!["https".to_string()]
    } else if args.http_only {
        vec!["http".to_string()]
    } else {
        vec!["https".to_string(), "http".to_string()]
    };

    let opts = Arc::new(ProbeOptions {
        schemes,
        retries: args.retries,
        max_body: args.max_body,
    });

    let client = Arc::new(
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(args.timeout))
            .connect_timeout(Duration::from_secs(args.timeout))
            .redirect(reqwest::redirect::Policy::limited(10))
            .user_agent(concat!("vedette/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("failed to build HTTP client")?,
    );

    // Pick the input source.
    let source = if let Some(url) = args.redis.clone() {
        Source::Redis {
            url,
            queue: args.queue.clone(),
        }
    } else if let Some(path) = args.list.clone() {
        Source::File(path)
    } else {
        Source::Stdin
    };

    // host channel: producer -> consumer
    let (host_tx, host_rx) = mpsc::channel::<String>(1024);
    // result channel: probe tasks -> writer
    let (res_tx, mut res_rx) = mpsc::channel::<vedette::ProbeResult>(1024);

    // Writer task owns the output and serializes all writes.
    let output = args.output.clone();
    let ok_count = Arc::new(AtomicU64::new(0));
    let total_count = Arc::new(AtomicU64::new(0));
    let (wok, wtotal) = (ok_count.clone(), total_count.clone());
    let writer = tokio::spawn(async move {
        let mut out: Box<dyn AsyncWrite + Unpin + Send> = match output {
            Some(path) => Box::new(
                tokio::fs::File::create(&path)
                    .await
                    .with_context(|| format!("cannot create {}", path.display()))?,
            ),
            None => Box::new(tokio::io::stdout()),
        };
        let mut buf = BufWriter::new(&mut out);
        while let Some(result) = res_rx.recv().await {
            wtotal.fetch_add(1, Ordering::Relaxed);
            if result.ok {
                wok.fetch_add(1, Ordering::Relaxed);
            }
            let line = serde_json::to_string(&result).unwrap_or_else(|_| "{}".into());
            buf.write_all(line.as_bytes()).await?;
            buf.write_all(b"\n").await?;
            buf.flush().await?;
        }
        buf.flush().await?;
        Ok::<(), anyhow::Error>(())
    });

    // Producer task feeds hosts into host_tx.
    let producer = tokio::spawn(async move { input::run(source, host_tx).await });

    // Consumer drains hosts and probes up to `concurrency` at a time.
    let concurrency = args.concurrency.max(1);
    ReceiverStream::new(host_rx)
        .for_each_concurrent(concurrency, |host| {
            let client = client.clone();
            let opts = opts.clone();
            let res_tx = res_tx.clone();
            async move {
                let result = probe(client, &host, &opts).await;
                let _ = res_tx.send(result).await;
            }
        })
        .await;

    // All probes done: close the result channel so the writer can finish.
    drop(res_tx);
    writer.await.context("writer task panicked")??;

    match producer.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("vedette: input error: {e:#}"),
        Err(e) => eprintln!("vedette: producer task panicked: {e}"),
    }

    if !args.silent {
        eprintln!(
            "vedette: probed {} host(s), {} responded",
            total_count.load(Ordering::Relaxed),
            ok_count.load(Ordering::Relaxed)
        );
    }

    Ok(())
}
