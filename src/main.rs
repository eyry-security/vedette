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
use vedette::output::{render_result, OutputFormat};
use vedette::probe::{probe, ProbeOptions};
use vedette::resolver::Dns;

/// Fast, multi-threaded HTTP prober. Reads hosts from a file, stdin, or a Redis
/// queue, probes them concurrently, and streams the results.
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

    /// Output file for results (default: stdout).
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Output responding URLs only, one per line; failed probes are omitted.
    #[arg(long, alias = "urls")]
    url_only: bool,

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

const STREAM_FLUSH_INTERVAL: Duration = Duration::from_millis(250);

async fn write_results<W>(
    out: W,
    mut res_rx: mpsc::Receiver<vedette::ProbeResult>,
    ok_count: Arc<AtomicU64>,
    total_count: Arc<AtomicU64>,
    output_format: OutputFormat,
    flush_every: Duration,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = BufWriter::new(out);
    let mut since_flush = 0u32;
    let mut flush_tick = tokio::time::interval(flush_every);
    flush_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            result = res_rx.recv() => {
                let Some(result) = result else { break };
                total_count.fetch_add(1, Ordering::Relaxed);
                if result.ok {
                    ok_count.fetch_add(1, Ordering::Relaxed);
                }
                if let Some(line) = render_result(&result, output_format)? {
                    buf.write_all(line.as_bytes()).await?;
                    buf.write_all(b"\n").await?;
                    since_flush += 1;
                    if since_flush >= 32 {
                        buf.flush().await?;
                        since_flush = 0;
                    }
                }
            }
            _ = flush_tick.tick(), if since_flush > 0 => {
                buf.flush().await?;
                since_flush = 0;
            }
        }
    }
    buf.flush().await?;
    Ok(())
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

    // One shared async resolver, used for the ips field and for connecting.
    let dns = Dns::new();

    let client = Arc::new(
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .tls_info(true)
            .timeout(Duration::from_secs(args.timeout))
            .connect_timeout(Duration::from_secs(args.timeout))
            .redirect(reqwest::redirect::Policy::limited(10))
            .pool_max_idle_per_host(0)
            .dns_resolver(Arc::new(dns.clone()))
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
    let output_format = if args.url_only {
        OutputFormat::Urls
    } else {
        OutputFormat::JsonLines
    };
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
        write_results(out, res_rx, wok, wtotal, output_format, STREAM_FLUSH_INTERVAL).await
    });

    // Producer task feeds hosts into host_tx.
    let producer = tokio::spawn(async move { input::run(source, host_tx).await });

    // Consumer drains hosts and probes up to `concurrency` at a time.
    let concurrency = args.concurrency.max(1);
    ReceiverStream::new(host_rx)
        .for_each_concurrent(concurrency, |host| {
            let client = client.clone();
            let dns = dns.clone();
            let opts = opts.clone();
            let res_tx = res_tx.clone();
            async move {
                let result = probe(client, &dns, &host, &opts).await;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_only_flag_and_alias_parse() {
        assert!(
            Args::try_parse_from(["vedette", "--url-only"])
                .unwrap()
                .url_only
        );
        assert!(
            Args::try_parse_from(["vedette", "--urls"])
                .unwrap()
                .url_only
        );
    }

    #[test]
    fn json_lines_remain_the_default() {
        assert!(!Args::try_parse_from(["vedette"]).unwrap().url_only);
    }

    use tokio::io::{AsyncBufReadExt, BufReader};

    #[tokio::test]
    async fn quiet_stream_flushes_before_result_channel_closes() {
        let (writer_io, reader_io) = tokio::io::duplex(4096);
        let (tx, rx) = mpsc::channel(1);
        let ok_count = Arc::new(AtomicU64::new(0));
        let total_count = Arc::new(AtomicU64::new(0));
        let task = tokio::spawn(write_results(
            writer_io,
            rx,
            ok_count,
            total_count.clone(),
            OutputFormat::JsonLines,
            Duration::from_millis(10),
        ));

        tx.send(vedette::ProbeResult::failed("quiet.test", "quiet.test", "test"))
            .await
            .unwrap();

        let mut reader = BufReader::new(reader_io);
        let mut line = String::new();
        tokio::time::timeout(Duration::from_millis(250), reader.read_line(&mut line))
            .await
            .expect("quiet result was not flushed")
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).unwrap()["host"],
            "quiet.test"
        );
        assert_eq!(total_count.load(Ordering::Relaxed), 1);

        drop(tx);
        task.await.unwrap().unwrap();
    }
}
