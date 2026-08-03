//! Input sources. Each producer reads hosts and sends them into a channel that
//! the probe consumer drains concurrently.

use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc::Sender;

/// Where hosts come from.
pub enum Source {
    /// Read one host per line from a file.
    File(PathBuf),
    /// Read one host per line from stdin.
    Stdin,
    /// Block-pop hosts from a Redis list (`BRPOP`), streaming forever.
    Redis { url: String, queue: String },
}

/// Read hosts from a file or stdin, sending each non-empty, non-comment line.
async fn produce_lines<R>(reader: R, tx: Sender<String>) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        let host = line.trim().to_string();
        if host.is_empty() || host.starts_with('#') {
            continue;
        }
        if tx.send(host).await.is_err() {
            break; // consumer gone
        }
    }
    Ok(())
}

/// Continuously BRPOP hosts from a Redis list until the consumer drops.
async fn produce_redis(url: &str, queue: &str, tx: Sender<String>) -> Result<()> {
    let client = redis::Client::open(url).context("invalid redis url")?;
    let mut con = client
        .get_multiplexed_async_connection()
        .await
        .context("redis connect failed")?;

    loop {
        // BRPOP blocks until an item is available; returns (list_key, value).
        let popped: Option<(String, String)> = redis::cmd("BRPOP")
            .arg(queue)
            .arg(0) // 0 = block indefinitely
            .query_async(&mut con)
            .await
            .context("redis BRPOP failed")?;

        match popped {
            Some((_, host)) => {
                let host = host.trim().to_string();
                if host.is_empty() {
                    continue;
                }
                if tx.send(host).await.is_err() {
                    break;
                }
            }
            None => break,
        }
    }
    Ok(())
}

/// Drive the given source, sending hosts into `tx`. Returns when the source is
/// exhausted (file/stdin) or the consumer has gone away.
pub async fn run(source: Source, tx: Sender<String>) -> Result<()> {
    match source {
        Source::File(path) => {
            let file = tokio::fs::File::open(&path)
                .await
                .with_context(|| format!("cannot open {}", path.display()))?;
            produce_lines(file, tx).await
        }
        Source::Stdin => produce_lines(tokio::io::stdin(), tx).await,
        Source::Redis { url, queue } => produce_redis(&url, &queue, tx).await,
    }
}
