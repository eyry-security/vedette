# Vedette

Fast, multi-threaded HTTP prober. What's live, and what is it.

Part of [Eyry](https://eyry.io) — a *vedette* is the forward scout, the picket
boat sent ahead of the fleet.

## What it does

- Takes hosts from a file, stdin, or a Redis queue (streaming `BRPOP`) and
  probes them concurrently (default 50).
- For each host: status code, title, server header, tech fingerprint,
  resolved IPs, body hash, response time.
- Writes one JSON object per line (JSONL) — the shared host/service schema the
  rest of the suite speaks, so output flows straight into a queue or scanner.
- Dead hosts are still emitted, with `"ok": false` and an `error` field — so
  nothing is silently dropped.

MIT licensed. Use only against systems you are authorized to test.

## Install

```sh
git clone https://github.com/eyry-security/vedette
cd vedette
cargo build --release
# binary at ./target/release/vedette
```

Rust 1.70+ (2021 edition).

## Usage

```sh
# From a file (one host per line)
vedette -l hosts.txt -o results.jsonl

# From stdin
cat hosts.txt | vedette -o results.jsonl

# Print only live final URLs, one per line
foretop --scope example.com | vedette --url-only --silent

# Stream from a Redis list (blocking BRPOP), runs until interrupted
vedette --redis redis://127.0.0.1:6379 --queue vedette:hosts -o results.jsonl

# Tune it
vedette -l hosts.txt -c 200 -t 8 --https-only -o results.jsonl
```

Inputs may be bare hosts (`admin.example.com`), `host:port`, or full URLs
(`https://example.com`). For a bare host, Vedette probes `https` then `http`
concurrently (https wins); http-only and dead hosts don't pay a second serial
timeout. Lines that are JSON objects with a `host` field (e.g. from
`foretop --json`) have the host extracted automatically, so
`foretop --scope example.com | vedette` and
`foretop --scope example.com --json | vedette` both work.

### Options

| Flag | Default | Description |
| --- | --- | --- |
| `-l, --list <FILE>` | – | Input file, one host per line |
| `--redis <URL>` | – | Read hosts from a Redis list via `BRPOP` |
| `--queue <KEY>` | `vedette:hosts` | Redis list key |
| `-o, --output <FILE>` | stdout | Write results here |
| `--url-only` | off | Write only successful final URLs, one per line (`--urls` alias) |
| `-c, --concurrency <N>` | `50` | Concurrent probes |
| `-t, --timeout <SECS>` | `10` | Per-request timeout |
| `--retries <N>` | `1` | Retries per scheme after the first attempt |
| `--max-body <BYTES>` | `524288` | Stop reading each body after N bytes (0 = unlimited) |
| `--https-only` / `--http-only` | – | Restrict schemes |
| `--silent` | – | Suppress the stderr summary |

`vedette --version` prints the version.

## Output

One JSON object per line (JSONL). Real output from a single probe:

```sh
$ echo 'eyry.io' | vedette --silent
```

```json
{
  "input": "eyry.io",
  "ok": true,
  "url": "https://www.eyry.io/",
  "scheme": "https",
  "host": "eyry.io",
  "port": 443,
  "status": 200,
  "title": "Eyry — The AppSec Pipeline: Build, Break, Harden, Watch",
  "server": "Vercel",
  "content_type": "text/html; charset=utf-8",
  "content_length": 54185,
  "redirects": 1,
  "ips": ["216.198.79.1"],
  "tech": ["Vercel", "Next.js"],
  "body_sha256": "d9ae3dfd19aabbec6bdb1e4ff3f49ce787c1cce0f3046273f27767bdf57e055e",
  "response_time_ms": 505,
  "timestamp": "2026-10-04T07:43:00Z"
}
```

For URL pipelines, `--url-only` prints only the final URL of each successful
probe and omits failed hosts. Redirect destinations are preserved:

```sh
$ printf 'eyry.io\noffline.invalid\n' | vedette --url-only --silent
https://www.eyry.io/
```

Notes:

- For a bare host, https and http are probed **concurrently** (https wins); the
  scheme can also be pinned with `--https-only` / `--http-only`.
- The body is streamed and cut off at `--max-body` (default 512 KB), so Vedette
  never downloads a huge page. `body_sha256` and, when there is no
  `Content-Length` header, `content_length` reflect the bytes actually read.
- DNS uses a shared async resolver (public resolvers, both A and AAAA). A host
  that resolves to nothing is reported immediately as failed without wasting
  HTTP attempts.

## As a library

The prober is usable from Rust code — not just the CLI:

```rust
use std::sync::Arc;
use vedette::{probe, ProbeOptions};
use vedette::resolver::Dns;

#[tokio::main]
async fn main() {
    let client = Arc::new(reqwest::Client::new());
    let dns = Dns::new();
    let result = probe(client, &dns, "example.com", &ProbeOptions::default()).await;
    println!("{}", serde_json::to_string(&result).unwrap());
}
```

## Where it fits

```
Foretop (new hosts) → Purser (queue) → Vedette (probe) → Rutt (store) → Aplomado (AI review)
```

Vedette is the probe stage: it confirms what's alive and fingerprints it, fast
and at scale — nothing downstream runs on guesses.

## The Eyry suite

- **eyry**: one CLI that wires the data plane together — discover → queue → probe → store
- **vedette**: fast, multi-threaded HTTP prober (Rust) — confirms what is live and fingerprints it
- **foretop**: pluggable live feed of new hosts, starting with Certificate Transparency logs
- **purser**: Redis-backed priority work queue — hot/warm/cold lanes, retries, dead-letter queue
- **rutt**: Postgres store for the host lifecycle (discovered → probed → reviewed) with an append-only scan log
- **pinnace**: general multi-turn agent runtime — compaction, tools, Docker sandbox, resumable sessions
- **aplomado**: AI security reviewer built on Pinnace — target in, structured findings out
- **quarterdeck**: agent control plane — scheduler, wake/sleep, identity and memory, IRC-style chat, ChatOps, pipeline orchestration
## Roadmap

- TLS certificate details (subject/issuer/SAN/expiry) as structured fields
- Preserve request paths for full-URL inputs
- Custom ports and port lists
- Optional CSV output

## License

MIT © Eyry

---

Use only against systems you are authorized to test.
