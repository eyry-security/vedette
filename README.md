# Vedette

Fast, multi-threaded HTTP prober. The forward scout of the [Eyry](https://eyry.io) recon suite.

Vedette takes a list or stream of hosts, probes `80`/`443` concurrently, and writes one JSON
record per host. It is small, quick, and Unix-y: read from a file, stdin, or a Redis queue, and
pipe the JSONL output into whatever comes next.

MIT licensed. Use it only against systems you are authorized to test.

## Install

```sh
git clone https://github.com/eyry-security/vedette
cd vedette
cargo build --release
# binary at ./target/release/vedette
```

## Usage

```sh
# From a file (one host per line)
vedette -l hosts.txt -o results.jsonl

# From stdin
cat hosts.txt | vedette -o results.jsonl

# Stream from a Redis list (blocking BRPOP), runs until interrupted
vedette --redis redis://127.0.0.1:6379 --queue vedette:hosts -o results.jsonl

# Tune it
vedette -l hosts.txt -c 200 -t 8 --https-only -o results.jsonl
```

Inputs may be bare hosts (`admin.example.com`), `host:port`, or full URLs
(`https://example.com`). For a bare host, Vedette tries `https` then `http` by default.

### Options

| Flag | Default | Description |
| --- | --- | --- |
| `-l, --list <FILE>` | – | Input file, one host per line |
| `--redis <URL>` | – | Read hosts from a Redis list via `BRPOP` |
| `--queue <KEY>` | `vedette:hosts` | Redis list key |
| `-o, --output <FILE>` | stdout | Write JSONL results here |
| `-c, --concurrency <N>` | `50` | Concurrent probes |
| `-t, --timeout <SECS>` | `10` | Per-request timeout |
| `--retries <N>` | `1` | Retries per scheme after the first attempt |
| `--max-body <BYTES>` | `524288` | Stop reading each body after N bytes (0 = unlimited) |
| `--https-only` / `--http-only` | – | Restrict schemes |
| `--silent` | – | Suppress the stderr summary |

## Output

One JSON object per line (JSONL). This is the shared host/service schema the rest of the Eyry
suite speaks, so Vedette output flows straight into a queue or scanner.

```json
{
  "input": "www.eyry.io",
  "ok": true,
  "url": "https://www.eyry.io/",
  "scheme": "https",
  "host": "www.eyry.io",
  "port": 443,
  "status": 200,
  "title": "Eyry Cyber Security",
  "server": "Vercel",
  "content_type": "text/html; charset=utf-8",
  "content_length": 43777,
  "ips": ["216.198.79.65", "64.29.17.65"],
  "tech": ["Vercel", "Next.js", "React"],
  "body_sha256": "c4aa86…",
  "response_time_ms": 170,
  "timestamp": "2026-08-03T01:50:06Z"
}
```

Hosts that do not respond are still emitted, with `"ok": false` and an `error` field, so nothing
is silently dropped.

Notes:
- For a bare host, https and http are probed **concurrently** (https wins); http-only and dead
  hosts don't pay a second serial timeout.
- The body is streamed and cut off at `--max-body` (default 512 KB), so Vedette never downloads a
  huge page. `body_sha256` and, when there is no `Content-Length` header, `content_length` reflect
  the bytes actually read.

## As a library

```rust
use vedette::{probe, ProbeOptions};

let client = reqwest::Client::new();
let result = probe(&client, "example.com", &ProbeOptions::default()).await;
println!("{}", serde_json::to_string(&result)?);
```

## Where it fits

```
Foretop (new hosts) → Purser (queue) → Vedette (probe + fingerprint) → Aplomado (AI review)
```

Vedette is the first stage: confirm what is live and worth a closer look, fast. See the suite at
[github.com/eyry-security](https://github.com/eyry-security).

## Roadmap

- TLS certificate details (subject/issuer/SAN/expiry) as structured fields
- Preserve request paths for full-URL inputs
- Custom ports and port lists
- Optional CSV / plain output

## License

MIT © Eyry
