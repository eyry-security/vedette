# vedette

> Fast, multi-threaded HTTP prober (Rust).

Part of **[Eyry](https://eyry.io)** — open-source, agentic recon & offensive security tooling for
bug bounty hunters, red teamers, and pentesters. Vedette is the forward scout: it probes new hosts fast and hands results to the rest of the suite.

## Status

🚧 **Early development.** Structure and APIs will change. Star/watch to follow along, and see
[eyry.io](https://eyry.io).

## What it does

- Probe ports 80/443 across many hosts, fast (Rust, multi-threaded)
- Retries and basic fingerprinting (status, server, title, TLS)
- Streaming JSONL in/out so it pipes cleanly into other tools

## Install

_Coming soon._

## The Eyry suite

- **Vedette** — fast, multi-threaded HTTP prober (Rust)
- **Foretop** — configurable producer of new hosts from pluggable feeds (certstream first)
- **Purser** — Redis-backed priority queue & work distributor (hot/warm/cold/DLQ)
- **Pinnace** — general multi-turn agent runtime: compaction, tools, Docker sandbox
- **Aplomado** — AI security scanner/reviewer built on Pinnace
- **Quarterdeck** — agent control plane: scheduler, events, IRC-style chat + pipeline orchestration

## License

MIT © Eyry
