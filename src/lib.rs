//! Vedette — a fast, multi-threaded HTTP prober.
//!
//! The forward scout of the Eyry recon suite. Consumes a list or stream of
//! hosts, probes 80/443 concurrently, and emits one JSON record per host.
//!
//! This crate is usable as a library (`probe`, `ProbeResult`) or via the
//! `vedette` binary.

pub mod input;
pub mod model;
pub mod probe;

pub use model::ProbeResult;
pub use probe::{probe, ProbeOptions};
