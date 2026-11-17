//! Fuzz harness for the wasm plugin-ABI intake boundary (attack-surface
//! row: `crates/plugin-host-wasm` + `crates/plugin-api` — the audit's 4
//! unfuzzed boundaries, closed).
//!
//! One pass = hostile `.lumenext` package bytes into
//! [`crate::install::validate_package`] — the full intake path a
//! double-opened package takes: zip central-directory walk
//! ([`crate::package::read_package`], size-capped), manifest TOML parse,
//! origin/kind/API-window checks, provenance hash and signature
//! bookkeeping. Nothing is installed and nothing executes (doc 06 §5.7:
//! inspect/validate never installs) — the same guarantee
//! [`ExtensionStore::inspect`](crate::install::ExtensionStore::inspect)
//! gives the UI.
//!
//! Panic-free by construction: every layer returns a typed
//! [`HostError`](crate::error::HostError)/`PackageError`; nothing here
//! unwraps.

/// The registry-gate-visible harness body (called by
/// `fuzz/fuzz_targets/fuzz_plugin_package.rs`).
pub fn fuzz_plugin_package(data: &[u8]) {
    let _ = crate::install::validate_package(data);
}
