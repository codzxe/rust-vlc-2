//! Fuzz harness for the "source URI" trust boundary (attack-surface row:
//! `crates/input` + `crates/media-types` — the audit's 4 unfuzzed
//! boundaries, closed).
//!
//! One pass = hostile URI text into [`media_types::ids::SourceUri::parse`]
//! and, when it parses, the `file:` resolution chain
//! ([`crate::uri::resolve_file`]). Panic-free by construction: both entry
//! points return a typed `EngineError`; nothing here unwraps, and
//! `resolve_file` only canonicalizes (read-only syscalls, never writes),
//! which is exactly the path a hostile playlist entry would drive.

use media_types::ids::SourceUri;

/// The registry-gate-visible harness body (called by
/// `fuzz/fuzz_targets/fuzz_uri_source.rs`).
pub fn fuzz_uri_source(data: &[u8]) {
    let Some(text) = std::str::from_utf8(data).ok() else {
        return;
    };
    if let Ok(uri) = SourceUri::parse(text) {
        let _ = crate::uri::resolve_file(&uri);
    }
}
