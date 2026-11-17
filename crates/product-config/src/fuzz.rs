//! Fuzz harness for the "settings (TOML)" trust boundary — the
//! product-config half (attack-surface row: `crates/settings-schema` +
//! `crates/product-config` — the audit's 4 unfuzzed boundaries, closed).
//!
//! One pass = hostile TOML text into [`load_str`] (full validation:
//! parse + structural schema walk + pattern matchers + diagnostics) and
//! [`load_partial_str`] (the sparse-layer path every overlay document
//! takes). The schema is a permissive `{"type":"object"}` document: an
//! empty root would skip the structural walk, this one runs it while
//! still letting every hostile *value* shape through.
//!
//! Panic-free by construction: both entry points return the full
//! diagnostic list; nothing here unwraps.

use serde_json::json;

use crate::{Schema, load_partial_str, load_str};

/// The registry-gate-visible harness body (called by
/// `fuzz/fuzz_targets/fuzz_settings_toml.rs`).
pub fn fuzz_settings_toml(data: &[u8]) {
    let Ok(schema) = Schema::from_json(json!({"type": "object"})) else {
        return;
    };
    let Ok(src) = std::str::from_utf8(data) else {
        return;
    };
    let _ = load_str("fuzz.toml", src, &schema);
    let _ = load_partial_str("fuzz.toml", src, &schema);
}
