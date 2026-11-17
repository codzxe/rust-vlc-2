//! Fuzz harness for the "settings (TOML)" trust boundary — the
//! settings-schema half (attack-surface row: `crates/settings-schema` +
//! `crates/product-config`): hostile schema DSL text into
//! [`parse_str`], the parser that turns settings definition files into
//! the schema every product config is validated against.
//!
//! Panic-free by construction: `parse_str` returns the full
//! `SchemaDiagnostic` list; nothing here unwraps.

/// The harness body (called by `fuzz/fuzz_targets/fuzz_settings_toml.rs`
/// as its second pass, same convention as `fuzz_hls_playlist`).
pub fn fuzz_schema_dsl(data: &[u8]) {
    let Ok(src) = std::str::from_utf8(data) else {
        return;
    };
    let _ = crate::parse_str(src);
}
