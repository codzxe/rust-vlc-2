// fuzz_settings_toml — the settings-TOML target (attack-surface gap:
// "settings (TOML)" had zero fuzz targets — closed with the audit's
// 4-boundary fix).
//
// One call = TWO passes (both panic-free by construction):
//
// 1. `product_config::fuzz::fuzz_settings_toml` — hostile TOML into the
//    layered loader (parse + structural schema walk + pattern matchers).
//    This is the registry-gate-visible in-crate harness call.
// 2. `settings_schema::fuzz::fuzz_schema_dsl` — hostile schema DSL text
//    into `parse_str`, the parser that builds the schema every product
//    config is validated against.
//
// Seeds: fuzz/corpus/fuzz_settings_toml/ — real `product.toml` and
// `locales/en-US.toml` heads from the repo.
//
// Build:  cargo +nightly fuzz run fuzz_settings_toml

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    product_config::fuzz::fuzz_settings_toml(data);
    settings_schema::fuzz::fuzz_schema_dsl(data);
});
