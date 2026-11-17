// fuzz_plugin_package — the wasm plugin-ABI intake target
// (attack-surface gap: "wasm plugin ABI" had zero fuzz targets — closed
// with the audit's 4-boundary fix).
//
// Thin libFuzzer shim: the harness body is the in-crate
// `plugin_host_wasm::fuzz` module (panic-free by construction); one
// call = hostile `.lumenext` bytes through `validate_package` (zip
// central directory, manifest TOML, provenance hash, signature
// bookkeeping). Nothing installs, nothing executes.
//
// Seeds: fuzz/corpus/fuzz_plugin_package/ — a minimal real-shaped
// package (manifest.toml + plugin.wasm from
// plugins/extensions/metadata-provider, packaged with the entry names
// `read_package` expects).
//
// Build:  cargo +nightly fuzz run fuzz_plugin_package

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    plugin_host_wasm::fuzz::fuzz_plugin_package(data);
});
