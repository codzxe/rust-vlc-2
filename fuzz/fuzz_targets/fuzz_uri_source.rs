// fuzz_uri_source — the source-URI target (attack-surface gap: "source
// URI" had zero fuzz targets — closed with the audit's 4-boundary fix).
//
// Thin libFuzzer shim: the harness body is the in-crate `input::fuzz`
// module (panic-free by construction, bounds documented there); one
// call = hostile URI text through `SourceUri::parse` and, when it
// parses, the `file:` resolution chain.
//
// Seeds: fuzz/corpus/fuzz_uri_source/ — the URI shapes the engine
// accepts (file/http/https + a device scheme), drawn from the crates'
// own tests.
//
// Build (once nightly is wired):  cargo +nightly fuzz run fuzz_uri_source

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    input::fuzz::fuzz_uri_source(data);
});
