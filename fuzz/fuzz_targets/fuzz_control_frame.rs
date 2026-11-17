// fuzz_control_frame — the control-protocol wire target (attack-surface
// gap: "control protocol" had zero fuzz targets — closed with the
// audit's 4-boundary fix).
//
// Thin libFuzzer shim: the harness body is the in-crate
// `control_protocol::fuzz` module (panic-free by construction); one
// call = the server-role frame reader (the production path), the HTTP
// upgrade head, the close payload, and the message assembler — all with
// the production caps.
//
// Seeds: fuzz/corpus/fuzz_control_frame/ — a masked text frame, an
// upgrade request head, and a close payload, per the RFC 6455 shapes
// the crate's own tests use.
//
// Build:  cargo +nightly fuzz run fuzz_control_frame

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    control_protocol::fuzz::fuzz_control_frame(data);
});
