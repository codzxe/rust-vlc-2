//! Fuzz harness for the control-protocol wire boundary (attack-surface
//! row: `crates/control-protocol` + `apps/control-server` — the audit's 4
//! unfuzzed boundaries, closed).
//!
//! One pass drives the exact entry points `server.rs` drives on an
//! untrusted connection, with the production caps
//! ([`crate::server::Limits::DEFAULT_MAX_FRAME_BYTES`] /
//! `DEFAULT_MAX_MESSAGE_BYTES`):
//!
//! 1. [`frame::read_frame`] — server-role frame decode (masked client
//!    frames, the production path at server.rs:546);
//! 2. [`http::read_upgrade_request`] — the HTTP upgrade head;
//! 3. [`frame::parse_close_payload`] — close code + reason;
//! 4. the [`frame::MessageAssembler`] reassembly loop — fragment storms,
//!    capped exactly like the server's.
//!
//! Panic-free by construction: every entry point returns a typed
//! [`crate::error::ProtocolError`]; the assembler loop is bounded by the
//! input length (each iteration consumes stream bytes or breaks).

use std::io::Cursor;

use crate::frame::{self, MessageAssembler};
use crate::http;
use crate::server::Limits;

/// The registry-gate-visible harness body (called by
/// `fuzz/fuzz_targets/fuzz_control_frame.rs`).
pub fn fuzz_control_frame(data: &[u8]) {
    // 1. server-role frame decode (the production read path).
    let mut r = Cursor::new(data);
    let _ = frame::read_frame(&mut r, Limits::DEFAULT_MAX_FRAME_BYTES);

    // 2. the HTTP upgrade request head.
    let mut h = Cursor::new(data);
    let _ = http::read_upgrade_request(&mut h);

    // 3. close payload (status code + UTF-8 reason).
    let _ = frame::parse_close_payload(data);

    // 4. reassembly: feed frames until the stream is exhausted or a typed
    //    protocol error stops the loop (bounded by the input length).
    let mut a = Cursor::new(data);
    let mut asm = MessageAssembler::new(Limits::DEFAULT_MAX_MESSAGE_BYTES);
    while let Ok(Some(f)) = frame::read_frame(&mut a, Limits::DEFAULT_MAX_FRAME_BYTES) {
        if asm.push(f).is_err() {
            break;
        }
    }
}
