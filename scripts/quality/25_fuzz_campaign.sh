#!/usr/bin/env bash
# T25 - fuzz campaign over the repo's real targets (cargo-fuzz + sanitizers).
#
# The repo ships 35 fuzz targets with seeds but wires none of them into a gate.
# This runs them for a bounded time each, keeps every crash artifact, and
# reports which targets are actually alive. A target that crashes once is a
# permanent regression case (fuzz/corpus/<target>/).
#
# Usage: 25_fuzz_campaign.sh [seconds-per-target] [target ...]
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

mkdir -p "$OUT/fuzz/campaign"
SECS="${1:-60}"; shift || true
if [ "$#" -gt 0 ]; then TARGETS=("$@"); else
  mapfile -t TARGETS < <(ls fuzz/fuzz_targets/*.rs 2>/dev/null | xargs -n1 basename 2>/dev/null | sed 's/\.rs$//')
fi

head1 "25. fuzz campaign: ${#TARGETS[@]} target(s) x ${SECS}s"

if ! need cargo-fuzz; then
  say "install: cargo install --locked cargo-fuzz  (needs nightly for -Zsanitizer)"
  exit 0
fi
if [ "${#TARGETS[@]}" -eq 0 ]; then
  not_run "fuzz-campaign" "no targets under fuzz/fuzz_targets/"
  exit 0
fi

SUMMARY="$OUT/fuzz/campaign/summary.txt"
: > "$SUMMARY"

# cargo-fuzz needs the nightly toolchain (its -Zsanitizer/sancov flags),
# but the workspace's rust-toolchain.toml pin (stable) silently hijacks
# every `cargo` subprocess cargo-fuzz spawns: on audit run 35 all 39
# targets died at "error: the option `Z` is only accepted on the nightly
# compiler", exit=1 with 0 artifacts - which the artifact-only crash
# count read as "clean". RUSTUP_TOOLCHAIN overrides the pin for the
# whole process tree.
#
# The target is pinned to the host triple explicitly: cargo-fuzz prefers
# musl when its std is installed, and "sanitizer is incompatible with
# statically linked libc" kills the build at -Ctarget-feature=crt-static
# (run 37). The host (glibc, dynamic crt) is the ASan-compatible one.
export RUSTUP_TOOLCHAIN=nightly
HOST_TRIPLE="$(rustc -vV | awk '/^host:/ {print $2}')"

crashes=0
build_failures=0
for t in "${TARGETS[@]}"; do
  say ""
  say "--- $t (${SECS}s)"
  log="${OUT}/fuzz/campaign/${t}.log"
  cargo fuzz run --target "$HOST_TRIPLE" "$t" -- -max_total_time="$SECS" -rss_limit_mb=4096 > "$log" 2>&1
  rc=$?
  arts=0
  if [ -d "fuzz/artifacts/$t" ]; then
    arts=$(find "fuzz/artifacts/$t" -type f 2>/dev/null | wc -l | tr -d ' ')
    mkdir -p "$OUT/fuzz/campaign/artifacts-$t"
    cp -r "fuzz/artifacts/$t/." "$OUT/fuzz/campaign/artifacts-$t/" 2>/dev/null || true
  fi
  if [ "$arts" -gt 0 ]; then
    crashes=$((crashes + 1))
    say "CRASH: $arts artifact(s) -> fuzz/artifacts/$t/ (kept in reports)"
  elif [ "$rc" -ne 0 ]; then
    # A non-zero run WITHOUT a crash artifact is a build/infra failure
    # (the run-35 shape) - never "clean". It must fail the campaign or
    # the lane stays hollow: green while fuzzing nothing.
    build_failures=$((build_failures + 1))
    say "BUILD/RUN FAILURE (exit=$rc, no crash artifact) - see $log"
  else
    say "clean (exit=$rc)"
  fi
  printf '%-28s exit=%-3s artifacts=%s\n' "$t" "$rc" "$arts" >> "$SUMMARY"
done

head1 "campaign result"
cat "$SUMMARY"
say ""
say "$crashes of ${#TARGETS[@]} targets produced artifacts; $build_failures failed to build/run"
say "written: $SUMMARY"
[ "$crashes" -eq 0 ] && [ "$build_failures" -eq 0 ]
