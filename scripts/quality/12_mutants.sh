#!/usr/bin/env bash
# T12 - MUTATION TESTING (primary task). Answers: are the tests real?
#
# Usage:
#   12_mutants.sh list              # size the problem, no build
#   12_mutants.sh crate <name>      # full run for one crate
#   12_mutants.sh diff              # changed lines only (requires .git)
#   12_mutants.sh full [--shard i/N]
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

need cargo-mutants || exit 0
mkdir -p "$OUT/mutants"

# Never mutate: tests, generated code, the template member, the excluded tauri app.
# Plus ALL 13 MPD scanner hang sites in crates/playlists/src/mpd.rs (audit
# runs 44582085806 + 44771219869, lab exp_A 2026-11-20):
#   advance_char 750/751, truncated_at_eof 767, next_token 784/787/791/842,
#   resync_attr 959, Driver::on_end 1589, parse_xs_duration 1936/1951/1957/1971.
# Cursor-freeze and token-freeze mutants make skip_ws / scan_start_tag's
# damage-resync / skip_after spin forever; the resync path pushes one
# MpdWarning::BadTag per iteration (~31MB/s/worker, lab: 1.4GB in 45s), and
# four workers pinned on consecutive sites cross the VM memory ceiling in
# ~40-80s - BEFORE any --timeout can fire. Proof: run 44582085806 shard 6
# died 77s after mpd.rs:740 (full cluster ahead); run 44771219869 shard 6,
# with only advance_char/truncated_at_eof excluded, entered the next_token
# quartet 784/787/791/842 on four workers and the runner died 42s later.
# No timeout wins that race, so the sites are excluded from generation: a
# guaranteed hang is auto-caught, carries zero discrimination signal, and
# its finding (unbounded loop + unbounded warning growth on damaged MPD
# input) is already recorded here and in the audit verdict. advance_char /
# truncated_at_eof are matched by function name (every mutant hangs); the
# other ten are matched by exact file:line anchors from exp_A on 239f779 -
# re-derive them if mpd.rs ever shifts.
EXCLUDE_RE="(^|/)(tests|benches|examples)/|_template|desktop-tauri|schemas/generated|Scanner<'a>::advance_char|Scanner<'a>::truncated_at_eof|mpd\.rs:(784|787|791|842|959|1589|1936|1951|1957|1971):"

# 90s per mutant, not 1800s (audit runs 44582085806 + 44771219869): a
# hang-class mutant (loop-bound / counter mutation in a parser or serve
# loop) must cost 90s of one worker, not 30 min - slice 6 burned 2.5h of
# worker time on five 1800s timeouts (hls serve/fetch loops) before dying.
# The cap bounds FLAT hangs only: a memory balloon (the mpd.rs warning-push
# spins above, ~31MB/s x 4 workers) crosses the VM ceiling in ~40-80s,
# before this cap can fire - balloons are neutralised by excluding their
# sites, never by timeout. The cap also bounds the unmutated baseline:
# legit baselines are <= 5s (slice 3 post-IVF-exclusion: 1046 tests in
# 4.3s; slice 5: 2s) and legit per-mutant tests are <= 11s across every
# shard log so far. If anything ever exceeds it the failure is LOUD, FAST
# and NAMES the culprit - run 44771219869 shard 4 proved it: one 85s IVF
# lane in the unmutated baseline hit the cap and cargo-mutants exited 4 in
# 3 minutes with the test name in the log, instead of the old silent
# 132-minute runner death. That is this cap working as designed; raise it
# deliberately, never to accommodate a hang.
TIMEOUT="${MUTANTS_TIMEOUT:-90}"
JOBS="${MUTANTS_JOBS:-8}"
# The wall budget for one shard (GNU timeout, minutes). A FULL sweep is
# ~20-30 h per shard on a 4-core runner (per-mutant = incremental build +
# the mutated package's suite; ~4,800 mutants per shard) - far past the
# workflow's 330-min job cap, which used to kill the shard mid-run with
# exit 143. The budget ends the run CLEANLY instead: cargo-mutants traps
# the signal and writes its (partial, honestly-labeled) outcomes.json,
# and the score aggregates what was actually tested.
BUDGET_MIN="${MUTANTS_BUDGET_MIN:-285}"
# Tests excluded from MUTATION runs only (nextest filterset, appended
# after cargo-mutants' `--` passthrough). The IVF family lanes are
# wall-clock-paced e2e rows: their Playing-boundary assertion holds on
# an idle gate runner but flakes under a mutation shard's 8-way load
# (audit run 44263998011: 2 of 8 shard baselines died on
# ivf_av1_family_lane racing to end-of-media - 1051 tests cancelled,
# zero mutants tested), and av1_lanes_decode_the_full_stream is the third
# sibling: an unmutated-baseline row needing 85s+ of real AV1 decode
# under 4-way shard load (run 44771219869 shard 4: 1046/1047 baseline
# tests passed in 4.3s, this one was SIGTERM'd at the 90s cap and the
# shard failed in 3 minutes with zero mutants tested). They still gate
# every CI push; mutation runs just don't re-prove them per-mutant.
# Excluded by exact full nextest test name (unit test keeps its module
# path, integration tests are bare).
MUTANTS_TEST_FILTER='not(test(=ivf_av1_family_lane) | test(=ivf_vp9_family_lane) | test(=containers::ivf::tests::av1_lanes_decode_the_full_stream))'

cmd="${1:-list}"
shift || true

case "$cmd" in
  list)
    head1 "mutant census (no build)"
    cargo mutants --list --workspace \
      --exclude-re "$EXCLUDE_RE" \
      2>/dev/null | tee "$OUT/mutants/list.txt" | tail -5
    total=$(grep -c ':' "$OUT/mutants/list.txt" 2>/dev/null || echo 0)
    say ""
    say "total mutants: $total"
    say "per crate:"
    grep ':' "$OUT/mutants/list.txt" 2>/dev/null | cut -d: -f1 | sed 's#.*/src/##' | cut -d/ -f1 | sort | uniq -c | sort -rn | head -40
    ;;
  crate)
    pkg="${1:?crate name required}"
    head1 "mutation run: $pkg (timeout ${TIMEOUT}s, jobs $JOBS)"
    mkdir -p "$OUT/mutants/$pkg"
    cargo mutants -p "$pkg" \
      --test-tool nextest \
      --jobs "$JOBS" --timeout "$TIMEOUT" \
      --exclude-re "$EXCLUDE_RE" \
      --json --output "$OUT/mutants/$pkg/outcomes.json" \
      2>&1 | tee "$OUT/mutants/$pkg/run.log" | tail -40
    ;;
  diff)
    if [ ! -d .git ]; then
      not_run "cargo-mutants --in-diff" "no .git in this working copy (blocker B1)"
      say "run this in the real clone:"
      say "  cargo mutants --in-diff <(git diff origin/main...) --test-tool nextest --timeout 60"
      exit 0
    fi
    base="${1:-origin/main}"
    head1 "mutation run: --in-diff against $base"
    cargo mutants --in-diff <(git diff "$base"...) \
      --test-tool nextest --jobs "$JOBS" --timeout "$TIMEOUT" \
      --exclude-re "$EXCLUDE_RE" \
      2>&1 | tee "$OUT/mutants/in-diff.log" | tail -40
    ;;
  full)
    # Per-shard output so a sharded matrix (CI) or a sequential local run
    # never overwrites another shard's evidence.
    #
    # Shard remap: the frozen workflow matrix dispatches 1..8, but
    # cargo-mutants shards are 0-based (k must be < n) - as-is, shard
    # 8/8 died at 'invalid value' and slice 0 was NEVER RUN. Map the
    # workflow's 1-based N onto cargo-mutants' 0-based k so all eight
    # slices run exactly once.
    shard="all"
    prev=""
    for a in "$@"; do
      [ "$prev" = "--shard" ] && shard="${a%%/*}"
      prev="$a"
    done
    ARGS=()
    if [ "$shard" != "all" ] && [ "$shard" -ge 1 ] 2>/dev/null; then
      n=""
      prev=""
      for a in "$@"; do
        [ "$prev" = "--shard" ] && n="${a##*/}"
        prev="$a"
      done
      ARGS=(--shard "$((shard - 1))/$n")
      for a in "$@"; do
        case "$a" in --shard|*/$n) ;; *) ARGS+=("$a") ;; esac
      done
      say "shard remap: workflow 1-based $shard/$n -> cargo-mutants $((shard - 1))/$n"
      shard="$((shard - 1))"
      set -- "${ARGS[@]}"
    fi
    head1 "full workspace mutation run (shard $shard, budget ${BUDGET_MIN}m, baseline cap ${TIMEOUT}s) ${*:-}"
    # NOTE: cargo-mutants 27.x rejects --timeout together with
    # --timeout-multiplier (mutually exclusive strategies - absolute
    # cap vs baseline-relative). The absolute cap is the deterministic
    # choice across shards and runners; the 3x multiplier was a
    # leftover from the run-36 repair and killed all 8 shards at
    # argument parsing (audit run 44245799715: zero mutants tested).
    timeout "${BUDGET_MIN}m" cargo mutants --workspace --test-tool nextest \
      --jobs "$JOBS" --timeout "$TIMEOUT" \
      --exclude-re "$EXCLUDE_RE" "$@" \
      --output "$OUT/mutants/full-shard-$shard" \
      -- -E "$MUTANTS_TEST_FILTER" \
      2>&1 | tee "$OUT/mutants/full-shard-$shard.log"
    # NOTE: no `| tail -40` on the stream - tail cannot emit a line until its
    # input ENDS, so while a shard is running the step log shows nothing, and
    # when the RUNNER dies (SIGTERM, runs 62/71/73/75) tail is killed before
    # it ever flushes: we lost the mutant-level progress AND the workspace
    # log (the artifact upload step never runs on a dead runner either). The
    # tee'd file still captures everything for the artifact; the step log now
    # streams the same lines live, so a mid-run death names the exact mutant
    # being tested when the VM went down (four rounds flew blind on this).
    rc=${PIPESTATUS[0]}
    # 124 = the budget ended the run: partial outcomes are the evidence
    # (the score reports mutants actually tested), never a failure.
    # Any other non-zero - including 'no mutants were tested' baseline
    # failures - FAILS the shard (the run-36 shape: five shards green
    # with zero mutants tested, because the 60s default timed out the
    # baseline and the plumbing swallowed the error).
    if [ "$rc" -eq 124 ]; then
      say ""
      say "mutation budget exhausted after ${BUDGET_MIN}m - outcomes.json holds the partial, honestly-labeled results"
    elif [ "$rc" -ne 0 ]; then
      say ""
      say "cargo-mutants FAILED (exit $rc) - see $OUT/mutants/full-shard-$shard.log"
      exit "$rc"
    fi
    ;;
  *)
    say "usage: 12_mutants.sh {list|crate <name>|diff [base]|full [--shard i/N]}"
    exit 2
    ;;
esac

head1 "how to read this"
cat <<'TXT'
caught   = a test noticed the behaviour change  -> the test is real
MISSED   = no test noticed                      -> fake test OR dead code
timeout  = the mutant hung                      -> finding: unbounded loop
unviable = did not compile                      -> neutral

Every MISSED mutant is a defect in the test suite, and the line it points at
is a line of production code with no behavioural constraint.
TXT
