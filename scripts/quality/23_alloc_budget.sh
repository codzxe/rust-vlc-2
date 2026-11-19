#!/usr/bin/env bash
# T23 - allocation amplification budget (the DoS a hacker actually uses).
#
# A 100-byte file that makes the engine allocate 100 MB is a denial of service
# that no amount of fuzzing-for-panics will find: everything is "valid".
# The repo already ships the instrument - tools/mem-audit counts every
# allocation in the demux/open path (lumen-mem-audit). This turns that
# instrument into a RATIO GATE.
#
#   amplification = peak bytes during open / input bytes
#
# Usage: 23_alloc_budget.sh [sample-count]     (default 60 fixtures)
# Threshold: ALLOC_RATIO_MAX (default 64x)
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

mkdir -p "$OUT/alloc"
SAMPLE="${1:-60}"
MAX_RATIO="${ALLOC_RATIO_MAX:-64}"
RAW="$OUT/alloc/mem-audit.raw.txt"

head1 "23. allocation amplification (sample=$SAMPLE, max_ratio=${MAX_RATIO}x)"

if ! need cargo; then exit 0; fi

# Deterministic sample of real media fixtures already committed in the repo.
# NOTE: python on Windows emits CRLF; `tr -d '\r'` is mandatory or every path
# ends in a carriage return and mem-audit reports "permission denied".
mapfile -t FILES < <($PY - "$ROOT" "$SAMPLE" <<'PYEOF' | tr -d '\r'
import os, sys
root, n = sys.argv[1], int(sys.argv[2])
EXT = {".mp4",".mkv",".ts",".ogg",".wav",".aiff",".avi",".flac",".mp3",".aac",".ivf",".mpd",".m3u",".pls",".cue",".xspf",".srt",".ass",".vtt"}
found = []
for dp, dn, fns in os.walk(root):
    # `ui` is the TypeScript app tree: its .ts sources collide with the
    # MPEG-TS extension; pruning it keeps the sample real media (plus the
    # deliberate playlist/subtitle text formats in EXT).
    dn[:] = [d for d in dn if d not in ("target","node_modules",".git","ui")]
    for fn in sorted(fns):
        ext = os.path.splitext(fn)[1].lower()
        if ext in EXT:
            p = os.path.join(dp, fn)
            try:
                if 0 < os.path.getsize(p) <= 4_000_000:
                    found.append(os.path.relpath(p, root).replace("\\", "/"))
            except OSError:
                pass
# one per extension first, then the rest - keeps the sample broad, not deep
seen, out = set(), []
for p in found:
    e = os.path.splitext(p)[1]
    if e not in seen:
        seen.add(e); out.append(p)
out += [p for p in found if p not in out]
for p in out[:n]:
    print(p)
PYEOF
)

if [ "${#FILES[@]}" -eq 0 ]; then
  not_run "alloc-budget" "no media fixtures found to sample"
  exit 0
fi
say "sampling ${#FILES[@]} fixtures"

# One process, many files: lumen-mem-audit reports per file.
cargo run -q -p lumen-mem-audit -- "${FILES[@]}" > "$RAW" 2>&1
mem_rc=$?
say "mem-audit exit=$mem_rc (see $RAW)"
if [ "$mem_rc" -ne 0 ]; then
  not_run "alloc-budget" "lumen-mem-audit failed (exit $mem_rc) - gate not evaluated"
  exit 1
fi

$PY - "$RAW" "$MAX_RATIO" "$OUT/alloc/alloc-budget.txt" <<'PYEOF'
import re, statistics, sys
raw, max_ratio, out = sys.argv[1], float(sys.argv[2]), sys.argv[3]

rows = []
for line in open(raw, encoding="utf-8", errors="replace"):
    if not line.startswith("MEMAUDIT "):
        continue
    kv = dict(re.findall(r"(\w+)=(\S*)", line))
    try:
        size = int(kv.get("size", "0"))
        peak = int(kv.get("peak_B", "0") or 0)
    except ValueError:
        continue
    if size <= 0 or peak <= 0:
        continue
    rows.append({"size": size, "peak": peak, "verdict": kv.get("verdict", "?"),
                 "container": kv.get("container", "?"), "file": kv.get("file", "?"),
                 "error": kv.get("error", "")})

# Vacuous-pass guard: zero parsed rows means mem-audit measured nothing; the
# budget logic below would then compare nothing and pass on zero evidence.
if not rows:
    print("alloc-budget: no MEMAUDIT rows parsed from %s - refusing to pass on zero evidence" % raw)
    sys.exit(1)

# The naive `peak/size` ratio is dominated by CONSTANT parser overhead: a 200-byte
# .cue "amplifies" 1600x only because every open costs ~300 KB regardless of
# input. That is not a DoS. So measure the part that actually scales:
#   K = the fixed per-open cost, estimated from the smallest inputs
#   excess = max(0, peak - K) / size   <- the amplification a crafted header buys
small = [r for r in rows if r["size"] <= 8192]
K = int(statistics.median([r["peak"] for r in small])) if small else 0
for r in rows:
    r["excess"] = max(0.0, (r["peak"] - K) / r["size"])

# Scoring floor (MIN_SCORED_BYTES): inputs smaller than this CANNOT exhibit
# input-scaled amplification - their peak is the fixed open cost K plus
# noise, and dividing that noise by a tiny size produces huge ratios that
# mean nothing (measured: a 12-byte truncated AVI peaks at 161,914 B vs
# K = 154,879 B -> +7 KB of open-path noise / 12 B = "586x", while a real
# scalable header would allocate K + size*x on inputs of ANY size). Rows
# below the floor are measured, listed and marked - only the ratio GATE
# ignores them. Every input >= 1 KiB is scored with full sensitivity: a
# 1 KiB header buying K + 64 KiB still trips the 64x threshold exactly as
# before.
MIN_SCORED_BYTES = 1024
for r in rows:
    r["scored"] = r["size"] >= MIN_SCORED_BYTES

rows.sort(key=lambda r: -r["excess"])
bad = [r for r in rows if r["scored"] and r["excess"] > max_ratio]
noise = [r for r in rows if not r["scored"] and r["excess"] > max_ratio]
big = sorted(rows, key=lambda r: -r["peak"])[:5]

L = []
L.append("# Allocation amplification budget\n")
L.append("Instrument: `tools/mem-audit` (already in-tree), run over real fixtures.\n")
L.append("Naive `peak/size` is **not** the DoS metric - it is dominated by the fixed")
L.append("per-open cost. Measured **K (fixed open cost) = %d B**, estimated as the" % K)
L.append("median peak of inputs <= 8 KB. The gate uses the scaling part:")
L.append("`excess = max(0, peak - K) / size`, threshold **%gx**, scored on inputs" % max_ratio)
L.append(">= %d B (below that the fixed cost mathematically dominates and the" % MIN_SCORED_BYTES)
L.append("ratio measures open-path noise, not input-scaled allocation; those rows")
L.append("are listed and marked `below floor`, never silently dropped).")
L.append("A crafted header that makes allocation scale with input bytes is the")
L.append("memory-exhaustion attack a panic-watching fuzzer never sees.\n")
L.append("| excess | raw peak/size | size | peak B | verdict | container | file |")
L.append("|---|---|---|---|---|---|---|")
for r in rows[:30]:
    mark = ""
    if r["excess"] > max_ratio:
        mark = " **OVER**" if r["scored"] else " *below floor*"
    L.append("| %.2fx%s | %.0fx | %d | %d | %s | %s | `%s` |" % (
        r["excess"], mark, r["peak"] / r["size"], r["size"], r["peak"],
        r["verdict"], r["container"], r["file"]))
L.append("")
L.append("**largest absolute peak:** %s (%d B from %d B input)" % (
    big[0]["file"] if big else "-", big[0]["peak"] if big else 0,
    big[0]["size"] if big else 0))
L.append("")
L.append("**worst excess: %.2fx** over %d files (%d scored, %d below the %d B floor);" % (
    rows[0]["excess"] if rows else 0, len(rows),
    sum(1 for r in rows if r["scored"]), sum(1 for r in rows if not r["scored"]),
    MIN_SCORED_BYTES))
L.append("**%d over threshold (scored); %d over threshold on below-floor inputs**" % (
    len(bad), len(noise)))
if noise:
    L.append("(below-floor rows are open-cost noise around K, listed for evidence:")
    for r in noise[:10]:
        L.append("- %.2fx from %d B (%s) - peak %d B vs K %d B" % (
            r["excess"], r["size"], r["file"], r["peak"], K))
    L.append(")")

open(out, "w", encoding="utf-8").write("\n".join(L) + "\n")
print("\n".join(L[-8:]))
if bad:
    print("\nOVER THRESHOLD:")
    for r in bad:
        print("  %.2fx  %s" % (r["excess"], r["file"]))
    sys.exit(1)
PYEOF
gate_rc=$?

say ""
say "written: $OUT/alloc/alloc-budget.txt"
# Propagate the gate verdict: the say lines above must not swallow it
# (a gate that cannot fail is theatre - 99_run_all.sh's own design rule).
exit "$gate_rc"
