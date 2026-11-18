#!/usr/bin/env python3
"""known_upstream.py — the fuzz campaign's third-party panic registry.

libfuzzer-sys installs a panic hook that aborts BEFORE unwinding, so
no in-process containment (catch_unwind at our decoder boundaries)
can keep an exact-pinned engine's panic from killing a campaign
target. This classifier lets the campaign close a crashing target as
known-upstream IFF the crash is a registered third-party panic site.

The honesty contract (enforced here, not by convention):
  * the panic's file path must live under .cargo/registry (a
    dependency) — workspace code can never be allowlisted;
  * crate name, version, file:line and the panic message must match
    a registry entry EXACTLY;
  * a crash with no panic message in the log (sanitizer findings:
    LSan leaks, OOM, timeouts) never qualifies.

Usage:
  known_upstream.py --target NAME --log PATH --registry PATH   # classify
  known_upstream.py --list [--registry PATH]                   # list entries
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# The default registry lives beside the campaign it governs.
DEFAULT_REGISTRY = Path(__file__).resolve().parents[2] / "fuzz" / "known-upstream.json"

# "panicked at <path>:<line>:<col>:" possibly wrapped over lines.
PANIC_RE = re.compile(
    r"panicked at\s+(\S+?):(\d+):\d+", re.MULTILINE
)
# Panic messages we understand well enough to match exactly.
MESSAGE_RE = re.compile(
    r"panicked at\s+\S+?:\d+:\d+:\s*\n?\s*([^\n]+)", re.MULTILINE
)


def load_registry(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        doc = json.load(fh)
    entries = doc.get("entries", [])
    if not isinstance(entries, list):
        raise SystemExit(f"registry {path}: 'entries' is not a list")
    return entries


def parse_panic(log_text: str) -> tuple[str, str] | None:
    """Return (panic_site "path:line", panic_message) or None."""
    site = PANIC_RE.search(log_text)
    if not site:
        return None
    msg = MESSAGE_RE.search(log_text)
    message = msg.group(1).strip() if msg else ""
    return f"{site.group(1)}:{site.group(2)}", message


def location_matches(location: str, panic_site: str) -> bool:
    """Match a registry location against a panic site.

    Two shapes:
      "src/foo.rs:123"      — exact line;
      "src/foo.rs:123-145"  — inclusive line range (an arithmetic
                              cluster inside one third-party block:
                              registering every `- 1` line separately
                              is whack-a-mole, and each site in the
                              cluster shares one analysis).
    """
    if ":" not in location:
        return False
    file_part, line_part = location.rsplit(":", 1)
    site_file, _, site_line = panic_site.rpartition(":")
    if not site_file.endswith(file_part):
        return False
    if "-" in line_part:
        try:
            lo, hi = (int(x) for x in line_part.split("-", 1))
            return lo <= int(site_line) <= hi
        except ValueError:
            return False
    return site_line == line_part


def classify(target: str, log_path: Path, entries: list[dict]) -> tuple[bool, str]:
    """Match the log's panic against the registry for `target`."""
    try:
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False, "unreadable log"

    parsed = parse_panic(log_text)
    if parsed is None:
        return False, "no panic message in log (sanitizer/infra finding)"
    panic_path, message = parsed

    # Hard rule 1: dependency code only, never workspace code.
    if "/.cargo/registry/" not in panic_path:
        return False, f"panic outside .cargo/registry: {panic_path}"

    for entry in entries:
        if entry.get("target") != target:
            continue
        crate_dir = f"{entry['crate']}-{entry['version']}"
        if crate_dir not in panic_path:
            continue
        if not location_matches(entry["location"], panic_path):
            continue
        # Exact message match (the registry stores the full line).
        if entry["panic_message"] not in message:
            continue
        return True, (
            f"{crate_dir} {entry['location']} — {entry['panic_message']} "
            f"[{entry.get('class', '?')}]"
        )

    return False, f"unregistered panic site: {panic_path}: {message}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target")
    ap.add_argument("--log", type=Path)
    ap.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    entries = load_registry(args.registry)

    if args.list:
        for e in entries:
            print(
                f"  {e['target']}: {e['crate']}-{e['version']} "
                f"{e['location']} — {e['panic_message']} [{e['class']}]"
            )
        return 0

    if not args.target or not args.log:
        ap.error("--target and --log are required (or --list)")

    known, detail = classify(args.target, args.log, entries)
    print(
        f"known-upstream: {args.target}: {'YES' if known else 'NO'} — {detail}",
        file=sys.stderr,
    )
    return 0 if known else 1


if __name__ == "__main__":
    raise SystemExit(main())
