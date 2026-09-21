#!/usr/bin/env python3
"""Rule replay tester CLI (R3.5) — run rule fixtures through the real engine.

Usage:
  python scripts/rule_replay.py                    # all tests/replays/*.json
  python scripts/rule_replay.py path/fixture.json  # specific fixtures
  python scripts/rule_replay.py --list             # show bundled fixtures
  python scripts/rule_replay.py --quiet fixture    # verdict only, no timeline

Prints the verdict timeline (frame, decision, rule, why) and the golden-replay
verdict; exits 1 when any expect entry fails (CI-friendly). The same core
backs POST /api/rules/test and the pytest runner — no shadow logic here.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packages.ai.replay import EPOCH, run_replay


def _print_timeline(timeline):
    for entry in timeline:
        extra = {k: v for k, v in entry.items()
                 if k not in ("frame", "t", "rule_id", "rule_type", "track_id", "decision")}
        t = (entry["t"] - EPOCH).total_seconds()
        print(f"  f{entry['frame']:>4} t={t:<6g} {entry['decision']:<19} "
              f"{entry['rule_type']}/{entry['rule_id']} [{entry['track_id']}] {extra or ''}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Rule replay tester (R3.5)")
    ap.add_argument("fixtures", nargs="*",
                    help="fixture JSON paths (default: tests/replays/*.json)")
    ap.add_argument("--list", action="store_true", help="list bundled fixtures and exit")
    ap.add_argument("--quiet", action="store_true", help="verdict only, no timeline")
    args = ap.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    if args.list:
        for p in sorted((root / "tests" / "replays").glob("*.json")):
            fx = json.loads(p.read_text())
            print(f"{p.name}: {fx.get('description', '')}")
        return 0
    paths = [Path(p) for p in args.fixtures]
    if not paths:
        paths = sorted((root / "tests" / "replays").glob("*.json"))
    if not paths:
        print("no fixtures found", file=sys.stderr)
        return 1
    failures = 0
    for path in paths:
        fx = json.loads(path.read_text())
        result = run_replay(fx["camera_id"], fx["rules"], fx["frames"],
                            expect=fx.get("expect"))
        summary = result["summary"]
        print(f"== {path.name}: frames={result['frames']} "
              f"trace={len(result['timeline'])} events={summary['total_events']} "
              f"pass={result.get('pass')}")
        if not args.quiet:
            _print_timeline(result["timeline"])
        for err in result.get("expect_errors", []):
            print(f"  FAIL {err}")
            failures += 1
        if result.get("truncated"):
            print("  WARN timeline truncated at cap")
    print(f"\n{len(paths)} fixture(s), {failures} expect failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
