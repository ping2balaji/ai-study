"""
Filter session flows by a time range.

Inputs:
- Flows JSON produced by group_s1ap_flows.py
- S1AP-only pcap (optional for filling missing times)
- Start and end time bounds

Filtering:
- Default mode "contained": keep flows where start_time >= START and end_time <= END.
- Mode "overlap": keep flows that intersect the interval [START, END].

Time formats accepted for --start/--end:
- Epoch seconds (e.g., 1695205007.123)
- ISO 8601 (e.g., 2025-09-20T11:37:04Z or 2025-09-20T11:37:04+00:00)
  Naive datetimes (without timezone) are treated as UTC.

Usage:
  python testcodes-ignore/src/filter_flows_by_time.py \
    --flows testcodes-ignore/sample-pcap/session-flows-20250920-113704.json \
    --pcap  testcodes-ignore/sample-pcap/sample-s1ap.s1ap-only.pcapng \
    --start 2025-09-20T11:30:00Z --end 2025-09-20T11:40:00Z \
    [--mode contained|overlap] [--tshark "C:\\Program Files\\Wireshark\\tshark.exe"] \
    [--out path/to/output.json]

Output:
- Writes a JSON array of filtered flows (same shape as input) to a file
  named 'session-flows-<YYYYMMDD-HHMMSS>-filtered.json' next to the input
  flows JSON (unless --out is provided).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional


def have_tshark(tshark_path: str) -> bool:
    return shutil.which(tshark_path) is not None


def parse_time(value: str) -> float:
    """Parse a time string into epoch seconds (float).

    Accepts:
    - numeric epoch seconds (int/float)
    - ISO 8601 like 'YYYY-MM-DDTHH:MM:SS[.fff][Z|+HH:MM]'
    Naive datetimes are treated as UTC.
    """
    s = str(value).strip()
    # Try numeric epoch first
    try:
        return float(s)
    except ValueError:
        pass
    # Normalize Z to +00:00 for fromisoformat
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid time format: '{value}'. Use epoch seconds or ISO 8601."
        )


def build_frame_time_map(tshark: str, pcap: str) -> Dict[int, float]:
    """Return mapping frame.number -> frame.time_epoch as float using tshark.

    Runs:
      tshark -r <pcap> -T fields -E header=y -e frame.number -e frame.time_epoch
    """
    cmd = [
        tshark,
        "-r",
        pcap,
        "-T",
        "fields",
        "-E",
        "header=y",
        "-e",
        "frame.number",
        "-e",
        "frame.time_epoch",
    ]
    try:
        proc = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.CalledProcessError as e:
        err = e.stderr.strip() or e.stdout.strip()
        raise RuntimeError(f"tshark failed exporting frame times (exit {e.returncode}): {err}")

    m: Dict[int, float] = {}
    lines = proc.stdout.splitlines()
    if not lines:
        return m
    header = lines[0].split(",")
    # Expect [frame.number, frame.time_epoch]
    for line in lines[1:]:
        parts = line.split(",")
        if len(parts) < 2:
            continue
        try:
            fno = int(parts[0].strip() or 0)
        except ValueError:
            continue
        try:
            t = float(parts[1].strip())
        except ValueError:
            continue
        if fno:
            m[fno] = t
    return m


def fill_missing_times(flows: List[dict], frame_time: Dict[int, float]) -> None:
    """Populate start_time/end_time for flows with missing values using frame_time map."""
    for flow in flows:
        st = flow.get("start_time")
        en = flow.get("end_time")
        if st is not None and en is not None:
            continue
        frames = flow.get("frames") or []
        times = [frame_time[n] for n in frames if n in frame_time]
        if not times:
            continue
        flow["start_time"] = min(times)
        flow["end_time"] = max(times)


def ensure_parent(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Filter session flows JSON by time range.")
    ap.add_argument("--flows", required=True, help="Input flows JSON (from group_s1ap_flows.py)")
    ap.add_argument("--pcap", required=True, help="S1AP-only pcap (used if times need filling)")
    ap.add_argument("--start", required=True, type=parse_time, help="Start time (epoch or ISO 8601)")
    ap.add_argument("--end", required=True, type=parse_time, help="End time (epoch or ISO 8601)")
    ap.add_argument("--mode", choices=["contained", "overlap"], default="contained", help="Filter mode")
    ap.add_argument("--tshark", default="tshark", help="Path to tshark (if times need filling)")
    ap.add_argument(
        "--out",
        help=(
            "Output JSON path (default: session-flows-<YYYYMMDD-HHMMSS>-filtered.json next to the flows JSON)"
        ),
    )
    args = ap.parse_args(argv)

    if not os.path.exists(args.flows):
        print(f"Flows JSON not found: {args.flows}", file=sys.stderr)
        return 2
    if not os.path.exists(args.pcap):
        print(f"PCAP not found: {args.pcap}", file=sys.stderr)
        return 2
    if args.start > args.end:
        print("Start time must be <= end time", file=sys.stderr)
        return 2

    with open(args.flows, "r", encoding="utf-8") as f:
        try:
            flows: List[dict] = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Invalid JSON in flows file: {e}", file=sys.stderr)
            return 2
    if not isinstance(flows, list):
        print("Flows JSON root must be an array", file=sys.stderr)
        return 2

    # Ensure all flows have start/end times. If not, try to fill using tshark + pcap
    need_fill = any((flow.get("start_time") is None or flow.get("end_time") is None) for flow in flows)
    if need_fill:
        if not have_tshark(args.tshark):
            print("tshark not found; cannot fill missing times from pcap", file=sys.stderr)
        else:
            try:
                frame_time = build_frame_time_map(args.tshark, args.pcap)
                fill_missing_times(flows, frame_time)
            except Exception as e:
                print(f"Failed to fill times from pcap: {e}", file=sys.stderr)

    start = float(args.start)
    end = float(args.end)

    def keep(flow: dict) -> bool:
        st = flow.get("start_time")
        en = flow.get("end_time")
        if st is None or en is None:
            return False
        st = float(st)
        en = float(en)
        if args.mode == "contained":
            return st >= start and en <= end
        else:  # overlap
            return not (en < start or st > end)

    filtered = [f for f in flows if keep(f)]

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    # Place output next to the flows JSON by default
    default_out = os.path.join(
        os.path.dirname(os.path.abspath(args.flows)) or ".",
        f"session-flows-{ts}-filtered.json",
    )
    out_path = args.out or default_out

    try:
        ensure_parent(out_path)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(filtered, f, indent=2)
        print(f"Wrote filtered flows JSON: {out_path}")
    except OSError as e:
        print(f"Failed to write JSON file '{out_path}': {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
