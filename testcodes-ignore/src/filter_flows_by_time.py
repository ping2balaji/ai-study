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
    --start 2025-09-17T18:50:00Z --end 2025-09-17T19:00:00Z \
    [--mode contained|overlap] [--tshark "C:\\Program Files\\Wireshark\\tshark.exe"] \
    [--out path/to/output.json] [--debug] [--showtime] [--showframenum]

Output:
- Writes a JSON object to a file named 'session-flows-<YYYYMMDD-HHMMSS>-filtered.json' next to
  the input flows JSON (unless --out is provided) with the following shape:

  {
    "total_flows": <int>,
    "csv_header": "frame.number,frame.time_epoch,...,_ws.col.Info",
    "flows": [
      {
        "flow_no": <int starting at 1>,
        "enb_ue_s1ap_id": <int|null>,
        "mme_ue_s1ap_id": <int|null>,
        // start_time and end_time appear only when --showtime is provided
        // "start_time": "YYYY-MM-DDTHH:MM:SS.mmmZ" | null,
        // "end_time": "YYYY-MM-DDTHH:MM:SS.mmmZ" | null,
        // frames appear only when --showframenum is provided
        // "frames": [<int>, ...],
        "pkt_summary_csv": ["<row>", ...]
      },
      ...
    ]
  }
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
import shlex
from typing import Dict, List, Optional, Tuple


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


TSHARK_SUMMARY_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "sctp.srcport",
    "sctp.dstport",
    "s1ap.RRC_Establishment_Cause",
    "s1ap.ENB_UE_S1AP_ID",
    "s1ap.MME_UE_S1AP_ID",
    "s1ap.radioNetwork",
    "e212.tai.mcc",
    "e212.tai.mnc",
    "s1ap.tAC",
    "s1ap.CellIdentity",
    "_ws.col.Info",
]


def tshark_csv_for_frames(tshark: str, pcap: str, frames: List[int], *, debug: bool = False) -> Tuple[Optional[str], List[str]]:
    """Return (header_line, CSV data lines) for frames from pcap using tshark.

    For very large frame lists, runs multiple tshark calls and concatenates results
    while keeping only the first header.
    """
    if not frames:
        return None, []

    lines_accum: List[str] = []
    header_line: Optional[str] = None

    # Chunk by command length to be safe on Windows command line limits
    chunk: List[int] = []
    current_len = 0
    max_chars = 6000  # conservative within Windows cmd length (~8k)

    def format_cmd_for_log(cmd: List[str]) -> str:
        # Render command similar to cross-platform shell usage, emphasizing -E values with double quotes
        out: List[str] = []
        i = 0
        while i < len(cmd):
            arg = str(cmd[i])
            if arg == "-E" and i + 1 < len(cmd):
                val = str(cmd[i + 1])
                out.append("-E")
                out.append(f'"{val}"')
                i += 2
                continue
            # Quote arguments containing spaces or braces for readability
            if any(ch in arg for ch in [' ', '{', '}', ',']):
                out.append(f'"{arg}"')
            else:
                out.append(arg)
            i += 1
        return " ".join(out)

    def run_chunk(frames_chunk: List[int]) -> None:
        # Use outer-scope header_line to track first header capture
        nonlocal header_line
        if not frames_chunk:
            return
        frame_list = ",".join(str(int(n)) for n in frames_chunk)
        display_filter = f"frame.number in {{{frame_list}}}"
        cmd = [
            tshark,
            "-r",
            pcap,
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-E",
            "header=y",
            "-E",
            "separator=,",
            "-E",
            "quote=d",
            "-E",
            "occurrence=f",
        ]
        for f in TSHARK_SUMMARY_FIELDS:
            cmd += ["-e", f]
        if debug:
            cmd_str = format_cmd_for_log(cmd)
            print(f"[DEBUG] Running tshark for {len(frames_chunk)} frames: {cmd_str}", file=sys.stderr)
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
            print(f"tshark summary failed: {err}", file=sys.stderr)
            return
        chunk_lines = proc.stdout.splitlines()
        if not chunk_lines:
            return
        if header_line is None:
            header_line = chunk_lines[0]
        # Always drop the header from each chunk
        data_only = chunk_lines[1:] if len(chunk_lines) > 1 else []
        lines_accum.extend(data_only)

    for n in frames:
        s = str(int(n))
        # +2 for comma/spacing in list representation overhead
        if current_len + len(s) + 2 > max_chars and chunk:
            run_chunk(chunk)
            chunk = []
            current_len = 0
        chunk.append(int(n))
        current_len += len(s) + 1
    if chunk:
        run_chunk(chunk)

    return header_line, lines_accum


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
    ap.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug logs about filtering and tshark commands",
    )
    ap.add_argument(
        "--showtime",
        action="store_true",
        help="Include ISO UTC start_time/end_time in the output flows",
    )
    ap.add_argument(
        "--showframenum",
        action="store_true",
        help="Include frames[] array in each output flow",
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
    if args.debug:
        print(f"[DEBUG] Filtering flows: total={len(flows)} start={start} end={end} mode={args.mode}", file=sys.stderr)

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
    if args.debug:
        print(f"[DEBUG] Filtered flows kept: {len(filtered)}", file=sys.stderr)

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    # Place output next to the flows JSON by default
    default_out = os.path.join(
        os.path.dirname(os.path.abspath(args.flows)) or ".",
        f"session-flows-{ts}-filtered.json",
    )
    out_path = args.out or default_out

    # Enrich with numbering and per-session CSV summaries (requires tshark)
    if not have_tshark(args.tshark):
        print("tshark not found; required to build pkt_summary_csv", file=sys.stderr)
        return 2

    enriched: List[dict] = []
    csv_header_line: Optional[str] = None
    for idx, flow in enumerate(filtered, start=1):
        frames = flow.get("frames") or []
        if args.debug:
            enb = flow.get("enb_ue_s1ap_id")
            mme = flow.get("mme_ue_s1ap_id")
            st = flow.get("start_time")
            en = flow.get("end_time")
            print(f"[DEBUG] Creating flow #{idx} enb={enb} mme={mme} frames={len(frames)} start={st} end={en}", file=sys.stderr)
        header, csv_lines = tshark_csv_for_frames(args.tshark, args.pcap, frames, debug=args.debug)
        if csv_header_line is None and header:
            csv_header_line = header
        # Ensure flow_no is the first field, then original fields (except raw epoch times and optionally frames)
        new_flow: Dict[str, object] = {"flow_no": idx}
        excluded_keys = {"start_time", "end_time"}
        if not args.showframenum:
            excluded_keys.add("frames")
        for k, v in flow.items():
            if k not in excluded_keys:
                new_flow[k] = v
        # Optionally include ISO UTC times at the end
        if args.showtime:
            def iso_ms(v: Optional[float]) -> Optional[str]:
                if v is None:
                    return None
                dt = datetime.fromtimestamp(float(v), tz=timezone.utc)
                return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
            new_flow["start_time"] = iso_ms(flow.get("start_time"))
            new_flow["end_time"] = iso_ms(flow.get("end_time"))
        new_flow["pkt_summary_csv"] = csv_lines
        enriched.append(new_flow)

    # Fallback header if tshark produced none (empty flows): build from known fields
    if csv_header_line is None:
        csv_header_line = ",".join(TSHARK_SUMMARY_FIELDS)

    result_obj = {
        "total_flows": len(enriched),
        "csv_header": csv_header_line,
        "flows": enriched,
    }

    try:
        ensure_parent(out_path)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result_obj, f, indent=2)
        print(f"Wrote filtered flows JSON: {out_path}")
    except OSError as e:
        print(f"Failed to write JSON file '{out_path}': {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
