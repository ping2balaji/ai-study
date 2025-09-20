"""
Group S1AP frames (by frame.number) into UE sessions (flows) using the CSV
export you generated and the S1AP-only pcap for edge cases.

Flow key: (ENB_UE_S1AP_ID, MME_UE_S1AP_ID)

Rules:
- If both IDs present: assign to that flow.
- If only ENB ID present (e.g., Initial UE Message): keep pending by ENB and
  attach to the first flow discovered for that ENB when MME ID appears.
- If neither ID present (node-level msgs like MMEConfigurationTransfer/ErrorIndication): ignore.
- If IDs are missing but present inside UE-S1AP-IDs IE (e.g., UEContextReleaseCommand),
  fetch them per-frame from the pcap using tshark and then assign.

Usage:
  python testcodes-ignore/src/group_s1ap_flows.py \
    --csv testcodes-ignore/s1ap-only-10k-pkts.s1ap.csv \
    --pcap testcodes-ignore/s1ap-only-10k-pkts.s1ap-only.pcapng \
    [--tshark "C:\\Program Files\\Wireshark\\tshark.exe"]
    [--out path/to/output.json]

Output:
  Prints a JSON array to stdout and also writes it to a file named
  'session-flows-<YYYYMMDD-HHMMSS>.json' next to the CSV (unless --out is
  provided). Each element represents one flow with:
  - enb_ue_s1ap_id: integer ENB UE S1AP ID
  - mme_ue_s1ap_id: integer MME UE S1AP ID
  - start_time: earliest frame.time_epoch in the flow (float seconds)
  - end_time: latest frame.time_epoch in the flow (float seconds)
  - frames: sorted list of frame numbers in this flow
"""

from __future__ import annotations

import argparse
import csv
import os
import shutil
import subprocess
import sys
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Tuple
import json
from datetime import datetime


CSV_FIELDS = {
    "frame": "frame.number",
    "time": "frame.time_epoch",
    "enb": "s1ap.ENB_UE_S1AP_ID",
    "mme": "s1ap.MME_UE_S1AP_ID",
    "proc": "s1ap.procedureCode",
}


def _to_int(s: str) -> Optional[int]:
    if s is None:
        return None
    s = str(s).strip()
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        try:
            if s.lower().startswith("0x"):
                return int(s, 16)
        except ValueError:
            return None
    return None


def have_tshark(tshark_path: str) -> bool:
    return shutil.which(tshark_path) is not None


def get_available_fields(tshark: str) -> set:
    """Return set of available field abbreviations from tshark -G fields."""
    try:
        proc = subprocess.run(
            [tshark, "-G", "fields"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.CalledProcessError as e:
        err = e.stderr.strip() or e.stdout.strip()
        raise RuntimeError(f"tshark -G fields failed (exit {e.returncode}): {err}")
    fields: set = set()
    for line in proc.stdout.splitlines():
        # Expected format: F\t<abbrev>\t... ; be defensive
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] in ("F", "f"):
            fields.add(parts[1])
    return fields


def build_frame_id_map(tshark: str, pcap: str) -> Dict[int, Tuple[Optional[int], Optional[int]]]:
    """Run one tshark pass to collect ENB/MME IDs per frame, including nested IE IDs.

    Returns: { frame.number -> (enb_id, mme_id) } with ints or None.
    """
    available = get_available_fields(tshark)

    # Always include top-level IDs
    nested_enb = []
    nested_mme = []

    # Include any additional s1ap.*ENB_UE_S1AP_ID / *MME_UE_S1AP_ID fields if present
    for f in sorted(available):
        if not f.startswith("s1ap."):
            continue
        if f == "s1ap.ENB_UE_S1AP_ID" or f == "s1ap.MME_UE_S1AP_ID":
            continue
        if f.endswith("ENB_UE_S1AP_ID"):
            nested_enb.append(f)
        elif f.endswith("MME_UE_S1AP_ID"):
            nested_mme.append(f)

    extract_fields = [
        "frame.number",
        "s1ap.ENB_UE_S1AP_ID",
        "s1ap.MME_UE_S1AP_ID",
        *nested_enb,
        *nested_mme,
    ]

    cmd = [
        tshark,
        "-r",
        pcap,
        "-Y",
        "s1ap",
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
    for f in extract_fields:
        cmd += ["-e", f]

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
        raise RuntimeError(f"tshark failed building ID map (exit {e.returncode}): {err}")

    frame_map: Dict[int, Tuple[Optional[int], Optional[int]]] = {}
    reader = csv.DictReader(proc.stdout.splitlines())
    for row in reader:
        fno = _to_int(row.get("frame.number", ""))
        if fno is None:
            continue
        enb = _to_int(row.get("s1ap.ENB_UE_S1AP_ID", ""))
        mme = _to_int(row.get("s1ap.MME_UE_S1AP_ID", ""))
        if enb is None:
            for nf in nested_enb:
                enb = _to_int(row.get(nf, ""))
                if enb is not None:
                    break
        if mme is None:
            for nf in nested_mme:
                mme = _to_int(row.get(nf, ""))
                if mme is not None:
                    break
        frame_map[fno] = (enb, mme)
    return frame_map


def group_flows(
    rows: Iterable[Dict[str, str]], *, frame_ids: Dict[int, Tuple[Optional[int], Optional[int]]]
) -> Dict[Tuple[int, int], List[int]]:
    flows: Dict[Tuple[int, int], List[int]] = defaultdict(list)
    enb_pending: Dict[int, List[int]] = defaultdict(list)
    enb_to_pair: Dict[int, Tuple[int, int]] = {}

    for r in rows:
        frame = _to_int(r.get(CSV_FIELDS["frame"], ""))
        if frame is None:
            continue
        enb = _to_int(r.get(CSV_FIELDS["enb"], ""))
        mme = _to_int(r.get(CSV_FIELDS["mme"], ""))

        # If IDs missing, attempt to fill from the prebuilt per-frame map (covers nested IE case)
        if (enb is None or mme is None) and frame in frame_ids:
            e2, m2 = frame_ids.get(frame, (None, None))
            if enb is None:
                enb = e2
            if mme is None:
                mme = m2

        if enb is not None and mme is not None:
            key = (enb, mme)
            # Attach any pending frames for this ENB to this first observed pair
            if enb not in enb_to_pair:
                enb_to_pair[enb] = key
                if enb in enb_pending:
                    flows[key].extend(enb_pending.pop(enb))
            # If ENB already mapped to a pair, use that pair (handles later-only-enb frames)
            else:
                key = enb_to_pair[enb]
            flows[key].append(frame)
        elif enb is not None and mme is None:
            # Pending until we see a pair for this ENB
            if enb in enb_to_pair:
                flows[enb_to_pair[enb]].append(frame)
            else:
                enb_pending[enb].append(frame)
        else:
            # Neither ID -> ignore (node-level or unrelated)
            continue

    # Sort frames in each flow
    for key in flows:
        flows[key] = sorted(set(flows[key]))
    return flows


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Group S1AP frames into UE sessions (flows) by IDs.")
    ap.add_argument("--csv", required=True, help="CSV exported from tshark")
    ap.add_argument("--pcap", required=True, help="S1AP-only pcap used to recover nested IDs")
    ap.add_argument("--tshark", default="tshark", help="Path to tshark executable")
    ap.add_argument(
        "--out",
        help=(
            "Output JSON path (default: session-flows-<YYYYMMDD-HHMMSS>.json next to the CSV)"
        ),
    )
    args = ap.parse_args(argv)
    # example: uv run python3 .\src\group_s1ap_flows.py 
    # --csv .\testcodes-ignore\s1ap-only-10k-pkts.s1ap.csv 
    # --pcap .\testcodes-ignore\s1ap-only-10k-pkts.s1ap-only.pcapng
    
    if not os.path.exists(args.csv):
        print(f"CSV not found: {args.csv}", file=sys.stderr)
        return 2
    if not os.path.exists(args.pcap):
        print(f"PCAP not found: {args.pcap}", file=sys.stderr)
        return 2
    if not have_tshark(args.tshark):
        print(f"tshark not found at '{args.tshark}'", file=sys.stderr)
        return 2

    # Build a single-pass map of frame -> (enb, mme) including nested IE values
    frame_ids = build_frame_id_map(args.tshark, args.pcap)

    # Load CSV fully to capture frame times as well
    with open(args.csv, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    # Map frame -> time_epoch (float)
    frame_time: Dict[int, float] = {}
    for r in rows:
        fn = _to_int(r.get(CSV_FIELDS["frame"], ""))
        if fn is None:
            continue
        ts_raw = (r.get(CSV_FIELDS["time"], "") or "").strip()
        try:
            ts = float(ts_raw) if ts_raw else None
        except ValueError:
            ts = None
        if ts is not None:
            frame_time[fn] = ts

    flows = group_flows(rows, frame_ids=frame_ids)

    # Build JSON objects per flow
    result: List[Dict] = []
    for (enb, mme), frames in flows.items():
        times = [frame_time.get(n) for n in frames if n in frame_time]
        start = min(times) if times else None
        end = max(times) if times else None
        result.append({
            "enb_ue_s1ap_id": enb,
            "mme_ue_s1ap_id": mme,
            "start_time": start,
            "end_time": end,
            "frames": frames,
        })

    # Order by start time then by first frame
    result.sort(key=lambda x: (x["start_time"] if x["start_time"] is not None else float("inf"), x["frames"][0] if x["frames"] else float("inf")))

    # Determine output JSON path
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    default_out = os.path.join(os.path.dirname(os.path.abspath(args.csv)) or ".", f"session-flows-{ts}.json")
    out_path = args.out or default_out
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        # Log to stderr to avoid corrupting stdout JSON
        print(f"Wrote flows JSON: {out_path}", file=sys.stderr)
    except OSError as e:
        print(f"Failed to write JSON file '{out_path}': {e}", file=sys.stderr)

    # Still print JSON to stdout for piping/consumers
    print(json.dumps(result, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
