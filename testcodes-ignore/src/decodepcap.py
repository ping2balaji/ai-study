"""
Create an S1AP-only pcap and a CSV summary using TShark.

This wraps the exact commands you validated manually:
1) tshark -r <in> -Y s1ap -F pcapng -w <s1ap-only.pcapng>
2) tshark -r <s1ap-only.pcapng> -Y s1ap -T fields 
   -E "header=y" -E "separator=," -E "quote=d" -E "occurrence=f"
   -e frame.number -e frame.time_epoch -e ip.src -e ip.dst 
   -e ipv6.src -e ipv6.dst -e sctp.srcport -e sctp.dstport 
   -e s1ap.ENB_UE_S1AP_ID -e s1ap.MME_UE_S1AP_ID -e s1ap.procedureCode
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from typing import Optional, Tuple


def have_tshark(tshark_path: str) -> bool:
    return shutil.which(tshark_path) is not None


def ensure_parent(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)


def s1ap_only_pcap(in_pcap: str, out_pcap: str, tshark: str) -> None:
    cmd = [
        tshark,
        "-r",
        in_pcap,
        "-Y",
        "s1ap and !(s1ap.procedureCode == 10)",
        "-F",
        "pcapng",
        "-w",
        out_pcap,
    ]
    try:
        ensure_parent(out_pcap)
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        err = e.stderr.decode(errors="ignore").strip() if hasattr(e.stderr, "decode") else str(e)
        raise RuntimeError(f"tshark failed filtering S1AP (exit {e.returncode}): {err}")


def s1ap_csv(in_pcap: str, out_csv: str, tshark: str) -> None:
    # Using the exact options/fields that worked in your environment.
    cmd = [
        tshark,
        "-r",
        in_pcap,
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
        "-e",
        "frame.number",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "ipv6.src",
        "-e",
        "ipv6.dst",
        "-e",
        "sctp.srcport",
        "-e",
        "sctp.dstport",
        "-e",
        "s1ap.ENB_UE_S1AP_ID",
        "-e",
        "s1ap.MME_UE_S1AP_ID",
        "-e",
        "s1ap.procedureCode",
    ]
    try:
        ensure_parent(out_csv)
        with open(out_csv, "w", encoding="utf-8", newline="") as f:
            subprocess.run(cmd, check=True, stdout=f, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        err = e.stderr.decode(errors="ignore").strip() if hasattr(e.stderr, "decode") else str(e)
        raise RuntimeError(f"tshark failed exporting CSV (exit {e.returncode}): {err}")


def default_out_paths(in_pcap: str) -> Tuple[str, str]:
    base = os.path.splitext(os.path.basename(in_pcap))[0]
    dir_ = os.path.dirname(in_pcap) or "."
    s1ap_pcap = os.path.join(dir_, f"{base}.s1ap-only.pcapng")
    csv_out = os.path.join(dir_, f"{base}.s1ap.csv")
    return s1ap_pcap, csv_out


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Create S1AP-only pcap and CSV using tshark.")
    p.add_argument("pcap", help="Input pcap/pcapng path")
    p.add_argument("--tshark", default="tshark", help="Path to tshark executable")
    p.add_argument("--s1ap-out", help="Output S1AP-only pcapng path (default: <input>.s1ap-only.pcapng)")
    p.add_argument("--csv-out", help="Output CSV path (default: <input>.s1ap.csv)")
    args = p.parse_args(argv)
    # example: uv run python3 .\testcodes-ignore\test_decodepcap.py .\testcodes-ignore\s1ap-only-10k-pkts.pcapng

    if not os.path.exists(args.pcap):
        print(f"Input not found: {args.pcap}", file=sys.stderr)
        return 2
    if not have_tshark(args.tshark):
        print(f"tshark not found at '{args.tshark}'", file=sys.stderr)
        return 2

    s1ap_pcap_out, csv_out = default_out_paths(args.pcap)
    if args.s1ap_out:
        s1ap_pcap_out = args.s1ap_out
    if args.csv_out:
        csv_out = args.csv_out

    s1ap_only_pcap(args.pcap, s1ap_pcap_out, args.tshark)
    s1ap_csv(s1ap_pcap_out, csv_out, args.tshark)

    print(f"S1AP-only pcap: {s1ap_pcap_out}")
    print(f"S1AP CSV: {csv_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

