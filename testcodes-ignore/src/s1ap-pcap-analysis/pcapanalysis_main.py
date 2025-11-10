from __future__ import annotations

"""
Run the S1AP three-step toolchain (filter -> group -> export) in one go.

Instead of calling each helper manually, this wrapper wires up the outputs of
every stage to the next one and exposes the most common knobs as CLI options.
"""

import argparse
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Sequence


BASE_DIR = Path(__file__).resolve().parent
STEP1 = BASE_DIR / "pcap-filter-s1-pkts.py"
STEP2 = BASE_DIR / "group-all-s1flows-from-pcap.py"
STEP3 = BASE_DIR / "export-s1flows-to-json.py"


def default_step1_outputs(pcap: Path) -> tuple[Path, Path]:
    base = pcap.stem
    return pcap.with_name(f"{base}.s1ap-only.pcapng"), pcap.with_name(f"{base}.s1ap.csv")


def default_flows_path(csv_path: Path) -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return csv_path.with_name(f"session-flows-{ts}.json")


def default_export_path(flows_path: Path) -> Path:
    return flows_path.with_name(f"{flows_path.stem}-filtered.json")


def run(step: str, cmd: Sequence[str]) -> None:
    printable = " ".join(shlex.quote(part) for part in cmd)
    print(f"[pcapanalysis] {step}: {printable}")
    subprocess.run(cmd, check=True)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run the S1AP pcap pipeline end-to-end.")
    p.add_argument("pcap", help="Input capture (.pcap/.pcapng)")
    p.add_argument("--tshark", default="tshark", help="Path to tshark executable")

    # Step 1
    p.add_argument("--s1ap-out", help="Override for <input>.s1ap-only.pcapng")
    p.add_argument("--csv-out", help="Override for <input>.s1ap.csv")

    # Step 2
    p.add_argument("--flows-out", help="Destination JSON for grouped flows")
    p.add_argument("--flow-start", help="Only keep flows fully inside [start,end] during grouping")
    p.add_argument("--flow-end", help="Only keep flows fully inside [start,end] during grouping")

    # Step 3
    p.add_argument("--export-start", help="Export flows starting at/after this time (ISO or epoch)")
    p.add_argument("--export-end", help="Export flows ending at/before this time (ISO or epoch)")
    p.add_argument("--export-mode", choices=["contained", "overlap"], default="contained")
    p.add_argument("--export-out", help="Final filtered JSON path")
    p.add_argument("--failed-flows-only", action="store_true", help="Keep only flows with failure keywords")
    p.add_argument("--showtime", action="store_true", help="Include ISO timestamps in export")
    p.add_argument("--showframenum", action="store_true", help="Include raw frame lists in export")
    p.add_argument("--export-debug", action="store_true", help="Enable verbose logs from export stage")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    pcap = Path(args.pcap).expanduser().resolve()
    if not pcap.exists():
        parser.error(f"Input capture not found: {pcap}")

    s1ap_pcap, csv_path = default_step1_outputs(pcap)
    if args.s1ap_out:
        s1ap_pcap = Path(args.s1ap_out).expanduser()
    if args.csv_out:
        csv_path = Path(args.csv_out).expanduser()

    if (args.flow_start is None) ^ (args.flow_end is None):
        parser.error("Provide both --flow-start and --flow-end to trim during grouping.")

    flows_path = Path(args.flows_out).expanduser() if args.flows_out else default_flows_path(csv_path)

    if (args.export_start is None) ^ (args.export_end is None):
        parser.error("Provide both --export-start and --export-end to trim during export.")

    export_path = (
        Path(args.export_out).expanduser() if args.export_out else default_export_path(flows_path)
    )

    python_exec = sys.executable
    if not python_exec:
        parser.error("Cannot determine Python executable to run helper scripts.")

    # Step 1
    step1_cmd: List[str] = [
        python_exec,
        str(STEP1),
        str(pcap),
        "--tshark",
        args.tshark,
        "--s1ap-out",
        str(s1ap_pcap),
        "--csv-out",
        str(csv_path),
    ]

    # Step 2
    step2_cmd: List[str] = [
        python_exec,
        str(STEP2),
        "--csv",
        str(csv_path),
        "--pcap",
        str(s1ap_pcap),
        "--tshark",
        args.tshark,
        "--out",
        str(flows_path),
    ]
    if args.flow_start and args.flow_end:
        step2_cmd.extend(["--start", args.flow_start, "--end", args.flow_end])

    # Step 3
    step3_cmd: List[str] = [
        python_exec,
        str(STEP3),
        "--flows",
        str(flows_path),
        "--pcap",
        str(s1ap_pcap),
        "--tshark",
        args.tshark,
        "--mode",
        args.export_mode,
        "--out",
        str(export_path),
    ]
    if args.export_start and args.export_end:
        step3_cmd.extend(["--start", args.export_start, "--end", args.export_end])
    if args.failed_flows_only:
        step3_cmd.append("--failed-flows-only")
    if args.showtime:
        step3_cmd.append("--showtime")
    if args.showframenum:
        step3_cmd.append("--showframenum")
    if args.export_debug:
        step3_cmd.append("--debug")

    try:
        run("Step 1 (filter+CSV)", step1_cmd)
        run("Step 2 (group flows)", step2_cmd)
        run("Step 3 (export flows)", step3_cmd)
    except subprocess.CalledProcessError as exc:
        print(f"[pcapanalysis] {exc.cmd} failed with exit code {exc.returncode}", file=sys.stderr)
        return exc.returncode or 1

    print(
        "[pcapanalysis] Done.\n"
        f"  S1AP pcap : {s1ap_pcap}\n"
        f"  S1AP CSV  : {csv_path}\n"
        f"  Flows JSON: {flows_path}\n"
        f"  Export JSON: {export_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
