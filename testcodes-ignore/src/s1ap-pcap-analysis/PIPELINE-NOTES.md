# S1AP Pipeline Cheatsheet

This repo’s S1AP tooling is a three-step assembly line. Keep this handy when jumping into a new session so you know which script does what, the expected inputs/outputs, and the usual command lines.

## 1. `pcap-filter-s1-pkts.py`
- **Purpose:** Split an arbitrary capture into S1AP-only traffic and produce a CSV summary of the same frames. Filters out `s1ap.procedureCode == 10` (MME status transfer) to keep files lean.
- **Inputs:** Any `.pcap/.pcapng` plus a `tshark` binary.
- **Outputs (defaults live next to the input):**
  - `<input>.s1ap-only.pcapng` – the filtered capture.
  - `<input>.s1ap.csv` – CSV columns include `frame.number`, `frame.time_epoch`, IPv4/IPv6 endpoints, SCTP ports, S1AP IDs, and `s1ap.procedureCode`.
- **Key options:** `--s1ap-out`, `--csv-out`, `--tshark`.
- **Example:**  
  ```powershell
  python testcodes-ignore/src/s1ap-pcap-analysis/pcap-filter-s1-pkts.py `
    testcodes-ignore/src/s1ap-pcap-analysis/sample-pcap/stanford-1.pcapng `
    --tshark "C:\Program Files\Wireshark\tshark.exe"
  ```

## 2. `group-all-s1flows-from-pcap.py`
- **Purpose:** Combine the per-frame CSV with the S1AP-only pcap to reconstruct UE “flows” keyed by `(ENB_UE_S1AP_ID, MME_UE_S1AP_ID)`.
- **How it works:** Loads the CSV for base fields, then runs a `tshark -G fields` pass plus a targeted pcap scan to recover nested UE IDs (covers messages where IDs hide in UE-S1AP-IDs IE). Frames without IDs are ignored; ENB-only frames are queued until a matching MME ID appears.
- **Outputs:** `session-flows-<timestamp>.json` (unless `--out` is set) containing `total_flows` and a `flows` array with IDs, `start_time`, `end_time`, and `frames[]`.
- **Filters:** Optional `--start/--end` (must be provided together) trims flows entirely inside a window.
- **Example:**  
  ```powershell
  python testcodes-ignore/src/s1ap-pcap-analysis/group-all-s1flows-from-pcap.py `
    --csv  testcodes-ignore/src/s1ap-pcap-analysis/sample-pcap/stanford-1.s1ap.csv `
    --pcap testcodes-ignore/src/s1ap-pcap-analysis/sample-pcap/stanford-1.s1ap-only.pcapng `
    --tshark "C:\Program Files\Wireshark\tshark.exe"
  ```

## 3. `export-s1flows-to-json.py`
- **Purpose:** Take the grouped flows JSON and emit a presentation-friendly JSON that can include timestamps, frame numbers, and full per-frame `_ws.col.Info` summaries.
- **Features:**
  - Optional time filtering via `--start/--end` (contained/overlap modes).
  - `--failed-flows-only` keeps flows whose packet summaries mention failure keywords (e.g., “radio-connection-with-ue-lost”, “rejected”, “abort”).
  - `--showframenum` adds the raw `frames[]`; `--showtime` adds ISO UTC strings.
  - Always rebuilds `pkt_summary_csv` by running `tshark` on the union of frame numbers so every flow carries its packet rows plus `csv_header`.
- **Outputs:** `session-flows-<timestamp>-filtered.json` unless `--out` is supplied.
- **Example:**  
  ```powershell
  python testcodes-ignore/src/s1ap-pcap-analysis/export-s1flows-to-json.py `
    --flows testcodes-ignore/src/s1ap-pcap-analysis/sample-pcap/session-flows-20251106-174154.json `
    --pcap  testcodes-ignore/src/s1ap-pcap-analysis/sample-pcap/stanford-1.s1ap-only.pcapng `
    --failed-flows-only --showtime --showframenum
  ```

## Workflow Tips
1. **Always run step 1 first** on the raw capture to get the `.s1ap-only.pcapng` and `.s1ap.csv`.
2. **Feed both outputs into step 2** to build/refresh `session-flows-*.json`.
3. **Use step 3 for analysis exports**—time slicing, failure hunting, frame summaries, etc.
4. Keep `tshark` accessible (PATH or `--tshark`) for every step; each script shells out multiple times.
5. For scheduled/automated use, apply the same naming scheme shown above so downstream scripts can auto-discover the companion files.
