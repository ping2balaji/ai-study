cd /data/n8n-data/

python3 pcap-filter-s1-pkts.py oneflow.pcapng

python3 group-all-s1flows-from-pcap.py --csv oneflow.s1ap.csv --pcap oneflow.s1ap-only.pcapng

python3 export-s1flows-to-json.py --flows session-flows-20250921-113321.json --pcap oneflow.s1ap-only.pcapng --start 2025-09-17T00:01:00Z --end 2025-09-18T23:59:00Z
OR
uv run python3 .\export-s1flows-to-json.py --flows .\sample-pcap\session-flows-20251106-225652.json --pcap .\sample-pcap\oneflow.s1ap-only.pcapng --tshark "C:\Program Files\Wireshark\tshark.exe" --failed-flows-only