1) To filter input pcap with only s1ap packet(without paging msgs to avoid noise)
tshark -r <in.pcap> -Y "s1ap and !(s1ap.procedureCode == 10)" -F pcapng -w <s1ap-only.pcapng>
2) To conver all s1ap packets into CSV file with their frameno, ip, sapids and procedurecode:
  tshark -r <s1ap-only.pcapng> -Y s1ap -T fields 
   -E "header=y" -E "separator=," -E "quote=d" -E "occurrence=f"
   -e frame.number -e frame.time_epoch -e ip.src -e ip.dst 
   -e ipv6.src -e ipv6.dst -e sctp.srcport -e sctp.dstport 
   -e s1ap.ENB_UE_S1AP_ID -e s1ap.MME_UE_S1AP_ID -e s1ap.procedureCode

3) To group all s1ap packets per ue-session using sapid and provide json output for each session frame-number with their start-time and end-time:
==> using python code.

4) To convert frames to json and feed it to LLM for analysis:
tshark.exe -r .\testcodes-ignore\s1ap-only-10k-pkts.s1ap-only.pcapng -Y "frame.number in {1,2,5,9}" -T json -J ip -J sctp -J s1ap > testcodes-ignore\selected3.json

