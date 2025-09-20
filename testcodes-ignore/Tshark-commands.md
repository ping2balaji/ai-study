1) To filter input pcap with only s1ap packet(without paging msgs to avoid noise)
tshark -r <in.pcap> -Y "s1ap and !(s1ap.procedureCode == 10)" -F pcapng -w <s1ap-only.pcapng>
2) To conver all s1ap packets into CSV file with their frameno, ip, sapids and procedurecode:
  tshark -r <s1ap-only.pcapng> -Y s1ap -T fields 
   -E "header=y" -E "separator=," -E "quote=d" -E "occurrence=f"
   -e frame.number -e frame.time_epoch -e ip.src -e ip.dst 
   -e ipv6.src -e ipv6.dst -e sctp.srcport -e sctp.dstport 
   -e s1ap.ENB_UE_S1AP_ID -e s1ap.MME_UE_S1AP_ID -e s1ap.procedureCode

   OR
   tshark -r <s1ap-only.pcapng> -Y s1ap -T fields -E "header=y" -E "separator=," -E "quote=d" -E "occurrence=f" -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e sctp.srcport -e sctp.dstport -e s1ap.RRC_Establishment_Cause -e s1ap.ENB_UE_S1AP_ID -e s1ap.MME_UE_S1AP_ID -e s1ap.radioNetwork -e e212.tai.mcc -e e212.tai.mnc -e s1ap.tAC -e s1ap.CellIdentity -e _ws.col.Info

3) To group all s1ap packets per ue-session using sapid and provide json output for each session frame-number with their start-time and end-time:
==> using python code.

4) To convert frames to json and feed it to LLM for analysis:
tshark -r .\sample.s1ap-only.pcapng -Y "frame.number in {4,7,12,13,16}" -T fields -E "header=y" -E "separator=," -E "quote=d" -E "occurrence=f" -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e sctp.srcport -e sctp.dstport -e s1ap.RRC_Establishment_Cause -e s1ap.ENB_UE_S1AP_ID -e s1ap.MME_UE_S1AP_ID -e s1ap.radioNetwork -e e212.tai.mcc -e e212.tai.mnc -e s1ap.tAC -e s1ap.CellIdentity -e _ws.col.Info

or for only s1ap: 
  -> tshark.exe -r .\one-flow.pcap -T json -J s1ap > one-flow.json
or for having more control we can use jq and filter json fields:
  4.1  tshark.exe -r .\one-flow.pcap -T json -J ip -J ipv6 -J sctp -J s1ap > one-flow-filtered.json
  4.2 Get-Content -Raw -Encoding Unicode .\one-flow-filtered.json |
  Set-Content -NoNewline -Encoding utf8 .\one-flow-filtered.utf8.json
  4.3 jq -f .\filter.jq .\one-flow-filtered.utf8.json > .\filtered.json


