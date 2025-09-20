## How to ask for this same level of analysis (prompt template)

If you want me to focus tightly on S1AP and give a quick verdict + ladder every time, use something like:

“Analyze this pcap for S1AP only. Identify the UE procedure (attach / service request / TAU / handover, etc.), tell me if it completed successfully, list any S1AP causes, and provide a compact ladder diagram (MME↔eNB).”

“Stick to S1-MME control-plane. Ignore S1-U/GTP-U and everything else. Tell me the procedure type, success/failure, key IDs (MME-UE-S1AP-ID / eNB-UE-S1AP-ID), and show a short ladder.”

“From this S1AP trace, determine if the procedure finished OK. If there’s a failure, name the S1AP/NAS cause. Output should be: Procedure, Verdict, Ladder.”

## If you want extras (only when present), add:

“Include InitialContextSetup / E-RAB details if applicable.”

“Report release cause (group+value) explicitly.”

“Note whether NAS payloads are ciphered (security header type).”

If you have another UE slice, drop it in and I’ll run the same playbook.