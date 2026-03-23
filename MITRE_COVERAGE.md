# MITRE ATT&CK Coverage Map

Framework version: ATT&CK v14  
Last updated: 2024

---

## Coverage Summary

| Tactic | Technique ID | Technique Name | Rule File | Platform |
|---|---|---|---|---|
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | detect_psexec | Splunk + Sentinel |
| Lateral Movement | T1047 | Windows Management Instrumentation | detect_wmi_remote_exec | Splunk + Sentinel |
| Privilege Escalation | T1134.001 | Access Token Manipulation: Token Impersonation | detect_sedebug_privilege | Splunk + Sentinel |
| Privilege Escalation | T1053.005 | Scheduled Task/Job: Scheduled Task | detect_suspicious_scheduled_task | Splunk + Sentinel |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | detect_lsass_access | Splunk + Sentinel |
| Credential Access | T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | detect_kerberoasting | Splunk + Sentinel |
| Impact | T1486 | Data Encrypted for Impact | detect_mass_file_rename | Splunk + Sentinel |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | detect_unusual_outbound_transfer | Splunk + Sentinel |

---

## Coverage by Tactic

```
Reconnaissance          ░░░░░░░░░░  0%
Resource Development    ░░░░░░░░░░  0%
Initial Access          ░░░░░░░░░░  0%
Execution               ░░░░░░░░░░  0%  (WMI covers T1047)
Persistence             ░░░░░░░░░░  0%  (Sched task partially covers)
Privilege Escalation    ██████░░░░  40% (2 of ~5 key techniques)
Defense Evasion         ░░░░░░░░░░  0%
Credential Access       ████████░░  60% (2 of ~3 key techniques)
Discovery               ░░░░░░░░░░  0%
Lateral Movement        ████████░░  60% (2 of ~3 key techniques)
Collection              ░░░░░░░░░░  0%
Command & Control       ░░░░░░░░░░  0%
Exfiltration            ████░░░░░░  30% (1 of ~3 key techniques)
Impact                  ████░░░░░░  30% (1 of ~3 key techniques)
```

---

## Planned Additions

| Priority | Technique | ID | Notes |
|---|---|---|---|
| High | Pass-the-Hash | T1550.002 | Event 4624 logon type 3 with NTLM |
| High | PowerShell Empire C2 | T1059.001 | Encoded commands + beaconing |
| High | DCSync | T1003.006 | Replication privilege abuse |
| Medium | Living off the Land Binaries | T1218 | LOLBins execution patterns |
| Medium | DNS Tunnelling | T1071.004 | High-frequency DNS to single domain |
| Low | Shadow Copy Deletion | T1490 | vssadmin.exe delete |
