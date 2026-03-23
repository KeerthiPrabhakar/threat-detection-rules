# Threat Detection Rule Set — Splunk & Microsoft Sentinel

A production-quality detection engineering project covering four high-priority attack categories across two SIEM platforms. Every rule is accompanied by documented reasoning, false positive guidance, and synthetic test data.

---

## Coverage

| Category | MITRE Tactic | Rules |
|---|---|---|
| Lateral Movement | TA0008 | PsExec, WMI remote execution |
| Privilege Escalation | TA0004 | SeDebugPrivilege abuse, Scheduled task creation |
| Credential Theft | TA0006 | LSASS access, Kerberoasting |
| Ransomware / Exfil | TA0040 / TA0010 | Mass file rename, Unusual outbound transfer |

**Platforms:** Splunk (SPL) · Microsoft Sentinel (KQL)  
**Total rules:** 8 per platform (16 total)

---

## Data Sources Required

### Splunk
- `index=wineventlog` — Windows Security Event Logs (Event IDs: 4688, 4698, 4703, 4769, 7045)
- `index=sysmon` — Sysmon Events (Event IDs: 10, 11, 23)
- `index=network` — Firewall/network logs (sourcetype=firewall)

### Microsoft Sentinel
- `SecurityEvent` — Windows Security Events
- `DeviceEvents` — Microsoft Defender for Endpoint (MDE)
- `DeviceFileEvents` — MDE file activity
- `CommonSecurityLog` — Firewall/network logs via CEF connector

---

## Repo Structure

```
threat-detection-rules/
├── README.md                        ← You are here
├── MITRE_COVERAGE.md                ← ATT&CK technique mapping
├── splunk/
│   ├── lateral_movement/
│   │   ├── detect_psexec.spl
│   │   └── detect_wmi_remote_exec.spl
│   ├── privilege_escalation/
│   │   ├── detect_sedebug_privilege.spl
│   │   └── detect_suspicious_scheduled_task.spl
│   ├── credential_theft/
│   │   ├── detect_lsass_access.spl
│   │   └── detect_kerberoasting.spl
│   └── ransomware_exfil/
│       ├── detect_mass_file_rename.spl
│       └── detect_unusual_outbound_transfer.spl
├── sentinel/
│   └── (mirrors splunk/ structure with .kql files)
├── docs/
│   └── reasoning/
│       ├── lateral_movement.md
│       ├── privilege_escalation.md
│       ├── credential_theft.md
│       └── ransomware_exfil.md
└── tests/
    └── sample_logs/
        ├── lateral_movement_samples.json
        ├── privilege_escalation_samples.json
        ├── credential_theft_samples.json
        └── ransomware_exfil_samples.json
```

---

## How to Use

### Importing into Splunk
1. Copy the `.spl` file content into Splunk Search & Reporting
2. Adjust `index=` values to match your environment
3. Save as a Scheduled Alert with the recommended cron schedule in each rule's header
4. Set threshold-based alerting as documented per rule

### Importing into Microsoft Sentinel
1. Navigate to **Sentinel → Analytics → Create → Scheduled query rule**
2. Paste the `.kql` content into the rule query field
3. Set the query period and frequency as documented in each rule's header
4. Configure entity mapping (Account, Host, IP) for incident enrichment

---

## Tuning Guidance

Each rule ships with conservative thresholds to minimise false positives in most environments. Before production deployment:

- Run each query in **retrospective mode** over 30 days of historical data
- Identify legitimate processes, hosts, and accounts that trigger the rule
- Add them to the whitelist/exclusion logic documented in each rule file
- Adjust numeric thresholds (e.g. file operation counts, SPN request counts) to your environment baseline

---

## Responsible Use

These detection rules are designed for **defensive security purposes only** — to detect adversarial activity within networks you are authorised to monitor. Do not use this content to facilitate unauthorised access to systems.

---


