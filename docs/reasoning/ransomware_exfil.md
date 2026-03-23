# Detection Reasoning: Ransomware & Data Exfiltration

## Overview

Ransomware and data exfiltration represent the late-stage, high-impact phases of an attack. By the time these detections fire, the attacker has likely already established persistence, escalated privileges, and moved laterally. The goal of these detections is therefore not just to detect the activity — it is to detect it fast enough to contain the blast radius.

For ransomware, minutes matter. A modern ransomware strain can encrypt tens of thousands of files per hour. The detection threshold and alert response time must be calibrated to enable containment within the first wave of encryption.

---

## Rule 1: Mass File Rename / Extension Change

### What the adversary is doing

Ransomware encrypts files and typically renames them with a new extension (`.locked`, `.enc`, `.xyz`, or a custom extension unique to the ransomware family). This creates a distinctive pattern at the filesystem level:

1. The ransomware process opens a file for reading
2. Writes the encrypted version with a new name/extension
3. Deletes the original

This generates a burst of `FileCreate` (Sysmon Event 11) and `FileDelete` (Sysmon Event 23) events — or `FileRenamed` in MDE — all from the same process, all in a very short timeframe, all with a consistent new extension.

Modern ransomware is optimised for speed. Families like LockBit 3.0 can encrypt 250GB+ per hour by using asynchronous I/O and multi-threading. This means the detection window is narrow — the rule runs every 2 minutes deliberately.

### What normal looks like

High file-operation volume from a single process is legitimate in:
- Backup software (Veeam, Backup Exec) — but creates files with consistent known extensions and in backup staging directories
- File migration tools (robocopy, rsync) — rename patterns are predictable
- AV quarantine — moves files to a quarantine folder but uses consistent naming
- Compressors (7zip, WinRAR) — create archives but don't delete originals at high volume

The `unique_extensions <= 2` filter is the key differentiator: ransomware always converges on a single new extension, whereas backup and migration tools either preserve extensions or create a known extension (`.bak`, `.vbk`).

### Why this detection works

The combination of high volume AND low extension diversity is highly specific to ransomware. Legitimate high-volume file operations almost always involve many different file types (many extensions). Ransomware touches every file type but outputs a single extension.

The 2-minute bucket window is deliberately narrow — it catches the initial wave, which is the most important window for containment.

### False positive analysis

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Backup software running a full backup | High | Whitelist backup agent binary by SHA256 hash; add backup staging paths to exclusion |
| File migration project | Medium | Temporary whitelist by hostname during migration window |
| Mass file type conversion (e.g. batch image processing) | Medium | Input has many extensions, output has one — matches the pattern. Whitelist by specific tool. |
| Archive creation (7zip archiving a large folder) | Low-Medium | Archives to a single `.7z` file, not many individual renames — different I/O pattern |

### Analyst response

1. **Immediate priority: network isolation** — if ransomware is confirmed, isolate the host from the network before investigating. Network shares can be encrypted in addition to local drives.
2. Identify the ransomware binary via `InitiatingProcessFileName` and `InitiatingProcessSHA256`
3. Check whether network shares are also affected — look for high file-operation volume on file servers from the isolated host's IP
4. Identify patient zero: check how the ransomware binary arrived (email attachment via Event 4663 on mail server, web download via proxy logs, lateral movement from another host)
5. Notify incident response team and legal/comms — ransomware is typically a notifiable event under GDPR/NIS2
6. **Do not reboot the host** — memory forensics may recover the encryption key if the ransomware family is known to store it in memory

---

## Rule 2: Unusual Outbound Data Transfer

### What the adversary is doing

Before deploying ransomware (or instead of it), sophisticated threat actors exfiltrate sensitive data to use as leverage in double-extortion attacks. The exfiltration step involves bulk data transfer from an internal host to an external server controlled by the attacker — often using legitimate protocols (HTTPS, FTP, cloud storage APIs) to blend in with normal traffic.

The technical signatures are:
- Large total data volume to a single destination within a short window
- Destination is a new IP not previously seen in the environment
- Process initiating the transfer may be a LOLBin (certutil, curl, bitsadmin) or a legitimate tool abused for staging (WinSCP, FileZilla installed by the attacker)

### What normal looks like

Large outbound transfers are legitimate from:
- Cloud backup agents (Azure Backup, AWS S3 sync, Veeam Cloud)
- Software update servers (Windows Update, antivirus signature downloads)
- Video conferencing (Teams, Zoom, Webex)
- CDN-heavy SaaS applications (Salesforce, Office 365)
- Developer CI/CD pipelines (pushing builds to cloud repositories)

The key distinguishing factors are: known destination IPs/domains, known source processes, and consistent transfer patterns (same size, same time every day).

### Why this detection works

The detection combines volume threshold with threat intelligence enrichment. Unknown destinations above the volume threshold are flagged even if they are not on a known-bad list — exfiltration infrastructure is often freshly provisioned and not yet in threat intel feeds. The `ThreatConfidence` field from the ThreatIntelligenceIndicator table adds risk scoring when the destination IS in a feed.

The 1-hour bucket window captures both rapid bulk exfil and slower "low and slow" exfil that tries to stay under per-connection thresholds.

### False positive analysis

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Cloud backup agent | High | Whitelist backup agent source IPs; add backup provider IP ranges to known_good list |
| Large file transfer to cloud storage (Dropbox, OneDrive) | Medium | Whitelist known cloud storage CDN IP ranges |
| Developer pushing large build artifact | Medium | Filter by known developer hosts and source IP; correlate with CI/CD schedule |
| Video call with screen share and recording | Low-Medium | Conferencing IPs are well-documented; add to exclusion |

### Analyst response

1. Identify the source process on the source host — use `DeviceNetworkEvents` (MDE) or endpoint process-to-network correlation in Splunk
2. Is the destination IP in any threat intelligence feed? Check VirusTotal, AbuseIPDB, and your TIP
3. Identify **what** was transferred — check file access events (Event 4663) on the source host for the same timeframe
4. Determine whether data included PII, financial records, or IP — this determines notification obligations under GDPR/NIS2
5. If confirmed exfiltration: preserve forensic image before any remediation, notify legal and DPO
6. Rotate any credentials that may have been stored on the source host (environment variables, config files, browser-saved passwords)
