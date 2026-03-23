# Detection Reasoning: Credential Theft

## Overview

Credential theft is one of the most impactful phases of an attack — once an attacker holds valid credentials, they can blend into normal user activity, bypass many security controls, and move laterally without triggering network-level anomaly detection. Detecting credential theft before the stolen credentials are used is the ideal outcome.

Both techniques here target Active Directory credentials: LSASS memory dumping targets credentials cached in memory on any domain-joined machine, while Kerberoasting targets service account password hashes from the domain controller itself.

---

## Rule 1: LSASS Memory Access

### What the adversary is doing

`lsass.exe` (Local Security Authority Subsystem Service) holds NTLM password hashes, Kerberos tickets, and plaintext credentials (in older configurations) for all users who have logged into a Windows machine. Tools like Mimikatz, ProcDump (abused), Task Manager (export), and custom injection code target lsass.exe to extract this material.

The Windows API call `OpenProcess` with the target being lsass.exe is logged by Sysmon as Event ID 10 (ProcessAccess). The `GrantedAccess` field shows the specific permissions requested — `PROCESS_VM_READ` (0x0010) combined with `PROCESS_QUERY_INFORMATION` (0x0400) gives the `0x1010` access mask that is the Mimikatz signature.

### What normal looks like

A small number of system processes legitimately open LSASS:
- `MsMpEng.exe` (Windows Defender) — scans lsass for malware
- `WerFault.exe` — generates crash dumps when lsass crashes (rare)
- `csrss.exe`, `wininit.exe` — Windows subsystem processes
- Task Manager — when a user manually creates a memory dump (requires admin)

All legitimate accesses come from signed, system-level processes. No user application should ever need to open lsass.exe.

### Why this detection works

This is one of the highest-fidelity detections in this entire rule set. The access mask `0x1010` is almost exclusively used by credential dumping tools — there is no legitimate scenario where a non-system process needs `PROCESS_VM_READ` on lsass. The false positive rate with a well-maintained whitelist is extremely low (< 1 per 1000 alerts).

The detection relies on **Sysmon with ProcessAccess auditing** — this is not logged by default Windows Event logging. Sysmon configuration must include a `ProcessAccess` rule targeting `lsass.exe`.

### False positive analysis

| Scenario | Likelihood | Mitigation |
|---|---|---|
| AV/EDR scanning lsass | High | Whitelist by SHA256 hash of the specific vendor binary |
| New security tool introduced | Medium | Add to hash whitelist during tool onboarding |
| Admin manually creating lsass dump via Task Manager | Low | Task Manager uses a different access mask; add to whitelist by name+hash |
| Penetration test | High (by design) | Coordinate with security team; suppress alert for test window |

### Analyst response

1. **Treat this as a critical incident immediately** — assume credential compromise until proven otherwise
2. Identify `SourceImage` and `SourceProcessSHA256` — check the hash against VirusTotal
3. If hash is unknown or malicious: isolate the host immediately
4. Reset passwords for ALL users who have logged into that host (check Event 4624 for the last 30 days)
5. Check for outbound connections from the host in the 5 minutes following this event (C2 callback with exfiltrated hashes)
6. Assume NTLM hashes have been extracted — check for pass-the-hash activity (Event 4624 logon type 3 with NTLM auth) from unusual source IPs

---

## Rule 2: Kerberoasting

### What the adversary is doing

Kerberoasting exploits the fact that any authenticated domain user can request a Kerberos service ticket (TGS) for any service account that has a Service Principal Name (SPN). The TGS ticket is encrypted with the service account's NTLM hash. The attacker requests tickets for many service accounts, takes them offline, and cracks them with tools like Hashcat or John the Ripper.

The attack is stealthy because requesting TGS tickets is legitimate domain behaviour — every time a user accesses a file share or database, a TGS is requested. The attack pattern is distinguishable only by the **volume and variety** of requests and the **encryption type** (RC4/0x17 is specifically requested because it is weaker and faster to crack than AES).

### What normal looks like

Normal TGS requests have these characteristics:
- Low volume from any single user (1–5 per hour for typical user activity)
- Consistent SPN targets (a user always accesses the same file shares)
- Usually AES encryption type (0x12 or 0x11) in hardened environments
- Activity during business hours

### Why this detection works

The detection relies on two orthogonal signals:
1. **RC4 encryption type (0x17)** — in an AES-enforced environment, any RC4 TGS request is suspicious. In non-hardened environments, it narrows the field significantly.
2. **SPN count spike** — requesting 5+ unique SPNs in 10 minutes from a single account is not normal user behaviour. Kerberoasting tools enumerate all SPNs and request tickets for all of them in bulk.

The combination gives high specificity. The threshold of 5 SPNs is conservative — in a well-hardened environment with few SPNs, even 2–3 requests would be anomalous.

### False positive analysis

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Service account monitoring tool | Low-Medium | These typically use AES; whitelist by account name if RC4 is required |
| Developer testing Kerberos authentication | Medium | Filter by developer workstation OU; track during testing windows |
| Automated vulnerability scanner | Medium | Whitelist scanner source IP; schedule scans during maintenance windows |
| Penetration test | High (by design) | Pre-approve and document scope |

### Analyst response

1. Identify the source account and source IP — is the source IP a known workstation?
2. Check whether the account is a service account or a user account (service accounts requesting their own tickets is normal; user accounts requesting many service tickets is not)
3. Review `RequestedSPNs` — are these sensitive service accounts (SQL, backup, exchange)?
4. If confirmed Kerberoasting: reset passwords for ALL targeted service accounts immediately (assume hashes are already cracked offline)
5. Enforce AES-only Kerberos for all service accounts (remove `msDS-SupportedEncryptionTypes` value that permits RC4)
6. Consider implementing a Kerberoast canary account — a fake SPN with a complex password that triggers an alert the moment the hash is cracked and used
