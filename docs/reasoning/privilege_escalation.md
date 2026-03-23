# Detection Reasoning: Privilege Escalation

## Overview

Privilege escalation detections aim to catch the moment an attacker elevates from a standard user or service account context to SYSTEM or Domain Admin. This phase is critical to detect because once an attacker achieves SYSTEM-level access, the cost of containment rises dramatically — they can disable security tools, dump all credentials, and create persistent backdoors.

The two techniques here target different escalation paths: one through token manipulation (gaining SYSTEM-level capabilities without a formal privilege assignment), and one through abusing the Windows Task Scheduler to run code as SYSTEM.

---

## Rule 1: SeDebugPrivilege Abuse

### What the adversary is doing

`SeDebugPrivilege` is a Windows privilege that allows a process to read and write the memory of any other process on the system — including `lsass.exe` (which holds all credential material). It is normally held only by members of the local Administrators group and by SYSTEM processes.

When an attacker obtains this privilege on a standard user context (via token impersonation, stolen admin credentials, or an unpatched local privilege escalation), it is recorded in Event ID 4703 (Token Right Adjusted). The subsequent step is almost always LSASS memory reading (Mimikatz), making this detection a leading indicator of credential theft.

### What normal looks like

Processes that legitimately enable SeDebugPrivilege:
- Visual Studio and other IDEs (`devenv.exe`) — for attaching to processes
- Debuggers (`windbg.exe`, `ntsd.exe`)
- Some backup agents that need to snapshot process memory
- Windows Error Reporting (`WerFault.exe`)

All legitimate cases involve signed, known binaries. The process name is not sufficient for whitelisting — use SHA256 hash verification via your SIEM's watchlist feature.

### Why this detection works

The detection catches the privilege being **enabled** by an unexpected process. The key filter is:
- Not a known debugger/IDE
- Not a machine account (ending in `$`)
- Not SYSTEM itself

This gives a small but high-fidelity alert population. In a typical enterprise, this fires fewer than 5 times per month from legitimate sources once tuned — any additional fires warrant immediate investigation.

### False positive analysis

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Developer running Visual Studio debugger | High | Whitelist devenv.exe by hash; limit to developer workstation OU |
| Backup agent requiring memory access | Medium | Whitelist by SHA256 hash of the specific backup binary |
| Security product (AV/EDR) | Low-Medium | Known security products should be whitelisted centrally |
| New legitimate tool introduced to environment | Medium | Change management process should capture new tooling |

### Analyst response

1. Identify the process that enabled SeDebugPrivilege — is it signed? Is it a known tool?
2. Within 60 seconds of this event, check for Event ID 10 (Sysmon ProcessAccess) targeting lsass.exe from the same process
3. If LSASS access is confirmed: assume credential compromise of all accounts on that host
4. Check for network connections from the host within 5 minutes (potential C2 callback with dumped hashes)

---

## Rule 2: Suspicious Scheduled Task Created by Non-Admin

### What the adversary is doing

The Windows Task Scheduler allows processes to be run as any user, including SYSTEM (SID `S-1-5-18`). An attacker with a standard user account can create a scheduled task that runs as SYSTEM, effectively gaining SYSTEM-level code execution with a built-in persistence mechanism.

This technique is used for two purposes simultaneously: privilege escalation (running code as SYSTEM) and persistence (the task survives reboots). It is recorded in Event ID 4698 (Scheduled Task Created).

Attackers use this because:
- It survives reboots (persistence)
- It runs as SYSTEM without requiring SYSTEM access initially
- Task Scheduler is a legitimate Windows feature and often not monitored
- It can trigger on logon, idle, or specific times — flexible scheduling

### What normal looks like

Scheduled tasks are created legitimately by:
- Software installers (typically run during install, not ongoing)
- Windows Update, Defender, and built-in maintenance tasks (created by SYSTEM, not a user)
- Monitoring agents (created during agent installation by a service account)
- IT admin scripts for maintenance tasks

The distinguishing characteristic of legitimate scheduled task creation is that it is either done by SYSTEM/Administrator during a known installation, or by a known service account at a known time.

### Why this detection works

The detection combines two high-fidelity filters:
1. **Non-admin user creating the task** — standard users creating scheduled tasks is unusual outside of software installs
2. **Task runs as SYSTEM** — a standard user creating a SYSTEM-privileged task is almost never legitimate outside of a software installer

The secondary filter (LOLBin in the command line) catches cases where the creator account might not be standard but the command itself is suspicious.

### False positive analysis

| Scenario | Likelihood | Mitigation |
|---|---|---|
| Software installer creating a maintenance task | High | Correlate with Event 11707 (MSI install); filter during deployment windows |
| Developer creating a task for a test script | Medium | Filter by developer workstation OU; require RunAs standard user |
| Monitoring agent setup | Low | Service account will trigger only during initial installation |

### Analyst response

1. Examine `ExecCommand` for encoded payloads (`-EncodedCommand`, base64 strings, escaped characters)
2. Check whether `SubjectUserName` had any recent suspicious activity (failed logons, new logon from unusual IP)
3. Attempt to correlate with a software installation event in the same timeframe
4. If no installation event found: delete the task immediately and investigate the user account
