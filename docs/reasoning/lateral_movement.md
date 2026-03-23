# Detection Reasoning: Lateral Movement

## Overview

Lateral movement is the phase where an attacker who has gained initial access pivots to other systems in the network. It is often the most detectable phase of an intrusion because it generates activity that crosses system and network boundaries — activity that is fundamentally different from single-host behaviour.

The two techniques covered here (PsExec and WMI) are among the most commonly observed in real-world intrusions and red team engagements. Both are "living off the land" approaches — they abuse legitimate Windows functionality, which is precisely why they require behavioural detection rather than signature-based approaches.

---

## Rule 1: PsExec / Remote Service Creation

### What the adversary is doing

PsExec works by copying a small service binary (PSEXESVC.exe) to the target host's `ADMIN$` share, then using the Windows Service Control Manager to install and start it remotely. This generates a highly specific and consistent artefact: Event ID 7045 (New Service Installed) with the service name `PSEXESVC`.

Attackers use PsExec because:
- It is built into Sysinternals (trusted tool)
- It does not require pre-installed agents
- It provides interactive command execution over SMB
- Many organisations do not monitor service installation events

### What normal looks like

Legitimate PsExec usage in a modern enterprise is rare. It does exist — some IT teams use it for one-off admin tasks — but SCCM, Intune, Ansible, and similar tools have largely replaced it for systematic remote management. If your organisation has no formalised remote management tooling, you may see PsExec from specific IT admin machines during business hours.

### Why this detection works

Event ID 7045 is generated on the **target** machine, not the source. The service name `PSEXESVC` is hardcoded in the PsExec binary and is rarely changed by attackers (though renamed variants exist). This makes it a high-fidelity indicator — the signal is on the machine being attacked, not the machine doing the attacking, which means you catch it even if the source is an already-compromised host with no monitoring.

### False positive analysis

| Scenario | Likelihood | Mitigation |
|---|---|---|
| IT admin using PsExec for one-off tasks | Medium | Whitelist known admin hostnames; correlate with change tickets |
| SCCM/Ansible using service installation | Low | These use different service names — 7045 will fire but won't match PSEXESVC |
| Red team engagement | High (by design) | Confirm with security team before investigating |
| Attacker using renamed PsExec | Medium | Add `ServiceFileName LIKE "%psexec%"` as a secondary match |

### Analyst response

1. Identify the source host (check Event 4624 logon events on the target for the same timeframe)
2. Verify whether a change request exists for remote administration of the target host
3. If no change request: isolate target host and begin IR process
4. Check for subsequent Event 4688 (process creation) entries showing commands run via PsExec

---

## Rule 2: Unusual WMI Remote Execution

### What the adversary is doing

Windows Management Instrumentation (WMI) allows remote execution via the `Win32_Process.Create` method. When a remote WMI call spawns a process, that process appears on the target machine as a child of `WmiPrvSE.exe`. Attackers favour WMI because it is built into every Windows installation, generates minimal network traffic (uses RPC over port 135), and is rarely blocked.

Common attacker tools that use WMI for lateral movement: Empire, CrackMapExec (`--exec-method wmiexec`), Impacket's `wmiexec.py`.

### What normal looks like

`WmiPrvSE.exe` legitimately spawns processes — SCCM inventory scans, monitoring agents, and some antivirus products use WMI. The key baseline characteristics are:
- Known, signed binaries being spawned
- Consistent process names (same 1–2 child process types every time)
- Activity during business hours from known management servers
- Low volume of unique child processes

### Why this detection works

The detection triggers on two patterns that are atypical for legitimate WMI use:
1. A high number of **unique** process names spawned from WmiPrvSE — attackers run different commands each time, whereas SCCM always runs the same agent binary
2. A high **volume** of spawns in a short window — attackers chain commands rapidly, whereas legitimate use is infrequent

### False positive analysis

| Scenario | Likelihood | Mitigation |
|---|---|---|
| SCCM hardware inventory | Medium | Spawns consistent processes — add to known_admin_hosts lookup |
| Monitoring agent (Datadog, Dynatrace) | Low-Medium | Consistent process names — add to exclusion list |
| Software deployment via WMI | Medium | Correlate with deployment schedule; filter by source host |

### Analyst response

1. Identify the remote source IP initiating the WMI call (check network logs for inbound port 135 connections to the target)
2. Review `SpawnedProcesses` for LOLBins: `certutil`, `mshta`, `rundll32`, `regsvr32`, `bitsadmin`
3. Check for encoded PowerShell in `CommandLines` (`-EncodedCommand` or base64 strings)
4. If suspicious: capture memory of WmiPrvSE and spawned process before isolating
