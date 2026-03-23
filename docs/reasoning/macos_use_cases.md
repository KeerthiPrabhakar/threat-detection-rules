# Detection Use Cases: macOS

## Overview

The current repository is centered on Windows and Active Directory tradecraft. macOS requires a different detection model: less reliance on classic event IDs, more emphasis on process execution, Unified Logs, Endpoint Security telemetry, MDM events, file changes, and persistence artefacts.

The use cases below are written in the same style as the existing rule reasoning documents so they can be turned into Splunk or Sentinel content later.

---

## 1. Unsigned or Untrusted Binary Execution

### MITRE ATT&CK

- T1204.002 — User Execution: Malicious File
- T1553.002 — Subvert Trust Controls: Code Signing
- T1036 — Masquerading

### What the adversary is doing

An attacker executes a Mach-O binary, script, or dropped application bundle that is unsigned, ad hoc signed, or signed by an unexpected developer identity. This is common in initial access, loader deployment, and post-exploitation staging on macOS.

Common examples:
- Fake update apps
- Trojanised DMG payloads
- Unsigned command-line tools dropped into `/tmp`, `/private/tmp`, or the user profile

### Required telemetry

- Microsoft Defender for Endpoint `DeviceProcessEvents`
- Elastic Defend / CrowdStrike / SentinelOne process telemetry
- Apple Endpoint Security process execution events
- File metadata with signer, team ID, notarization, and quarantine attributes where available

### Detection logic

- Alert when a process launches from user-writable paths such as:
  - `/Users/*/Downloads/`
  - `/Users/*/Library/`
  - `/private/tmp/`
  - `/tmp/`
- Raise priority when any of the following are true:
  - No valid code signature
  - Ad hoc signature only
  - Unexpected Team ID
  - Parent process is `osascript`, `Terminal`, `zsh`, `bash`, or `python`
  - Quarantine attribute was recently present

### False positive analysis

- Internal developer tools built locally
- Security team tooling
- Admin troubleshooting scripts

### Analyst response

1. Validate the file path, signer, Team ID, and notarization status
2. Review the parent process chain and user context
3. Check whether the binary was downloaded from a browser, chat client, or email app
4. Isolate if the binary is unsigned and launched from a user-writable path without a valid business reason

---

## 2. Suspicious Persistence via LaunchAgents or LaunchDaemons

### MITRE ATT&CK

- T1543.001 — Create or Modify System Process: Launch Agent
- T1543.004 — Create or Modify System Process: Launch Daemon
- T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

### What the adversary is doing

Attackers establish persistence by creating or modifying plist files under:
- `/Library/LaunchDaemons/`
- `/Library/LaunchAgents/`
- `/Users/<user>/Library/LaunchAgents/`

This is one of the most common macOS persistence techniques because launchd starts these items automatically at boot or user logon.

### Required telemetry

- File creation and modification telemetry
- Process execution telemetry for `launchctl`, `plutil`, `defaults`, `osascript`, shell interpreters
- MDM or EDR telemetry capturing plist writes and service loads

### Detection logic

- Alert on new plist creation in launchd persistence paths
- Raise severity when:
  - The referenced executable is in a user-writable path
  - The plist uses `RunAtLoad` or `KeepAlive`
  - The creator process is a shell, script interpreter, or unsigned app
  - `launchctl bootstrap`, `load`, or `enable` occurs shortly after file creation

### False positive analysis

- Legitimate software installation and updates
- IT management agents
- Security tools and remote support software

### Analyst response

1. Review the plist `ProgramArguments` and referenced binary path
2. Check signer metadata for the referenced binary
3. Determine whether the creating process was an approved installer
4. Remove or disable the launch item if malicious and preserve the binary for triage

---

## 3. Credential Access Through Keychain Abuse

### MITRE ATT&CK

- T1555 — Credentials from Password Stores
- T1555.001 — Credentials from Password Stores: Keychain
- T1003 — OS Credential Dumping

### What the adversary is doing

An attacker attempts to access secrets stored in the macOS Keychain, often using:
- `security find-generic-password`
- `security dump-keychain`
- AppleScript prompts
- Abuse of user-approved TCC permissions

The goal is to retrieve saved credentials, tokens, certificates, or VPN secrets.

### Required telemetry

- Process execution logs
- Unified Log events related to `securityd`
- EDR telemetry for child processes and command lines
- TCC-related prompts and approvals where available

### Detection logic

- Alert on `security` command usage with arguments such as:
  - `dump-keychain`
  - `find-generic-password`
  - `find-internet-password`
  - `unlock-keychain`
- Raise priority when:
  - Executed by non-admin users outside normal admin tooling
  - Parent process is `osascript`, `python`, `zsh`, or a suspicious unsigned app
  - Followed by outbound network connections or archive creation

### False positive analysis

- Legitimate admin troubleshooting
- Developer automation scripts
- Password migration utilities

### Analyst response

1. Review the exact command line and parent process
2. Check for recent TCC prompts or user interaction
3. Correlate with archive creation, compression, or exfiltration activity
4. Reset exposed credentials if sensitive secrets may have been accessed

---

## 4. TCC Database Tampering or Abuse

### MITRE ATT&CK

- T1548 — Abuse Elevation Control Mechanism
- T1211 — Exploitation for Defense Evasion
- T1562.001 — Impair Defenses: Disable or Modify Tools

### What the adversary is doing

macOS Transparency, Consent, and Control (TCC) governs access to protected resources such as Full Disk Access, Screen Recording, Microphone, Camera, Desktop, Documents, and Downloads. Attackers seek these permissions to harvest data or surveil the user.

### Required telemetry

- File monitoring for TCC database paths
- Unified Logs
- MDM configuration changes
- Process execution telemetry for `sqlite3`, `tccutil`, and suspicious installers

Key locations:
- `/Library/Application Support/com.apple.TCC/TCC.db`
- `~/Library/Application Support/com.apple.TCC/TCC.db`

### Detection logic

- Alert on direct modification attempts to TCC databases
- Alert on new applications gaining sensitive permissions unexpectedly
- Raise severity when:
  - The granting process is not an MDM or known enterprise app
  - The app is unsigned or newly introduced
  - Screen recording, accessibility, or full disk access is granted to scripting tools

### False positive analysis

- New software deployment
- Accessibility tooling
- Approved MDM policy changes

### Analyst response

1. Identify which permission changed and for which app
2. Validate app signer, Team ID, and installation source
3. Review whether the change came from user approval, MDM, or direct tampering
4. Revoke access and isolate if the permission enables data theft or surveillance

---

## 5. Suspicious AppleScript or `osascript` Execution

### MITRE ATT&CK

- T1059.002 — Command and Scripting Interpreter: AppleScript
- T1059.004 — Command and Scripting Interpreter: Unix Shell
- T1204 — User Execution

### What the adversary is doing

Attackers abuse AppleScript and `osascript` to:
- Display fake prompts
- Execute shell commands
- Access browser data
- Automate credential theft or social engineering

This is common in macOS malware families and phishing-driven payload chains.

### Required telemetry

- Process execution with command lines
- Parent-child process relationships
- Unified Logs when Apple Events or automation prompts are logged

### Detection logic

- Alert when `osascript` executes commands containing:
  - `do shell script`
  - base64 blobs
  - `curl`, `sh`, `bash`, `zsh`, `python`
  - dialogs requesting passwords or MFA codes
- Raise severity when launched by:
  - Office apps
  - Browsers
  - Chat clients
  - Unsigned apps from Downloads

### False positive analysis

- Admin automation
- Developer scripts
- Helpdesk workflows

### Analyst response

1. Capture the command line and parent process
2. Review whether the script presented a fake authentication prompt
3. Check for follow-on network activity or persistence creation
4. Contain if `osascript` is being used as a launcher for shell execution

---

## 6. Defense Evasion via Security Tool Tampering

### MITRE ATT&CK

- T1562.001 — Impair Defenses: Disable or Modify Tools
- T1562.009 — Impair Defenses: Safe Mode Boot
- T1222 — File and Directory Permissions Modification

### What the adversary is doing

An attacker attempts to disable or impair macOS security controls, EDR, or logging. This can include unloading launch daemons, killing agents, deleting logs, or modifying configuration profiles.

### Required telemetry

- Process execution
- MDM audit logs
- File changes to agent configuration paths
- Service state changes for security tooling

### Detection logic

- Alert on attempts to stop or unload security services with:
  - `launchctl bootout`
  - `launchctl unload`
  - `kill`, `pkill`, `killall`
- Raise severity when targeted processes belong to:
  - MDE
  - CrowdStrike
  - SentinelOne
  - Jamf
  - Kandji
  - logging or audit agents

### False positive analysis

- Agent upgrades
- IT troubleshooting
- Device reprovisioning

### Analyst response

1. Identify the targeted service and initiating user
2. Validate whether there was an approved maintenance action
3. Look for follow-on persistence, credential access, or exfiltration
4. Re-enable protections and isolate if tampering is unauthorized

---

## 7. Mass File Rename or Encryption Activity on macOS

### MITRE ATT&CK

- T1486 — Data Encrypted for Impact
- T1490 — Inhibit System Recovery
- T1489 — Service Stop

### What the adversary is doing

Ransomware on macOS typically performs rapid file rewrites, renames, and extension changes across the user profile, synced cloud storage, or mounted shares.

### Required telemetry

- File creation, rename, and delete telemetry
- Process telemetry for the initiating binary
- Volume and network-share context where available

### Detection logic

- Alert when a single process performs a high volume of file operations in a short window
- Raise severity when:
  - New file extensions converge to one or two values
  - Target directories include `Desktop`, `Documents`, `Downloads`, or mounted volumes
  - The initiating binary is unsigned or launched from a user-writable path

### False positive analysis

- Backup clients
- File migration tools
- Bulk media conversion workflows

### Analyst response

1. Identify the initiating process and signer metadata
2. Check whether mounted volumes or cloud-synced folders were affected
3. Isolate the endpoint immediately if encryption behavior is confirmed
4. Preserve the binary and recent process tree for forensics

---

## 8. Large Outbound Transfer From a macOS Endpoint

### MITRE ATT&CK

- T1041 — Exfiltration Over C2 Channel
- T1567 — Exfiltration Over Web Service
- T1020 — Automated Exfiltration

### What the adversary is doing

After collection, the attacker stages and transfers data to external infrastructure using HTTPS, S3-compatible tools, cloud storage clients, or standard utilities like `curl`.

### Required telemetry

- Firewall or proxy logs
- Endpoint process-to-network correlation
- DNS logs
- EDR network telemetry

### Detection logic

- Alert on large outbound volume from a single macOS host to a rare or previously unseen destination
- Raise severity when:
  - The destination has poor reputation
  - The transfer occurs after archive creation
  - The initiating process is `curl`, `python`, `rclone`, `rsync`, or an unknown app
  - The destination is not a known corporate SaaS or backup provider

### False positive analysis

- Cloud backups
- Developer artifact uploads
- Video editing or media publishing workflows

### Analyst response

1. Identify the source process and command line
2. Review preceding archive, compression, or file collection activity
3. Validate destination ownership and business justification
4. Contain and preserve evidence if sensitive data likely left the device

---

## Prioritised macOS Rule Backlog

If you want to expand this repository for macOS, start here:

1. `Unsigned binary execution from Downloads or tmp`
2. `New LaunchAgent/LaunchDaemon referencing user-writable path`
3. `Keychain dump or credential retrieval via security CLI`
4. `Suspicious osascript spawning shell or curl`
5. `TCC permission grant to unexpected app`
6. `Mass file rename / ransomware pattern on macOS`
7. `Large outbound transfer correlated with archive creation`
8. `Security agent tampering via launchctl or killall`

## Recommended macOS Data Sources

- Apple Endpoint Security framework telemetry
- Unified Logs
- EDR process, file, and network events
- MDM audit logs
- DNS, proxy, and firewall logs
- File integrity monitoring for launchd and TCC paths
