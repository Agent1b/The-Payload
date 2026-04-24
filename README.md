# 💉 Extrasploit Agent — Detection-focused research on custom .NET payload evasion. Includes MITRE ATT&CK mapping, IOC analysis, and Sigma detection rules for blue teams.

> ⚠️ **DISCLAIMER:** This project was developed strictly for educational and research purposes in an isolated lab environment. No source code or binaries are provided — this repository contains **documentation and analysis only.**

---

## 📋 Overview

A custom-built Windows implant (agent) developed to study:
- Payload construction techniques for single-file .NET executables
- Endpoint detection bypass via PE header manipulation and console suppression
- Cross-compilation from Linux to Windows as an offensive development workflow
- Behavioral analysis from a defender's perspective — what artifacts does a custom payload leave?

**Research Question:** How do modern endpoint security solutions detect (or fail to detect) custom-built .NET payloads, and what indicators can SOC analysts use to identify them?

---

## 🎯 Objectives

1. Build a fully functional Windows implant from scratch — no existing frameworks
2. Cross-compile from attacker OS (Linux) to target OS (Windows) without a Windows dev environment
3. Achieve silent execution on Windows 11 with zero visible indicators
4. Test detection rates with Windows Defender enabled
5. Document all IOCs for blue team training and detection rule development
6. Map every technique to MITRE ATT&CK framework

---

## ⚙️ Payload Characteristics

| Property | Details |
|----------|---------|
| **Language** | C# (.NET 6.0) |
| **Target OS** | Windows 10 / 11 (x64) |
| **Delivery Method** | Direct execution (social engineering, USB, or dropper out of scope) |
| **Payload Type** | Full-featured agent with encrypted reverse connection to C2 |
| **Encryption** | AES-256-CBC with pre-shared key, fresh IV per message |
| **Size** | ~67MB (self-contained single-file with embedded .NET runtime) |
| **Persistence** | Registry Run key + file copy to %LOCALAPPDATA% |
| **Visibility** | Completely invisible — no console, no window, no tray icon |
| **Compilation** | Cross-compiled from Kali Linux using dotnet publish + PE patching |

---

## 🔬 Techniques Used

### Delivery
- **Method:** Agent is a standalone .exe that connects back to the C2 server on execution. Delivery mechanism (phishing, USB, dropper) is out of scope for this research — focus is on the implant itself.
- **MITRE ATT&CK:** T1204.002 — User Execution: Malicious File

### Execution
- **Method:** Standard PE execution. Agent calls `FreeConsole()` immediately on startup, then establishes encrypted TCP connection to C2. The PE header is patched post-build to set subsystem to WINDOWS_GUI (2), preventing Windows 11's Terminal from creating a visible console window before Main() runs.
- **MITRE ATT&CK:** T1106 — Native API (FreeConsole, Win32 P/Invoke)

### Evasion Techniques

#### 1. PE Header Subsystem Patching
**What:** Modifying the compiled executable's PE header to change the subsystem field from CONSOLE (3) to WINDOWS_GUI (2).  
**Why:** Windows 11 introduced a new Terminal application that intercepts console process creation at the OS level, before any application code runs. Traditional code-based hiding (ShowWindow, FreeConsole) runs too late.  
**Implementation:** Post-build Python script reads PE offset from DOS header at 0x3C, locates subsystem field at PE_OFFSET + 0x5C, overwrites 2-byte value from 03 00 to 02 00.  
**MITRE ATT&CK:** T1027.009 — Obfuscated Files: Embedded Payloads

#### 2. Console-Free Architecture
**What:** Zero console output throughout the entire codebase — no Console.WriteLine, no Console.Write, no Console.ReadLine anywhere.  
**Why:** Any Console.* call in .NET causes the runtime to allocate a console window, even in a WinExe application.  
**Implementation:** Custom Logger class writes exclusively to file. Log file only created when running from AppData (post-persistence), not during initial execution from Desktop/Downloads.  
**MITRE ATT&CK:** T1564.003 — Hide Artifacts: Hidden Window

#### 3. Self-Contained Single-File Deployment
**What:** Agent published as a single .exe file (~67MB) containing the entire .NET 6.0 runtime, all dependencies, and application code.  
**Why:** No dependency on target having .NET installed. No DLL files dropped alongside the executable. Single file is easier to deploy and leaves fewer filesystem artifacts.  
**Implementation:** dotnet publish with `/p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true /p:EnableCompressionInSingleFile=true`  
**MITRE ATT&CK:** T1027.002 — Obfuscated Files: Software Packing

#### 4. Encrypted Communications
**What:** All C2 traffic encrypted with AES-256-CBC, making deep packet inspection impossible without the key.  
**Why:** Plain-text C2 traffic is trivially detected by IDS/IPS. Encryption forces defenders to rely on traffic analysis (patterns, timing, volume) instead of content inspection.  
**Implementation:** Pre-shared 256-bit key (hex-encoded in config), random 16-byte IV per message, PKCS7 padding. Identical implementation in Python (controller) and C# (agent) verified with cross-language test vectors.  
**MITRE ATT&CK:** T1573.001 — Encrypted Channel: Symmetric Cryptography

#### 5. Conditional Logging
**What:** Agent only creates log files when running from its persistence install directory (AppData), never during initial execution.  
**Why:** Log files are forensic evidence. During initial execution from Desktop or Downloads, no files are created that would alert the user or leave additional artifacts.  
**Implementation:** Logger.Init() checks AppDomain.CurrentDomain.BaseDirectory — if path contains "AppData", logging enabled; otherwise null (no logging).  
**MITRE ATT&CK:** T1070.004 — Indicator Removal: File Deletion (prevention rather than removal)

### Persistence
- **Method:** Registry Run key at `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` + full file copy (exe + runtime) to `%LOCALAPPDATA%\WindowsSystemUpdate\`
- **Implementation details:** Copies ALL files from build directory using per-file try/catch (to skip locked files). Uses absolute paths via AppDomain.CurrentDomain.BaseDirectory (not relative — relative paths resolve to system32 when launched from startup).
- **MITRE ATT&CK:** T1547.001 — Boot/Logon Autostart: Registry Run Keys

### Command & Control
- **Method:** Persistent TCP connection with auto-reconnection (10-second retry). 4-byte little-endian length prefix framing. JSON message payloads with type-based routing. 30-second heartbeat interval with stale session cleanup.
- **MITRE ATT&CK:** T1571 — Non-Standard Port, T1095 — Non-Application Layer Protocol

---

## 🧪 Testing Results

### Detection Rate

| Security Tool | Detected? | Detection Type | Notes |
|--------------|-----------|---------------|-------|
| Windows Defender (Real-time) | No | N/A | Custom code has no known signature. Defender relies on signature matching for static detection. |
| Windows Defender (Behavior) | Partial | Behavioral | SetWindowsHookEx for keylogger triggered behavioral alert in some test runs |
| Sysmon | Yes | Telemetry | Process creation (Event 1), network connection (Event 3), and registry modification (Event 13) all logged correctly |
| Wireshark | Visible | Traffic analysis | Encrypted traffic visible but content unreadable. Timing patterns (30s heartbeat) detectable |

### IOCs Generated

| IOC Type | Value | Description |
|----------|-------|-------------|
| File Path | `%LOCALAPPDATA%\WindowsSystemUpdate\Agent.exe` | Persistence install location |
| File Size | ~67MB single .exe | Unusually large for a legitimate utility |
| Registry Key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsSystemUpdate` | Persistence mechanism |
| Network | Persistent TCP to attacker IP on port 4444 | C2 callback channel |
| Network Pattern | 30-second interval heartbeat | Regular beaconing pattern |
| Process | Agent.exe (no visible window) | GUI subsystem process with no GUI |
| File | `%LOCALAPPDATA%\WindowsSystemUpdate\agent.log` | Agent log file (post-persistence only) |
| PE Header | Subsystem = 2 (GUI) but no window created | Suspicious PE characteristic |

---

## 🛡️ Blue Team Takeaways

**How a SOC analyst should detect this payload:**

1. **Network layer:** Look for persistent outbound TCP connections to non-standard ports with encrypted (high-entropy) payloads at regular intervals. The 30-second heartbeat creates a detectable beaconing pattern. Tools: Zeek, RITA (Real Intelligence Threat Analytics), Suricata.

2. **Endpoint layer:** Monitor for SetWindowsHookEx calls (keylogger), GDI+ CopyFromScreen (screen capture), new processes in %LOCALAPPDATA% with GUI subsystem but no visible window. Tools: Sysmon, CrowdStrike Falcon, Carbon Black.

3. **Log analysis:** Sysmon Event ID 1 (Process Creation) — new unsigned exe from AppData. Event ID 3 (Network Connection) — persistent outbound on unusual port. Event ID 13 (Registry) — new Run key entry. Correlate all three for high-confidence detection.

4. **Behavioral indicators:** Large single-file .exe (~67MB) with embedded .NET runtime, no visible window despite running, continuous network activity, registry startup entry pointing to AppData.

**Recommended Sigma Detection Rules:**

```yaml
# Detection: Extrasploit-style persistence via Registry Run key
title: Suspicious Run Key Pointing to AppData
description: Detects registry Run key modifications that point to executables in user AppData
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject|contains: '\CurrentVersion\Run'
        Details|contains: '\AppData\Local\'
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1547.001
```

```yaml
# Detection: Large single-file .NET executable from unusual location
title: Large Executable in AppData with No Window
description: Detects execution of unusually large executables from user AppData
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image|contains: '\AppData\Local\'
    filter:
        Image|contains:
            - '\Microsoft\'
            - '\Google\'
            - '\Mozilla\'
    condition: selection and not filter
level: medium
tags:
    - attack.execution
    - attack.t1204.002
```

```yaml
# Detection: Regular beaconing pattern to non-standard port  
title: Potential C2 Beaconing - Regular Interval Connections
description: Detects processes making regular-interval outbound connections
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        Initiated: 'true'
        DestinationPort|gt: 1024
        Image|contains: '\AppData\'
    condition: selection
level: medium
tags:
    - attack.command_and_control
    - attack.t1571
```

---

## 🧪 Lab Environment

- **Attacker:** Kali Linux 2024.x on VMware — Python 3.13, .NET SDK 6.0 for cross-compilation
- **Target:** Windows 11 Pro 22H2 on VMware — .NET Runtime 6.0, Windows Defender enabled (real-time protection ON)
- **Network:** VMware host-only adapter, fully isolated, no internet access
- **AV Status:** Windows Defender real-time protection enabled during all testing
- **Monitoring:** Sysmon installed on target for telemetry collection, Wireshark on attacker for traffic analysis

---

## 📸 Screenshots

<!-- SCREENSHOTS TO TAKE -->

| Screenshot | Description |
|-----------|-------------|
| ![Build](screenshots/01_build_output.png) | Cross-compiling agent from Kali Linux — showing build flags and PE patch success |
| ![Silent](screenshots/02_silent_execution.png) | Agent running in Task Manager with NO visible window — GUI subsystem confirmed |
| ![Defender](screenshots/03_defender_scan.png) | Windows Defender scan showing no detection of the custom agent |
| ![Wireshark](screenshots/04_wireshark_traffic.png) | Encrypted C2 traffic in Wireshark — 4-byte length prefix + AES-encrypted payload visible |
| ![Sysmon](screenshots/05_sysmon_detection.png) | Sysmon events showing process creation, network connection, and registry modification |
| ![Persistence](screenshots/06_registry_runkey.png) | Registry Run key visible in regedit showing persistence entry |
| ![Reconnect](screenshots/07_reconnection.png) | Agent auto-reconnecting after connection drop — controller shows session reuse |
| ![PE Header](screenshots/08_pe_header.png) | PE header analysis (PE-bear or CFF Explorer) showing subsystem = 2 (GUI) |

---

## 📚 Key Learnings

1. **Custom payloads trivially bypass signature-based AV** — Windows Defender never flagged the agent because it has no known signature. This fundamentally demonstrates why enterprises need behavioral detection (EDR) and can't rely on traditional AV alone.

2. **The PE header is the OS-level gatekeeper** — Windows decides whether to create a console window based on a single 2-byte field in the PE header. Understanding this level of the Windows loader is essential for both offense (silent execution) and defense (suspicious PE characteristics).

3. **Cross-compilation eliminates the need for a Windows development environment** — The entire agent was built on Kali Linux using `dotnet publish`. This means attackers don't need to touch Windows to create Windows malware — important context for threat modeling.

4. **Network traffic patterns persist despite encryption** — Regular heartbeats, consistent packet sizes, and persistent connections create detectable signatures even when content is encrypted. This validates the value of network traffic analysis tools like RITA and Zeek.

5. **Persistence artifacts are the most reliable IOCs** — While the running agent can be stealthy, the persistence mechanism (registry key + file in AppData) leaves durable artifacts that survive across reboots and are discoverable by standard forensic procedures.

6. **Sigma rules can catch custom tools** — The three detection rules above would catch this payload despite having no signature. Behavioral patterns (large exe from AppData, Run key to AppData, regular outbound connections) are more durable than hash-based IOCs.

---

## 🔗 Related Projects

- [Custom RAT — C2 Framework Research](link-to-rat-repo) — The C2 infrastructure used to control this payload
- [Home Security Lab](link-to-homelab-repo) — The isolated VMware environment where testing was conducted

---

## 📬 Contact

**Michael Baazov**  
[LinkedIn](https://www.linkedin.com/in/michael-baazov-87417823b/) | [GitHub](https://github.com/Agent1b) | michbz@proton.me

---

*Understanding how payloads are built and how they evade detection is essential for developing effective defensive controls. Every technique documented here includes its corresponding detection method and Sigma rule — because offense informs defense.*
