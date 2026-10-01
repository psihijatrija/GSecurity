<div align="center">

# GSecurity

### Gorstak Windows **OEM hardening** & **first-boot** toolkit

*Ship a custom Windows image with registry policy, firewall posture, browser controls, and optional Gorstak security scriptswithout leaving everything scattered across random folders.*

[![Windows](https://img.shields.io/badge/OS-Windows-0078D6?style=flat&logo=windows&logoColor=white)](#)
[![Gorstak](https://img.shields.io/badge/Gorstak-OEM-5C6BC0?style=flat)](#)

</div>

---

## What this is

**GSecurity** is not a single executableit is an **ISO / deployment bundle** built around Microsofts unattended setup (`autounattend.xml`) and **`$OEM$` distribution folders**. It layers **Gorstak-branded defaults**, **aggressive system hardening** (mostly via `.reg` merges), and a **Bin** toolbox of PowerShell agents that complement [GEDR](https://gorstak.eu) and the broader Gorstak stack.

Use it when you want:

- A **repeatable** baseline after clean Windows install  
- **Enterprise-style** browser policies (extensions, PAC, QUIC toggles, SmartScreen levels)  
- **Firewall / Defender / ASR** and **telemetry reduction** in one import pass  
- **Shell quality-of-life** (admin PowerShell here, firewall desktop menu, file hashes, ownership shortcuts)  
- Optional **PowerShell EDR orchestration** (`Antivirus.ps1`) aligned with the GEDR product line  

---

## Repository map

```
GSecurity/
L Iso/
    + Autorun.inf          # Classic autorun  sources\setup.exe
    + autounattend.xml     # Unattended: locale, OEM info, local Admin, first-logon hooks
    L sources/
        L $OEM$/
            + $1/         # Extra files on disk (e.g. default user desktop extras)
            L $$/Setup/Scripts/
                + SetupComplete.cmd    # Post-setup: cd Bin, merge *.reg
                L Bin/                   # Core payload
                    + GSecurity.bat      # Elevated: import *.reg, ACL hardening, immediate reboot
                    + GSecurity.reg      # Main policy blob (browsers, certs, firewall, ASR, )
                    + Services.reg       # Per-service SvcHostSplitDisable entries
                    + Antivirus.ps1      # Large merged EDR / AV orchestrator (PowerShell)
                    + Retaliate.ps1      # Browser-focused connection monitor / retaliate logic
                    + RootkitKiller.ps1  # ETW-based unsigned HTTP listener cleanup helper
                    + Install-PasswordRotator.ps1
                    + GSecurity.inf      # Driver/catalog placeholder (if used in your build)
                    L  (logs, data, pid files appear at runtime)
```

---

## How setup is wired

### `autounattend.xml`

- **Manufacturer** is set to **Gorstak**; **SupportURL** points at your Discord invite.  
- **Region / language**: Croatian locale with **en-US** UI (adjust for your audience).  
- **Local account**: **`Admin`** with empty password in plaintext (suitable only for lab images**change this** for anything real).  
- **Auto logon** enabled with a very high logon count (kiosk-style; review before production).  
- **First logon** invokes a command under `C:\Windows\Setup\Scripts\`verify that path matches where your `$OEM$` copy lands and that the launcher (`cmd` vs `PowerShell` vs `runas`) matches the script you intend to run.

### `SetupComplete.cmd`

Runs after setup, switches to **`Bin`**, and **`reg import`s every `.reg` in alphabetical order**so naming matters (`GSecurity.reg` vs `Services.reg` order is deterministic).

### `GSecurity.bat` (under `Bin`)

A **separate**, more invasive path:

1. Self-elevates via UAC.  
2. Imports **all `*.reg` in its directory** (again: alphabetical).  
3. Applies **`takeown` / `icacls`** to selected system binaries (`WmiPrvSE.exe`, `dllhost.exe`, `conhost.exe`, `winmm.dll`, ).  
4. **`shutdown /r /t 0`**  **immediate reboot**.

> **Warning:** That batch is destructive to default ACLs and forces a reboot. Use only when you explicitly want that behavior; for many installs, **`SetupComplete.cmd` + `.reg` only** is enough.

---

## What `GSecurity.reg` covers (overview)

The file is large by design. At a high level it configures:

| Area | Examples |
|------|------------|
| **Browsers** | Managed policies for Brave, Chrome, Edge, Firefox, Zen, Arc, Vivaldi; forced extension lists; uBlock-style admin JSON; PAC URLs for filtering / proxy |
| **Trust store** | Removes or **disallows** specific root certificates; adds targeted trust entries |
| **Firewall** | Windows Firewall **on**, default **inbound block** / outbound allow profiles; disables common remote-admin surface in policy |
| **Defender** | **Attack Surface Reduction** rules enabled via policy |
| **Privacy / telemetry** | Reduced diagnostic data, WER tweaks, clipboard cloud off, etc. |
| **RDP / Remote assistance** | Largely **disabled** / restricted |
| **Hardening misc** | LSASS mitigation options, SMB signing paths, WinRM restrictions, IPv6 transition toggles, Game DVR off, gaming-oriented timer/GPU scheduler tweaks |
| **Explorer / shell** | Recycle bin behavior, seconds in clock, **context menus** (Take Ownership, Reset NTFS permissions, Open PowerShell/CMD as admin, file hashes, desktop firewall submenu) |
| **IPsec** | Embeds a **GSecurity Policy** block in the registry (advanced; validate on your build) |

Treat the `.reg` as **source**: diff it, trim what you do not want, and test on VMs.

---

## `Services.reg`

Sets **`SvcHostSplitDisable=1`** across a very wide list of Windows services so each gets its **own** `svchost` instancetrading **RAM** for **isolation** and easier **service-level troubleshooting**. This is a **deliberate performance / footprint trade-off**; not every deployment wants it.

---

## PowerShell tools in `Bin`

| Script | Role |
|--------|------|
| **`Antivirus.ps1`** | Monolithic **EDR/antivirus orchestrator**: managed job intervals, external job dispatch to `AgentsAntivirus\Bin` when present, learning mode, chaos/self-test switches. Version line in the header tracks **GEDR alignment** (e.g. v2.27.x - GEDR 27). Prefer **`GEDR.exe`** for production tray/service; keep this script for automation or ISO staging. |
| **`Retaliate.ps1`** | **Browser-only** network monitoring with optional retaliation logic; **games and non-browser apps** are excluded by design. |
| **`RootkitKiller.ps1`** | Uses **HTTP.sys ETW** patterns to find suspicious unsigned listeners; optional **scheduled-task** persistence. |
| **`Install-PasswordRotator.ps1`** | Password rotation helper (review before enabling in your environment). |

Typical flags for `Antivirus.ps1` (see script header for the full list):

```powershell
.\Antivirus.ps1              # normal run
.\Antivirus.ps1 -Uninstall   # remove persistence / stop
.\Antivirus.ps1 -LearningMode
.\Antivirus.ps1 -SelfTest
```

---

## Building a bootable image

1. Start from a **Windows installation ISO** or extracted `sources\install.wim`.  
2. Merge this repos **`Iso\sources\$OEM$`** tree into your medias **`sources\$OEM$`**.  
3. Place **`autounattend.xml`** at the **root of the ISO** (or pass it to setup per Microsofts docs).  
4. Replace **`[KEY]`** in `autounattend.xml` with a valid key or your KMS/retail flow.  
5. Rebuild ISO with **oscdimg**, **Media Creation Tool** workflow, or your preferred pipeline.  

Always **test in a VM** before touching physical machines.

---

## Relationship to GEDR

- **[GEDR](https://gorstak.eu)** (`GEDR.exe`) is the **tray + service** product with a defined release version (e.g. **28.0.0.0**).  
- **`Antivirus.ps1`** changelog lines document **parity goals** with GEDR; bump both when you ship a coordinated release.  
- Paths like `%ProgramData%\GEDR\` are expected to be **excluded** from aggressive cleanersalready reflected in older GEDR compatibility notes inside the script.

---

## Safety & ethics

- These settings are **powerful**: they can **break apps**, **block network paths**, and **change trust** for TLS.  
- **Empty default passwords** and **auto-logon** are **unsafe** on networkstreat sample XML as a **template**.  
- Some techniques (connection retaliation, killing processes) can **disrupt legitimate software**. Run only where you have **authorization** and **recovery plans**.

---

## Support

OEM information in `autounattend.xml` currently references **Gorstak** and a **Discord** support URLupdate to match your distribution channel.

---

<div align="center">

**GSecurity**  *Gorstak OEM & hardening layer*

</div>
---

## Comprehensive legal disclaimer

This project is intended for authorized defensive, administrative, research, or educational use only.

- Use only on systems, networks, and environments where you have explicit permission.
- Misuse may violate law, contracts, policy, or acceptable-use terms.
- Running security, hardening, monitoring, or response tooling can impact stability and may disrupt legitimate software.
- Validate all changes in a test environment before production use.
- This project is provided "AS IS", without warranties of any kind, including merchantability, fitness for a particular purpose, and non-infringement.
- Authors and contributors are not liable for direct or indirect damages, data loss, downtime, business interruption, legal exposure, or compliance impact.
- You are solely responsible for lawful operation, configuration choices, and compliance obligations in your jurisdiction.

---

<p align="center">
  <sub>Built with care by <strong>Gorstak</strong></sub>
</p>
