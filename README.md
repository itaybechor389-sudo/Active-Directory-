<div align="center">

```
╔══════════════════════════════════════════════════════════════════╗
║                    AD-SENTINEL  v1.0                             ║
║            Active Directory Security Auditor                     ║
╚══════════════════════════════════════════════════════════════════╝
```

# AD-Sentinel
### Active Directory Security Auditor


---

## Overview

AD-Sentinel connects from a Kali Linux attacker machine to a Windows Server Active Directory environment using LDAP/NTLM, performs network discovery, enumerates AD objects, and runs automated security checks — all through a dark, professional GUI interface.

**Lab Environment:**

| Role | IP Address | OS |
|------|-----------|-----|
| Attacker (Kali Linux) | `192.168.108.156` | Kali Linux 2024 |
| Domain Controller | `192.168.108.10` | Windows Server 2019 |
| Domain | `MYDOMAIN.LOCAL` | AD DS · DHCP · DNS |
| Subnet | `192.168.108.0/24` | — |

---

## Features

| Tab | What it Does |
|-----|-------------|
| **◈ Dashboard** | Live service status for all DC ports, environment overview, ping DC |
| **⬡ Network Scan** | nmap-based host discovery with 4 scan modes (ping, SYN, version, aggressive) |
| **◎ AD Enumeration** | LDAP enumeration of Users, Groups, Computers, OUs, and Privileged Accounts |
| **⚠ Security Audit** | Automated checks: null sessions, SMB signing, password policy, open ports, anonymous LDAP |
| **◉ Reports** | Export full security report as HTML, JSON, or plain Text |

---

## Installation

```bash
# 1. Clone or download the tool
git clone https://github.com/itaybechor389-sudo/ad-sentinel
cd ad-sentinel

# 2. Install Python dependencies (Kali Linux)
pip install customtkinter ldap3 --break-system-packages

# 3. Install system tools
sudo apt install nmap smbclient -y

# 4. Run
python3 ad_sentinel.py
```

---

## Usage

### Step 1 — Dashboard
- Click **CHECK SERVICES** to verify connectivity to the DC
- All critical services (LDAP, DNS, SMB, WinRM) show ONLINE/OFFLINE status in real time

### Step 2 — Network Scan
- Set subnet: `192.168.108.0/24`
- Choose scan mode (Host Discovery / SYN / Version / Aggressive)
- Click **START SCAN** — discovered hosts appear in the table with open ports

### Step 3 — AD Enumeration
- Enter DC IP, domain (`MYDOMAIN.LOCAL`), username, and password
- Click **CONNECT** → wait for `● CONNECTED`
- Enumerate each object type: Users, Groups, Computers, OUs, Admins

### Step 4 — Security Audit
- Select audit modules
- Click **RUN ALL AUDITS**
- Risk Score is calculated automatically (0–100)

### Step 5 — Reports
- Click **GENERATE** to export HTML / JSON / Text report
- HTML report includes full environment overview and color-coded findings

---

## Security Checks

| Check | Method | What It Detects |
|-------|--------|----------------|
| **Null Sessions** | `rpcclient -U '' -N` | Anonymous IPC$ access |
| **SMB Signing** | `nmap --script smb-security-mode` | Signing disabled / not enforced |
| **Password Policy** | rpcclient `getdompwinfo` | Weak minimum length, no complexity |
| **Open Ports** | Socket scan | Telnet (23), FTP (21), RDP (3389), WinRM (5985) |
| **Anonymous LDAP** | ldap3 anonymous bind | Unauthenticated LDAP enumeration |
| **AD Enumeration** | LDAP/NTLM queries | Users, groups, computers, privileged accounts |

---

## MITRE ATT&CK Mapping

| Security Check | Technique ID | Technique Name |
|----------------|-------------|----------------|
| AD User Enumeration | T1087.002 | Account Discovery: Domain Account |
| Null Session / Share Enum | T1135 | Network Share Discovery |
| SMB Signing Disabled | T1557.001 | Adversary-in-the-Middle: LLMNR/NBT-NS |
| Password Policy Weakness | T1110 | Brute Force |
| Open RDP | T1021.001 | Remote Services: Remote Desktop Protocol |
| Anonymous LDAP Bind | T1087.002 | Account Discovery: Domain Account |

---

## Tech Stack

```
Python 3.x
├── customtkinter     — Premium dark GUI framework
├── ldap3             — LDAP / Active Directory queries (NTLM auth)
├── tkinter (ttk)     — Treeview tables
├── threading         — Non-blocking scans
├── socket            — Port connectivity checks
├── subprocess        — nmap / rpcclient execution
└── json / pathlib    — Report generation
```

---

## Project Structure

```
ad-sentinel/
├── ad_sentinel.py    — Main application (single file)
└── README.md         — This file
```

---

## Author

**Itay Bechor**
SOC Analyst Student | Cyberium Academy — John Bryce / ThinkCyber
Course: RTX2026 Network Security
GitHub: [@itaybechor389-sudo](https://github.com/itaybechor389-sudo)

---

<div align="center">


</div>
