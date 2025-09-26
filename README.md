# 🛡️ eJPT v2 Complete Study Guide

> **Comprehensive study guide for eLearnSecurity Junior Penetrator (eJPT) v2 certification exam**

A complete, practical study guide covering all eJPT v2 exam objectives with real lab examples, command references, and hands-on techniques. This guide follows the actual penetration testing methodology used in the exam.

## 🎯 About eJPT v2

The **eLearnSecurity Junior Penetrator (eJPT)** is a practical certification that validates your ability to:
- Perform network penetration testing
- Assess web applications for security vulnerabilities  
- Use penetration testing tools effectively
- Document findings professionally
- Think like an ethical hacker

**Exam Format:** 72-hour practical exam with real vulnerable machines  
**Passing Score:** Complete objectives and submit professional report  
**Prerequisites:** Basic networking and Linux knowledge recommended

## 📚 Study Guide Structure

### 🎓 **01 - Theory Foundations**
Essential background knowledge and core concepts
- [Networking Fundamentals](01-theory-foundations/networking-fundamentals.md) - TCP/IP, OSI model, protocols
- [eJPT Methodology](01-theory-foundations/ejpt-methodology.md) - Official testing approach
- [Linux Essentials](01-theory-foundations/linux-essentials.md) - Command line basics
- [Information Gathering Basics](01-theory-foundations/information-gathering-basics.md) - OSINT fundamentals

### 🔍 **02 - Reconnaissance** 
Passive and active information gathering techniques
- [Passive Reconnaissance](02-reconnaissance/passive-reconnaissance.md) - OSINT and passive discovery
- [Nmap Comprehensive Guide](02-reconnaissance/nmap-comprehensive-guide.md) - Complete nmap reference
- [Service Fingerprinting](02-reconnaissance/service-fingerprinting.md) - Service identification techniques

### 🌐 **03 - Host Discovery**
Network mapping and host identification
- [Network Discovery Methods](03-host-discovery/network-discovery-methods.md) - Finding live hosts
- [Network Range Scanning](03-host-discovery/network-ranges-scanning.md) - Subnet enumeration

### 🔌 **04 - Port Scanning**
Port enumeration and service discovery
- [Port Scanning Techniques](04-port-scanning/port-scanning-techniques.md) - Various scanning methods
- [Nmap Scripting Engine](04-port-scanning/nmap-scripting-engine.md) - NSE scripts and automation
- [Manual Scanning Methods](04-port-scanning/manual-scanning-methods.md) - Non-nmap techniques

### 🕵️ **05 - Service Enumeration**
Deep service analysis and vulnerability identification
- [HTTP Enumeration Complete](05-service-enumeration/http-enumeration-complete.md) - Web server analysis
- [Web Directory Enumeration](05-service-enumeration/web-directory-enumeration.md) - Directory busting
- [FTP Complete Guide](05-service-enumeration/ftp-complete-guide.md) - FTP service testing
- [SSH Enumeration](05-service-enumeration/ssh-enumeration.md) - SSH service analysis
- [SMB Enumeration Complete](05-service-enumeration/smb-enumeration-complete.md) - Windows sharing
- [DNS Enumeration](05-service-enumeration/dns-enumeration.md) - DNS reconnaissance
- [Database Enumeration](05-service-enumeration/database-enumeration.md) - MySQL, MSSQL testing
- [SMTP Enumeration Complete](05-service-enumeration/smtp-enumeration-complete.md) - Email service testing

### 🛡️ **06 - Vulnerability Assessment**
Automated and manual vulnerability discovery
- [Automated Vulnerability Scanning](06-vulnerability-assessment/automated-vulnerability-scanning.md) - Scanner usage
- [Manual Testing Techniques](06-vulnerability-assessment/manual-testing-techniques.md) - Manual assessment
- [Vulnerability Research](06-vulnerability-assessment/vulnerability-research.md) - CVE research methods
- [WMAP Vulnerability Scanning](06-vulnerability-assessment/wmap-vulnerability-scanning.md) - Metasploit scanner
- [DavTest WebDAV Scanner](06-vulnerability-assessment/davtest-webdav-scanner.md) - WebDAV testing

### 💥 **07 - Exploitation**
Active exploitation techniques and payload delivery
- [Metasploit Essentials](07-exploitation/metasploit-essentials.md) - Complete Metasploit guide
- [Payload Generation](07-exploitation/payload-generation.md) - Custom payload creation
- [Common Exploits](07-exploitation/common-exploits.md) - Frequently used exploits
- [SQL Injection Complete Guide](07-exploitation/sql-injection-complete-guide.md) - SQLi techniques
- [Web Exploitation](07-exploitation/web-exploitation.md) - Web application attacks
- [Privilege Escalation](07-exploitation/privilege-escalation.md) - Post-compromise escalation
- [Shellshock Exploitation](07-exploitation/shellshock-exploitation-complete.md) - CVE-2014-6271

### 🔐 **08 - Password Attacks**
Credential attack techniques and tools
- [Hydra Complete Guide](08-password-attacks/hydra-complete-guide.md) - Brute force attacks
- [Hash Cracking](08-password-attacks/hash-cracking.md) - Password hash cracking
- [Password Lists & Wordlists](08-password-attacks/password-lists-wordlists.md) - Dictionary attacks

### 🌐 **09 - Web Application Pentesting**
Specialized web application security testing
- [Web Reconnaissance](09-web-application-pentesting/web-reconnaissance.md) - Web app discovery
- [Authentication Testing](09-web-application-pentesting/authentication-testing.md) - Login mechanisms
- [Injection Attacks](09-web-application-pentesting/injection-attacks.md) - Various injection types
- [File Upload Attacks](09-web-application-pentesting/file-upload-attacks.md) - Upload vulnerabilities

### 🎯 **10 - Post-Exploitation**
Maintaining access and lateral movement
- [Maintaining Access](10-post-exploitation/maintaining-access.md) - Persistence techniques
- [File Transfer Methods](10-post-exploitation/file-transfer-methods.md) - Data movement
- [Data Exfiltration](10-post-exploitation/data-exfiltration.md) - Information extraction
- [Covering Tracks](10-post-exploitation/covering-tracks.md) - Anti-forensics

### 📝 **11 - Reporting**
Professional documentation and reporting
- [eJPT Reporting Guide](11-reporting/ejpt-reporting-guide.md) - Report structure and format
- [Letter of Engagement](11-reporting/letter-of-engagement.md) - Scope documentation

## 🚀 Quick Start Guide

### For Complete Beginners:
1. **Start Here:** [Theory Foundations](01-theory-foundations/) - Build essential knowledge
2. **Practice Labs:** Set up VirtualBox with Kali Linux and Metasploitable
3. **Follow Order:** Progress through sections 01-11 sequentially
4. **Hands-On:** Practice every command in a lab environment

### For Experienced Users:
1. **Assessment:** Review [eJPT Methodology](01-theory-foundations/ejpt-methodology.md)
2. **Tool Focus:** Jump to specific tools you need to master
3. **Practice:** Focus on weak areas identified in practice exams
4. **Exam Prep:** Review [Reporting Guide](11-reporting/ejpt-reporting-guide.md)

## 🛠️ Required Tools & Lab Setup

### Essential Tools (Pre-installed in Kali Linux):
- **nmap** - Network scanning and enumeration
- **Metasploit Framework** - Exploitation platform
- **Burp Suite Community** - Web application testing
- **Hydra** - Password brute forcing
- **Gobuster** - Directory enumeration
- **Netcat** - Network connectivity
- **John the Ripper** - Password cracking

### Recommended Lab Environment:
```bash
# Virtual Machines Needed:
- Kali Linux 2024.x (Attacker machine)
- Metasploitable2 (Target practice)
- DVWA (Web application testing)
- VulnHub machines (Additional practice)

# Network Setup:
- NAT Network for machine communication
- Host-only network for isolation
- Minimum 8GB RAM, 50GB storage
```

## 📊 Study Plan & Timeline

### **Intensive (2-4 weeks):**
- **Week 1:** Theory + Reconnaissance (Sections 01-02)
- **Week 2:** Discovery + Scanning + Enumeration (Sections 03-05)
- **Week 3:** Assessment + Exploitation (Sections 06-07)  
- **Week 4:** Passwords + Web + Post-Exploitation + Reporting (Sections 08-11)

### **Standard (6-8 weeks):**
- **Weeks 1-2:** Foundations and Theory (Section 01)
- **Weeks 3-4:** Information Gathering (Sections 02-05)
- **Weeks 5-6:** Vulnerability Assessment and Exploitation (Sections 06-07)
- **Weeks 7-8:** Web Applications and Reporting (Sections 08-11)

### **Extended (3-4 months):**
- **Month 1:** Theory and Basic Tools (Sections 01-04)
- **Month 2:** Service Enumeration and Assessment (Sections 05-06)
- **Month 3:** Exploitation Techniques (Sections 07-09)
- **Month 4:** Post-Exploitation and Practice Exams (Sections 10-11)

## 🎯 eJPT Exam Tips

### Before the Exam:
- [ ] Complete at least 5 practice penetration tests
- [ ] Master nmap, Metasploit, Burp Suite, and Hydra
- [ ] Practice report writing with real findings
- [ ] Set up proper lab environment for practice
- [ ] Review methodology and ensure consistent approach

### During the Exam:
- [ ] **Take notes** of everything you discover and attempt
- [ ] **Screenshot all findings** with timestamps
- [ ] **Follow methodology** systematically - don't skip steps
- [ ] **Manage time** - you have 72 hours but use them wisely
- [ ] **Document as you go** - don't wait until the end

### After Exploitation:
- [ ] **Maintain detailed logs** of all successful attacks
- [ ] **Collect evidence** properly with proper timestamps
- [ ] **Verify findings** before including in report
- [ ] **Write clear, professional report** following provided template

## 📈 Progress Tracking

Track your progress through the study guide:

```
Theory Foundations:     [■■■■■] 100% Complete
Reconnaissance:         [■■■■■] 100% Complete
Host Discovery:         [■■■■■] 100% Complete
Port Scanning:          [■■■■■] 100% Complete
Service Enumeration:    [■■■■■] 100% Complete
Vulnerability Assessment: [■■■■□] 80% Complete
Exploitation:           [■■■□□] 60% Complete
Password Attacks:       [■■■□□] 60% Complete
Web Application Testing: [■■□□□] 40% Complete
Post-Exploitation:      [■□□□□] 20% Complete
Reporting:              [■■■■■] 100% Complete
```

## 🤝 Contributing

This study guide is continuously improved based on:
- **Real exam experiences** from successful candidates
- **Updated tool versions** and new techniques
- **Community feedback** and suggestions
- **Latest eJPT syllabus** changes

### How to Contribute:
1. **Fork** this repository
2. **Create** feature branch (`git checkout -b feature/improvement`)
3. **Commit** your changes (`git commit -am 'Add new technique'`)
4. **Push** to branch (`git push origin feature/improvement`)
5. **Create** Pull Request with detailed description

### Contribution Guidelines:
- Include **real lab examples** with actual command outputs
- Follow the **established template format** for consistency
- **Test all commands** in actual lab environment
- **Provide screenshots** where helpful
- **Update documentation** if adding new tools

## 📜 License & Disclaimer

This study guide is released under the **MIT License** - see [LICENSE](LICENSE) file for details.

### Educational Use Only:
- **Purpose:** Educational and certification preparation only
- **Ethics:** Always obtain proper authorization before testing
- **Legal:** Respect all applicable laws and regulations
- **Responsibility:** Users are responsible for their actions

### Acknowledgments:
- **eLearnSecurity** for creating the eJPT certification
- **InfoSec Community** for sharing knowledge and techniques
- **Tool Developers** for creating the security tools referenced
- **Contributors** who help improve this guide

## 📞 Support & Community

### Study Resources:
- **Official eJPT:** [elearnsecurity.com](https://elearnsecurity.com)
- **Practice Labs:** INE, VulnHub, HackTheBox
- **Documentation:** Each tool's official documentation

### Community Support:
- **Discord:** InfoSec study groups
- **Reddit:** r/eJPT, r/cybersecurity, r/AskNetsec
- **Forums:** InfoSec-related discussion forums

---

## 🚀 Ready to Start?

**Begin your eJPT journey:**
1. **Clone this repository:** `git clone https://github.com/yourusername/eJPT-Study-Guide.git`
2. **Set up your lab** following the setup guide
3. **Start with Section 01** - Theory Foundations
4. **Practice consistently** - hands-on experience is key
5. **Track progress** using the checklist above

**Remember:** The eJPT is a practical exam that tests your ability to think like a penetration tester. Focus on understanding concepts, not just memorizing commands.

**Good luck on your eJPT journey!** 🎯

---

*Last updated: January 2025 | eJPT v2 Syllabus Compliant*
