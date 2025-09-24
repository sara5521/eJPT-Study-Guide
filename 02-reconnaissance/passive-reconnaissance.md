# 🕵️ Passive Reconnaissance - Information Gathering Without Detection

**Complete guide to passive reconnaissance techniques for gathering intelligence without directly interacting with target systems**
**Location:** `02-reconnaissance/passive-reconnaissance.md`

## 🎯 What is Passive Reconnaissance?

Passive reconnaissance is the process of gathering information about a target without directly interacting with their systems or networks. This approach leaves no traces in target logs and reduces the risk of detection during the information gathering phase.

Key characteristics include:
- No direct contact with target systems
- Utilizes publicly available information
- Leverages third-party sources and databases
- Forms the foundation for active reconnaissance
- Critical for understanding the attack surface

## 📦 Tools and Resources Required

### Pre-installed Tools (Kali Linux):
- **whois** - Domain registration information
- **dig** - DNS lookup utility
- **nslookup** - DNS query tool
- **host** - DNS lookup utility
- **curl/wget** - Web content retrieval

### Online Resources:
- Search engines (Google, Bing, DuckDuckGo)
- Social media platforms
- Professional networking sites
- Public databases and directories

## 🔧 Basic Methodology and Workflow

### Passive Reconnaissance Workflow:
1. **Target Definition:** Clearly define scope and objectives
2. **Domain Intelligence:** Gather domain and DNS information
3. **Search Engine Reconnaissance:** Use advanced search operators
4. **Social Media Intelligence:** Collect information from social platforms
5. **Technical Fingerprinting:** Identify technologies and services
6. **Documentation:** Record all findings systematically

### Command Structure:
```bash
# Basic domain information
whois target-domain.com

# DNS enumeration
dig target-domain.com
nslookup target-domain.com

# Subdomain discovery
dig @8.8.8.8 target-domain.com ANY
```

## ⚙️ Domain and DNS Intelligence

### WHOIS Information Gathering:
| Command | Purpose | Example |
|---------|---------|---------|
| `whois domain.com` | Domain registration details | `whois google.com` |
| `whois -h whois.arin.net IP` | IP address ownership | `whois -h whois.arin.net 8.8.8.8` |
| `whois -h whois.radb.net domain.com` | Routing information | `whois -h whois.radb.net google.com` |

### DNS Enumeration Commands:
| Command | Purpose | Example |
|---------|---------|---------|
| `dig domain.com` | Basic DNS lookup | `dig google.com` |
| `dig domain.com MX` | Mail server records | `dig google.com MX` |
| `dig domain.com NS` | Name server records | `dig google.com NS` |
| `dig domain.com TXT` | Text records | `dig google.com TXT` |
| `dig @ns1.domain.com domain.com AXFR` | Zone transfer attempt | `dig @ns1.google.com google.com AXFR` |

## 🧪 Real Lab Examples

### Example 1: Domain Information Gathering
```bash
# Gather basic domain information
whois targetcorp.com
# Output: Shows registrant details, creation date, name servers, registrar

# DNS record enumeration
dig targetcorp.com
# Output: A records showing IP addresses

dig targetcorp.com MX
# Output: Mail server information
# targetcorp.com. 3600 IN MX 10 mail.targetcorp.com.
# targetcorp.com. 3600 IN MX 20 mail2.targetcorp.com.

dig targetcorp.com NS
# Output: Name servers
# targetcorp.com. 86400 IN NS ns1.targetcorp.com.
# targetcorp.com. 86400 IN NS ns2.targetcorp.com.
```

### Example 2: Advanced DNS Enumeration
```bash
# Reverse DNS lookup
dig -x 192.168.1.100
# Output: PTR record showing hostname

# Zone transfer attempt
dig @ns1.targetcorp.com targetcorp.com AXFR
# Output: Either complete zone data or "Transfer failed" message

# TXT records (often contain useful information)
dig targetcorp.com TXT
# Output: SPF records, verification tokens, other technical data
```

### Example 3: Subdomain Discovery via DNS
```bash
# Common subdomain enumeration
dig www.targetcorp.com
dig mail.targetcorp.com
dig ftp.targetcorp.com
dig admin.targetcorp.com

# DNS brute force using host command
host www.targetcorp.com
host mail.targetcorp.com
# Output: IP addresses for existing subdomains
```

## 🔍 Search Engine Intelligence (OSINT)

### Google Dorking Operators:
| Operator | Purpose | Example |
|----------|---------|---------|
| `site:` | Search within specific site | `site:targetcorp.com` |
| `filetype:` | Search for specific file types | `site:targetcorp.com filetype:pdf` |
| `intitle:` | Search in page titles | `intitle:"login" site:targetcorp.com` |
| `inurl:` | Search in URLs | `inurl:admin site:targetcorp.com` |
| `cache:` | View cached version | `cache:targetcorp.com` |

### Social Media Intelligence:
| Platform | Information Gathered | Search Techniques |
|----------|---------------------|-------------------|
| LinkedIn | Employee information, org structure | Company pages, employee searches |
| Facebook | Company pages, employee profiles | Graph search, public posts |
| Twitter | Real-time information, announcements | Hashtag searches, user timelines |
| GitHub | Source code, configuration files | Repository searches, user profiles |

## 🧪 Advanced Lab Examples

### Example 4: Complete Passive Reconnaissance Workflow
```bash
# Phase 1: Basic domain intelligence
whois targetcorp.com > recon_results.txt
echo "=== DNS Records ===" >> recon_results.txt
dig targetcorp.com ANY >> recon_results.txt

# Phase 2: Subdomain enumeration
echo "=== Subdomains ===" >> recon_results.txt
for sub in www mail ftp admin api blog shop; do
    host $sub.targetcorp.com >> recon_results.txt 2>/dev/null
done

# Phase 3: Web technologies identification
curl -I http://targetcorp.com > web_headers.txt
# Output: Server headers revealing web technologies
# Server: Apache/2.4.41 (Ubuntu)
# X-Powered-By: PHP/7.4.3
```

### Example 5: Advanced Search Engine Reconnaissance
```bash
# Search for sensitive files
# Google search: site:targetcorp.com filetype:pdf
# Results: Employee directories, financial reports, technical documentation

# Search for login portals
# Google search: site:targetcorp.com inurl:login
# Results: Administrative interfaces, customer portals

# Search for configuration files
# Google search: site:targetcorp.com filetype:xml OR filetype:conf
# Results: Configuration files, potentially with credentials
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Domain information gathering (25%)** - WHOIS, DNS enumeration
- **Search engine reconnaissance (20%)** - Google dorking, OSINT
- **DNS record analysis (20%)** - Understanding different record types
- **Subdomain discovery (15%)** - Passive subdomain enumeration
- **Information documentation (10%)** - Systematic record keeping
- **Technology identification (10%)** - Passive fingerprinting

### Critical Commands to Master:
```bash
# Must-know commands for exam
whois target-domain.com          # Domain registration details
dig target-domain.com            # Basic DNS lookup
dig target-domain.com MX         # Mail server discovery
dig target-domain.com NS         # Name server identification
host target-ip                   # Reverse DNS lookup
curl -I http://target-domain.com # HTTP headers analysis
```

### eJPT Exam Scenarios:
1. **Scenario 1: Target Organization Research**
   - Required skills: Domain analysis, employee identification
   - Expected commands: whois, dig, social media searches
   - Success criteria: Complete organizational profile

2. **Scenario 2: Infrastructure Mapping**
   - Required skills: DNS enumeration, subdomain discovery
   - Expected commands: dig with various record types, zone transfer attempts
   - Success criteria: Network infrastructure understanding

### Exam Tips and Tricks:
- **Tip 1:** Always start with passive reconnaissance before active scanning
- **Tip 2:** Document everything - passive recon findings guide active testing
- **Tip 3:** Use multiple DNS servers for comprehensive results
- **Tip 4:** Combine multiple OSINT sources for complete picture

### Common eJPT Questions:
- Identifying mail servers through DNS records
- Discovering subdomains through passive techniques
- Extracting organizational information from WHOIS data
- Using search engines to find sensitive information

## ⚠️ Common Issues & Troubleshooting

### Issue 1: DNS Queries Returning No Results
**Problem:** DNS queries fail or return empty results
**Cause:** DNS server restrictions or domain protection
**Solution:**
```bash
# Try different DNS servers
dig @8.8.8.8 target-domain.com
dig @1.1.1.1 target-domain.com
dig @208.67.222.222 target-domain.com

# Use different query types
dig target-domain.com ANY
nslookup target-domain.com
host target-domain.com
```

### Issue 2: WHOIS Information Limited
**Problem:** WHOIS queries return minimal information
**Cause:** Privacy protection services or registry policies
**Solution:**
```bash
# Try different WHOIS servers
whois -h whois.arin.net domain.com
whois -h whois.ripe.net domain.com

# Historical WHOIS data (manual research)
# Use archive.org or historical databases
```

### Issue 3: Search Engine Blocking
**Problem:** Search engines limiting or blocking automated queries
**Prevention:**
```bash
# Use manual searches instead of automated tools
# Vary search patterns and timing
# Use different search engines alternately
```

## 🔗 Integration with Other Tools

### Passive → Active Reconnaissance Flow:
```bash
# Passive reconnaissance provides targets for active scanning
# Step 1: Passive discovery
whois targetcorp.com | grep "Name Server" > nameservers.txt

# Step 2: Results feed into active reconnaissance
# Use discovered subdomains for nmap scanning
# Use identified technologies for vulnerability assessment
```

### Integration with Documentation:
```bash
# Create comprehensive target profile
echo "=== Target Profile ===" > target_profile.txt
echo "Domain: targetcorp.com" >> target_profile.txt
whois targetcorp.com | grep -E "(Registrant|Admin|Tech)" >> target_profile.txt
dig targetcorp.com | grep -A1 "ANSWER SECTION" >> target_profile.txt
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **WHOIS Records:** Save complete registration information
2. **DNS Records:** Document all discovered DNS entries
3. **Search Results:** Screenshot relevant search engine results
4. **Social Media Findings:** Document employee and organizational information

### Passive Reconnaissance Report Template:
```markdown
## Passive Reconnaissance Results

### Target Information
- Primary Domain: target-domain.com
- Date/Time: 2024-XX-XX XX:XX UTC
- Scope: Passive information gathering only

### Domain Intelligence
- **Registrant:** Organization details from WHOIS
- **Creation Date:** Domain age and history
- **Name Servers:** DNS infrastructure

### DNS Records Summary
```bash
# All DNS records discovered
dig results_summary
```

### Discovered Assets
- **Subdomains:** List of identified subdomains
- **Mail Servers:** Email infrastructure
- **Technologies:** Identified web technologies
- **Social Media:** Relevant social media presence

### Key Findings
- Finding 1: Significant discovery with implications
- Finding 2: Potential security concerns identified
- Finding 3: Useful intelligence for next phase
```

### Automation Scripts:
```bash
#!/bin/bash
# Passive reconnaissance automation script
domain=$1
echo "Starting passive reconnaissance for: $domain"

# WHOIS information
whois $domain > ${domain}_whois.txt

# DNS enumeration
dig $domain > ${domain}_dns.txt
dig $domain MX >> ${domain}_dns.txt
dig $domain NS >> ${domain}_dns.txt
dig $domain TXT >> ${domain}_dns.txt

echo "Results saved to ${domain}_* files"
```

## 📚 Additional Resources

### Official Documentation:
- DNS RFC standards: https://www.ietf.org/rfc/rfc1035.txt
- WHOIS protocol: https://tools.ietf.org/html/rfc3912

### OSINT Frameworks:
- OSINT Framework: https://osintframework.com/
- Intel Techniques: https://inteltechniques.com/
- Maltego Community: https://www.maltego.com/

### Practice Resources:
- OSINT exercises: Various CTF platforms
- Legal OSINT targets: Public organizations, bug bounty scopes
- Training labs: TryHackMe OSINT rooms

### Related Tools:
- **theHarvester:** Automated email and subdomain discovery
- **Maltego:** Visual link analysis and OSINT
- **Shodan:** Internet-connected device search engine
- **Recon-ng:** Web-based reconnaissance framework
