# 🔍 Passive Reconnaissance - Complete eJPT Guide

**Comprehensive passive information gathering techniques for eJPT exam preparation and penetration testing methodology**

**Location:** `02-reconnaissance/passive-reconnaissance.md`

## 🎯 What is Passive Reconnaissance?

Passive reconnaissance involves gathering information about a target without directly interacting with their systems or infrastructure. This stealthy approach to intelligence collection allows penetration testers to build a comprehensive profile of their target organization through publicly available sources, search engines, social media platforms, and various online databases. The key advantage is remaining undetected while collecting valuable information that can guide later testing phases.

Key capabilities include:
- Information gathering without detection or attribution
- Target profiling through multiple intelligence sources
- Infrastructure mapping via public records and databases
- Personnel identification and organizational structure analysis
- Technology stack discovery through various online sources
- Security posture assessment through exposed information

## 📦 Core Components Overview

Passive reconnaissance encompasses four primary intelligence gathering disciplines that work synergistically to provide comprehensive target understanding:

- **Google Dorking & Search Intelligence (35%)** - Advanced search techniques for discovering exposed information
- **Shodan & Internet Infrastructure Discovery (25%)** - Internet-connected device and service enumeration
- **Social Media OSINT (20%)** - Human intelligence gathering from social platforms
- **WHOIS & DNS Intelligence (20%)** - Domain registration and infrastructure analysis

## 🔧 Google Dorking & Advanced Search Intelligence

### Understanding Google Dorking
Google Dorking leverages Google's powerful search operators to discover information that organizations may not intend to be publicly accessible. This technique uses specific search queries to find exposed files, login pages, database dumps, configuration files, and vulnerable applications.

### Essential Search Operators
| Operator | Purpose | Example | eJPT Priority |
|----------|---------|---------|---------------|
| `site:` | Search specific domain | `site:example.com` | ⭐⭐⭐ |
| `filetype:` | Search specific file types | `filetype:pdf` | ⭐⭐⭐ |
| `inurl:` | Search in URL | `inurl:admin` | ⭐⭐⭐ |
| `intitle:` | Search in page title | `intitle:"admin panel"` | ⭐⭐⭐ |
| `intext:` | Search in page content | `intext:"confidential"` | ⭐⭐ |
| `"exact phrase"` | Exact match search | `"database backup"` | ⭐⭐⭐ |
| `cache:` | View cached page | `cache:example.com` | ⭐⭐ |
| `-` | Exclude terms | `site:target.com -www` | ⭐⭐ |

### Critical Google Dorks for eJPT
```bash
# Essential configuration file discovery
site:target.com filetype:conf
site:target.com filetype:ini  
site:target.com filetype:xml
site:target.com inurl:config filetype:php

# Database and backup file discovery
site:target.com filetype:sql
site:target.com filetype:db
site:target.com filetype:bak
site:target.com "database backup"

# Admin panel and login discovery
site:target.com inurl:admin
site:target.com inurl:administrator
site:target.com intitle:"admin panel"
site:target.com inurl:login

# Directory listing exploitation
site:target.com intitle:"index of" "parent directory"
intitle:"index of" site:target.com
```

### Practical Google Dorking Example
```bash
# Target: example.com
# Step 1: Basic domain enumeration
site:example.com

# Step 2: Configuration file discovery
site:example.com filetype:conf OR filetype:ini OR filetype:xml
# Results: Found web.config, database.ini, application.xml

# Step 3: Admin interface discovery
site:example.com inurl:admin OR inurl:administrator
# Results: admin.example.com/panel, example.com/administrator

# Step 4: Directory listing exploitation
site:example.com intitle:"index of"
# Results: /files/ directory with employee documents
```

## ⚙️ Shodan & Internet Infrastructure Discovery

### Understanding Shodan
Shodan scans the entire internet and collects banner information from open ports and services, making it invaluable for discovering internet-facing infrastructure without directly interacting with target systems.

### Web Interface Usage
```bash
# Basic search syntax
apache port:80 country:US

# Organization-specific searches
org:"Target Company"
org:"Target Company" port:80,443

# Service-specific discovery
ssh port:22
mysql port:3306
ftp port:21
```

### CLI Installation and Setup
```bash
# Install Shodan CLI
pip install shodan

# Configure API key (get from account.shodan.io)
shodan init YOUR_API_KEY

# Verify setup
shodan info
# Output: Account information and query credits
```

### Essential Shodan Commands for eJPT
```bash
# Organization discovery
shodan search "org:TARGET_ORG" --limit 100

# Web service enumeration  
shodan search "org:TARGET port:80,8080,443,8443" --limit 50

# SSH service discovery
shodan search "org:TARGET port:22" --fields ip_str,product,version

# Database service discovery
shodan search "org:TARGET port:3306,5432,1433" --fields ip_str,port,product

# Host information gathering
shodan host 8.8.8.8
```

### Shodan Integration Workflow
```bash
# Phase 1: Discover organization assets
shodan search "org:TARGET_ORG" --fields ip_str,port --limit 500 > shodan_targets.txt

# Phase 2: Extract unique IP addresses
cat shodan_targets.txt | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u > ip_list.txt

# Phase 3: Feed into active scanning tools
nmap -sS -sV -iL ip_list.txt -oA shodan_confirmed_scan
```

## 🌐 Social Media OSINT & Human Intelligence

### Understanding Social Media OSINT
Social Media OSINT involves collecting publicly available information from social platforms to understand the human element of target organizations, identifying potential attack vectors and gathering information for social engineering.

### LinkedIn Intelligence Gathering
```bash
# Manual LinkedIn reconnaissance workflow
1. Navigate to target company LinkedIn page
2. Analyze "About" section for:
   - Company size and structure
   - Technologies mentioned
   - Office locations
3. Click "See all X employees on LinkedIn"
4. Document key personnel:
   - IT Staff: Names, roles, tenure
   - Security Team: Managers, analysts
   - Developers: Technologies, projects
   - Executives: Decision makers

# Information extraction priorities
- IT Administrator contacts
- Security team composition
- Technology stack mentions
- Recent hires (potential security gaps)
- Employee connections and relationships
```

### Twitter/X Intelligence Collection
```bash
# Search techniques for Twitter intelligence
"from:@company_handle"                    # Official company tweets
"company_name employees"                  # Employee-related discussions  
"#companyname OR @companyname"           # Hashtag and mention analysis
"@company_handle maintenance"            # System maintenance announcements
"company_name VPN" OR "company_name login" # Infrastructure complaints

# Analysis focus areas
- Planned maintenance windows
- Technology frustrations (VPN issues, system problems)
- New employee announcements
- Company culture and internal processes
- Emergency contact information
- Work-from-home policies and procedures
```

### GitHub Repository Analysis
```bash
# GitHub intelligence workflow
1. Search for organization: github.com/TARGET_ORG
2. Analyze public repositories for:
   - Technology stack identification
   - Configuration file examples
   - Development practices
   - API endpoints and structure
   - Database schemas and models

# Key information to extract
- Programming languages and frameworks
- Database connection examples
- API documentation and endpoints
- Development server configurations  
- Third-party service integrations
- Security implementations (or lack thereof)
```

### Social Media OSINT Integration
```bash
# Complete social media reconnaissance chain
linkedin_employee_enumeration → email_format_discovery → phishing_target_list
github_technology_discovery → vulnerability_research → exploit_identification  
twitter_infrastructure_intel → maintenance_window_timing → attack_scheduling
```

## 📝 WHOIS & DNS Intelligence Analysis

### Understanding WHOIS & DNS Enumeration
WHOIS provides domain registration details and administrative information, while DNS enumeration reveals technical infrastructure, subdomains, and service configurations that expand the attack surface.

### Essential WHOIS Commands
```bash
# Domain registration analysis
whois target.com
# Extract: Registration date, registrar, contacts, name servers

# IP address investigation
whois 192.0.2.1  
# Extract: ISP information, geographical location, allocation details

# Multiple registry queries
whois -h whois.arin.net 192.0.2.1      # ARIN registry
whois -h whois.ripe.net 192.0.2.1      # RIPE registry
whois -h whois.apnic.net 192.0.2.1     # APNIC registry
```

### Comprehensive DNS Enumeration
```bash
# Complete DNS record discovery
dig target.com ANY                      # All available DNS records
dig target.com A +short                 # IPv4 addresses
dig target.com AAAA +short              # IPv6 addresses  
dig target.com MX +short                # Mail servers
dig target.com NS +short                # Name servers
dig target.com TXT +short               # Text records (SPF, DKIM, etc.)
dig target.com CNAME +short             # Canonical name records

# Advanced DNS queries
dig @8.8.8.8 target.com ANY             # Query specific DNS server
dig +trace target.com                   # Show query path
dig -x 192.0.2.1                       # Reverse DNS lookup
```

### Subdomain Discovery Techniques
```bash
# Method 1: Manual subdomain enumeration
common_subs="www mail ftp admin test dev staging api"
for sub in $common_subs; do
    dig $sub.target.com +short | grep -v "^$" && echo "$sub.target.com exists"
done

# Method 2: Fierce subdomain discovery
fierce -dns target.com
# Output: Discovered subdomains with IP addresses

# Method 3: DNSrecon comprehensive scanning
dnsrecon -d target.com -t std
# Output: Standard enumeration with A, AAAA, CNAME, MX records

# Method 4: Zone transfer attempts
for ns in $(dig target.com NS +short); do
    echo "Attempting zone transfer from $ns"
    dig @$ns target.com AXFR
done
```

### DNS Intelligence Analysis Workflow
```bash
# Complete DNS intelligence gathering
echo "Starting DNS enumeration for $TARGET"

# Phase 1: Basic DNS enumeration  
dig $TARGET ANY > ${TARGET}_dns_all.txt
dig $TARGET MX +short > ${TARGET}_mail_servers.txt
dig $TARGET NS +short > ${TARGET}_name_servers.txt

# Phase 2: Subdomain discovery
fierce -dns $TARGET > ${TARGET}_subdomains.txt
dnsrecon -d $TARGET -t std >> ${TARGET}_subdomains.txt

# Phase 3: IP address extraction and analysis
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' ${TARGET}_*.txt | sort -u > ${TARGET}_ip_addresses.txt

# Phase 4: WHOIS analysis of discovered IPs
while read ip; do
    whois $ip >> ${TARGET}_whois_analysis.txt
    echo "---" >> ${TARGET}_whois_analysis.txt
done < ${TARGET}_ip_addresses.txt
```

## 🧪 Real Lab Examples

### Example 1: Complete Target Organization Analysis
```bash
# Target: example-corp.com
# Phase 1: Google Dorking Discovery
site:example-corp.com filetype:pdf
# Results: Employee handbook (15 pages), Security policy document
# Intelligence: Company uses Windows AD, Cisco firewalls

# Phase 2: Shodan Infrastructure Discovery  
shodan search "org:Example Corporation" --fields ip_str,port,product
# Results: 23 IP addresses, Apache/2.4.41, OpenSSH 7.4
# Intelligence: Web servers on ports 80/443, SSH access on port 22

# Phase 3: Social Media Intelligence
# LinkedIn analysis: 45 employees, IT team of 5, recent AWS migration
# Twitter mentions: Complaints about VPN downtime, Teams integration issues
# GitHub: example-corp organization with 12 public repos using PHP/MySQL

# Phase 4: DNS/WHOIS Analysis
whois example-corp.com
# Results: Registered 2015, expires 2026, admin@example-corp.com
dig example-corp.com ANY
# Results: Mail servers at mail.example-corp.com, www at 203.0.113.10

# Correlation Analysis
# Cross-reference: Shodan IPs match DNS A records
# Personnel mapping: LinkedIn employees correlate with GitHub contributors
# Technology confirmation: Multiple sources confirm PHP/MySQL/Apache stack
```

### Example 2: Subdomain Discovery and Analysis
```bash
# Target: secure-finance.com
# Method 1: DNS enumeration
dig secure-finance.com ANY
# Results: www, mail, ns1, ns2 subdomains

# Method 2: Automated subdomain discovery
fierce -dns secure-finance.com
# Results: Additional subdomains found
# admin.secure-finance.com: 198.51.100.25
# api.secure-finance.com: 198.51.100.26  
# staging.secure-finance.com: 192.168.1.100 (internal IP leaked)

# Method 3: Google dorking validation
site:*.secure-finance.com -site:www.secure-finance.com
# Results: Confirms admin and api subdomains, discovers dev.secure-finance.com

# Method 4: Shodan correlation
shodan search "org:Secure Finance" port:80,443
# Results: Confirms discovered IP addresses, reveals additional services
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT Success

#### Information Gathering Phase (40% of reconnaissance)
- **Google Dorking proficiency**: Master site:, filetype:, inurl:, intitle: operators
- **Shodan web interface**: Organization searches, service discovery, geographic filtering
- **DNS enumeration**: Complete record analysis, subdomain discovery techniques
- **WHOIS interpretation**: Extract actionable intelligence from registration data

#### Intelligence Analysis Phase (35% of reconnaissance)  
- **Cross-source validation**: Correlate findings across multiple platforms
- **Technology stack identification**: Map complete infrastructure from passive sources
- **Personnel enumeration**: Identify key IT and security staff through social media
- **Attack surface mapping**: Document all discovered entry points and services

#### Documentation and Reporting Phase (25% of reconnaissance)
- **Evidence collection**: Screenshots, command outputs, organized data files
- **Intelligence correlation**: Connect related findings across different sources
- **Risk prioritization**: Identify most valuable targets and attack vectors
- **Report preparation**: Structure findings for technical team consumption

### Critical Commands for eJPT Exam
```bash
# Google Dorking essentials (must memorize)
site:target.com filetype:pdf              # Document discovery
site:target.com inurl:admin                # Admin panel discovery  
site:target.com intitle:"index of"         # Directory listing discovery
site:target.com filetype:sql OR filetype:db # Database file discovery

# DNS enumeration essentials
dig target.com ANY                         # Complete DNS record enumeration
dig target.com MX +short                   # Mail server identification
fierce -dns target.com                     # Automated subdomain discovery
whois target.com                          # Domain registration analysis

# Shodan web interface searches (no CLI required for basic eJPT)
org:"Target Organization"                  # Organization asset discovery
target.com port:80,443                    # Web service identification
ssh port:22 org:"Target"                  # SSH service discovery
```

### eJPT Exam Scenarios and Solutions

#### Scenario 1: Initial Target Assessment
**Question**: "Given the domain example.com, identify all publicly accessible web services."
**Solution Process**:
```bash
# Step 1: DNS enumeration for IP discovery
dig example.com A +short
# Result: 203.0.113.10

# Step 2: Subdomain discovery  
fierce -dns example.com
# Results: www, mail, admin, api subdomains

# Step 3: Shodan verification
# Search: org:"Example" port:80,443
# Results: Confirms web services on ports 80, 443, 8080

# Step 4: Google dorking for additional services
site:example.com inurl:admin OR inurl:login
# Results: admin.example.com/panel, api.example.com/docs
```

#### Scenario 2: Employee and Technology Intelligence
**Question**: "Identify key technical personnel and technology stack for the target organization."
**Solution Process**:
```bash
# Step 1: LinkedIn reconnaissance
# Navigate to company LinkedIn page
# Results: IT team of 4, mentions AWS, Python, MySQL

# Step 2: GitHub analysis
# Search: github.com/target-org
# Results: Public repos showing Django, PostgreSQL, Redis

# Step 3: Google dorking for technology confirmation
site:target.com "powered by" OR "built with" OR "using"
# Results: Confirms Django framework, mentions Docker

# Final intelligence: Python/Django web application, PostgreSQL database, AWS infrastructure
```

## ⚠️ Common Issues & Troubleshooting

### Google Dorking Issues
**Issue**: Too many generic results or Google blocking searches
**Solutions**:
```bash
# Use more specific operators
site:target.com inurl:admin -inurl:wp-admin
site:target.com filetype:pdf -"user manual"

# Alternative search engines
# DuckDuckGo: site:target.com admin
# Bing: site:target.com filetype:conf
```

### Shodan Access Limitations
**Issue**: Free account limitations (100 results per search)
**Solutions**:
```bash
# Use specific filters to maximize relevant results
org:"Target" port:80,443 country:US
org:"Target" apache                    # Instead of broad searches

# Break down large result sets
org:"Target" port:80                   # Separate search
org:"Target" port:443                  # Separate search
```

### DNS Resolution Problems
**Issue**: DNS queries failing or incomplete results
**Solutions**:
```bash
# Try multiple DNS servers
dig @8.8.8.8 target.com ANY
dig @1.1.1.1 target.com ANY  
dig @208.67.222.222 target.com ANY

# Check local DNS configuration
cat /etc/resolv.conf
```

### Social Media Access Restrictions
**Issue**: Limited LinkedIn visibility without account
**Solutions**:
```bash
# Google search alternative
site:linkedin.com "Target Company" "employee"
# Use cached/archived versions when possible
# Focus on public company pages and posts
```

## 🔗 Integration with Active Reconnaissance

### Passive to Active Workflow Transition
```bash
# Phase 1: Passive reconnaissance completion
google_dorking_results → discovered_admin_panels.txt
shodan_intelligence → confirmed_services.txt
social_media_osint → employee_profiles.txt  
dns_enumeration → subdomain_list.txt

# Phase 2: Active reconnaissance preparation
cat discovered_services.txt subdomain_list.txt | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' > active_targets.txt

# Phase 3: Validation scanning
nmap -sS -sV -iL active_targets.txt -oA passive_to_active_validation

# Phase 4: Service enumeration
for service in $(cat confirmed_services.txt); do
    # Targeted service enumeration based on passive findings
done
```

### Intelligence-Driven Active Scanning
```bash
# Use passive intelligence to optimize active scanning
# Example: Passive reconnaissance reveals Apache 2.4.41 on port 8080
nmap -p 8080 --script http-enum target.com
nikto -h http://target.com:8080

# Example: Passive reconnaissance identifies SSH on non-standard port
nmap -p 2222 --script ssh-enum-algos target.com
```

## 📝 Documentation and Reporting Framework

### Evidence Collection Standards
```markdown
## Passive Reconnaissance Report Structure

### Executive Summary
- Target organization overview
- Reconnaissance methodology employed  
- Key findings and risk assessment
- Recommended next steps

### Intelligence Sources
- Google Dorking: X queries executed, Y results analyzed
- Shodan: X searches performed, Y services identified
- Social Media: X platforms analyzed, Y personnel identified
- DNS/WHOIS: X domains enumerated, Y subdomains discovered

### Key Findings
#### Infrastructure Intelligence
- Web Services: IP addresses, technologies, versions
- Mail Services: Server configurations, security settings
- DNS Infrastructure: Authoritative servers, zone configurations
- Network Ranges: Confirmed IP blocks and geographic locations

#### Personnel Intelligence  
- Key IT Staff: Names, roles, contact information, social profiles
- Organizational Structure: Department sizes, reporting relationships
- Technology Skills: Mentioned technologies, certifications, projects
- Security Awareness: Public information sharing, potential vulnerabilities

#### Technology Stack Assessment
- Web Technologies: Frameworks, CMS platforms, server software
- Database Systems: Types, versions, connection methods
- Cloud Services: Providers, service types, configurations
- Security Tools: Mentioned security products, implementations

### Risk Assessment
- High Risk: Exposed sensitive information, vulnerable services
- Medium Risk: Information disclosure, technology fingerprinting
- Low Risk: General organizational information, public data

### Recommendations
- Information security policy review
- Public information exposure assessment  
- Employee security awareness training
- Technical security control implementation
```

### Automated Documentation
```bash
#!/bin/bash
# passive_recon_documentation.sh
TARGET=$1
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
REPORT_DIR="passive_recon_${TARGET}_${DATE}"

mkdir -p $REPORT_DIR/{screenshots,data,analysis}

echo "# Passive Reconnaissance Report for $TARGET" > $REPORT_DIR/report.md
echo "Date: $(date)" >> $REPORT_DIR/report.md
echo "" >> $REPORT_DIR/report.md

# Google Dorking documentation
echo "## Google Dorking Results" >> $REPORT_DIR/report.md
# Add automated google dorking results

# Shodan documentation  
echo "## Shodan Intelligence" >> $REPORT_DIR/report.md
# Add shodan search results

# DNS enumeration documentation
echo "## DNS Enumeration Results" >> $REPORT_DIR/report.md
# Add DNS findings

echo "Passive reconnaissance documentation completed: $REPORT_DIR"
```

## 📚 Additional Resources and References

### Essential Learning Resources
- **SANS SEC487**: Open-Source Intelligence (OSINT) Gathering and Analysis
- **OSINT Framework**: osintframework.com - Comprehensive tool directory
- **IntelTechniques**: inteltechniques.com - Michael Bazzell's OSINT methodology
- **Bellingcat**: bellingcat.com - Advanced online investigation techniques

### Official Documentation
- Google Search Operators: developers.google.com/search/docs
- Shodan Documentation: developer.shodan.io
- DNS Protocol RFC 1035: tools.ietf.org/html/rfc1035
- WHOIS Protocol RFC 3912: tools.ietf.org/html/rfc3912

### Community Resources
- Reddit r/OSINT: Active community for technique sharing
- OSINT Curious: osintcurio.us - Weekly OSINT challenges
- Trace Labs: tracelabs.org - Crowdsourced OSINT for good

### Advanced Tools and Frameworks
- **theHarvester**: Email harvesting and subdomain enumeration
- **Recon-ng**: Modular reconnaissance framework
- **Maltego**: Visual link analysis and data mining platform
- **SpiderFoot**: Automated OSINT collection and analysis
- **Amass**: Advanced subdomain enumeration and network mapping

### Legal and Ethical Considerations
- Always respect terms of service for all platforms
- Only collect publicly available information
- Document all sources and methods for evidence integrity
- Maintain professional boundaries during social media research
- Consider privacy implications and data protection regulations
