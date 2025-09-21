# 🔍 Google Dorking - Advanced Search Reconnaissance

Google Dorking is the practice of using advanced Google search operators to find sensitive information, vulnerabilities, and security misconfigurations exposed on websites.
**Location:** `02-information-gathering/passive-reconnaissance/google-dorking.md`

## 🎯 What is Google Dorking?

Google Dorking (also known as Google Hacking) leverages Google's powerful search operators to discover information that organizations may not intend to be publicly accessible. By using specific search queries, penetration testers can find exposed files, login pages, database dumps, configuration files, and vulnerable applications without directly interacting with the target systems.

Key capabilities include:
- Finding exposed sensitive files and directories
- Discovering vulnerable web applications and versions
- Locating database dumps and backup files
- Identifying misconfigured systems and services
- Gathering employee information and organizational data

## 📦 Installation and Setup

### Prerequisites:
- Web browser with internet access
- Basic understanding of search operators
- Target domain or organization identified

### No Installation Required:
```bash
# Google Dorking uses standard web browsers
# Access through: https://www.google.com

# Verification - test basic dork
site:example.com filetype:pdf
```

### Recommended Tools:
```bash
# Install additional OSINT tools for enhanced dorking
apt install dork-cli
apt install googler

# Browser extensions for automated dorking
# - DorkNet
# - Google Hacking Database (GHDB) extension
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Target Identification:** Define target domains and organizations
2. **Operator Selection:** Choose appropriate search operators
3. **Query Construction:** Build effective search queries
4. **Result Analysis:** Analyze and validate findings

### Command Structure:
```bash
# Basic syntax in Google search
operator:value additional_terms

# Multiple operators
operator1:value1 operator2:value2 "exact phrase"

# Example workflow
site:target.com filetype:pdf
inurl:admin site:target.com
intitle:"index of" site:target.com
```

## ⚙️ Command Line Options

### Site-Specific Operators:
| Operator | Purpose | Example |
|----------|---------|---------|
| `site:` | Search specific domain | `site:example.com` |
| `inurl:` | Search in URL | `inurl:admin` |
| `intitle:` | Search in page title | `intitle:"admin panel"` |
| `intext:` | Search in page content | `intext:"confidential"` |

### File Type Operators:
| Operator | Purpose | Example |
|----------|---------|---------|
| `filetype:` | Search specific file types | `filetype:pdf` |
| `ext:` | Alternative to filetype | `ext:sql` |
| `-filetype:` | Exclude file types | `-filetype:html` |

### Content Operators:
| Operator | Purpose | Example |
|----------|---------|---------|
| `"exact phrase"` | Exact match search | `"database backup"` |
| `*` | Wildcard operator | `admin * panel` |
| `OR` | Boolean OR search | `admin OR administrator` |
| `-` | Exclude terms | `site:target.com -www` |

### Advanced Operators:
| Operator | Purpose | Example |
|----------|---------|---------|
| `cache:` | View cached page | `cache:example.com` |
| `related:` | Find related sites | `related:target.com` |
| `info:` | Get page information | `info:example.com` |
| `link:` | Find pages linking to URL | `link:target.com` |

## 🧪 Real Lab Examples

### Example 1: Finding Exposed Configuration Files
```bash
# Search for exposed configuration files
site:target.com filetype:conf
site:target.com filetype:ini
site:target.com filetype:xml

# Expected findings
# - web.config files
# - database.ini files
# - application.xml files

# Advanced search for specific configs
site:target.com inurl:config filetype:php
# Output: Found 15 results including database connection files
```

### Example 2: Database and Backup File Discovery
```bash
# Search for database dumps
site:target.com filetype:sql
site:target.com filetype:db
site:target.com "database backup"

# Search for backup files
site:target.com filetype:bak
site:target.com filetype:old
site:target.com intitle:"index of" backup

# Results analysis
# Found: backup_2023.sql (15MB database dump)
# Found: users.db.bak (contains user credentials)
```

### Example 3: Admin Panel and Login Page Discovery
```bash
# Search for admin interfaces
site:target.com inurl:admin
site:target.com inurl:administrator
site:target.com intitle:"admin panel"

# Search for login pages
site:target.com inurl:login
site:target.com intitle:"login" OR intitle:"sign in"
site:target.com "please enter your username"

# Example findings
# admin.target.com/panel - WordPress admin
# target.com/administrator - Custom CMS login
# target.com/secure/login.php - Application login
```

### Example 4: Employee and Email Harvesting
```bash
# Search for employee information
site:target.com filetype:pdf "employee handbook"
site:target.com "email" OR "@target.com"
site:linkedin.com "company:target"

# Directory listing exploitation
site:target.com intitle:"index of" "parent directory"
# Found: /files/ directory with employee documents
# Found: /uploads/ directory with resumes and CVs
```

### Example 5: Vulnerable Application Discovery
```bash
# Search for specific vulnerable applications
site:target.com "powered by phpMyAdmin"
site:target.com "Apache Tomcat" "Version"
site:target.com "WordPress" inurl:wp-admin

# Search for error messages revealing technology stack
site:target.com "MySQL Error" OR "SQL syntax error"
site:target.com "Warning: include" filetype:php

# Results
# Found: phpMyAdmin 4.8.1 (known vulnerabilities)
# Found: WordPress 5.2 with admin panel exposed
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Information Gathering (25%)** - Using Google Dorking for passive reconnaissance
- **Target Enumeration (20%)** - Discovering subdomains and exposed services
- **Vulnerability Discovery (15%)** - Finding misconfigurations and exposed files
- **OSINT Techniques (10%)** - Gathering organizational intelligence

### Critical Commands to Master:
```bash
# Essential dorks for eJPT exam
site:target.com                    # Basic domain enumeration
site:target.com filetype:pdf       # Document discovery
site:target.com inurl:admin        # Admin panel discovery
intitle:"index of" site:target.com # Directory listing exploitation
```

### eJPT Exam Scenarios:
1. **Passive Reconnaissance Phase:**
   - Use Google Dorking to gather initial target information
   - Document all discovered subdomains and services
   - Identify technology stack and versions

2. **Vulnerability Assessment Phase:**
   - Search for exposed configuration files
   - Locate backup files and database dumps
   - Find admin panels and login interfaces

### Exam Tips and Tricks:
- **Tip 1:** Always start with basic `site:` operator before advanced queries
- **Tip 2:** Document all findings with screenshots for reporting
- **Tip 3:** Combine multiple operators for more specific results
- **Tip 4:** Use quotation marks for exact phrase matching

### Common eJPT Questions:
- Finding exposed directories using intitle:"index of"
- Locating admin panels with inurl: operator
- Discovering file types with filetype: operator

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Too Many Generic Results
**Problem:** Google returns too many irrelevant results
**Cause:** Search query is too broad or lacks specificity
**Solution:**
```bash
# Add more specific operators
site:target.com inurl:admin -inurl:wp-admin
# Exclude common false positives
site:target.com filetype:pdf -"user manual"
```

### Issue 2: Google Blocking or Rate Limiting
**Problem:** Google shows CAPTCHA or blocks searches
**Solution:**
```bash
# Use alternative search engines
# DuckDuckGo: !g site:target.com
# Bing: site:target.com filetype:pdf
# Use VPN or proxy to change IP address
```

### Issue 3: No Results Found
**Problem:** Searches return no relevant results
**Prevention:**
```bash
# Try variations of domain
site:target.com OR site:www.target.com
# Use wildcard subdomains
site:*.target.com
```

### Issue 4: Outdated Information
**Problem:** Cached or old information appears in results
**Optimization:**
```bash
# Check cached versions
cache:target.com/admin
# Use date filters in Google search tools
# Verify findings manually
```

## 🔗 Integration with Other Tools

### Primary Integration: Google Dorking → Manual Verification → Automated Scanning
```bash
# Step 1: Google Dorking for discovery
site:target.com inurl:admin

# Step 2: Manual verification
curl -I https://target.com/admin

# Step 3: Automated scanning with discovered endpoints
nmap -p 80,443 target.com
nikto -h https://target.com/admin
```

### Secondary Integration: Google Dorking → Subdomain Enumeration
```bash
# Use dorking results to feed subdomain tools
site:*.target.com | grep -oE '[a-zA-Z0-9.-]+\.target\.com'

# Feed results to subdomain takeover tools
sublist3r -d target.com
```

### Advanced Workflows:
```bash
# Automated Google Dorking with custom scripts
python3 dorkbot.py -d target.com
# Combine with other OSINT tools
theHarvester -d target.com -b google
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Full browser screenshots showing search query and results
2. **URLs:** Complete URLs of discovered resources
3. **Content Analysis:** Brief description of sensitive information found
4. **Timestamps:** When the information was discovered

### Report Template Structure:
```markdown
## Google Dorking Results

### Target Information
- Target Domain: target.com
- Date/Time: 2024-01-15 14:30:00 UTC
- Search Engine: Google.com

### Search Queries Executed
```bash
site:target.com filetype:pdf
site:target.com inurl:admin
intitle:"index of" site:target.com
```

### Key Findings
- **Exposed Admin Panel:** https://target.com/admin/login.php
- **Database Backup:** https://target.com/backups/users.sql
- **Configuration File:** https://target.com/config/database.ini

### Risk Assessment
- **High Risk:** Database backups containing user credentials
- **Medium Risk:** Exposed admin panels without protection
- **Low Risk:** Public documents revealing organizational structure

### Recommendations
- Remove or restrict access to sensitive files
- Implement proper access controls on admin interfaces
- Review and secure all backup file locations
```

### Automation Scripts:
```bash
# Basic automated dorking script
#!/bin/bash
target="$1"
echo "Starting Google Dorking for $target"

# Common dorks array
dorks=(
    "site:$target filetype:pdf"
    "site:$target inurl:admin"
    "site:$target intitle:login"
    "site:$target filetype:sql"
    "site:$target intitle:'index of'"
)

# Execute each dork and save results
for dork in "${dorks[@]}"; do
    echo "Executing: $dork"
    # Use googler or custom API to automate
    googler --count 10 "$dork" >> dorking_results.txt
    sleep 2  # Rate limiting
done
```

## 📚 Additional Resources

### Official Documentation:
- Google Search Operators Guide: https://developers.google.com/search/docs
- Google Hacking Database (GHDB): https://www.exploit-db.com/google-hacking-database
- Advanced Search Tips: https://www.google.com/advanced_search

### Learning Resources:
- "Google Hacking for Penetration Testers" - Detailed tutorial series
- SANS SEC487 - Open-Source Intelligence (OSINT) Gathering and Analysis
- OSINT Framework: https://osintframework.com/

### Community Resources:
- Reddit r/OSINT: Active community for OSINT techniques
- OSINT Discord Servers: Real-time collaboration
- Null Byte WonderHowTo: Practical Google Dorking tutorials

### Related Tools:
- **Shodan:** Internet-connected device discovery (complements Google Dorking)
- **theHarvester:** Email and subdomain harvesting with Google integration
- **Recon-ng:** Framework that includes Google Dorking modules
- **SpiderFoot:** Automated OSINT tool with Google search capabilities
