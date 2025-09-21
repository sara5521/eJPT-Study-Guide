# 🔍 Shodan - Search Engine for Internet-Connected Devices

Shodan is a search engine that lets cybersecurity professionals discover internet-connected devices and services worldwide by scanning and indexing banners from various protocols.
**Location:** `02-information-gathering/passive-reconnaissance/shodan.md`

## 🎯 What is Shodan?

Shodan is often called "the search engine for hackers" because it indexes information about internet-connected devices, including servers, routers, webcams, industrial control systems, and IoT devices. Unlike traditional search engines that index websites, Shodan scans the entire internet and collects banner information from open ports and services. This makes it an invaluable tool for passive reconnaissance, allowing penetration testers to gather intelligence about targets without directly interacting with them.

Shodan's capabilities include:
- Discovering exposed services and devices
- Identifying vulnerable systems and misconfigurations
- Geolocation mapping of internet infrastructure
- Historical data analysis of network changes
- Integration with other security tools and frameworks

## 📦 Installation and Setup

### Prerequisites:
- Internet connection for web interface access
- Python 3.x for API usage
- Valid email address for account creation

### Web Interface Setup:
```bash
# Access Shodan web interface
# Navigate to: https://www.shodan.io
# Create free account for basic access

# Verify account via email
# Login to access dashboard
```

### API Setup (Optional):
```bash
# Install Shodan Python library
pip install shodan

# Get API key from account settings
# https://account.shodan.io/

# Configure API key
shodan init YOUR_API_KEY_HERE

# Verify API setup
shodan info
# Expected output: Account information and query credits
```

### CLI Installation:
```bash
# Shodan CLI comes with Python package
pip install shodan

# Verify installation
shodan --help
# Expected output: Available commands and options
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Account Setup:** Create free Shodan account for web access
2. **Search Planning:** Define target scope and search parameters
3. **Query Execution:** Use web interface or API for searches
4. **Result Analysis:** Filter and analyze discovered devices/services
5. **Data Export:** Save results for further analysis and reporting

### Web Interface Structure:
```
# Basic search syntax
search_term

# Advanced search with filters
search_term port:443 country:US

# Multiple filters combination
apache port:80,8080 country:GB city:London
```

### API Command Structure:
```bash
# Basic CLI search
shodan search "search_query"

# Search with count
shodan count "search_query"

# Host information lookup
shodan host IP_ADDRESS
```

## ⚙️ Command Line Options

### Basic CLI Commands:
| Command | Purpose | Example |
|---------|---------|---------|
| `search` | Search for devices/services | `shodan search "apache"` |
| `count` | Count search results | `shodan count "nginx"` |
| `host` | Get host information | `shodan host 8.8.8.8` |
| `info` | Show account information | `shodan info` |

### Search Parameters:
| Parameter | Purpose | Example |
|-----------|---------|---------|
| `port:` | Filter by port number | `apache port:80` |
| `country:` | Filter by country code | `ssh country:US` |
| `city:` | Filter by city name | `mysql city:London` |
| `org:` | Filter by organization | `org:"Amazon"` |

### Output Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `--fields` | Specify output fields | `--fields ip_str,port,org` |
| `--limit` | Limit number of results | `--limit 100` |
| `--format` | Output format | `--format json` |
| `--save` | Save to file | `--save results.json` |

## 🧪 Real Lab Examples

### Example 1: Discovering Web Servers
```bash
# Web interface search for Apache servers
# Search query: apache port:80
# Results: Found 2,847,329 results

# Filtered search for specific country
# Search query: apache port:80 country:US
# Results: Found 892,445 results in United States

# CLI equivalent
shodan search "apache port:80 country:US" --limit 10
# Output: List of IP addresses with Apache servers on port 80 in US
```

### Example 2: Finding SSH Services
```bash
# Search for SSH services globally
# Web interface query: ssh port:22

# CLI search with detailed output
shodan search "ssh" --fields ip_str,port,org,hostnames --limit 20
# Output:
# 192.168.1.100    22    Example Corp    [server.example.com]
# 10.0.0.50       22    Test Org        [test-server.org]

# Count SSH servers by country
shodan count "ssh country:GB"
# Output: 45,892
```

### Example 3: Industrial Control Systems Discovery
```bash
# Search for Modbus protocol devices
# Web interface query: port:502

# Search for SCADA systems
shodan search "scada" --fields ip_str,port,product,version
# Output:
# 203.0.113.15    80    Schneider Electric    v2.1
# 198.51.100.25   502   Modicon M221         v1.0

# Geographic analysis
shodan search "port:502 country:DE" --limit 5
# Output: Industrial devices in Germany on Modbus port 502
```

### Example 4: Host Information Gathering
```bash
# Detailed host analysis
shodan host 8.8.8.8
# Output:
# IP: 8.8.8.8
# Organization: Google LLC
# Operating System: Unknown
# Ports: 53, 443
# Services: DNS, HTTPS

# Historical data analysis
shodan host 8.8.8.8 --history
# Output: Shows historical scan data and changes over time
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Passive reconnaissance techniques** - 25% exam importance
- **Service discovery and enumeration** - 20% exam importance  
- **Intelligence gathering without detection** - 15% exam importance
- **Integration with active reconnaissance** - 10% exam importance

### Critical Commands to Master:
```bash
# Web interface searches for exam scenarios
apache port:80 country:TARGET_COUNTRY    # Web server discovery
ftp port:21                              # FTP service discovery
ssh port:22 org:"TARGET_ORG"            # SSH service enumeration
mysql port:3306                          # Database service discovery

# CLI commands for automation
shodan search "target_service" --limit 50
shodan count "service_type country:XX"
shodan host TARGET_IP
```

### eJPT Exam Scenarios:
1. **Initial Target Discovery:** Use Shodan to identify internet-facing services of target organization
   - Required skills: Search filtering, result analysis
   - Expected commands: Organization-based searches, port filtering
   - Success criteria: Identify key services and IP ranges

2. **Service Enumeration:** Discover specific services running on target infrastructure
   - Required skills: Protocol-specific searches, banner analysis
   - Expected commands: Port-based searches, service identification
   - Success criteria: Map attack surface without active scanning

### Exam Tips and Tricks:
- **Free account limitations:** Understand 100 results limit per search
- **Search optimization:** Use specific filters to maximize relevant results
- **Data correlation:** Combine Shodan results with other OSINT sources
- **Time management:** Use web interface for quick searches, CLI for detailed analysis

### Common eJPT Questions:
- How many web servers does the target organization expose?
- What database services are publicly accessible?
- Which SSH versions are running on target infrastructure?

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Limited Search Results
**Problem:** Free account only shows first 100 results per search
**Cause:** Shodan's freemium model limits result visibility
**Solution:**
```bash
# Use more specific search filters
shodan search "target_service country:US city:NewYork"

# Break down broad searches into smaller chunks
shodan search "apache port:80" --limit 100
shodan search "apache port:8080" --limit 100
```

### Issue 2: API Key Configuration Problems
**Problem:** CLI commands fail with authentication errors
**Solution:**
```bash
# Verify API key setup
shodan info

# Reinitialize if needed
shodan init NEW_API_KEY

# Check configuration file
cat ~/.shodan/api_key
```

### Issue 3: Search Query Syntax Errors
**Problem:** Complex queries return unexpected results
**Prevention:**
```bash
# Test simple queries first
shodan search "apache"

# Add filters incrementally
shodan search "apache port:80"
shodan search "apache port:80 country:US"
```

### Issue 4: Rate Limiting Issues
**Problem:** API requests exceed rate limits
**Optimization:**
```bash
# Check account limits
shodan info

# Use count before full search
shodan count "query" 

# Implement delays in scripts
sleep 1
```

## 🔗 Integration with Other Tools

### Primary Integration: Shodan → Nmap → Service Enumeration
```bash
# Phase 1: Shodan discovery
shodan search "org:TARGET_ORG" --fields ip_str --limit 100 > targets.txt

# Phase 2: Extract IP addresses
cat targets.txt | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' > ip_list.txt

# Phase 3: Active scanning with Nmap
nmap -sS -sV -iL ip_list.txt -oA active_scan

# Phase 4: Cross-reference results
# Compare Shodan banners with Nmap service detection
```

### Secondary Integration: Shodan + Recon-ng
```bash
# Import Shodan API key into Recon-ng
recon-ng
[recon-ng][default] > keys add shodan_api YOUR_API_KEY

# Use Shodan module for reconnaissance
[recon-ng][default] > use recon/domains-hosts/shodan_hostname
[recon-ng][default][shodan_hostname] > set SOURCE target.com
[recon-ng][default][shodan_hostname] > run
```

### Advanced Workflows:
```bash
# Automated reconnaissance pipeline
# 1. Shodan passive discovery
# 2. DNS enumeration correlation  
# 3. Active port scanning validation
# 4. Service version confirmation

shodan search "org:TARGET" --fields ip_str,port,product > shodan_results.txt
dig @8.8.8.8 target.com ANY >> dns_results.txt
nmap -sS -p$(cat shodan_results.txt | cut -d: -f2 | sort -u | tr '\n' ',') target_range
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Search results pages, filter configurations
2. **Command Outputs:** CLI search results with timestamps
3. **Data Files:** Exported results in JSON/CSV format
4. **Query History:** Record of all search queries used

### Report Template Structure:
```markdown
## Shodan Passive Reconnaissance Results

### Target Information
- Organization: TARGET_ORG_NAME
- Search Date: 2025-09-21
- Shodan Account: analyst@company.com

### Search Queries Executed
```bash
# All queries with result counts
shodan search "org:TARGET_ORG" --count
# Result: 147 devices found

shodan search "TARGET_ORG port:80,443" --count  
# Result: 89 web services identified
```

### Key Findings
- **Web Services:** 89 HTTP/HTTPS services across 45 IP addresses
- **SSH Access:** 23 SSH services with various version information
- **Database Services:** 5 MySQL instances, 2 PostgreSQL servers
- **Geographic Distribution:** Services across US (67%), UK (23%), DE (10%)

### Risk Assessment
- **High Risk:** 12 services with known vulnerabilities
- **Medium Risk:** 34 services with outdated software versions
- **Information Disclosure:** 8 services revealing internal hostnames

### Recommendations
- Implement proper firewall rules for database services
- Update SSH configurations on identified servers
- Review public-facing service necessity
```

### Automation Scripts:
```bash
#!/bin/bash
# Shodan reconnaissance automation script

TARGET_ORG="$1"
OUTPUT_DIR="shodan_results_$(date +%Y%m%d)"

mkdir -p "$OUTPUT_DIR"

echo "Starting Shodan reconnaissance for: $TARGET_ORG"

# General organization search
shodan search "org:\"$TARGET_ORG\"" --fields ip_str,port,product,version --limit 500 > "$OUTPUT_DIR/general_search.txt"

# Web services discovery
shodan search "org:\"$TARGET_ORG\" port:80,8080,443,8443" --fields ip_str,port,product --limit 200 > "$OUTPUT_DIR/web_services.txt"

# SSH services discovery  
shodan search "org:\"$TARGET_ORG\" port:22" --fields ip_str,product,version --limit 100 > "$OUTPUT_DIR/ssh_services.txt"

# Database services discovery
shodan search "org:\"$TARGET_ORG\" port:3306,5432,1433" --fields ip_str,port,product --limit 50 > "$OUTPUT_DIR/database_services.txt"

echo "Shodan reconnaissance completed. Results saved in: $OUTPUT_DIR"
```

## 📚 Additional Resources

### Official Documentation:
- Official Shodan website: https://www.shodan.io
- API documentation: https://developer.shodan.io
- Python library: https://github.com/achillean/shodan-python

### Learning Resources:
- Shodan search guide: Complete tutorial on advanced search techniques
- Video course: "Mastering Shodan for Cybersecurity" - comprehensive training
- Practice labs: TryHackMe Shodan room - hands-on exercises

### Community Resources:
- Forums: Shodan community forums for tips and tricks
- Discord: InfoSec community Discord channels
- Reddit: r/AskNetsec and r/cybersecurity communities

### Related Tools:
- **Censys:** Alternative internet scanning platform with similar capabilities
- **BinaryEdge:** Complementary service for internet-wide scanning
- **ZoomEye:** Chinese equivalent with different coverage areas
- **Upgrade path:** Shodan Enterprise for advanced features and unlimited queries
