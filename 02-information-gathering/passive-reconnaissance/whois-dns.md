# 🔍 WHOIS & DNS Enumeration - Domain Intelligence Gathering

**WHOIS and DNS enumeration tools for gathering comprehensive domain and network information during reconnaissance phase.**

**Location:** `02-information-gathering/passive-reconnaissance/whois-dns.md`

## 🎯 What is WHOIS & DNS Enumeration?

WHOIS and DNS enumeration are fundamental passive reconnaissance techniques used to gather detailed information about domain names, IP addresses, and network infrastructure. WHOIS provides registration details, contact information, and administrative data, while DNS enumeration reveals the technical infrastructure, subdomains, and service configurations of target organizations.

Key capabilities include:
- Domain registration and ownership information
- DNS record enumeration and analysis
- Subdomain discovery and mapping
- Network infrastructure identification
- Contact information and administrative details
- Historical DNS data and changes

## 📦 Installation and Setup

### Prerequisites:
- Internet connectivity for WHOIS queries
- DNS resolver access
- Basic understanding of DNS record types

### Installation:
```bash
# WHOIS tools (usually pre-installed)
apt update && apt install whois

# DNS enumeration tools
apt install dnsutils bind9-dnsutils
apt install fierce dnsrecon sublist3r

# Verification
whois --version
dig -v
nslookup -version
```

### Initial Configuration:
```bash
# Configure DNS servers (optional)
echo "nameserver 8.8.8.8" >> /etc/resolv.conf
echo "nameserver 1.1.1.1" >> /etc/resolv.conf

# Verify DNS resolution
nslookup google.com
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **WHOIS Lookup:** Gather registration and ownership information
2. **DNS Record Enumeration:** Discover technical infrastructure
3. **Subdomain Discovery:** Map the target's domain landscape
4. **Zone Transfer Attempts:** Test for DNS misconfigurations

### Command Structure:
```bash
# WHOIS syntax
whois [options] domain_or_ip

# DNS query syntax
dig [options] domain [record_type]
nslookup [record_type] domain [dns_server]

# Subdomain enumeration
fierce -dns domain
dnsrecon -d domain -t std
```

## ⚙️ Command Line Options

### WHOIS Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-h server` | Specify WHOIS server | `whois -h whois.arin.net 192.168.1.1` |
| `-p port` | Specify port number | `whois -p 43 domain.com` |
| `-H` | Hide legal disclaimers | `whois -H example.com` |
| `-i` | Inverse lookup | `whois -i admin-c HANDLE` |

### DIG Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `+short` | Brief output only | `dig +short example.com A` |
| `+trace` | Show query path | `dig +trace example.com` |
| `+norecurse` | No recursive queries | `dig +norecurse example.com` |
| `@server` | Query specific DNS server | `dig @8.8.8.8 example.com` |
| `-x` | Reverse DNS lookup | `dig -x 192.168.1.1` |

### NSLOOKUP Commands:
| Command | Purpose | Example |
|---------|---------|---------|
| `set type=A` | Set record type | `nslookup > set type=MX` |
| `server` | Change DNS server | `nslookup > server 8.8.8.8` |
| `ls -d` | List domain records | `nslookup > ls -d example.com` |

## 🧪 Real Lab Examples

### Example 1: Complete Domain Intelligence Gathering
```bash
# Phase 1: WHOIS domain lookup
whois example.com
# Output: Registration date, registrar, name servers, contact information

# Phase 2: WHOIS IP lookup for name servers
whois 192.0.2.1
# Output: IP allocation information, ISP details, geographical location

# Phase 3: DNS record enumeration
dig example.com ANY
# Output: All available DNS records (A, AAAA, MX, NS, TXT, etc.)

# Phase 4: Specific record queries
dig example.com MX +short
# Output: mail.example.com. 10, backup-mail.example.com. 20

dig example.com TXT +short
# Output: "v=spf1 include:_spf.example.com ~all"
```

### Example 2: Subdomain Discovery Workflow
```bash
# Method 1: Using fierce
fierce -dns example.com
# Output: Discovered subdomains with IP addresses
# www.example.com: 192.0.2.10
# mail.example.com: 192.0.2.20
# ftp.example.com: 192.0.2.30

# Method 2: Using dnsrecon
dnsrecon -d example.com -t std
# Output: Standard enumeration with A, AAAA, CNAME, MX records

# Method 3: Manual subdomain testing
for sub in www mail ftp admin test dev staging; do
    dig $sub.example.com +short
done
# Output: IP addresses for existing subdomains
```

### Example 3: Zone Transfer Attempt
```bash
# Step 1: Identify name servers
dig example.com NS +short
# Output: ns1.example.com, ns2.example.com

# Step 2: Attempt zone transfer
dig @ns1.example.com example.com AXFR
# Output: Either zone transfer data or "Transfer failed"

# Step 3: Try all name servers
for ns in $(dig example.com NS +short); do
    echo "Trying zone transfer from $ns"
    dig @$ns example.com AXFR
done
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **WHOIS Analysis (25%):** Extracting actionable intelligence from registration data
- **DNS Record Enumeration (30%):** Comprehensive infrastructure mapping
- **Subdomain Discovery (20%):** Expanding attack surface identification
- **Information Correlation (25%):** Connecting gathered data for targeting

### Critical Commands to Master:
```bash
# Essential WHOIS commands
whois target.com                    # Primary domain lookup
whois 192.168.1.1                 # IP address investigation
whois -h whois.arin.net IP         # Specific registry queries

# Critical DNS enumeration
dig target.com ANY                 # Complete record enumeration
dig target.com MX +short          # Mail server identification
dig target.com NS +short          # Name server discovery
nslookup target.com               # Basic DNS resolution
```

### eJPT Exam Scenarios:
1. **Domain Intelligence Gathering:** Given a target domain, extract all available registration and technical information
   - Required skills: WHOIS interpretation, DNS record analysis
   - Expected commands: whois, dig, nslookup
   - Success criteria: Complete infrastructure mapping

2. **Subdomain Discovery:** Identify all subdomains for expanded attack surface
   - Required skills: Manual enumeration, automated tools
   - Expected commands: fierce, dnsrecon, manual dig queries
   - Success criteria: Comprehensive subdomain list with IP addresses

### Exam Tips and Tricks:
- **Tip 1:** Always check both domain and IP WHOIS data for complete picture
- **Tip 2:** Use multiple DNS servers (8.8.8.8, 1.1.1.1) for comprehensive results
- **Tip 3:** Document name servers for potential zone transfer attempts
- **Tip 4:** Correlate DNS data with other reconnaissance findings

### Common eJPT Questions:
- What mail servers are configured for the target domain?
- Who is the administrative contact for the domain registration?
- What subdomains can be discovered through DNS enumeration?

## ⚠️ Common Issues & Troubleshooting

### Issue 1: WHOIS Query Limitations
**Problem:** WHOIS queries being blocked or rate-limited
**Cause:** Excessive queries or IP-based restrictions
**Solution:**
```bash
# Use different WHOIS servers
whois -h whois.verisign-grs.com example.com
whois -h whois.iana.org example.com

# Add delays between queries
sleep 2 && whois example.com
```

### Issue 2: DNS Resolution Failures
**Problem:** Unable to resolve domain names or get DNS responses
**Solution:**
```bash
# Try different DNS servers
dig @8.8.8.8 example.com
dig @1.1.1.1 example.com
dig @208.67.222.222 example.com

# Check local DNS configuration
cat /etc/resolv.conf
```

### Issue 3: Incomplete WHOIS Information
**Problem:** Limited or redacted WHOIS data due to privacy protection
**Prevention:**
```bash
# Try historical WHOIS data sources
# Check multiple registrar databases
whois -h whois.networksolutions.com example.com
whois -h whois.godaddy.com example.com
```

### Issue 4: Zone Transfer Denial
**Problem:** All name servers properly configured to deny zone transfers
**Optimization:**
```bash
# Focus on individual record enumeration
dig example.com A
dig example.com AAAA
dig example.com MX
dig example.com TXT
dig example.com CNAME
```

## 🔗 Integration with Other Tools

### Primary Integration: WHOIS → Google Dorking → Port Scanning
```bash
# Step 1: WHOIS reconnaissance
whois target.com | grep -E "(Name Server|Admin|Tech)" > whois_data.txt

# Step 2: Extract email domains for Google dorking
grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' whois_data.txt

# Step 3: DNS enumeration for IP addresses
dig target.com A +short > target_ips.txt
```

### Secondary Integration: DNS Enumeration → Service Discovery
```bash
# Extract all IP addresses from DNS records
dig target.com ANY | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u > all_ips.txt

# Feed into port scanning
nmap -iL all_ips.txt -F

# Cross-reference with subdomain discovery
fierce -dns target.com | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' >> all_ips.txt
```

### Advanced Workflows:
```bash
# Comprehensive domain intelligence workflow
echo "Starting comprehensive domain enumeration for $TARGET"
whois $TARGET > ${TARGET}_whois.txt
dig $TARGET ANY > ${TARGET}_dns.txt
fierce -dns $TARGET > ${TARGET}_subdomains.txt
dnsrecon -d $TARGET -t std > ${TARGET}_dnsrecon.txt
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** WHOIS output showing registration details and contact information
2. **Command Outputs:** Complete DNS record enumeration results
3. **Subdomain Lists:** All discovered subdomains with corresponding IP addresses
4. **Zone Transfer Results:** Evidence of any successful zone transfers or denials

### Report Template Structure:
```markdown
## WHOIS & DNS Enumeration Results

### Target Information
- Target Domain: target.com
- Date/Time: 2024-01-15 14:30:00 UTC
- Tools Used: whois, dig, fierce, dnsrecon

### Commands Executed
```bash
whois target.com
dig target.com ANY
fierce -dns target.com
dig @ns1.target.com target.com AXFR
```

### Key Findings

#### Registration Information
- Registrar: Example Registrar Inc.
- Registration Date: 2010-03-15
- Expiration Date: 2025-03-15
- Administrative Contact: admin@target.com
- Technical Contact: tech@target.com

#### DNS Infrastructure
- Name Servers: ns1.target.com (192.0.2.1), ns2.target.com (192.0.2.2)
- Mail Servers: mail.target.com (priority 10), backup.target.com (priority 20)
- Web Servers: www.target.com (192.0.2.10)

#### Discovered Subdomains
- www.target.com: 192.0.2.10
- mail.target.com: 192.0.2.20
- ftp.target.com: 192.0.2.30
- admin.target.com: 192.0.2.40

### Security Concerns
- Zone transfer attempts: All properly denied
- Contact information: Partially exposed in WHOIS
- Subdomain exposure: Multiple services discovered

### Recommendations
- Implement WHOIS privacy protection
- Review subdomain exposure and necessity
- Ensure proper DNS security configurations
```

### Automation Scripts:
```bash
#!/bin/bash
# domain_intel.sh - Automated domain intelligence gathering

TARGET=$1
OUTPUT_DIR="recon_${TARGET}_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTPUT_DIR

echo "[+] Starting domain intelligence gathering for $TARGET"

# WHOIS enumeration
echo "[+] Performing WHOIS lookup..."
whois $TARGET > $OUTPUT_DIR/whois_domain.txt
whois $(dig $TARGET +short | head -1) > $OUTPUT_DIR/whois_ip.txt

# DNS enumeration
echo "[+] Performing DNS enumeration..."
dig $TARGET ANY > $OUTPUT_DIR/dns_all_records.txt
dig $TARGET A +short > $OUTPUT_DIR/dns_a_records.txt
dig $TARGET MX +short > $OUTPUT_DIR/dns_mx_records.txt
dig $TARGET NS +short > $OUTPUT_DIR/dns_ns_records.txt
dig $TARGET TXT +short > $OUTPUT_DIR/dns_txt_records.txt

# Subdomain discovery
echo "[+] Discovering subdomains..."
fierce -dns $TARGET > $OUTPUT_DIR/fierce_subdomains.txt 2>/dev/null
dnsrecon -d $TARGET -t std > $OUTPUT_DIR/dnsrecon_output.txt

# Zone transfer attempts
echo "[+] Attempting zone transfers..."
for ns in $(dig $TARGET NS +short); do
    echo "Trying $ns" >> $OUTPUT_DIR/zone_transfer_attempts.txt
    dig @$ns $TARGET AXFR >> $OUTPUT_DIR/zone_transfer_attempts.txt 2>&1
done

echo "[+] Domain intelligence gathering complete. Results saved to $OUTPUT_DIR/"
```

## 📚 Additional Resources

### Official Documentation:
- WHOIS Protocol RFC 3912: https://tools.ietf.org/html/rfc3912
- DNS Protocol RFC 1035: https://tools.ietf.org/html/rfc1035
- BIND9 Documentation: https://bind9.readthedocs.io/

### Learning Resources:
- DNS and BIND Book: Comprehensive DNS administration guide
- SANS SEC401: DNS enumeration techniques and methodology
- Cybrary DNS Fundamentals: https://cybrary.it/course/dns-fundamentals

### Community Resources:
- DNS-OARC Forums: https://www.dns-oarc.net/
- NANOG Mailing Lists: Network operator discussions
- /r/networking: Reddit community for networking professionals

### Related Tools:
- theHarvester: Email and subdomain harvesting from public sources
- Amass: Advanced subdomain enumeration and network mapping
- DNSdumpster: Web-based DNS reconnaissance and research
