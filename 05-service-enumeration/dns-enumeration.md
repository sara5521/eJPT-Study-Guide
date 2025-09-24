# 🔧 DNS Enumeration - Domain Name System Analysis

DNS enumeration involves discovering DNS servers, performing zone transfers, subdomain discovery, and DNS record analysis for reconnaissance.
**Location:** `05-service-enumeration/dns-enumeration.md`

## 🎯 What is DNS Enumeration?

DNS enumeration is the process of gathering information about DNS infrastructure and domain records. This includes discovering subdomains, mail servers, and other services associated with a domain.

## 📦 Installation and Setup

DNS enumeration uses common networking tools:

```bash
# Basic DNS tools (usually pre-installed)
dig google.com
nslookup google.com
host google.com

# Install additional DNS tools
apt install dnsrecon fierce dnsutils

# Verify installations
dig -v
dnsrecon --help
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **DNS Server Discovery:** Identify DNS servers
2. **Zone Transfer Testing:** Attempt AXFR requests
3. **Record Enumeration:** Query different DNS record types
4. **Subdomain Discovery:** Find subdomains and services

### Command Structure:
```bash
# Basic DNS queries
dig domain.com
nslookup domain.com
host domain.com

# Specific record types
dig domain.com MX
dig domain.com NS
dig domain.com AAAA
```

## ⚙️ Command Line Options

### Dig Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `@server` | Query specific DNS server | `dig @8.8.8.8 domain.com` |
| `MX` | Mail exchange records | `dig domain.com MX` |
| `NS` | Name server records | `dig domain.com NS` |
| `AXFR` | Zone transfer request | `dig @ns1.domain.com domain.com AXFR` |

### Nslookup Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-type=record` | Specify record type | `nslookup -type=MX domain.com` |
| `server` | Set DNS server | `nslookup> server 8.8.8.8` |
| `-debug` | Enable debug mode | `nslookup -debug domain.com` |

## 🧪 Real Lab Examples

### Example 1: Basic DNS Record Enumeration
```bash
# Discover basic DNS information
dig ine.local
# Output: A records, nameservers, and basic domain info

# Check for mail servers
dig ine.local MX
# Output: Mail exchange records and priorities

# Find authoritative name servers
dig ine.local NS
# Output: Authoritative DNS servers for domain
```

### Example 2: Zone Transfer Testing
```bash
# Identify name servers first
dig ine.local NS
# Output: ns1.ine.local, ns2.ine.local

# Attempt zone transfer
dig @ns1.ine.local ine.local AXFR
# If successful: Complete zone file contents
# If failed: Transfer failed or refused

# Try alternate name servers
dig @ns2.ine.local ine.local AXFR
```

### Example 3: Subdomain Discovery
```bash
# Manual subdomain testing
dig www.ine.local
dig ftp.ine.local  
dig mail.ine.local
dig admin.ine.local

# Automated subdomain enumeration with dnsrecon
dnsrecon -d ine.local -t brt -D /usr/share/wordlists/dnsrecon.txt
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **DNS record analysis (35%)** - Understanding DNS infrastructure
- **Zone transfer testing (30%)** - Attempting information disclosure
- **Subdomain discovery (25%)** - Finding additional attack surfaces  
- **DNS server identification (10%)** - Mapping DNS infrastructure

### Critical Commands to Master:
```bash
# Must-know commands for exam
dig domain.com                                     # Basic DNS lookup
dig domain.com NS                                  # Find name servers
dig @nameserver domain.com AXFR                   # Zone transfer attempt
nslookup -type=MX domain.com                      # Mail server discovery
```

### eJPT Exam Scenarios:
1. **DNS Infrastructure Mapping:** Discover DNS servers and record types
   - Required skills: DNS record interpretation, server identification
   - Expected commands: dig, nslookup with various record types
   - Success criteria: Map complete DNS infrastructure

2. **Zone Transfer Exploitation:** Attempt DNS zone transfers for information gathering
   - Required skills: Zone transfer techniques, nameserver identification
   - Expected commands: AXFR queries against discovered nameservers
   - Success criteria: Extract zone information or identify transfer restrictions

### Exam Tips and Tricks:
- **Try all nameservers:** Zone transfers may be allowed on secondary servers
- **Check multiple record types:** A, AAAA, MX, NS, CNAME, TXT records
- **Test subdomains:** Common subdomains often reveal additional services
- **Document everything:** DNS information is crucial for attack planning

### Common eJPT Questions:
- Enumerate DNS records for target domains
- Attempt zone transfers to gather domain information
- Identify mail servers and additional subdomains

## ⚠️ Common Issues & Troubleshooting

### Issue 1: DNS Resolution Failures
**Problem:** DNS queries failing or timing out
**Solution:**
```bash
# Use specific DNS servers
dig @8.8.8.8 domain.com
dig @1.1.1.1 domain.com

# Check local DNS configuration
cat /etc/resolv.conf
```

### Issue 2: Zone Transfer Denied
**Problem:** AXFR requests being refused
**Solution:**
```bash
# Try all discovered nameservers
for ns in $(dig domain.com NS +short); do
    echo "Trying $ns"
    dig @$ns domain.com AXFR
done

# Check if zone transfer is partially allowed
dig @nameserver domain.com ANY
```

### Issue 3: Incomplete DNS Information
**Problem:** Limited DNS records returned
**Solution:**
```bash
# Query different record types explicitly
dig domain.com A
dig domain.com AAAA
dig domain.com MX  
dig domain.com NS
dig domain.com CNAME
dig domain.com TXT
```

## 🔗 Integration with Other Tools

### Primary Integration: DNS → Subdomain Discovery → Port Scanning
```bash
# Step 1: DNS enumeration discovers subdomains
dnsrecon -d domain.com -t brt

# Step 2: Extract discovered hosts
# mail.domain.com, www.domain.com, ftp.domain.com

# Step 3: Port scan discovered hosts
nmap -sV mail.domain.com www.domain.com ftp.domain.com
```

### Secondary Integration: DNS → Zone Transfer → Target Expansion
```bash
# Successful zone transfer reveals internal hosts
dig @nameserver domain.com AXFR | grep -E "^[a-zA-Z0-9]"

# Use revealed hostnames for expanded reconnaissance
nmap -sV internal-host.domain.com
```

### Advanced Workflows:
```bash
# Comprehensive DNS enumeration pipeline
#!/bin/bash
domain=$1

echo "=== DNS Record Enumeration ==="
for record in A AAAA MX NS CNAME TXT; do
    echo "Querying $record records:"
    dig $domain $record +short
done

echo "=== Zone Transfer Testing ==="
for ns in $(dig $domain NS +short); do
    echo "Testing zone transfer on $ns:"
    dig @$ns $domain AXFR
done

echo "=== Subdomain Discovery ==="
dnsrecon -d $domain -t brt -D /usr/share/wordlists/dnsrecon.txt
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** DNS query results and zone transfer attempts
2. **Command Outputs:** Complete dig/nslookup results
3. **Discovered Hosts:** List of subdomains and services found
4. **DNS Infrastructure:** Nameservers and mail servers identified

### Report Template Structure:
```markdown
## DNS Enumeration Results

### Target Information
- Domain: ine.local
- Date/Time: 2024-11-26 13:08 IST
- DNS Servers Tested: ns1.ine.local, ns2.ine.local

### Commands Executed
```bash
# Basic DNS enumeration
dig ine.local
dig ine.local MX
dig ine.local NS

# Zone transfer attempts
dig @ns1.ine.local ine.local AXFR
dig @ns2.ine.local ine.local AXFR
```

### DNS Infrastructure
- **Authoritative Nameservers:** ns1.ine.local, ns2.ine.local
- **Mail Servers:** mail.ine.local (priority 10)
- **Web Servers:** www.ine.local (A: 192.168.1.10)
- **FTP Servers:** ftp.ine.local (A: 192.168.1.15)

### Zone Transfer Results
- **ns1.ine.local:** Zone transfer REFUSED
- **ns2.ine.local:** Zone transfer REFUSED
- **Security Status:** Zone transfers properly restricted

### Discovered Subdomains
- www.ine.local → 192.168.1.10
- mail.ine.local → 192.168.1.20
- ftp.ine.local → 192.168.1.15
- admin.ine.local → 192.168.1.5

### Attack Surface Analysis
- **Web Services:** HTTP/HTTPS on www.ine.local
- **Mail Services:** SMTP on mail.ine.local
- **File Transfer:** FTP on ftp.ine.local
- **Administrative:** Potential admin interface on admin.ine.local

### Recommendations
- Monitor DNS queries for reconnaissance attempts
- Ensure zone transfers are restricted to authorized servers
- Implement DNS security extensions (DNSSEC)
- Regular audit of DNS records and subdomains
```

### Automation Scripts:
```bash
# DNS enumeration automation script
#!/bin/bash
DOMAIN=$1
OUTPUT_DIR="dns-enum-$(date +%Y%m%d-%H%M%S)"
mkdir $OUTPUT_DIR

echo "Starting DNS enumeration of $DOMAIN"

# Basic DNS record enumeration
echo "[+] Enumerating DNS records..."
for record_type in A AAAA MX NS CNAME TXT SOA; do
    echo "=== $record_type Records ===" >> $OUTPUT_DIR/dns_records.txt
    dig $DOMAIN $record_type +short >> $OUTPUT_DIR/dns_records.txt
    echo >> $OUTPUT_DIR/dns_records.txt
done

# Zone transfer testing
echo "[+] Testing zone transfers..."
dig $DOMAIN NS +short > $OUTPUT_DIR/nameservers.txt
while read nameserver; do
    echo "Testing zone transfer on $nameserver" >> $OUTPUT_DIR/zone_transfers.txt
    dig @$nameserver $DOMAIN AXFR >> $OUTPUT_DIR/zone_transfers.txt
    echo "---" >> $OUTPUT_DIR/zone_transfers.txt
done < $OUTPUT_DIR/nameservers.txt

# Subdomain discovery
echo "[+] Discovering subdomains..."
if command -v dnsrecon > /dev/null; then
    dnsrecon -d $DOMAIN -t brt -D /usr/share/wordlists/dnsrecon.txt > $OUTPUT_DIR/subdomains.txt
fi

# Common subdomain manual testing
echo "[+] Testing common subdomains..."
common_subs="www ftp mail admin test dev staging api blog forum shop"
for sub in $common_subs; do
    result=$(dig $sub.$DOMAIN +short)
    if [ ! -z "$result" ]; then
        echo "$sub.$DOMAIN → $result" >> $OUTPUT_DIR/found_subdomains.txt
    fi
done

echo "[+] DNS enumeration complete! Results in $OUTPUT_DIR/"
echo "[+] Summary of discoveries:"
cat $OUTPUT_DIR/found_subdomains.txt 2>/dev/null
```

## 📚 Additional Resources

### Official Documentation:
- DNS RFC 1034/1035: https://tools.ietf.org/html/rfc1034
- BIND DNS Server: https://www.isc.org/bind/
- DNS Security Extensions (DNSSEC): https://tools.ietf.org/html/rfc4033

### Learning Resources:
- DNS protocol internals and security implications
- Zone transfer security and best practices
- DNS reconnaissance techniques and countermeasures

### Community Resources:
- DNS enumeration techniques and tools
- Subdomain discovery methodologies
- DNS security testing approaches

### Related Tools:
- fierce: Domain scanner for subdomain discovery
- sublist3r: Python tool for subdomain enumeration
- amass: Advanced subdomain discovery tool
