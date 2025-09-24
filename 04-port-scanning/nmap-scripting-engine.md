# 🔧 Nmap Scripting Engine (NSE) - Advanced Port Scanning and Service Detection

NSE provides advanced capabilities for service detection, vulnerability scanning, and network discovery through Lua scripts.
**Location:** `04-port-scanning/nmap-scripting-engine.md`

## 🎯 What is Nmap Scripting Engine?

The Nmap Scripting Engine (NSE) is a powerful feature that allows users to write and execute scripts to automate various network tasks. Key capabilities include:
- Service and version detection
- Vulnerability detection and exploitation
- Network discovery and reconnaissance
- Malware detection
- Custom automation scripts

## 📦 Installation and Setup

### Prerequisites:
- Nmap installed with NSE support
- Lua runtime (usually included with Nmap)

### Installation:
```bash
# NSE comes pre-installed with Nmap
nmap --version
# Expected output: Nmap version 7.94 ( https://nmap.org )

# Verify NSE scripts location
ls /usr/share/nmap/scripts/ | wc -l
# Expected: 600+ scripts available
```

### Script Categories:
```bash
# View script categories
nmap --script-help categories

# Common categories:
# auth, broadcast, brute, default, discovery, dos, exploit, 
# external, fuzzer, intrusive, malware, safe, version, vuln
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Script Selection:** Choose appropriate scripts for target
2. **Execution:** Run nmap with NSE scripts
3. **Analysis:** Interpret script outputs
4. **Follow-up:** Use results for further exploitation

### Command Structure:
```bash
# Basic syntax
nmap --script [category|script-name] target

# Example workflow from lab
nmap demo1.ine.local                    # Basic port scan first
nmap --script http-enum demo1.ine.local # Then enumerate HTTP
```

## ⚙️ Command Line Options

### Script Selection Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `--script [name]` | Run specific script | `nmap --script http-title target` |
| `--script [category]` | Run script category | `nmap --script vuln target` |
| `--script-args` | Pass script arguments | `nmap --script http-enum --script-args http-enum.basepath=/admin/ target` |

### Script Information Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `--script-help [name]` | Get script help | `nmap --script-help http-enum` |
| `--script-trace` | Enable script debugging | `nmap --script-trace --script http-title target` |
| `--script-updatedb` | Update script database | `nmap --script-updatedb` |

### Output Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-oN file` | Normal output to file | `nmap --script vuln -oN scan.txt target` |
| `-oX file` | XML output for parsing | `nmap --script discovery -oX results.xml target` |
| `--open` | Show only open ports | `nmap --script default --open target` |

## 🧪 Real Lab Examples

### Example 1: HTTP Service Enumeration (From Lab Screenshot)
```bash
# Step 1: Basic port scan to identify services
nmap demo1.ine.local
# Output: 80/tcp open http

# Step 2: HTTP enumeration using NSE
nmap --script http-enum demo1.ine.local
# Output: Discovers web directories and files

# Step 3: Get HTTP title and headers
nmap --script http-title,http-headers demo1.ine.local
# Output: Shows web application details
```

### Example 2: Comprehensive Service Detection
```bash
# Service version detection with NSE
nmap -sV --script default demo1.ine.local
# Output: Detailed service information with default scripts

# Vulnerability scanning
nmap --script vuln demo1.ine.local
# Output: Identifies known vulnerabilities
```

### Example 3: Multiple Target Network Scanning
```bash
# Network discovery with NSE
nmap --script broadcast-ping 192.180.108.0/24
# Output: Discovers live hosts

# SMB enumeration on network
nmap --script smb-enum-shares 192.180.108.0/24 -p 445
# Output: Available SMB shares on network hosts
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **HTTP enumeration (40%)** - Critical for web application testing
- **SMB enumeration (30%)** - Common in Windows environments  
- **Service detection (20%)** - Identifying attack vectors
- **Vulnerability scanning (10%)** - Finding exploitable services

### Critical Commands to Master:
```bash
# Must-know commands for exam
nmap --script http-enum target           # Web directory enumeration
nmap --script smb-enum-shares target     # SMB share discovery
nmap --script ftp-anon target            # Anonymous FTP access
nmap --script ssh-hostkey target         # SSH key fingerprinting
```

### eJPT Exam Scenarios:
1. **Web Application Discovery:** Use http-* scripts to enumerate web services
   - Required skills: HTTP enumeration, directory discovery
   - Expected commands: `--script http-enum,http-title,http-methods`
   - Success criteria: Identify upload forms, admin panels, hidden directories

2. **Network Service Enumeration:** Discover and enumerate various network services
   - Required skills: Multi-protocol enumeration
   - Expected commands: `--script smb-*,ftp-*,ssh-*`  
   - Success criteria: Find accessible shares, anonymous access, version information

### Exam Tips and Tricks:
- **Combine scripts:** Use comma-separated script names for efficiency
- **Use categories:** `--script safe` for non-intrusive scanning
- **Check script args:** Many scripts have useful parameters via `--script-args`
- **Save outputs:** Always use `-oN` to save results for reporting

### Common eJPT Questions:
- Enumerate web directories and identify upload functionality
- Find SMB shares accessible without authentication
- Identify service versions for vulnerability research

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Scripts Not Found or Outdated
**Problem:** Script database outdated or missing scripts
**Cause:** NSE scripts not updated or custom script location issues
**Solution:**
```bash
# Update NSE script database
nmap --script-updatedb

# Verify script location
locate http-enum.nse
# Should show: /usr/share/nmap/scripts/http-enum.nse
```

### Issue 2: Script Arguments Not Working
**Problem:** Script arguments not being passed correctly
**Solution:**
```bash
# Correct syntax with script arguments
nmap --script http-enum --script-args http-enum.displayall target

# Check script help for argument format
nmap --script-help http-enum
```

### Issue 3: Permission Issues with Scripts
**Problem:** Scripts require root privileges for certain operations
**Solution:**
```bash
# Run with appropriate privileges
sudo nmap --script smb-enum-shares target

# Use TCP connect scan if SYN scan fails
nmap -sT --script default target
```

### Issue 4: Script Performance Issues
**Problem:** Scripts running slowly or timing out
**Optimization:**
```bash
# Increase timing template
nmap -T4 --script http-enum target

# Limit concurrent scripts
nmap --script vuln --script-args max-parallelism=10 target
```

## 🔗 Integration with Other Tools

### Primary Integration: Nmap → NSE → Metasploit
```bash
# Step 1: Nmap discovers services
nmap -sV --script default target > services.txt

# Step 2: NSE identifies vulnerabilities  
nmap --script vuln target > vulnerabilities.txt

# Step 3: Use results in Metasploit
grep -i "CVE\|exploit" vulnerabilities.txt
# Feed identified CVEs into Metasploit search
```

### Secondary Integration: NSE → Manual Testing
```bash
# HTTP enumeration results guide manual testing
nmap --script http-enum target | grep -E "(Interesting|Found)"
# Use discovered paths for manual directory traversal and file upload testing
```

### Advanced Workflows:
```bash
# Comprehensive enumeration pipeline
nmap -p- --script discovery target               # Full port discovery
nmap -p$(ports) --script default,safe target     # Service enumeration
nmap -p$(http_ports) --script http-* target      # Web-specific scanning
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** NSE script outputs showing discovered services/vulnerabilities
2. **Command Outputs:** Full nmap results with script outputs  
3. **Log Files:** Save all scan results with timestamps
4. **Script Details:** Document which scripts were used and why

### Report Template Structure:
```markdown
## NSE Scanning Results

### Target Information
- Target: demo1.ine.local (192.63.4.3)
- Date/Time: 2024-11-26 13:08 IST
- Scanner Version: Nmap 7.94SVN

### Commands Executed
```bash
# Service discovery
nmap demo1.ine.local

# HTTP enumeration  
nmap --script http-enum demo1.ine.local

# Vulnerability scanning
nmap --script vuln demo1.ine.local
```

### Key Findings
- HTTP service on port 80 running XODA web application
- File upload functionality discovered at /upload.php
- Anonymous access enabled on discovered directories

### Recommendations
- Implement proper file upload validation
- Restrict directory browsing permissions
- Update web application to latest version
```

### Automation Scripts:
```bash
# Automated NSE enumeration script
#!/bin/bash
target=$1
echo "Starting NSE enumeration of $target"
nmap --script discovery $target -oN discovery_$target.txt
nmap --script http-* $target -p 80,443,8080 -oN http_$target.txt  
nmap --script smb-* $target -p 445 -oN smb_$target.txt
echo "NSE enumeration complete. Check output files."
```

## 📚 Additional Resources

### Official Documentation:
- NSE Documentation: https://nmap.org/book/nse.html
- Script Database: https://nmap.org/nsedoc/
- NSE Tutorial: https://nmap.org/book/nse-tutorial.html

### Learning Resources:
- Nmap Network Scanning book: https://nmap.org/book/
- NSE Script Writing: https://nmap.org/book/nse-script-format.html
- Video tutorials: Search for "NSE scripting tutorials"

### Community Resources:
- Nmap mailing lists: https://nmap.org/mailman/listinfo/
- GitHub NSE scripts: https://github.com/nmap/nmap/tree/master/scripts
- Security forums discussing NSE usage

### Related Tools:
- Masscan: High-speed port scanner alternative
- Zmap: Internet-wide network scanner  
- Nessus/OpenVAS: Comprehensive vulnerability scanners that complement NSE
