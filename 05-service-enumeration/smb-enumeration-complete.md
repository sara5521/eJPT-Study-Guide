# 🔧 SMB Enumeration - Complete Reconnaissance Guide

SMB (Server Message Block) enumeration is a critical skill for penetration testing that involves discovering and analyzing SMB services to identify shares, permissions, and potential attack vectors. This protocol is commonly found on Windows systems and provides file sharing, printer access, and inter-process communication capabilities.

**Location:** `05-service-enumeration/smb-enumeration-complete.md`

## 📋 SMB Enumeration Quick Reference

### Essential Commands Cheat Sheet:
```bash
nmap -p139,445 target          # Port scan
smbclient -L target -N         # List shares  
rpcclient -U "" -N target      # Test null session
enum4linux -a target          # Full enumeration
nmblookup -A target           # NetBIOS lookup
nmap --script smb* target     # SMB scripts
```

### Critical Information to Extract:
- Computer/NetBIOS names
- Workgroup/Domain information  
- Available shares and permissions
- SMB/Samba version numbers
- Null session accessibility

## 🎯 What is SMB Enumeration?

SMB enumeration is the process of gathering information about SMB/CIFS services running on target systems. This includes identifying available shares, user accounts, system information, and access permissions. Key capabilities include:

- **Share Discovery**: Identifying available network shares and their permissions
- **User Enumeration**: Discovering user accounts and group memberships  
- **System Information**: Gathering OS details, computer names, and domain information
- **Version Detection**: Identifying SMB protocol versions and potential vulnerabilities

## 📦 Installation and Setup

### Prerequisites:
- Kali Linux or similar penetration testing distribution
- Network connectivity to target SMB services
- Basic understanding of Windows networking concepts

### Installation:
```bash
# Update package lists
apt update

# Install SMB enumeration tools (usually pre-installed)
apt install smbclient enum4linux nmap samba-common-bin

# Install additional tools
apt install nbtscan rpcclient samba-client

# Verification
smbclient --version
# Expected output: Version 4.x.x
nmap --version
# Expected output: Nmap 7.x.x
rpcclient --version
# Expected output: Version information
```

### Initial Configuration:
```bash
# Configure SMB client for older protocols (if needed)
echo "client min protocol = NT1" >> /etc/samba/smb.conf

# Test basic connectivity
ping target_ip
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Port Discovery**: Identify SMB ports (139, 445) on target systems
2. **Service Detection**: Determine SMB version and services running
3. **Share Enumeration**: List available shares and their permissions
4. **Authentication Testing**: Test null sessions and weak credentials
5. **Information Gathering**: Extract system details and user information

### Command Structure:
```bash
# Basic SMB port scanning
nmap -p 139,445 target_ip

# Share enumeration
smbclient -L target_ip -N

# Connecting to specific shares
smbclient //target_ip/sharename -U username

# Advanced enumeration
enum4linux -a target_ip
```

## ⚙️ Command Line Options

### Nmap SMB Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-p 139,445` | Scan SMB ports | `nmap -p 139,445 192.168.1.10` |
| `-sV` | Version detection | `nmap -sV -p 445 target_ip` |
| `--script smb*` | Run SMB scripts | `nmap --script smb* target_ip` |
| `-sU --top-ports 25` | UDP scan for NetBIOS | `nmap -sU --top-ports 25 target_ip` |

### SMBClient Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-L` | List shares | `smbclient -L //target_ip -N` |
| `-N` | No password (null session) | `smbclient -L target_ip -N` |
| `-U` | Specify username | `smbclient -U guest //target_ip/share` |
| `-c` | Execute commands | `smbclient //target_ip/share -c "ls"` |

### Enum4linux Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-a` | All enumeration | `enum4linux -a target_ip` |
| `-S` | Share enumeration | `enum4linux -S target_ip` |
| `-U` | User enumeration | `enum4linux -U target_ip` |
| `-G` | Group enumeration | `enum4linux -G target_ip` |

### RPCClient Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-U ""` | Empty username for null session | `rpcclient -U "" target_ip` |
| `-N` | No password prompt | `rpcclient -U "" -N target_ip` |
| `-c` | Execute RPC commands | `rpcclient -U "" -N -c "enumdomusers" target_ip` |
| `-W` | Specify workgroup/domain | `rpcclient -U "" -N -W RECONLABS target_ip` |

## 🧪 Real Lab Examples

### Example 1: Basic SMB Port Discovery
```bash
# Initial nmap scan for SMB services
nmap demo.ine.local

# Expected output from lab:
Starting Nmap 7.945VN ( https://nmap.org ) at 2024-07-05 09:54 IST
Nmap scan report for demo.ine.local (192.220.69.3)
Host is up (0.000020s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
MAC Address: 02:42:C0:DC:45:03 (Unknown)
```

### Example 2: SMB Version Detection and Service Information
```bash
# Detailed service version detection
nmap -sV -p 445 demo.ine.local

# Lab output showing Samba version:
PORT     STATE SERVICE     VERSION
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: RECONLABS)
MAC Address: 02:42:C0:DC:45:03 (Unknown)
Service Info: Host: SAMBA-RECON
```

### Example 3: SMB Share Discovery with Null Session
```bash
# Test null session access to list shares
smbclient -L demo.ine.local -N

# Successful null session results:
Sharename       Type      Comment
---------       ----      -------
public          Disk      
john            Disk      
aisha           Disk
emma            Disk      
everyone        Disk      
IPC$            IPC       IPC Service (samba.recon.lab)

# Server information from smbclient output:
Server          Comment
-------         -------
Workgroup       Master
---------       ------
RECONLABS       SAMBA-RECON
```

### Example 4: Testing Null Sessions with RPCClient
```bash
# Test anonymous RPC connection to verify null session access
rpcclient -U "" -N demo.ine.local

# Successful connection indicates null session is allowed:
rpcclient $>

# Anonymous connection allowed - no errors during connection
# This confirms that null sessions are permitted on the target
```

### Example 5: Advanced SMB OS Discovery Using NSE Scripts
```bash
# Advanced SMB OS discovery using NSE script
nmap --script smb-os-discovery.nse -p 445 demo.ine.local

# Detailed results from script:
Host script results:
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: demo
|   NetBIOS computer name: SAMBA-RECON\x00
|   Domain name: ine.local
|   FQDN: demo.ine.local
|_  System time: 2024-07-05T04:28:50+00:00
```

### Example 6: NetBIOS Name Resolution
```bash
# NetBIOS lookup for computer name discovery
nmblookup -A demo.ine.local

# Lab results showing NetBIOS information:
Looking up status of 192.220.69.3
        SAMBA-RECON     <00> -         H <ACTIVE>
        SAMBA-RECON     <03> -         H <ACTIVE>
        SAMBA-RECON     <20> -         H <ACTIVE>
        ..__MSBROWSE__. <01> - <GROUP> H <ACTIVE>
        RECONLABS       <00> - <GROUP> H <ACTIVE>
        RECONLABS       <1d> -         H <ACTIVE>
        RECONLABS       <1e> - <GROUP> H <ACTIVE>

        MAC Address = 00-00-00-00-00-00
```

### Example 7: UDP Service Discovery for NetBIOS
```bash
# Scan top UDP ports for NetBIOS services
nmap -sU --top-ports 25 demo.ine.local

# Lab results showing NetBIOS services:
PORT     STATE         SERVICE
137/udp  open          netbios-ns
138/udp  open|filtered netbios-dgm
139/udp  closed        netbios-ssn
445/udp  closed        microsoft-ds
# ... other closed ports omitted for brevity
```

### Example 8: Metasploit SMB Version Detection (Advanced Verification)
```bash
# Using Metasploit for precise version identification
msfconsole -q
use auxiliary/scanner/smb/smb_version
set RHOSTS demo.ine.local
exploit

# Metasploit results:
[+] 192.220.69.3:445    - SMB Detected (versions:1, 2, 3) (preferred dialect:SMB 3.1.1)
[+] 192.220.69.3:445    - Host could not be identified: Windows 6.1 (Samba 4.3.11-Ubuntu)
[*] demo.ine.local:445  - Scanned 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT (85% exam relevance):
- **SMB Port Identification** (95% importance) - Identifying ports 139/445
- **Share Enumeration** (90% importance) - Discovering accessible shares
- **Null Session Testing** (85% importance) - Testing anonymous access
- **Version Detection** (80% importance) - Identifying SMB/Samba versions
- **NetBIOS Name Resolution** (75% importance) - Computer name discovery

### Critical Commands to Master:
```bash
# Port scanning for SMB services
nmap -p 139,445 target_ip

# Share enumeration with null session
smbclient -L target_ip -N

# Version detection
nmap -sV -p 445 target_ip

# NetBIOS computer name lookup
nmblookup -A target_ip

# RPC null session test
rpcclient -U "" -N target_ip

# SMB OS discovery script
nmap --script smb-os-discovery.nse -p 445 target_ip
```

### eJPT Exam Scenarios:

1. **Network Share Discovery:** Students must identify all available SMB shares on target systems
   - Required skills: Port scanning, share enumeration
   - Expected commands: `nmap -p 139,445`, `smbclient -L`
   - Success criteria: List all discoverable shares

2. **System Information Gathering:** Determine computer names, workgroups, and OS versions
   - Required skills: NetBIOS queries, version detection
   - Expected commands: `nmblookup -A`, `nmap --script smb-os-discovery`
   - Success criteria: Extract system identification details

3. **Anonymous Access Testing:** Verify which shares allow null session access and test RPC connectivity
   - Required skills: Null session testing, permission analysis, RPC enumeration
   - Expected commands: `smbclient -L target -N`, `rpcclient -U "" -N target`
   - Success criteria: Identify accessible shares and confirm null session status

### eJPT Success Metrics:
- **Time Allocation**: Maximum 10 minutes for complete SMB enumeration
- **Must-Find Information**: Computer name, workgroup, shares list, SMB version
- **Critical Skills**: Null session testing, version detection, share discovery
- **Common Exam Traps**: Missing UDP NetBIOS scan, not testing RPC access
- **Documentation Requirements**: Screenshot all findings, save command outputs

### Exam Tips and Tricks:
- **Systematic Approach**: Follow the enumeration workflow consistently
- **Time Management**: SMB enumeration should take 5-10 minutes per target
- **Documentation**: Always record computer names and workgroup information
- **Null Sessions First**: Test null sessions before attempting authentication
- **Multiple Verification**: Use both nmap and smbclient for comprehensive coverage
- **Script Usage**: Leverage nmap scripts for additional information gathering

### Common eJPT Questions:
- "What is the NetBIOS computer name of the target system?"
- "List all available SMB shares on the target"
- "What version of Samba is running on the target?"

## 🚫 Common Beginner Mistakes

### Issue 1: Skipping UDP NetBIOS Enumeration
**Mistake**: Only scanning TCP ports and missing NetBIOS name services
**Impact**: Missing computer names, workgroup information, and service details
**Solution**: Always include UDP scan for ports 137-138
```bash
# Correct approach - include UDP scan
nmap -sU --top-ports 25 target_ip
nmblookup -A target_ip
```

### Issue 2: Not Testing Null Sessions Thoroughly
**Mistake**: Assuming SMB requires authentication without testing anonymous access
**Impact**: Missing easy reconnaissance opportunities and accessible shares
**Solution**: Always test both smbclient and rpcclient null sessions
```bash
# Test both methods
smbclient -L target_ip -N
rpcclient -U "" -N target_ip
```

### Issue 3: Ignoring SMB Version Information
**Mistake**: Not collecting specific version details for exploit research
**Impact**: Missing potential vulnerability exploitation opportunities
**Solution**: Use multiple tools to get precise version information
```bash
# Get detailed version info
nmap -sV -p 445 target_ip
nmap --script smb-protocols target_ip
```

### Issue 4: Poor Documentation Practices
**Mistake**: Not saving command outputs and screenshots systematically
**Impact**: Losing critical findings needed for reporting and exam answers
**Solution**: Document everything with timestamps and organized file structure
```bash
# Create organized output directory
mkdir smb_enum_$(date +%Y%m%d_%H%M%S)
# Save all outputs to files
```

## ⚠️ Technical Issues & Troubleshooting

### Issue 1: SMB Connection Refused
**Problem:** Connection refused errors when attempting SMB enumeration
**Cause:** Target system may not have SMB services running or firewall blocking
**Solution:**
```bash
# Verify ports are actually open
nmap -p 139,445 target_ip

# Try alternative enumeration methods
enum4linux target_ip
```

### Issue 2: Protocol Negotiation Failed
**Problem:** "protocol negotiation failed" errors with modern Windows systems
**Cause:** SMB version compatibility issues
**Solution:**
```bash
# Force SMB version 1 support
echo "client min protocol = NT1" >> /etc/samba/smb.conf

# Use specific SMB version in smbclient
smbclient -L target_ip --option='client min protocol=NT1'
```

### Issue 3: Access Denied Errors
**Problem:** "Access denied" when trying to enumerate shares
**Cause:** Target requires authentication or null sessions disabled
**Solution:**
```bash
# Try with guest account
smbclient -L target_ip -U guest

# Attempt with common credentials
smbclient -L target_ip -U administrator
```

### Issue 4: Incomplete Enumeration Results
**Problem:** Tools return limited information
**Cause:** Insufficient enumeration techniques or missing tools
**Solution:**
```bash
# Combine multiple enumeration tools
nmap --script smb* target_ip
enum4linux -a target_ip
nbtscan -A target_ip
```

### Issue 5: No Shares Visible Despite Open Ports
**Problem:** SMB ports open but no shares enumerated
**Cause:** Restrictive share permissions or null session restrictions
**Solution:**
```bash
# Try different authentication methods
smbclient -L target_ip -U ""
smbclient -L target_ip -U guest%guest
enum4linux -u guest -p guest target_ip
```

### Issue 1: SMB Connection Refused
**Problem:** Connection refused errors when attempting SMB enumeration
**Cause:** Target system may not have SMB services running or firewall blocking
**Solution:**
```bash
# Verify ports are actually open
nmap -p 139,445 target_ip

# Try alternative enumeration methods
enum4linux target_ip
```

### Issue 2: Protocol Negotiation Failed
**Problem:** "protocol negotiation failed" errors with modern Windows systems
**Cause:** SMB version compatibility issues
**Solution:**
```bash
# Force SMB version 1 support
echo "client min protocol = NT1" >> /etc/samba/smb.conf

# Use specific SMB version in smbclient
smbclient -L target_ip --option='client min protocol=NT1'
```

### Issue 3: Access Denied Errors
**Problem:** "Access denied" when trying to enumerate shares
**Cause:** Target requires authentication or null sessions disabled
**Solution:**
```bash
# Try with guest account
smbclient -L target_ip -U guest

# Attempt with common credentials
smbclient -L target_ip -U administrator
```

### Issue 4: Incomplete Enumeration Results
**Problem:** Tools return limited information
**Cause:** Insufficient enumeration techniques or missing tools
**Solution:**
```bash
# Combine multiple enumeration tools
nmap --script smb* target_ip
enum4linux -a target_ip
nbtscan -A target_ip
```

## 🔗 Integration with Other Tools

### Primary Integration: Nmap → SMBClient → RPCClient → Enum4linux
```bash
# Complete SMB reconnaissance workflow
nmap -p 139,445 target_ip | grep open

# If SMB ports are open, enumerate shares
smbclient -L target_ip -N

# Test null session with RPC
rpcclient -U "" -N target_ip

# Detailed enumeration with enum4linux
enum4linux -a target_ip
```

### Secondary Integration: SMB → Exploitation Tools
```bash
# After identifying SMB version, search for exploits
searchsploit samba 4.3.11

# Use Metasploit modules for further testing
msfconsole
search smb auxiliary
```

### Advanced Workflows:
```bash
# Automated SMB reconnaissance pipeline
nmap -p 139,445 --open target_range > open_smb_hosts.txt
for host in $(cat open_smb_hosts.txt | grep "Nmap scan report" | awk '{print $5}'); do
    echo "Enumerating $host"
    smbclient -L $host -N
    enum4linux -S $host
done
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Capture nmap scan results, share listings, and system information
2. **Command Outputs:** Save all enumeration results in text files
3. **Log Files:** Preserve detailed logs from enum4linux and other tools
4. **Configuration Files:** Document any SMB client configuration changes

### Report Template Structure:
```markdown
## SMB Enumeration Results

### Target Information
- Target: 192.220.69.3 (demo.ine.local)
- Date/Time: 2024-07-05 09:54 IST
- Tools Used: Nmap 7.945VN, SMBClient, Enum4linux

### Commands Executed
```bash
# Port discovery
nmap -p 139,445 demo.ine.local

# Share enumeration
smbclient -L demo.ine.local -N

# Version detection
nmap -sV -p 445 demo.ine.local

# NetBIOS lookup
nmblookup -A demo.ine.local
```

### Key Findings
- **Open Ports**: 139/tcp (netbios-ssn), 445/tcp (microsoft-ds)
- **SMB Version**: Samba smbd 3.X - 4.X (specifically 4.3.11-Ubuntu)
- **Computer Name**: SAMBA-RECON
- **Workgroup**: RECONLABS
- **Available Shares**: public, john, aisha, emma, everyone, IPC$ (all accessible via null session)
- **IPC Service**: samba.recon.lab service available
- **Null Session Status**: Confirmed allowed via both smbclient and rpcclient testing

### Recommendations
- Disable null session access to prevent unauthorized enumeration
- Implement proper share permissions and access controls
- Update Samba to latest version to address potential vulnerabilities
```

### Automation Scripts:
```bash
#!/bin/bash
# Enhanced SMB enumeration automation script
target=$1

# Input validation
if [ -z "$1" ]; then
    echo "Usage: $0 <target_ip>"
    echo "Example: $0 192.168.1.10"
    exit 1
fi

# Create timestamped output directory
output_dir="smb_enum_$(date +%Y%m%d_%H%M%S)"
mkdir $output_dir

echo "[+] Starting comprehensive SMB enumeration for $target"
echo "[+] Results will be saved in $output_dir/"
echo ""

# Phase 1: Port Discovery
echo "[+] Phase 1: Scanning SMB ports (139, 445)..."
nmap -p 139,445 -sV $target | tee $output_dir/01_port_scan.txt

# Check if SMB ports are open
if grep -q "open" $output_dir/01_port_scan.txt; then
    echo "[✓] SMB ports detected, proceeding with enumeration"
    echo ""
    
    # Phase 2: Share Discovery
    echo "[+] Phase 2: Discovering SMB shares..."
    smbclient -L $target -N > $output_dir/02_shares.txt 2>&1
    if [ $? -eq 0 ]; then
        echo "[✓] Share enumeration completed successfully"
        cat $output_dir/02_shares.txt | grep -E "(Sharename|IPC|Disk)"
    else
        echo "[!] Share enumeration failed, trying alternative methods"
    fi
    echo ""
    
    # Phase 3: RPC Null Session Test
    echo "[+] Phase 3: Testing RPC null session..."
    echo "quit" | rpcclient -U "" -N $target > $output_dir/03_rpc_test.txt 2>&1
    if grep -q "rpcclient" $output_dir/03_rpc_test.txt; then
        echo "[✓] RPC null session allowed"
    else
        echo "[!] RPC null session denied or failed"
    fi
    echo ""
    
    # Phase 4: NetBIOS Information
    echo "[+] Phase 4: Gathering NetBIOS information..."
    nmblookup -A $target > $output_dir/04_netbios.txt 2>&1
    if [ $? -eq 0 ]; then
        echo "[✓] NetBIOS lookup completed"
        grep -E "(<00>|<20>|<03>)" $output_dir/04_netbios.txt
    fi
    echo ""
    
    # Phase 5: Advanced Scripts
    echo "[+] Phase 5: Running advanced SMB scripts..."
    nmap --script smb-os-discovery.nse -p 445 $target > $output_dir/05_smb_scripts.txt
    echo "[✓] SMB scripts completed"
    echo ""
    
    # Phase 6: Comprehensive Enumeration
    echo "[+] Phase 6: Running comprehensive enum4linux scan..."
    enum4linux -a $target > $output_dir/06_enum4linux.txt 2>&1
    echo "[✓] Comprehensive enumeration completed"
    echo ""
    
    # Generate Summary Report
    echo "[+] Generating summary report..."
    {
        echo "=== SMB ENUMERATION SUMMARY ==="
        echo "Target: $target"
        echo "Date: $(date)"
        echo "================================"
        echo ""
        echo "OPEN PORTS:"
        grep "open" $output_dir/01_port_scan.txt
        echo ""
        echo "COMPUTER NAME:"
        grep "Computer name:" $output_dir/05_smb_scripts.txt
        echo ""
        echo "WORKGROUP:"
        grep -i "workgroup" $output_dir/01_port_scan.txt
        echo ""
        echo "SHARES DISCOVERED:"
        grep -E "^\s*\w+\s+(Disk|IPC)" $output_dir/02_shares.txt
        echo ""
        echo "NULL SESSION STATUS:"
        if grep -q "rpcclient" $output_dir/03_rpc_test.txt; then
            echo "Null sessions ALLOWED"
        else
            echo "Null sessions DENIED"
        fi
    } > $output_dir/00_SUMMARY.txt
    
    echo "[✓] Summary report generated: $output_dir/00_SUMMARY.txt"
    echo ""
    echo "=== QUICK RESULTS ==="
    cat $output_dir/00_SUMMARY.txt
    
else
    echo "[!] No SMB ports found open on $target"
    echo "[-] Enumeration cannot proceed"
fi

echo ""
echo "[+] SMB enumeration completed!"
echo "[+] All results saved in: $output_dir/"
```

## 📚 Additional Resources

### Official Documentation:
- Samba Project: https://www.samba.org/
- Microsoft SMB Documentation: https://docs.microsoft.com/en-us/windows-server/storage/file-server/
- Nmap SMB Scripts: https://nmap.org/nsedoc/categories/smb.html

### Learning Resources:
- eJPT Course Materials: Focus on SMB enumeration modules
- HackTheBox Academy: SMB enumeration pathway
- TryHackMe: Network Services room covering SMB

### Community Resources:
- /r/AskNetsec: SMB enumeration discussions
- Security Stack Exchange: SMB-related questions
- OSCP/eJPT Discord communities

### Related Tools:
- **rpcclient**: RPC-based enumeration alternative
- **smbmap**: Python-based SMB share enumeration tool
- **crackmapexec**: Advanced SMB enumeration and exploitation framework
