# 🌐 Linux Network Commands - Essential Network Tools

Essential Linux network commands for eJPT penetration testing and network reconnaissance.
**Location:** `01-theory-foundations/linux-fundamentals/network-commands.md`

## 🎯 What are Linux Network Commands?

Linux network commands are built-in utilities that allow penetration testers to interact with networks, gather information, test connectivity, and perform network diagnostics. These commands form the foundation of network reconnaissance and are essential tools in every penetration tester's toolkit.

Key categories include:
- **Connectivity Testing:** ping, traceroute, telnet
- **Network Configuration:** ifconfig, ip, route
- **DNS Resolution:** nslookup, dig, host
- **Network Statistics:** netstat, ss, lsof
- **File Transfer:** wget, curl, scp, nc

## 📦 Installation and Setup

### Prerequisites:
- Linux system (Kali Linux recommended for penetration testing)
- Network access for testing commands
- Basic understanding of TCP/IP networking

### Verification:
```bash
# Check if essential commands are available
which ping traceroute netstat wget curl
# Expected output: paths to all commands

# Test basic connectivity
ping -c 1 8.8.8.8
# Expected output: successful ping response
```

## 🔧 Basic Usage Categories

### Basic Command Structure:
1. **Connectivity Testing:** Verify network reachability
2. **Information Gathering:** Collect network and system data
3. **Configuration Review:** Check network settings
4. **Transfer Operations:** Move files across networks

## ⚙️ Essential Network Commands

### Connectivity Testing Commands:
| Command | Purpose | Example |
|---------|---------|---------|
| `ping` | Test ICMP connectivity | `ping -c 4 192.168.1.1` |
| `traceroute` | Trace network path | `traceroute google.com` |
| `telnet` | Test TCP port connectivity | `telnet 192.168.1.1 80` |
| `nc` (netcat) | Network connections and listening | `nc -zv 192.168.1.1 22` |

### Network Information Commands:
| Command | Purpose | Example |
|---------|---------|---------|
| `ifconfig` | Network interface configuration | `ifconfig eth0` |
| `ip` | Modern network configuration | `ip addr show` |
| `route` | Display routing table | `route -n` |
| `netstat` | Network connections and statistics | `netstat -tulpn` |
| `ss` | Modern netstat replacement | `ss -tulpn` |

### DNS Resolution Commands:
| Command | Purpose | Example |
|---------|---------|---------|
| `nslookup` | DNS lookup | `nslookup google.com` |
| `dig` | Advanced DNS lookup | `dig google.com A` |
| `host` | Simple DNS lookup | `host google.com` |

### File Transfer Commands:
| Command | Purpose | Example |
|---------|---------|---------|
| `wget` | Download files from web | `wget http://example.com/file.txt` |
| `curl` | Transfer data from servers | `curl -I http://example.com` |
| `scp` | Secure copy over SSH | `scp file.txt user@host:/tmp/` |

## 🧪 Real Lab Examples

### Example 1: Network Reconnaissance Workflow
```bash
# Step 1: Check your network configuration
ifconfig
# Output: Shows network interfaces and IP addresses
# eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
#       inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255

# Step 2: Test connectivity to gateway
ping -c 3 192.168.1.1
# Output: 3 packets transmitted, 3 received, 0% packet loss

# Step 3: Check open ports on local system
netstat -tulpn | grep LISTEN
# Output: Shows all listening services
# tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1234/sshd
# tcp 0 0 127.0.0.1:3306 0.0.0.0:* LISTEN 5678/mysqld

# Step 4: Test remote service connectivity
nc -zv 192.168.1.10 80
# Output: Connection to 192.168.1.10 80 port [tcp/http] succeeded!
```

### Example 2: DNS Investigation
```bash
# Check DNS resolution
nslookup google.com
# Output: Server: 8.8.8.8, Address: 8.8.8.8#53
#         Non-authoritative answer: Name: google.com, Address: 142.250.191.14

# Advanced DNS lookup
dig google.com MX
# Output: Shows mail exchange records
# google.com. 300 IN MX 10 smtp.google.com.

# Reverse DNS lookup
dig -x 8.8.8.8
# Output: 8.8.8.8.in-addr.arpa. 7200 IN PTR dns.google.
```

### Example 3: Port Scanning with Built-in Tools
```bash
# Quick port check using netcat
for port in 21 22 23 25 53 80 110 443 993 995; do
    nc -zv 192.168.1.1 $port 2>&1 | grep succeeded
done
# Output: Shows which ports are open
# Connection to 192.168.1.1 22 port [tcp/ssh] succeeded!
# Connection to 192.168.1.1 80 port [tcp/http] succeeded!

# Check routing table
route -n
# Output: Kernel IP routing table
# Destination Gateway Genmask Flags Metric Ref Use Iface
# 0.0.0.0 192.168.1.1 0.0.0.0 UG 100 0 0 eth0
# 192.168.1.0 0.0.0.0 255.255.255.0 U 100 0 0 eth0
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Network Connectivity Testing (25%)** - Using ping, traceroute, telnet for reachability
- **Network Configuration Analysis (20%)** - Reading ifconfig, route, netstat outputs
- **DNS Resolution and Investigation (15%)** - Using nslookup, dig for domain analysis
- **Port Connectivity Testing (20%)** - Using netcat and telnet for service discovery
- **File Transfer Operations (20%)** - Using wget, curl for payload delivery

### Critical Commands to Master:
```bash
# Network interface information
ifconfig                    # Check network configuration
ip addr show               # Modern way to view interfaces

# Connectivity testing
ping -c 4 target_ip        # Test ICMP connectivity
traceroute target_ip       # Trace network path
nc -zv target_ip port      # Test TCP port connectivity

# Network discovery
netstat -tulpn             # Show listening services
ss -tulpn                  # Modern netstat replacement
route -n                   # Display routing table

# DNS operations
nslookup domain.com        # Basic DNS lookup
dig domain.com A           # Advanced DNS queries
host domain.com            # Simple hostname resolution
```

### eJPT Exam Scenarios:
1. **Network Discovery Scenario:**
   - Use ping to test connectivity to multiple hosts
   - Use netstat to identify local services
   - Use traceroute to understand network topology

2. **Service Enumeration Scenario:**
   - Use telnet to test specific service ports
   - Use nc to verify service availability
   - Use curl to test HTTP services

### Exam Tips and Tricks:
- **Tip 1:** Always use `-c` option with ping to limit packet count
- **Tip 2:** Combine `netstat -tulpn` with `grep` to filter specific services
- **Tip 3:** Use `nc -zv` for quick port checks without sending data
- **Tip 4:** Master `curl -I` for HTTP header analysis

### Common eJPT Questions:
- Identifying network interfaces and their configurations
- Testing connectivity to specific hosts and ports
- Understanding routing table entries
- Performing DNS lookups and reverse lookups

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Permission Denied Errors
**Problem:** Some network commands require root privileges
**Solution:**
```bash
# Use sudo for privileged operations
sudo netstat -tulpn
sudo traceroute target_ip

# Or switch to root user
su -
netstat -tulpn
```

### Issue 2: DNS Resolution Failures
**Problem:** DNS lookups fail or return incorrect results
**Solution:**
```bash
# Check DNS configuration
cat /etc/resolv.conf

# Use specific DNS server
nslookup google.com 8.8.8.8
dig @8.8.8.8 google.com A

# Test connectivity to DNS server
ping -c 2 8.8.8.8
```

### Issue 3: Network Interface Not Found
**Problem:** Interface commands show "device not found"
**Solution:**
```bash
# List all available interfaces
ip link show

# Check if interface is up
ip link set eth0 up

# Verify interface status
ifconfig -a
```

### Issue 4: Firewall Blocking Connections
**Problem:** Network tools can't connect due to firewall rules
**Solution:**
```bash
# Check iptables rules
sudo iptables -L

# Temporarily disable firewall (for testing only)
sudo ufw disable

# Test with different protocols
nc -u target_ip port    # UDP instead of TCP
```

## 🔗 Integration with Other Tools

### Primary Integration: Network Commands → Nmap → Service Enumeration
```bash
# Step 1: Basic connectivity and network discovery
ping -c 1 192.168.1.0/24
ifconfig | grep "inet " | awk '{print $2}'

# Step 2: Quick port checks feed into nmap
nc -zv 192.168.1.10 80 && nmap -sV -p80 192.168.1.10

# Step 3: DNS information feeds into further enumeration
dig example.com | grep -E "^example.com" | awk '{print $5}' | xargs nmap -sS
```

### Secondary Integration: Network Commands → Metasploit
```bash
# Network reconnaissance provides targets for metasploit
netstat -rn | grep "^0.0.0.0" | awk '{print $2}'  # Find gateway
ping -c 1 gateway_ip && msfconsole -x "use auxiliary/scanner/discovery/arp_sweep; set RHOSTS gateway_network/24; run"
```

### Advanced Workflows:
```bash
# Complete network assessment workflow
# 1. Local network analysis
ifconfig | grep -E "(inet|ether)"
route -n | grep "^0.0.0.0"

# 2. Connectivity testing
ping -c 2 $(route -n | grep "^0.0.0.0" | awk '{print $2}')

# 3. Service discovery on gateway
nc -zv $(route -n | grep "^0.0.0.0" | awk '{print $2}') 22 80 443 2>&1 | grep succeeded
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Network Configuration Screenshots:** ifconfig, route, netstat outputs
2. **Connectivity Test Results:** ping and traceroute outputs showing network paths
3. **Service Discovery Evidence:** netcat and telnet results showing open ports
4. **DNS Resolution Results:** nslookup and dig outputs for domain analysis

### Report Template Structure:
```markdown
## Network Assessment Results

### Target Network Information
- Network Range: 192.168.1.0/24
- Gateway: 192.168.1.1
- DNS Servers: 8.8.8.8, 8.8.4.4
- Assessment Date: [timestamp]

### Network Configuration
```bash
# Local interface configuration
ifconfig eth0
# Output: [interface_details]

# Routing table
route -n
# Output: [routing_table]
```

### Connectivity Testing
- Gateway connectivity: ✓ Successful (ping response in 1ms)
- External connectivity: ✓ Successful (Google DNS reachable)
- Internal network: ✓ Multiple hosts responding

### Service Discovery
- Host 192.168.1.1: SSH (22), HTTP (80), HTTPS (443)
- Host 192.168.1.10: SSH (22), MySQL (3306)
- Host 192.168.1.20: HTTP (80), FTP (21)

### DNS Analysis
- Domain resolution: ✓ Working properly
- Reverse DNS: ✓ Configured for internal network
- DNS servers: ✓ Responding normally
```

### Automation Scripts:
```bash
#!/bin/bash
# Network discovery automation script
echo "=== Network Configuration ===" > network_report.txt
ifconfig >> network_report.txt
echo -e "\n=== Routing Table ===" >> network_report.txt
route -n >> network_report.txt
echo -e "\n=== DNS Configuration ===" >> network_report.txt
cat /etc/resolv.conf >> network_report.txt
```
