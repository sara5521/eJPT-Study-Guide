# 🔧 Manual Scanning Methods - Custom Port Scanning Techniques

Manual scanning techniques using basic tools and custom scripts for targeted port scanning and service discovery.
**Location:** `04-port-scanning/manual-scanning-methods.md`

## 🎯 What are Manual Scanning Methods?

Manual scanning methods involve using basic networking tools and custom scripts to perform port scanning and service enumeration without relying on comprehensive tools like Nmap. Key capabilities include:

- Custom Bash/Python scripts for port scanning
- Banner grabbing using netcat and telnet
- UDP service discovery
- Stealth scanning techniques
- Protocol-specific enumeration

## 📦 Installation and Setup

### Prerequisites:

- Basic networking tools (netcat, telnet, bash)
- Text processing tools (grep, awk, sed)
- Basic scripting knowledge

### Installation:

```bash
# Install essential tools
apt update && apt install netcat telnet curl wget

# Verify installations
nc -h | head -1
telnet --version
curl --version
```

### Setting Up Environment:

```bash
# Create working directory
mkdir ~/manual-scanning
cd ~/manual-scanning

# Set up common variables
export TARGET="demo1.ine.local"
export TARGET_IP="192.63.4.3"
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:

1. **Host Discovery:** Verify target is reachable
1. **Port Scanning:** Check for open ports
1. **Service Identification:** Banner grabbing and service enumeration
1. **Custom Scripts:** Automate repetitive tasks

### Command Structure:

```bash
# Basic connectivity test (from lab)
ping -c 4 demo1.ine.local

# Manual port checking
nc -zv target_ip port_range
timeout 1 bash -c "echo >/dev/tcp/target/port" && echo "open"
```

## ⚙️ Command Line Options

### Netcat Options:

|Option      |Purpose                 |Example                |
|------------|------------------------|-----------------------|
|`-z`        |Zero-I/O mode (scanning)|`nc -zv target 80`     |
|`-v`        |Verbose output          |`nc -zv target 1-100`  |
|`-w timeout`|Connection timeout      |`nc -w 3 -zv target 80`|
|`-u`        |UDP mode                |`nc -uzv target 53`    |

### Bash TCP Options:

|Method              |Purpose             |Example                      |
|--------------------|--------------------|-----------------------------|
|`/dev/tcp/host/port`|TCP connection test |`echo > /dev/tcp/target/80`  |
|`/dev/udp/host/port`|UDP connection test |`echo > /dev/udp/target/53`  |
|`timeout`           |Limit execution time|`timeout 1 bash -c "command"`|

### Banner Grabbing Options:

|Tool    |Purpose                |Example                               |
|--------|-----------------------|--------------------------------------|
|`telnet`|Interactive banner grab|`telnet target 80`                    |
|`nc`    |Netcat banner grab     |`echo "GET / HTTP/1.0" | nc target 80`|
|`curl`  |HTTP banner grab       |`curl -I target`                      |

## 🧪 Real Lab Examples

### Example 1: Custom Bash Port Scanner (From Lab Screenshots)

```bash
# Create the port scanner script from lab
#!/bin/bash
for port in {1..1000}; do
    timeout 1 bash -c "echo >/dev/tcp/$1/$port" 2>/dev/null && echo "port $port is open"
done

# Save as bash-port-scanner.sh
chmod +x bash-port-scanner.sh

# Execute on target (as shown in lab)
./bash-port-scanner.sh 192.180.108.3
# Output: 
# port 21 is open
# port 22 is open  
# port 80 is open
```

### Example 2: Netcat Banner Grabbing

```bash
# HTTP banner grabbing
echo -e "GET / HTTP/1.0\r\n\r\n" | nc demo1.ine.local 80
# Output: HTTP headers and server information

# SSH banner grabbing
nc demo1.ine.local 22
# Output: SSH-2.0-OpenSSH_X.X server banner

# FTP banner grabbing
nc 192.180.108.3 21
# Output: FTP server banner and version
```

### Example 3: UDP Service Discovery

```bash
# DNS service check
echo -e "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01" | nc -u target 53

# SNMP community string testing
echo -e "\x30\x0c\x02\x01\x00\x04\x06public\xa0\x05\x02\x03\x00\x00\x00" | nc -u target 161

# NTP service check
ntpdate -q target
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:

- **Custom script creation (35%)** - Building port scanners and automation
- **Banner grabbing (30%)** - Service identification and enumeration
- **Manual verification (20%)** - Confirming automated scan results
- **Stealth techniques (15%)** - Avoiding detection during scanning

### Critical Commands to Master:

```bash
# Must-know commands for exam
timeout 1 bash -c "echo >/dev/tcp/target/port"  # Quick port check
nc -zv target 1-1000                           # Netcat port scan
echo "command" | nc target port                # Banner grabbing
curl -I http://target                          # HTTP header analysis
```

### eJPT Exam Scenarios:

1. **Custom Port Scanner Creation:** Build bash script for port scanning
- Required skills: Bash scripting, TCP connections, loop structures
- Expected commands: `/dev/tcp` connections, timeout usage, range scanning
- Success criteria: Identify open ports without automated tools
1. **Service Banner Analysis:** Manually identify services through banner grabbing
- Required skills: Protocol knowledge, banner interpretation
- Expected commands: netcat connections, protocol-specific requests
- Success criteria: Determine service versions and potential vulnerabilities

### Exam Tips and Tricks:

- **Use /dev/tcp:** Faster than netcat for simple connectivity tests
- **Combine with grep:** Filter results for specific services or ports
- **Script automation:** Create reusable scripts for common tasks
- **Document everything:** Manual methods require detailed documentation

### Common eJPT Questions:

- Create a port scanner script without using Nmap
- Identify web server version through manual banner grabbing
- Verify specific service availability using basic tools

## ⚠️ Common Issues & Troubleshooting

### Issue 1: /dev/tcp Not Available

**Problem:** /dev/tcp pseudo-device not supported in some shell environments
**Cause:** Non-bash shells or restricted environments
**Solution:**

```bash
# Verify bash shell
echo $SHELL
# Should show: /bin/bash

# Alternative using netcat
nc -w 1 -z target port
```

### Issue 2: Timeouts and Hanging Connections

**Problem:** Connections hanging indefinitely
**Solution:**

```bash
# Always use timeout with manual connections
timeout 3 bash -c "echo >/dev/tcp/target/port"

# Netcat with timeout
nc -w 2 target port
```

### Issue 3: Script Performance Issues

**Problem:** Port scanning scripts running too slowly
**Optimization:**

```bash
# Parallel scanning with background processes
for port in {1..1000}; do
    (timeout 1 bash -c "echo >/dev/tcp/target/$port" 2>/dev/null && echo "$port open") &
done
wait
```

### Issue 4: Banner Grabbing Incomplete Responses

**Problem:** Services not responding to manual banner requests
**Solution:**

```bash
# HTTP: Use proper headers
echo -e "GET / HTTP/1.1\r\nHost: target\r\n\r\n" | nc target 80

# Add delays for slow services
(echo "HELP"; sleep 2) | nc target 21
```

## 🔗 Integration with Other Tools

### Primary Integration: Manual → Nmap → Metasploit

```bash
# Step 1: Quick manual check to verify connectivity
timeout 1 bash -c "echo >/dev/tcp/target/80" && echo "HTTP accessible"

# Step 2: Focused Nmap scan based on manual results
nmap -p 80,22,21 -sV target

# Step 3: Use service information for exploitation
# Based on banner: SSH-2.0-OpenSSH_7.4 → search for OpenSSH 7.4 exploits
```

### Secondary Integration: Manual Scripts → Automated Tools

```bash
# Use custom scripts to prepare target lists
./bash-port-scanner.sh target | grep "open" | awk '{print $2}' > open_ports.txt

# Feed results to other tools
nmap -p $(cat open_ports.txt | tr '\n' ',') -sV target
```

### Advanced Workflows:

```bash
# Comprehensive manual enumeration pipeline
#!/bin/bash
target=$1

echo "=== Host Reachability ==="
ping -c 1 $target

echo "=== Quick Port Scan ==="
for port in 21 22 23 25 53 80 110 139 143 443 993 995; do
    timeout 1 bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null && echo "Port $port: OPEN"
done

echo "=== Banner Grabbing ==="
for port in $(./get-open-ports.sh $target); do
    echo "Banner for port $port:"
    timeout 2 nc $target $port < /dev/null
done
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:

1. **Screenshots:** Script outputs showing discovered services
1. **Command Outputs:** All manual commands and their results
1. **Script Files:** Save all custom scripts created
1. **Banner Information:** Complete service banners and versions

### Report Template Structure:

```markdown
## Manual Scanning Results

### Target Information
- Target: 192.180.108.3
- Scan Date: 2024-11-26
- Methods Used: Custom bash scripts, netcat, banner grabbing

### Commands Executed
```bash
# Port scanning script
./bash-port-scanner.sh 192.180.108.3

# Banner grabbing commands
nc 192.180.108.3 21
nc 192.180.108.3 22
echo "GET / HTTP/1.0" | nc 192.180.108.3 80
```

### Discovered Services

- Port 21/TCP: FTP (vsftpd 3.0.3)
- Port 22/TCP: SSH (OpenSSH 7.4)
- Port 80/TCP: HTTP (Apache/2.4.29)

### Custom Scripts Created

- bash-port-scanner.sh: TCP port scanner for ports 1-1000
- banner-grabber.sh: Automated banner collection script

### Recommendations

- Update SSH to latest version (7.4 has known vulnerabilities)
- Implement proper FTP access controls
- Review HTTP server configuration for security headers

```
### Automation Scripts:
```bash
# Comprehensive manual scanning script
#!/bin/bash
TARGET=$1
OUTPUT_DIR="manual-scan-$(date +%Y%m%d-%H%M%S)"
mkdir $OUTPUT_DIR

echo "Starting manual scan of $TARGET"

# Port scanning
echo "Running port scan..." 
./bash-port-scanner.sh $TARGET > $OUTPUT_DIR/ports.txt

# Banner grabbing for common ports
for port in 21 22 80 443; do
    if grep -q "port $port is open" $OUTPUT_DIR/ports.txt; then
        echo "Grabbing banner for port $port..."
        timeout 3 nc $TARGET $port < /dev/null > $OUTPUT_DIR/banner_$port.txt 2>&1
    fi
done

echo "Manual scan complete. Results in $OUTPUT_DIR/"
```

## 📚 Additional Resources

### Official Documentation:

- Netcat manual: man nc
- Bash networking: /dev/tcp and /dev/udp usage
- POSIX networking: socket programming basics

### Learning Resources:

- Bash scripting tutorials: Advanced I/O redirection
- Network programming: Understanding TCP/UDP protocols
- Port scanning techniques: Stealth and evasion methods

### Community Resources:

- GitHub: Custom port scanning scripts
- Security forums: Manual enumeration techniques
- CTF writeups: Creative scanning approaches

### Related Tools:

- Masscan: High-speed alternative to manual methods
- Unicornscan: Advanced manual scanning capabilities
- Hping3: Packet crafting for custom scanning