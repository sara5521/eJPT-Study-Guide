# 🔧 Bash Port Scanning - Manual Network Reconnaissance

Custom bash scripts for port scanning when traditional tools are unavailable or detected.
**Location:** `04-port-scanning/manual-techniques/bash-port-scanning.md`

## 🎯 What is Bash Port Scanning?
Bash port scanning involves using native Linux/Unix shell commands and scripting techniques to discover open ports on target systems. This method is particularly useful in restricted environments where traditional scanning tools like Nmap are blocked, unavailable, or might trigger security alerts. It leverages basic networking capabilities built into the operating system.

## 📦 Installation and Setup
No additional installation required - uses built-in bash and networking utilities.

```bash
# Verify bash availability
bash --version

# Check networking tools
which nc telnet timeout

# Create script directory
mkdir ~/port-scanners
cd ~/port-scanners
```

## 🔧 Basic Usage and Syntax

### Basic TCP Connection Test:
```bash
# Basic syntax for TCP connection
timeout 1 bash -c "echo >/dev/tcp/$1/$port" 2>/dev/null && echo "port $port is open"

# Single port test
timeout 1 bash -c "echo >/dev/tcp/192.168.1.1/80" && echo "Port 80 is open"
```

## ⚙️ Script Components and Options

### Core Bash Techniques:
| Method | Purpose | Example |
|--------|---------|---------|
| `/dev/tcp/` | TCP connection testing | `echo >/dev/tcp/target/port` |
| `timeout` | Connection timeout control | `timeout 1 command` |
| `for loop` | Port range iteration | `for port in {1..1000}` |
| `&&` | Success condition | `command && echo "success"` |
| `2>/dev/null` | Error suppression | `command 2>/dev/null` |

### Script Parameters:
| Component | Purpose | Usage |
|-----------|---------|-------|
| `$1` | Target IP address | `./script.sh 192.168.1.1` |
| `$port` | Port variable in loop | `for port in range` |
| `timeout 1` | 1-second timeout | Prevents hanging connections |
| `>/dev/null` | Output suppression | Reduces noise |

## 🧪 Real Lab Examples

### Example 1: Basic Port Scanner Script
```bash
# Create the script file
nano bash-port-scanner.sh

# Script content:
#!/bin/bash
for port in {1..1000}; do
  timeout 1 bash -c "echo >/dev/tcp/$1/$port" 2>/dev/null && echo "port $port is open"
done

# Make executable and run
chmod +x bash-port-scanner.sh
./bash-port-scanner.sh 192.180.108.3

# Expected output from lab:
# port 21 is open
# port 22 is open
# port 80 is open
```

### Example 2: Enhanced Script with Service Detection
```bash
# Advanced port scanner with service identification
#!/bin/bash
target=$1
echo "Scanning $target..."

for port in {1..1000}; do
  if timeout 1 bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null; then
    case $port in
      21) echo "port $port is open (FTP)" ;;
      22) echo "port $port is open (SSH)" ;;
      23) echo "port $port is open (Telnet)" ;;
      25) echo "port $port is open (SMTP)" ;;
      53) echo "port $port is open (DNS)" ;;
      80) echo "port $port is open (HTTP)" ;;
      443) echo "port $port is open (HTTPS)" ;;
      *) echo "port $port is open (Unknown service)" ;;
    esac
  fi
done
```

### Example 3: Targeted Port Scanning from Compromised System
```bash
# Lab scenario: Scanning from meterpreter session
meterpreter > shell
cd /tmp/
chmod +x ./nmap ./bash-port-scanner.sh

# Execute bash scanner on pivot network
./bash-port-scanner.sh 192.180.108.3

# Output shows discovered services:
# port 21 is open
# port 22 is open  
# port 80 is open

# Compare with nmap results
./nmap -p- 192.180.108.3
# Confirms: 21/tcp open ftp, 22/tcp open ssh, 80/tcp open http
```

### Example 4: Stealth Scanning with Random Delays
```bash
#!/bin/bash
target=$1
ports=(21 22 23 25 53 80 135 139 443 445 993 995 1723 3389 5900)

echo "Stealth scanning $target..."
for port in "${ports[@]}"; do
  # Random delay between 1-5 seconds
  sleep $((1 + RANDOM % 5))
  
  if timeout 1 bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null; then
    echo "[$port] - OPEN"
  fi
done
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Manual Port Discovery** - When Nmap is unavailable or blocked
- **Script Creation** - Building custom reconnaissance tools
- **Stealth Scanning** - Avoiding detection mechanisms
- **Post-Exploitation Scanning** - Network discovery from compromised systems

### Essential Commands for Exam:
```bash
# Must-know techniques
#!/bin/bash
for port in {1..1000}; do
  timeout 1 bash -c "echo >/dev/tcp/$1/$port" 2>/dev/null && echo "port $port is open"
done

# File upload and execution
chmod +x script_name.sh
./script_name.sh target_ip

# Background execution
nohup ./script_name.sh target_ip > results.txt &
```

### Exam Scenarios:
- **Scenario 1:** Traditional tools blocked by firewall - use bash techniques
- **Scenario 2:** Limited tool availability on compromised system - manual scripting required
- **Scenario 3:** Stealth requirements - avoid triggering IDS/IPS systems

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Script Permission Denied
**Problem:** Cannot execute script due to permission restrictions
**Solution:**
```bash
# Add execute permissions
chmod +x script_name.sh

# Alternative execution method
bash script_name.sh target_ip
```

### Issue 2: Connection Timeouts Too Long
**Problem:** Script hangs on unresponsive ports
**Solution:**
```bash
# Reduce timeout value
timeout 0.5 bash -c "echo >/dev/tcp/$target/$port"

# Add connection limits
ulimit -n 1024  # Limit open file descriptors
```

## 🔗 Integration with Other Tools

### Tool Chain Example:
```bash
# Integration workflow
./bash-port-scanner.sh target > open_ports.txt    # Discovery phase
nmap -sV -p$(cat open_ports.txt | grep open | cut -d' ' -f2 | tr '\n' ',') target  # Detailed scan
# Results feed into Metasploit module selection
```

## 📝 Documentation and Reporting

### Evidence to Collect:
- Script output showing discovered open ports
- Timestamps of scan execution
- Target systems and port ranges scanned
- Comparison with traditional tool results

### Command Outputs to Save:
```bash
# Save scan results with timestamps
./bash-port-scanner.sh 192.180.108.3 | tee scan_results_$(date +%Y%m%d_%H%M%S).txt

# Document script usage
echo "Scan executed: $(date)" >> scan_log.txt
echo "Target: 192.180.108.3" >> scan_log.txt
echo "Method: Bash TCP connection test" >> scan_log.txt
```
