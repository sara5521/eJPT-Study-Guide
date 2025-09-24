# 🔧 Manual Port Scanning Methods - Complete Study Guide

> **Comprehensive guide for manual port scanning techniques using basic tools and custom scripts**

**Document Path:** `04-port-scanning/manual-scanning-methods.md`  
**Level:** Beginner to Intermediate  

---

## 📋 Table of Contents
1. [Introduction & Concepts](#introduction--concepts)
2. [Prerequisites & Environment Setup](#prerequisites--environment-setup) 
3. [Core Tools & Commands](#core-tools--commands)
4. [Manual Scanning Techniques](#manual-scanning-techniques)
5. [Custom Script Development](#custom-script-development)
6. [Service Enumeration & Banner Grabbing](#service-enumeration--banner-grabbing)
7. [eJPT Exam Preparation](#ejpt-exam-preparation)
8. [Troubleshooting & Common Issues](#troubleshooting--common-issues)
9. [Practice Labs & Examples](#practice-labs--examples)
10. [Advanced Techniques](#advanced-techniques)

---

## 🎯 Introduction & Concepts

### What are Manual Scanning Methods?

Manual scanning methods involve using **basic networking tools** and **custom scripts** to perform port scanning and service enumeration **without relying on comprehensive tools** like Nmap. This approach provides:

**Key Advantages:**
- **Stealth:** Lower detection rates compared to automated tools
- **Customization:** Tailored scanning approach for specific scenarios  
- **Learning:** Deep understanding of networking protocols
- **Flexibility:** Works in restricted environments where advanced tools aren't available

**Core Capabilities:**
- ✅ Custom Bash/Python scripts for targeted port scanning
- ✅ Banner grabbing using netcat, telnet, and curl
- ✅ UDP service discovery and enumeration
- ✅ Stealth scanning techniques to avoid detection
- ✅ Protocol-specific service identification

**When to Use Manual Methods:**
- During penetration testing when stealth is required
- In environments where automated tools are blocked
- For educational purposes to understand networking fundamentals
- When you need precise control over scanning parameters

---

## 🛠️ Prerequisites & Environment Setup

### Required Knowledge
- **Networking Fundamentals:** TCP/UDP protocols, port concepts
- **Command Line Proficiency:** Linux/Unix command line navigation
- **Basic Scripting:** Bash scripting fundamentals
- **Protocol Understanding:** HTTP, FTP, SSH, DNS basics

### System Requirements

**Operating System:**
- Linux distribution (Ubuntu, Kali, CentOS)
- Windows with WSL (Windows Subsystem for Linux)
- macOS with Homebrew

**Essential Tools Installation:**

```bash
# Ubuntu/Debian Systems
sudo apt update && sudo apt install -y \
    netcat-traditional \
    netcat-openbsd \
    telnet \
    curl \
    wget \
    nmap \
    dnsutils \
    iputils-ping

# CentOS/RHEL Systems  
sudo yum install -y \
    nc \
    telnet \
    curl \
    wget \
    bind-utils \
    iputils

# Verify Installations
nc -h 2>&1 | head -5
telnet --version
curl --version | head -1
```

### Environment Configuration

**Create Organized Workspace:**
```bash
# Create main working directory
mkdir -p ~/penetration-testing/manual-scanning
cd ~/penetration-testing/manual-scanning

# Create subdirectories for organization
mkdir -p {scripts,results,logs,targets}

# Set up environment variables
cat >> ~/.bashrc << 'EOF'
# Manual Scanning Environment Variables
export SCAN_HOME="$HOME/penetration-testing/manual-scanning"
export TARGET_LIST="$SCAN_HOME/targets/targets.txt"
export SCAN_RESULTS="$SCAN_HOME/results"
EOF

source ~/.bashrc
```

**Create Target Configuration:**
```bash
# Example target configuration file
cat > $SCAN_HOME/targets/demo-targets.txt << 'EOF'
# Demo Targets for Practice
demo1.ine.local:192.168.1.10
testserver:10.0.0.5  
webapp:172.16.0.100
EOF
```

---

## 🔧 Core Tools & Commands

### Netcat - The Swiss Army Knife

**Netcat Overview:**  
Netcat (nc) is a versatile networking utility for reading from and writing to network connections using TCP or UDP protocols.

**Essential Netcat Options:**

| Option | Description | Usage Example | Purpose |
|--------|-------------|---------------|---------|
| `-z` | Zero-I/O mode (port scanning) | `nc -z target 80` | Port scanning without data exchange |
| `-v` | Verbose output | `nc -zv target 1-100` | Detailed connection information |
| `-w timeout` | Connection timeout | `nc -w 3 target 80` | Prevent hanging connections |
| `-u` | UDP mode | `nc -u target 53` | UDP protocol scanning |
| `-n` | No DNS resolution | `nc -zn 192.168.1.1 80` | Skip hostname lookups |
| `-p port` | Source port | `nc -p 12345 target 80` | Specify source port |

**Netcat Scanning Examples:**

```bash
# Single Port Check
nc -zv demo1.ine.local 80
# Output: Connection to demo1.ine.local 80 port [tcp/http] succeeded!

# Port Range Scanning  
nc -zv demo1.ine.local 1-100
# Scans ports 1 through 100

# Multiple Specific Ports
nc -zv demo1.ine.local 22 80 443 3389
# Check common service ports

# UDP Port Scanning
nc -zuv demo1.ine.local 53 161 514
# Check common UDP services

# Timeout Control
nc -w 2 -zv demo1.ine.local 1-1000
# 2-second timeout per connection
```

### Bash Built-in TCP/UDP Testing

**Understanding /dev/tcp and /dev/udp:**  
Bash provides special device files for network connectivity testing without external tools.

**Syntax and Usage:**

```bash
# Basic TCP Connection Test
timeout 1 bash -c "echo > /dev/tcp/target/port" && echo "Port Open" || echo "Port Closed"

# UDP Connection Test  
timeout 1 bash -c "echo > /dev/udp/target/port" && echo "UDP Accessible"

# With Error Handling
exec 3<>/dev/tcp/target/port 2>/dev/null && echo "Connected" || echo "Failed"
exec 3<&-  # Close file descriptor
```

**Advanced Bash Network Testing:**

```bash
# Function for Port Testing
test_port() {
    local host=$1
    local port=$2
    local timeout=${3:-1}
    
    timeout $timeout bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "✅ $host:$port - OPEN"
        return 0
    else
        echo "❌ $host:$port - CLOSED"  
        return 1
    fi
}

# Usage Examples
test_port demo1.ine.local 80
test_port 192.168.1.10 22 3
```

### Telnet for Interactive Testing

**Telnet Capabilities:**
- Interactive banner grabbing
- Protocol testing
- Service interaction
- Manual protocol communication

**Telnet Usage Examples:**

```bash
# Basic Connection
telnet demo1.ine.local 80
# Then type: GET / HTTP/1.0 [Enter][Enter]

# Quick Connection Test
echo "quit" | telnet demo1.ine.local 22
# Grab SSH banner and exit

# FTP Banner Grabbing
(echo "USER anonymous"; echo "PASS guest"; sleep 2; echo "QUIT") | telnet target 21

# SMTP Testing
(echo "EHLO test.com"; sleep 1; echo "QUIT") | telnet target 25
```

### Curl for HTTP/HTTPS Analysis

**HTTP Service Analysis:**

```bash
# Basic HTTP Headers
curl -I http://demo1.ine.local
# Output: HTTP headers including server information

# Verbose Connection Details  
curl -v http://demo1.ine.local
# Shows full HTTP conversation

# Follow Redirects
curl -L -I http://demo1.ine.local

# Custom Headers and Methods
curl -X OPTIONS -v http://demo1.ine.local
curl -H "User-Agent: Custom-Scanner" http://demo1.ine.local

# HTTPS Certificate Information
curl -k -v https://target.com 2>&1 | grep -E "(SSL|TLS|Certificate)"
```

---

## 🎯 Manual Scanning Techniques

### Host Discovery Methods

**1. ICMP Ping Discovery:**
```bash
# Basic Ping Test
ping -c 4 demo1.ine.local
# Output shows if host is reachable

# Ping Sweep for Network Range  
for ip in 192.168.1.{1..254}; do
    ping -c 1 -W 1 $ip >/dev/null 2>&1 && echo "$ip is alive" &
done
wait
```

**2. TCP Connect Discovery:**
```bash
# TCP SYN to common ports for host discovery
discover_host() {
    local target=$1
    local common_ports="22 23 25 53 80 110 135 139 443 993 995 3389"
    
    for port in $common_ports; do
        timeout 1 bash -c "echo > /dev/tcp/$target/$port" 2>/dev/null && {
            echo "✅ $target is alive (port $port open)"
            return 0
        }
    done
    echo "❌ $target appears down or filtered"
    return 1
}
```

### TCP Port Scanning Strategies

**1. Sequential Port Scanning:**
```bash
#!/bin/bash
# sequential_scanner.sh - Basic port scanner

target=$1
start_port=${2:-1}
end_port=${3:-1000}

echo "Scanning $target ports $start_port-$end_port..."

for port in $(seq $start_port $end_port); do
    timeout 1 bash -c "echo > /dev/tcp/$target/$port" 2>/dev/null && {
        echo "Port $port: OPEN"
    }
done
```

**2. Parallel Port Scanning:**
```bash
#!/bin/bash
# parallel_scanner.sh - Faster multi-threaded scanner

target=$1
max_jobs=50  # Adjust based on system capabilities

scan_port() {
    local target=$1
    local port=$2
    timeout 1 bash -c "echo > /dev/tcp/$target/$port" 2>/dev/null && echo "$port"
}

echo "Starting parallel scan of $target..."

for port in {1..1000}; do
    (($(jobs -r | wc -l) >= max_jobs)) && wait
    scan_port $target $port &
done
wait
```

**3. Stealth Scanning Techniques:**
```bash
# Random port order to avoid pattern detection
randomized_scan() {
    local target=$1
    local ports=$(seq 1 1000 | shuf)  # Randomize port order
    
    for port in $ports; do
        sleep $(echo "scale=2; $RANDOM/32767*2" | bc)  # Random delays
        timeout 1 bash -c "echo > /dev/tcp/$target/$port" 2>/dev/null && echo "$port"
    done
}

# Source port randomization
stealth_scan() {
    local target=$1
    local port=$2
    local source_port=$((RANDOM % 60000 + 1024))
    
    nc -p $source_port -w 1 -z $target $port 2>/dev/null && echo "$port open"
}
```

### UDP Port Scanning

**UDP Scanning Challenges:**
- No connection establishment (connectionless protocol)
- Timeouts don't always indicate closed ports
- Requires application-specific payloads for accurate results

**Basic UDP Scanning:**
```bash
#!/bin/bash
# udp_scanner.sh - UDP port scanner

udp_scan() {
    local target=$1
    local port=$2
    
    # Send empty UDP packet
    echo "" | nc -u -w 2 $target $port 2>/dev/null
    local result=$?
    
    if [ $result -eq 0 ]; then
        echo "UDP $port: OPEN|FILTERED"
    fi
}

# Common UDP ports to scan
udp_ports="53 67 68 69 123 135 137 138 161 162 514 1434"

for port in $udp_ports; do
    udp_scan $1 $port
done
```

**Protocol-Specific UDP Probes:**
```bash
# DNS Query (Port 53)
dns_probe() {
    local target=$1
    echo -e "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01" | \
    nc -u -w 2 $target 53 && echo "DNS service detected"
}

# SNMP Query (Port 161)  
snmp_probe() {
    local target=$1
    local community="public"
    echo -e "\x30\x19\x02\x01\x00\x04\x06${community}\xa0\x0c\x02\x04\x00\x00\x00\x00\x02\x01\x00\x30\x00" | \
    nc -u -w 2 $target 161 && echo "SNMP service detected"
}

# NTP Query (Port 123)
ntp_probe() {
    local target=$1
    echo -e "\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" | \
    nc -u -w 2 $target 123 && echo "NTP service detected"
}
```

---

## 🛠️ Custom Script Development

### Advanced Port Scanner Development

**Professional Port Scanner Script:**

```bash
#!/bin/bash
# advanced_port_scanner.sh - Professional manual port scanner
# Usage: ./advanced_port_scanner.sh <target> [options]

# Script configuration
SCRIPT_NAME="Advanced Manual Port Scanner"
VERSION="2.0"
AUTHOR="Penetration Tester"

# Default values
DEFAULT_TIMEOUT=2
DEFAULT_THREADS=20
DEFAULT_PORTS="1-1000"
OUTPUT_FORMAT="text"
VERBOSE=false

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Usage function
show_usage() {
    cat << EOF
$SCRIPT_NAME v$VERSION

Usage: $0 <target> [OPTIONS]

REQUIRED:
    target          Target IP address or hostname

OPTIONS:
    -p, --ports     Port range (default: $DEFAULT_PORTS)
    -t, --timeout   Connection timeout in seconds (default: $DEFAULT_TIMEOUT)
    -j, --threads   Max concurrent threads (default: $DEFAULT_THREADS)
    -v, --verbose   Enable verbose output
    -o, --output    Output file path
    -f, --format    Output format: text|json|xml (default: $OUTPUT_FORMAT)
    -h, --help      Show this help message

EXAMPLES:
    $0 192.168.1.1
    $0 demo1.ine.local -p 1-100 -t 1 -v
    $0 target.com -p 22,80,443,3389 -j 50 -o results.txt
    $0 192.168.1.0/24 -p 80,443 -f json

EOF
}

# Logging function
log_message() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")  echo -e "${BLUE}[INFO]${NC} $timestamp - $message" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC} $timestamp - $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $timestamp - $message" ;;
        "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} $timestamp - $message" ;;
    esac
    
    # Log to file if output specified
    [[ -n "$OUTPUT_FILE" ]] && echo "[$level] $timestamp - $message" >> "$OUTPUT_FILE.log"
}

# Port scanning function
scan_port() {
    local target=$1
    local port=$2
    local timeout=$3
    
    # Attempt connection using bash built-in
    timeout $timeout bash -c "exec 3<>/dev/tcp/$target/$port" 2>/dev/null
    if [ $? -eq 0 ]; then
        exec 3<&-  # Close file descriptor
        echo "OPEN:$port"
        return 0
    else
        echo "CLOSED:$port"
        return 1
    fi
}

# Service identification function
identify_service() {
    local target=$1
    local port=$2
    local timeout=$3
    
    case $port in
        21)  echo "FTP" ;;
        22)  echo "SSH" ;;
        23)  echo "Telnet" ;;
        25)  echo "SMTP" ;;
        53)  echo "DNS" ;;
        80)  echo "HTTP" ;;
        110) echo "POP3" ;;
        143) echo "IMAP" ;;
        443) echo "HTTPS" ;;
        993) echo "IMAPS" ;;
        995) echo "POP3S" ;;
        3389) echo "RDP" ;;
        5432) echo "PostgreSQL" ;;
        3306) echo "MySQL" ;;
        1433) echo "MSSQL" ;;
        *)   echo "Unknown" ;;
    esac
}

# Banner grabbing function
grab_banner() {
    local target=$1
    local port=$2
    local timeout=$3
    
    case $port in
        80|8080)
            echo -e "GET / HTTP/1.0\r\n\r\n" | timeout $timeout nc $target $port 2>/dev/null | head -1
            ;;
        22)
            timeout $timeout nc $target $port </dev/null 2>/dev/null | head -1
            ;;
        21)
            timeout $timeout nc $target $port </dev/null 2>/dev/null | head -1
            ;;
        25)
            timeout $timeout nc $target $port </dev/null 2>/dev/null | head -1
            ;;
        *)
            timeout $timeout nc $target $port </dev/null 2>/dev/null | head -1
            ;;
    esac
}

# Parse port range function
parse_ports() {
    local port_spec=$1
    
    if [[ $port_spec =~ ^([0-9]+)-([0-9]+)$ ]]; then
        # Range format: 1-1000
        seq ${BASH_REMATCH[1]} ${BASH_REMATCH[2]}
    elif [[ $port_spec =~ ^([0-9,]+)$ ]]; then
        # Comma-separated: 22,80,443
        echo $port_spec | tr ',' '\n'
    else
        log_message "ERROR" "Invalid port specification: $port_spec"
        exit 1
    fi
}

# Main scanning function
perform_scan() {
    local target=$1
    local timeout=$2
    local max_threads=$3
    shift 3
    local ports=("$@")
    
    local open_ports=()
    local total_ports=${#ports[@]}
    local completed=0
    
    log_message "INFO" "Starting scan of $target with $total_ports ports"
    log_message "INFO" "Timeout: ${timeout}s, Max threads: $max_threads"
    
    for port in "${ports[@]}"; do
        # Limit concurrent jobs
        while [ $(jobs -r | wc -l) -ge $max_threads ]; do
            sleep 0.1
        done
        
        # Scan port in background
        {
            result=$(scan_port $target $port $timeout)
            if [[ $result == "OPEN:$port" ]]; then
                local service=$(identify_service $target $port $timeout)
                local banner=""
                
                if $VERBOSE; then
                    banner=$(grab_banner $target $port $timeout)
                fi
                
                echo "RESULT:OPEN:$port:$service:$banner"
            fi
            
            # Progress indicator
            ((completed++))
            if [ $((completed % 50)) -eq 0 ] || [ $completed -eq $total_ports ]; then
                echo "PROGRESS:$completed:$total_ports" >&2
            fi
        } &
    done
    
    # Wait for all background jobs
    wait
    log_message "INFO" "Scan completed"
}

# Output formatting functions
format_text_output() {
    local target=$1
    shift
    local results=("$@")
    
    echo "=================================="
    echo "Manual Port Scan Results"
    echo "Target: $target"
    echo "Date: $(date)"
    echo "=================================="
    echo
    
    printf "%-8s %-12s %-20s\n" "PORT" "STATE" "SERVICE"
    echo "----------------------------------------"
    
    for result in "${results[@]}"; do
        IFS=':' read -r state port service banner <<< "$result"
        if [[ $state == "OPEN" ]]; then
            printf "%-8s %-12s %-20s\n" "$port/tcp" "open" "$service"
            [[ $VERBOSE && -n "$banner" ]] && echo "    Banner: $banner"
        fi
    done
}

format_json_output() {
    local target=$1
    shift
    local results=("$@")
    
    echo "{"
    echo "  \"target\": \"$target\","
    echo "  \"scan_date\": \"$(date -Iseconds)\","
    echo "  \"scanner\": \"$SCRIPT_NAME v$VERSION\","
    echo "  \"ports\": ["
    
    local first=true
    for result in "${results[@]}"; do
        IFS=':' read -r state port service banner <<< "$result"
        if [[ $state == "OPEN" ]]; then
            [[ $first == false ]] && echo ","
            echo -n "    {"
            echo -n "\"port\": $port, \"state\": \"open\", \"service\": \"$service\""
            [[ $VERBOSE && -n "$banner" ]] && echo -n ", \"banner\": \"$banner\""
            echo -n "}"
            first=false
        fi
    done
    
    echo
    echo "  ]"
    echo "}"
}

# Main execution
main() {
    local target=""
    local ports="$DEFAULT_PORTS"
    local timeout=$DEFAULT_TIMEOUT
    local threads=$DEFAULT_THREADS
    local output_file=""
    local format="$OUTPUT_FORMAT"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--ports)
                ports="$2"
                shift 2
                ;;
            -t|--timeout)
                timeout="$2"
                shift 2
                ;;
            -j|--threads)
                threads="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            -f|--format)
                format="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            -*)
                log_message "ERROR" "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                if [[ -z "$target" ]]; then
                    target="$1"
                else
                    log_message "ERROR" "Multiple targets not supported"
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Validate required parameters
    if [[ -z "$target" ]]; then
        log_message "ERROR" "Target is required"
        show_usage
        exit 1
    fi
    
    # Parse port specification
    local port_list=($(parse_ports "$ports"))
    if [[ ${#port_list[@]} -eq 0 ]]; then
        log_message "ERROR" "No valid ports specified"
        exit 1
    fi
    
    # Validate target reachability
    log_message "INFO" "Checking target reachability..."
    if ! ping -c 1 -W 2 "$target" >/dev/null 2>&1; then
        log_message "WARN" "Target may not be reachable via ICMP"
    fi
    
    # Perform the scan
    local scan_results=()
    while IFS= read -r line; do
        if [[ $line == RESULT:* ]]; then
            scan_results+=("${line#RESULT:}")
        elif [[ $line == PROGRESS:* ]]; then
            IFS=':' read -r _ completed total <<< "$line"
            echo -ne "\rProgress: $completed/$total ports scanned"
        fi
    done < <(perform_scan "$target" "$timeout" "$threads" "${port_list[@]}" 2>&1)
    
    echo # New line after progress
    
    # Format and display results
    if [[ ${#scan_results[@]} -gt 0 ]]; then
        log_message "SUCCESS" "Found ${#scan_results[@]} open ports"
        
        case $format in
            "json")
                output=$(format_json_output "$target" "${scan_results[@]}")
                ;;
            "text"|*)
                output=$(format_text_output "$target" "${scan_results[@]}")
                ;;
        esac
        
        # Display or save results
        if [[ -n "$output_file" ]]; then
            echo "$output" > "$output_file"
            log_message "INFO" "Results saved to: $output_file"
        else
            echo "$output"
        fi
    else
        log_message "WARN" "No open ports found"
    fi
}

# Run main function with all arguments
main "$@"
```

### Quick Scanner Collection

**1. Fast TCP Scanner:**
```bash
#!/bin/bash
# fast_tcp_scanner.sh - Quick TCP port scanner

fast_tcp_scan() {
    local target=$1
    echo "Fast TCP scan of $target..."
    
    # Common ports for quick assessment
    local quick_ports="21 22 23 25 53 80 110 135 139 443 445 993 995 1723 3306 3389 5432 5900 8080"
    
    for port in $quick_ports; do
        timeout 0.5 bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null && echo "✅ $port/tcp open"
    done
}

# Usage
fast_tcp_scan $1
```

**2. Banner Grabbing Script:**
```bash
#!/bin/bash
# banner_grabber.sh - Automated banner collection

grab_all_banners() {
    local target=$1
    local open_ports=($2)  # Pass open ports as space-separated string
    
    echo "Collecting banners from $target..."
    
    for port in "${open_ports[@]}"; do
        echo "=== Banner for port $port ==="
        
        case $port in
            80|8080|8000)
                echo -e "GET / HTTP/1.0\r\n\r\n" | timeout 3 nc $target $port
                ;;
            443|8443)
                echo -e "GET / HTTP/1.0\r\n\r\n" | timeout 3 openssl s_client -connect $target:$port -quiet 2>/dev/null
                ;;
            22)
                timeout 2 nc $target $port </dev/null
                ;;
            21)
                (echo "USER anonymous"; echo "QUIT") | timeout 3 nc $target $port
                ;;
            25|587)
                (echo "EHLO test.com"; echo "QUIT") | timeout 3 nc $target $port
                ;;
            *)
                timeout 2 nc $target $port </dev/null
                ;;
        esac
        echo
    done
}

# Example usage
# First scan for open ports, then grab banners
open_ports=$(./fast_tcp_scanner.sh $1 | grep "open" | awk '{print $2}' | cut -d'/' -f1)
grab_all_banners $1 "$open_ports"
```

---

## 🎯 Service Enumeration & Banner Grabbing

### HTTP/HTTPS Service Analysis

**Comprehensive Web Server Analysis:**

```bash
#!/bin/bash
# web_enum.sh - HTTP/HTTPS service enumeration

analyze_web_service() {
    local target=$1
    local port=${2:-80}
    local protocol="http"
    
    [[ $port -eq 443 || $port -eq 8443 ]] && protocol="https"
    
    echo "=== Web Service Analysis: $target:$port ==="
    
    # Basic HTTP headers
    echo "--- HTTP Headers ---"
    curl -s -I "$protocol://$target:$port/" | head -10
    
    # Server technology detection
    echo "--- Technology Stack ---"
    curl -s -I "$protocol://$target:$port/" | grep -i "server:\|x-powered-by:\|x-aspnet-version:"
    
    # Common security headers check
    echo "--- Security Headers ---"
    local headers=$(curl -s -I "$protocol://$target:$port/")
    
    echo -n "X-Frame-Options: "
    echo "$headers" | grep -i "x-frame-options" || echo "MISSING"
    
    echo -n "X-Content-Type-Options: "
    echo "$headers" | grep -i "x-content-type-options" || echo "MISSING"
    
    echo -n "X-XSS-Protection: "
    echo "$headers" | grep -i "x-xss-protection" || echo "MISSING"
    
    echo -n "Strict-Transport-Security: "
    echo "$headers" | grep -i "strict-transport-security" || echo "MISSING"
    
    # HTTP methods enumeration
    echo "--- Supported HTTP Methods ---"
    curl -s -X OPTIONS -v "$protocol://$target:$port/" 2>&1 | grep -i "allow:"
    
    # Directory/file discovery
    echo "--- Common Files/Directories ---"
    local common_paths="robots.txt sitemap.xml admin login.php wp-admin phpinfo.php test.html"
    
    for path in $common_paths; do
        response=$(curl -s -o /dev/null -w "%{http_code}" "$protocol://$target:$port/$path")
        case $response in
            200) echo "✅ /$path - Found (200)" ;;
            301|302) echo "🔄 /$path - Redirect ($response)" ;;
            403) echo "🔒 /$path - Forbidden (403)" ;;
            *) [[ $VERBOSE == true ]] && echo "❌ /$path - Not Found ($response)" ;;
        esac
    done
}

# SSL/TLS Certificate Analysis
analyze_ssl_certificate() {
    local target=$1
    local port=${2:-443}
    
    echo "=== SSL/TLS Certificate Analysis: $target:$port ==="
    
    # Certificate information
    echo "--- Certificate Details ---"
    echo | openssl s_client -connect $target:$port -servername $target 2>/dev/null | \
    openssl x509 -noout -text | grep -E "(Subject:|Issuer:|Not Before:|Not After:|DNS:|Subject Alternative Name)"
    
    # SSL/TLS version support
    echo "--- SSL/TLS Protocol Support ---"
    for version in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do
        echo -n "$version: "
        timeout 3 openssl s_client -connect $target:$port -$version </dev/null >/dev/null 2>&1 && \
        echo "✅ Supported" || echo "❌ Not supported"
    done
    
    # Cipher suite enumeration
    echo "--- Strong Cipher Suites ---"
    nmap --script ssl-enum-ciphers -p $port $target 2>/dev/null | \
    grep -E "(TLS_|cipher preference|compressors)"
}
```

### SSH Service Analysis

**SSH Banner and Configuration Analysis:**

```bash
#!/bin/bash
# ssh_enum.sh - SSH service enumeration

analyze_ssh_service() {
    local target=$1
    local port=${2:-22}
    
    echo "=== SSH Service Analysis: $target:$port ==="
    
    # SSH banner grabbing
    echo "--- SSH Banner ---"
    local banner=$(timeout 3 nc $target $port </dev/null 2>/dev/null | head -1)
    echo "$banner"
    
    # Extract SSH version
    local ssh_version=$(echo "$banner" | grep -oE "OpenSSH_[0-9]+\.[0-9]+" || echo "Unknown")
    echo "SSH Version: $ssh_version"
    
    # SSH algorithm enumeration (requires ssh client)
    echo "--- Supported Algorithms ---"
    ssh -o BatchMode=yes -o ConnectTimeout=3 -o PreferredAuthentications=none \
        -o PubkeyAuthentication=no $target -p $port 2>&1 | \
        grep -E "(kex_algorithms|server_host_key_algorithms|ciphers|macs)" || \
        echo "Algorithm enumeration requires interactive SSH client"
    
    # Common SSH vulnerabilities check
    echo "--- Vulnerability Indicators ---"
    case $ssh_version in
        *"OpenSSH_6.2"*|*"OpenSSH_6.3"*|*"OpenSSH_6.4"*|*"OpenSSH_6.5"*|*"OpenSSH_6.6"*)
            echo "⚠️  Potentially vulnerable to CVE-2016-0777, CVE-2016-0778"
            ;;
        *"OpenSSH_7.0"*|*"OpenSSH_7.1"*|*"OpenSSH_7.2"*)
            echo "⚠️  Potentially vulnerable to user enumeration"
            ;;
        *)
            echo "✅ No known critical vulnerabilities for this version"
            ;;
    esac
    
    # Authentication methods enumeration
    echo "--- Authentication Methods ---"
    timeout 5 ssh -o BatchMode=yes -o ConnectTimeout=3 -o PreferredAuthentications=none \
        -o PubkeyAuthentication=no invalid_user@$target -p $port 2>&1 | \
        grep -oE "(password|publickey|keyboard-interactive|gssapi)" | sort -u || \
        echo "Unable to enumerate authentication methods"
}
```

### FTP Service Analysis

**FTP Banner and Configuration Enumeration:**

```bash
#!/bin/bash
# ftp_enum.sh - FTP service enumeration

analyze_ftp_service() {
    local target=$1
    local port=${2:-21}
    
    echo "=== FTP Service Analysis: $target:$port ==="
    
    # FTP banner and basic info
    echo "--- FTP Banner ---"
    local ftp_session=$(timeout 5 nc $target $port <<EOF
USER anonymous
PASS anonymous@example.com
SYST
FEAT
HELP
QUIT
EOF
)
    
    echo "$ftp_session" | head -10
    
    # Extract FTP server type
    local server_type=$(echo "$ftp_session" | grep "220" | head -1)
    echo "Server: $server_type"
    
    # Check for anonymous login
    echo "--- Anonymous Access Test ---"
    if echo "$ftp_session" | grep -q "230.*anonymous"; then
        echo "✅ Anonymous login allowed"
        
        # Try to list directories with anonymous access
        echo "--- Anonymous Directory Listing ---"
        timeout 10 nc $target $port <<EOF | tail -20
USER anonymous
PASS anonymous@example.com
PASV
LIST
QUIT
EOF
    else
        echo "❌ Anonymous login denied"
    fi
    
    # Check for common FTP vulnerabilities
    echo "--- Security Analysis ---"
    if echo "$ftp_session" | grep -qi "vsftpd.*2\.3\.4"; then
        echo "⚠️  CRITICAL: vsftpd 2.3.4 detected (CVE-2011-2523 backdoor)"
    fi
    
    if echo "$ftp_session" | grep -qi "pure-ftpd"; then
        echo "ℹ️  Pure-FTPd detected - generally secure"
    fi
    
    # Check supported features
    echo "--- Supported Features ---"
    echo "$ftp_session" | grep -E "^211-|^214-" | head -10
}
```

### Database Service Analysis

**MySQL/PostgreSQL/MSSQL Service Enumeration:**

```bash
#!/bin/bash
# database_enum.sh - Database service enumeration

analyze_mysql_service() {
    local target=$1
    local port=${2:-3306}
    
    echo "=== MySQL Service Analysis: $target:$port ==="
    
    # MySQL banner grabbing (requires special packet)
    echo "--- MySQL Banner ---"
    local mysql_banner=$(timeout 3 nc $target $port </dev/null 2>/dev/null | strings | head -5)
    echo "$mysql_banner"
    
    # Version extraction
    local version=$(echo "$mysql_banner" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
    [[ -n "$version" ]] && echo "MySQL Version: $version"
    
    echo "--- Connection Test ---"
    # Simple connection test
    timeout 3 nc $target $port </dev/null >/dev/null 2>&1 && \
        echo "✅ MySQL service accessible" || \
        echo "❌ MySQL service not accessible"
}

analyze_postgresql_service() {
    local target=$1
    local port=${2:-5432}
    
    echo "=== PostgreSQL Service Analysis: $target:$port ==="
    
    # PostgreSQL connection attempt
    echo "--- PostgreSQL Banner ---"
    timeout 3 nc $target $port </dev/null 2>/dev/null | strings | head -3
    
    echo "--- Connection Test ---"
    timeout 3 nc $target $port </dev/null >/dev/null 2>&1 && \
        echo "✅ PostgreSQL service accessible" || \
        echo "❌ PostgreSQL service not accessible"
}

analyze_mssql_service() {
    local target=$1
    local port=${2:-1433}
    
    echo "=== MSSQL Service Analysis: $target:$port ==="
    
    echo "--- MSSQL Connection Test ---"
    timeout 3 nc $target $port </dev/null >/dev/null 2>&1 && \
        echo "✅ MSSQL service accessible" || \
        echo "❌ MSSQL service not accessible"
    
    # MSSQL version enumeration (requires specialized tools)
    echo "ℹ️  Use sqlcmd or nmap scripts for detailed MSSQL enumeration"
}
```

### SMTP Service Analysis

**SMTP Configuration and Security Analysis:**

```bash
#!/bin/bash
# smtp_enum.sh - SMTP service enumeration

analyze_smtp_service() {
    local target=$1
    local port=${2:-25}
    
    echo "=== SMTP Service Analysis: $target:$port ==="
    
    # SMTP banner and EHLO response
    echo "--- SMTP Banner and Capabilities ---"
    local smtp_session=$(timeout 10 nc $target $port <<EOF
EHLO test.example.com
HELP
QUIT
EOF
)
    
    echo "$smtp_session"
    
    # Extract server information
    local server_banner=$(echo "$smtp_session" | grep "220" | head -1)
    echo "Server: $server_banner"
    
    # Check for authentication methods
    echo "--- Authentication Methods ---"
    if echo "$smtp_session" | grep -qi "auth"; then
        echo "$smtp_session" | grep -i "auth"
    else
        echo "No authentication advertised"
    fi
    
    # Check for security features
    echo "--- Security Features ---"
    echo -n "STARTTLS: "
    echo "$smtp_session" | grep -qi "starttls" && echo "✅ Supported" || echo "❌ Not supported"
    
    echo -n "SIZE restrictions: "
    echo "$smtp_session" | grep -i "size" || echo "No size restrictions advertised"
    
    # User enumeration test (VRFY/EXPN)
    echo "--- User Enumeration Test ---"
    local user_enum=$(timeout 5 nc $target $port <<EOF
VRFY root
VRFY admin
VRFY administrator
EXPN root
QUIT
EOF
)
    
    if echo "$user_enum" | grep -q "252\|250"; then
        echo "⚠️  VRFY/EXPN commands may allow user enumeration"
        echo "$user_enum" | grep -E "^(250|252)"
    else
        echo "✅ VRFY/EXPN commands properly restricted"
    fi
    
    # Open relay test
    echo "--- Open Relay Test ---"
    local relay_test=$(timeout 10 nc $target $port <<EOF
EHLO test.example.com
MAIL FROM: <test@external.com>
RCPT TO: <test@external.com>
QUIT
EOF
)
    
    if echo "$relay_test" | grep -q "250.*RCPT"; then
        echo "⚠️  Potential open relay detected!"
    else
        echo "✅ Not an open relay"
    fi
}
```

---

## 🎯 eJPT Exam Preparation

### Essential Skills Breakdown

**Core Competencies Required:**

| Skill Category | Weight | Key Components | Practice Focus |
|----------------|---------|----------------|----------------|
| **Custom Script Creation** | 35% | Bash scripting, TCP/UDP scanning, loop structures | Build 5+ different scanner scripts |
| **Banner Grabbing** | 30% | Service identification, protocol knowledge, version detection | Practice on 20+ different services |
| **Manual Verification** | 20% | Confirming automated results, stealth techniques | Verify Nmap results manually |
| **Tool Integration** | 15% | Combining manual + automated, reporting, documentation | Create comprehensive workflows |

### eJPT-Focused Practice Scenarios

**Scenario 1: Custom Port Scanner Development**
```bash
# eJPT Challenge: Create a port scanner without Nmap
# Requirements: Scan ports 1-1000, identify open ports, basic service identification

#!/bin/bash
# ejpt_scanner.sh - eJPT exam-style scanner

ejpt_port_scanner() {
    local target=$1
    local start_port=${2:-1}
    local end_port=${3:-1000}
    
    echo "eJPT Port Scanner - Target: $target"
    echo "Scanning ports $start_port-$end_port..."
    echo "----------------------------------------"
    
    local open_ports=()
    local scan_start=$(date +%s)
    
    for port in $(seq $start_port $end_port); do
        # Progress indicator
        if [ $((port % 100)) -eq 0 ]; then
            echo "Progress: $port/$end_port ports scanned"
        fi
        
        # Port scan using bash built-in
        timeout 1 bash -c "exec 3<>/dev/tcp/$target/$port" 2>/dev/null && {
            exec 3<&-
            open_ports+=($port)
            
            # Basic service identification
            local service="unknown"
            case $port in
                21) service="ftp" ;;
                22) service="ssh" ;;
                23) service="telnet" ;;
                25) service="smtp" ;;
                53) service="dns" ;;
                80) service="http" ;;
                110) service="pop3" ;;
                143) service="imap" ;;
                443) service="https" ;;
                993) service="imaps" ;;
                995) service="pop3s" ;;
                3389) service="rdp" ;;
            esac
            
            echo "✅ Port $port/tcp open - $service"
        }
    done
    
    local scan_end=$(date +%s)
    local duration=$((scan_end - scan_start))
    
    echo "----------------------------------------"
    echo "Scan completed in ${duration} seconds"
    echo "Open ports found: ${#open_ports[@]}"
    echo "Open ports: ${open_ports[*]}"
    
    return ${#open_ports[@]}
}

# Usage for eJPT exam
ejpt_port_scanner demo1.ine.local 1 1000
```

**Scenario 2: Service Banner Collection for eJPT**
```bash
#!/bin/bash
# ejpt_banner_grabber.sh - Comprehensive banner collection for exam

ejpt_banner_collection() {
    local target=$1
    shift
    local ports=("$@")
    
    echo "eJPT Banner Collection - Target: $target"
    echo "========================================"
    
    for port in "${ports[@]}"; do
        echo
        echo "--- Port $port Banner ---"
        
        case $port in
            21) # FTP
                (echo "USER anonymous"; sleep 1; echo "QUIT") | timeout 5 nc $target $port
                ;;
            22) # SSH  
                timeout 3 nc $target $port </dev/null
                ;;
            25) # SMTP
                (echo "EHLO test.com"; sleep 1; echo "QUIT") | timeout 5 nc $target $port
                ;;
            53) # DNS
                echo "DNS service detected - use dig for further enumeration"
                ;;
            80) # HTTP
                echo -e "GET / HTTP/1.0\r\n\r\n" | timeout 5 nc $target $port | head -20
                ;;
            110) # POP3
                (echo "USER test"; sleep 1; echo "QUIT") | timeout 5 nc $target $port
                ;;
            143) # IMAP
                (echo "A001 CAPABILITY"; sleep 1; echo "A002 LOGOUT") | timeout 5 nc $target $port
                ;;
            443) # HTTPS
                echo -e "GET / HTTP/1.0\r\n\r\n" | timeout 5 openssl s_client -connect $target:$port -quiet 2>/dev/null | head -10
                ;;
            *) # Generic
                timeout 3 nc $target $port </dev/null
                ;;
        esac
    done
    
    echo
    echo "Banner collection completed!"
}

# Example usage for eJPT
# First scan for open ports, then collect banners
open_ports=($(ejpt_port_scanner demo1.ine.local | grep "open" | awk '{print $2}' | cut -d'/' -f1))
ejpt_banner_collection demo1.ine.local "${open_ports[@]}"
```

### eJPT Exam Simulation Environment

**Complete eJPT Practice Script:**
```bash
#!/bin/bash
# ejpt_practice.sh - Complete eJPT simulation environment

EJPT_TARGET=${1:-"demo1.ine.local"}
EJPT_RESULTS_DIR="ejpt-practice-$(date +%Y%m%d-%H%M%S)"

setup_ejpt_environment() {
    echo "Setting up eJPT practice environment..."
    mkdir -p $EJPT_RESULTS_DIR/{scripts,results,logs}
    cd $EJPT_RESULTS_DIR
    
    echo "Target: $EJPT_TARGET" > target-info.txt
    echo "Start time: $(date)" >> target-info.txt
}

ejpt_host_discovery() {
    echo "=== eJPT Task 1: Host Discovery ==="
    
    # Ping test
    echo "Testing host reachability..."
    if ping -c 3 $EJPT_TARGET >/dev/null 2>&1; then
        echo "✅ Host $EJPT_TARGET is reachable via ICMP"
    else
        echo "⚠️  Host not responding to ICMP - trying TCP probes"
        
        # TCP probe on common ports
        for port in 22 80 443; do
            timeout 2 bash -c "echo >/dev/tcp/$EJPT_TARGET/$port" 2>/dev/null && {
                echo "✅ Host reachable via TCP port $port"
                break
            }
        done
    fi
}

ejpt_port_scanning() {
    echo
    echo "=== eJPT Task 2: Port Scanning ==="
    
    # Quick scan of common ports
    echo "Scanning common ports..."
    local common_ports="21 22 23 25 53 80 110 135 139 443 445 993 995 1723 3306 3389 5432"
    local open_ports=()
    
    for port in $common_ports; do
        timeout 1 bash -c "echo >/dev/tcp/$EJPT_TARGET/$port" 2>/dev/null && {
            open_ports+=($port)
            echo "✅ $port/tcp open"
        }
    done
    
    echo "Open ports: ${open_ports[*]}" > results/open-ports.txt
    
    # Extended scan if requested
    read -p "Perform extended scan (1-1000)? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Extended scanning in progress..."
        for port in {1..1000}; do
            [ $((port % 100)) -eq 0 ] && echo "Progress: $port/1000"
            timeout 0.5 bash -c "echo >/dev/tcp/$EJPT_TARGET/$port" 2>/dev/null && {
                [[ ! " ${open_ports[@]} " =~ " $port " ]] && {
                    open_ports+=($port)
                    echo "✅ $port/tcp open (extended)"
                }
            }
        done
    fi
    
    echo "${open_ports[*]}" > results/all-open-ports.txt
    return ${#open_ports[@]}
}

ejpt_service_enumeration() {
    echo
    echo "=== eJPT Task 3: Service Enumeration ==="
    
    local open_ports=($(cat results/all-open-ports.txt))
    
    for port in "${open_ports[@]}"; do
        echo "--- Enumerating port $port ---" | tee -a results/service-enum.txt
        
        case $port in
            21)
                echo "FTP Service Detection:" | tee -a results/service-enum.txt
                timeout 5 nc $EJPT_TARGET $port </dev/null 2>&1 | tee -a results/service-enum.txt
                ;;
            22)
                echo "SSH Service Detection:" | tee -a results/service-enum.txt
                timeout 3 nc $EJPT_TARGET $port </dev/null 2>&1 | tee -a results/service-enum.txt
                ;;
            80|8080)
                echo "HTTP Service Detection:" | tee -a results/service-enum.txt
                curl -I http://$EJPT_TARGET:$port/ 2>/dev/null | tee -a results/service-enum.txt
                ;;
            443|8443)
                echo "HTTPS Service Detection:" | tee -a results/service-enum.txt
                curl -I -k https://$EJPT_TARGET:$port/ 2>/dev/null | tee -a results/service-enum.txt
                ;;
            *)
                echo "Generic Banner Grab:" | tee -a results/service-enum.txt
                timeout 3 nc $EJPT_TARGET $port </dev/null 2>&1 | tee -a results/service-enum.txt
                ;;
        esac
        echo | tee -a results/service-enum.txt
    done
}

ejpt_vulnerability_assessment() {
    echo
    echo "=== eJPT Task 4: Basic Vulnerability Assessment ==="
    
    # Check for common misconfigurations
    echo "Checking for common vulnerabilities..." | tee results/vulnerability-assessment.txt
    
    # Anonymous FTP
    if grep -q "^21$" results/all-open-ports.txt; then
        echo "Testing FTP anonymous access..." | tee -a results/vulnerability-assessment.txt
        (echo "USER anonymous"; echo "PASS anonymous"; echo "PWD"; echo "QUIT") | \
        timeout 10 nc $EJPT_TARGET 21 2>&1 | tee -a results/vulnerability-assessment.txt
    fi
    
    # HTTP methods
    if grep -q "^80$" results/all-open-ports.txt; then
        echo "Testing HTTP methods..." | tee -a results/vulnerability-assessment.txt
        curl -X OPTIONS -v http://$EJPT_TARGET/ 2>&1 | grep -i allow | tee -a results/vulnerability-assessment.txt
    fi
    
    # Default web pages
    if grep -q "^80$" results/all-open-ports.txt; then
        echo "Checking for default pages..." | tee -a results/vulnerability-assessment.txt
        for path in robots.txt phpinfo.php admin test.html; do
            response=$(curl -s -o /dev/null -w "%{http_code}" http://$EJPT_TARGET/$path)
            [[ $response == "200" ]] && echo "Found: /$path (200)" | tee -a results/vulnerability-assessment.txt
        done
    fi
}

generate_ejpt_report() {
    echo
    echo "=== eJPT Task 5: Report Generation ==="
    
    cat > results/ejpt-report.md << EOF
# eJPT Practice Report

**Target:** $EJPT_TARGET  
**Date:** $(date)  
**Tester:** eJPT Candidate  

## Executive Summary

This report contains the results of manual port scanning and service enumeration performed against the target system.

## Methodology

1. Host Discovery using ICMP and TCP probes
2. Port scanning using custom bash scripts
3. Service enumeration through banner grabbing
4. Basic vulnerability assessment

## Findings

### Open Ports
$(cat results/all-open-ports.txt | wc -w) open ports discovered:
$(cat results/all-open-ports.txt | tr ' ' '\n' | sed 's/^/- Port /' | sed 's/$//tcp/')

### Service Identification
$(cat results/service-enum.txt | grep -E "SSH|HTTP|FTP|SMTP" | head -10)

### Potential Vulnerabilities
$(cat results/vulnerability-assessment.txt | grep -E "Found|anonymous|200" || echo "No obvious vulnerabilities detected")

## Recommendations

1. Close unnecessary open ports
2. Update service versions to latest
3. Implement proper access controls
4. Regular security assessments

## Tools Used

- Custom bash port scanner
- Netcat for banner grabbing  
- Curl for HTTP analysis
- Manual enumeration techniques

EOF

    echo "✅ Report generated: results/ejpt-report.md"
    echo "✅ All results saved in: $EJPT_RESULTS_DIR"
}

# Main eJPT simulation execution
main_ejpt_simulation() {
    echo "🎯 eJPT Practice Environment Starting..."
    echo "Target: $EJPT_TARGET"
    echo
    
    setup_ejpt_environment
    ejpt_host_discovery | tee logs/host-discovery.log
    ejpt_port_scanning | tee logs/port-scanning.log
    ejpt_service_enumeration | tee logs/service-enum.log
    ejpt_vulnerability_assessment | tee logs/vuln-assessment.log
    generate_ejpt_report
    
    echo
    echo "🎯 eJPT Practice Session Complete!"
    echo "Review results in: $EJPT_RESULTS_DIR"
}

# Execute main function
main_ejpt_simulation
```

### Critical eJPT Commands to Master

**Must-Know Command Reference:**

```bash
# Core port scanning commands
timeout 1 bash -c "echo >/dev/tcp/target/port"     # Single port test
nc -zv target 1-1000                               # Netcat range scan
nc -zuv target 53 161 514                          # UDP port scan

# Banner grabbing essentials
echo -e "GET / HTTP/1.0\r\n\r\n" | nc target 80   # HTTP banner
nc target 22 </dev/null                            # SSH banner
(echo "USER anonymous"; echo "QUIT") | nc target 21 # FTP banner

# Service-specific enumeration
curl -I http://target                               # HTTP headers
nslookup target                                     # DNS lookup
dig target                                          # DNS enumeration

# Quick vulnerability checks
curl -X OPTIONS -v http://target                   # HTTP methods
curl -s http://target/robots.txt                   # Robots.txt
echo "VRFY root" | nc target 25                    # SMTP user enum
```

**eJPT Time Management Tips:**

| Task | Time Allocation | Key Focus |
|------|----------------|-----------|
| **Host Discovery** | 5 minutes | Verify target accessibility |
| **Port Scanning** | 15 minutes | Custom script for common ports |
| **Service Enumeration** | 20 minutes | Banner grab all open ports |
| **Vulnerability Check** | 15 minutes | Test for obvious misconfigurations |
| **Documentation** | 5 minutes | Save commands and results |

---

## ⚠️ Troubleshooting & Common Issues

### Issue Resolution Guide

**Problem 1: /dev/tcp Not Available**

*Symptoms:* `bash: /dev/tcp/target/port: No such file or directory`

*Root Cause:* Non-bash shell or restricted environment

*Solutions:*
```bash
# Verify current shell
echo $SHELL
ps -p $

# Force bash execution
bash -c "echo >/dev/tcp/target/port"

# Alternative using netcat
nc -w 1 -z target port

# Alternative using telnet
echo "quit" | timeout 1 telnet target port
```

**Problem 2: Connection Timeouts and Hanging**

*Symptoms:* Scripts hang indefinitely, no response from target

*Solutions:*
```bash
# Always use timeout with manual connections
timeout 3 bash -c "echo >/dev/tcp/target/port"

# Netcat with explicit timeout
nc -w 2 target port

# Multiple timeout strategies
{
    echo "test"
    sleep 1
    echo "quit"
} | timeout 5 nc target port
```

**Problem 3: Performance Issues with Large Port Ranges**

*Symptoms:* Slow scanning, system resource exhaustion

*Optimizations:*
```bash
# Parallel scanning with job control
scan_parallel() {
    local max_jobs=20
    for port in {1..1000}; do
        # Wait if too many background jobs
        while [ $(jobs -r | wc -l) -ge $max_jobs ]; do
            sleep 0.1
        done
        
        # Scan in background
        (timeout 1 bash -c "echo >/dev/tcp/$1/$port" 2>/dev/null && echo "$port open") &
    done
    wait  # Wait for all jobs to complete
}

# Use xargs for better performance
seq 1 1000 | xargs -n 1 -P 20 -I {} bash -c 'timeout 1 bash -c "echo >/dev/tcp/target/{}" 2>/dev/null && echo "{} open"'
```

**Problem 4: Incomplete Banner Grabbing**

*Symptoms:* Services not responding, truncated banners

*Solutions:*
```bash
# HTTP requires proper headers
http_banner_grab() {
    local target=$1
    local port=${2:-80}
    {
        echo -e "GET / HTTP/1.1\r"
        echo -e "Host: $target\r"
        echo -e "User-Agent: Manual-Scanner\r"
        echo -e "Connection: close\r"
        echo -e "\r"
    } | nc $target $port
}

# Add delays for slow services
slow_service_banner() {
    local target=$1
    local port=$2
    {
        echo "HELP"
        sleep 2
        echo "QUIT"
    } | nc $target $port
}

# Binary services need special handling
binary_service_test() {
    local target=$1
    local port=$2
    timeout 3 nc $target $port </dev/null 2>/dev/null | strings | head -5
}
```

**Problem 5: UDP Scanning Difficulties**

*Symptoms:* No response from UDP services, false negatives

*Solutions:*
```bash
# Protocol-specific UDP probes
udp_dns_probe() {
    local target=$1
    # DNS query packet for example.com
    printf "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01" | \
    nc -u -w 2 $target 53
}

udp_snmp_probe() {
    local target=$1
    # SNMP GetRequest for system description
    printf "\x30\x19\x02\x01\x00\x04\x06public\xa0\x0c\x02\x04\x00\x00\x00\x00\x02\x01\x00\x30\x00" | \
    nc -u -w 2 $target 161
}

udp_ntp_probe() {
    local target=$1
    # NTP request packet
    printf "\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" | \
    nc -u -w 2 $target 123
}
```

**Problem 6: Script Portability Issues**

*Symptoms:* Scripts fail on different Linux distributions

*Solutions:*
```bash
# Check for required tools at script start
check_dependencies() {
    local deps=("nc" "timeout" "curl" "ping")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo "Missing dependencies: ${missing[*]}"
        echo "Install with: apt-get install ${missing[*]// / }"
        exit 1
    fi
}

# Handle different netcat versions
detect_netcat_version() {
    if nc -h 2>&1 | grep -q "openbsd"; then
        NC_TYPE="openbsd"
    elif nc -h 2>&1 | grep -q "traditional"; then
        NC_TYPE="traditional"  
    else
        NC_TYPE="unknown"
    fi
    
    echo "Detected netcat type: $NC_TYPE"
}

# Cross-platform timeout handling
safe_timeout() {
    local duration=$1
    shift
    local command="$@"
    
    if command -v timeout >/dev/null 2>&1; then
        timeout "$duration" bash -c "$command"
    else
        # Fallback for systems without timeout
        bash -c "$command" &
        local pid=$!
        sleep "$duration"
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    fi
}
```

### Debugging and Diagnostics

**Script Debugging Techniques:**

```bash
#!/bin/bash
# debug_scanner.sh - Enhanced debugging for manual scanners

# Enable debugging modes
set -euo pipefail  # Exit on error, undefined vars, pipe failures
# set -x           # Uncomment for command tracing

# Logging function with multiple levels
debug_log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        DEBUG)   [[ ${DEBUG:-0} == 1 ]] && echo "[DEBUG] $timestamp: $message" >&2 ;;
        INFO)    echo "[INFO] $timestamp: $message" ;;
        WARN)    echo "[WARN] $timestamp: $message" >&2 ;;
        ERROR)   echo "[ERROR] $timestamp: $message" >&2 ;;
    esac
}

# Enhanced port scan with debugging
debug_port_scan() {
    local target=$1
    local port=$2
    local timeout_duration=${3:-1}
    
    debug_log DEBUG "Attempting connection to $target:$port (timeout: ${timeout_duration}s)"
    
    # Test network connectivity first
    if ! ping -c 1 -W 1 "$target" >/dev/null 2>&1; then
        debug_log WARN "Target $target may not be reachable via ICMP"
    fi
    
    # Multiple connection methods for reliability
    local methods=("bash_builtin" "netcat" "telnet")
    local success=false
    
    for method in "${methods[@]}"; do
        debug_log DEBUG "Trying method: $method"
        
        case $method in
            bash_builtin)
                timeout "$timeout_duration" bash -c "exec 3<>/dev/tcp/$target/$port" 2>/dev/null && {
                    exec 3<&-
                    debug_log DEBUG "Success with bash builtin"
                    success=true
                    break
                }
                ;;
            netcat)
                if command -v nc >/dev/null 2>&1; then
                    nc -w "$timeout_duration" -z "$target" "$port" 2>/dev/null && {
                        debug_log DEBUG "Success with netcat"
                        success=true
                        break
                    }
                fi
                ;;
            telnet)
                if command -v telnet >/dev/null 2>&1; then
                    echo "quit" | timeout "$timeout_duration" telnet "$target" "$port" >/dev/null 2>&1 && {
                        debug_log DEBUG "Success with telnet"
                        success=true
                        break
                    }
                fi
                ;;
        esac
    done
    
    if $success; then
        debug_log INFO "Port $port/tcp is open on $target"
        return 0
    else
        debug_log DEBUG "Port $port/tcp appears closed on $target"
        return 1
    fi
}

# Network diagnostics function
network_diagnostics() {
    local target=$1
    
    echo "=== Network Diagnostics for $target ==="
    
    # Basic connectivity
    echo "--- Connectivity Tests ---"
    ping -c 3 "$target" && echo "✅ ICMP reachable" || echo "❌ ICMP not reachable"
    
    # DNS resolution
    echo "--- DNS Resolution ---"
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Target is IP address: $target"
        # Reverse DNS lookup
        if command -v dig >/dev/null 2>&1; then
            dig -x "$target" +short | head -1 || echo "No reverse DNS"
        fi
    else
        echo "Resolving hostname: $target"
        if command -v dig >/dev/null 2>&1; then
            dig "$target" +short | head -5
        elif command -v nslookup >/dev/null 2>&1; then
            nslookup "$target" | grep "Address" | tail -n +2
        fi
    fi
    
    # Route tracing (if available)
    echo "--- Network Path ---"
    if command -v traceroute >/dev/null 2>&1; then
        echo "Traceroute (first 5 hops):"
        timeout 10 traceroute "$target" 2>/dev/null | head -5
    elif command -v tracepath >/dev/null 2>&1; then
        echo "Tracepath (first 5 hops):"
        timeout 10 tracepath "$target" 2>/dev/null | head -5
    fi
    
    # MTU discovery
    echo "--- MTU Discovery ---"
    for size in 1500 1200 800 576; do
        if ping -c 1 -M do -s $((size - 28)) "$target" >/dev/null 2>&1; then
            echo "✅ MTU $size bytes supported"
            break
        else
            echo "❌ MTU $size bytes failed"
        fi
    done
}
```

---

## 🚀 Practice Labs & Examples

### Lab Environment Setup

**Virtual Lab Configuration:**

```bash
#!/bin/bash
# setup_practice_lab.sh - Create practice environment

setup_virtual_targets() {
    echo "Setting up practice lab environment..."
    
    # Create target list for practice
    cat > practice_targets.conf << 'EOF'
# Practice Lab Targets
# Format: name:ip:description
demo1:192.168.1.10:Basic web server with SSH
demo2:192.168.1.11:FTP server with web interface  
demo3:192.168.1.12:Database server (MySQL/PostgreSQL)
demo4:192.168.1.13:Mail server (SMTP/IMAP/POP3)
demo5:192.168.1.14:Multi-service server
EOF

    # Create practice scenarios
    mkdir -p practice-scenarios/{beginner,intermediate,advanced}
    
    # Beginner scenarios
    cat > practice-scenarios/beginner/scenario1.md << 'EOF'
# Beginner Scenario 1: Basic Port Scanning

**Objective:** Identify open ports on demo1 (192.168.1.10)

**Tasks:**
1. Create a bash script to scan ports 1-100
2. Identify service running on port 80
3. Grab HTTP banner information
4. Document findings

**Expected Results:**
- Ports 22, 80 should be open
- SSH and HTTP services identified
- Apache web server version detected
EOF

    echo "✅ Practice lab environment created"
    echo "📁 Check practice-scenarios/ for exercises"
}

# Execute lab setup
setup_virtual_targets
```

### Progressive Practice Exercises

**Exercise 1: Basic Port Scanner (Beginner)**

```bash
#!/bin/bash
# exercise1_basic_scanner.sh - Beginner port scanning exercise

echo "🎯 Exercise 1: Basic Port Scanner"
echo "Objective: Scan ports 1-100 on target"
echo

read -p "Enter target IP/hostname: " TARGET
read -p "Start port [1]: " START_PORT
read -p "End port [100]: " END_PORT

START_PORT=${START_PORT:-1}
END_PORT=${END_PORT:-100}

echo "Scanning $TARGET ports $START_PORT-$END_PORT..."

# Student implementation area
# TODO: Implement port scanning loop
# Hints: 
# - Use for loop with seq command
# - Use timeout with bash /dev/tcp
# - Track open ports in array

open_ports=()
scan_start=$(date +%s)

for port in $(seq $START_PORT $END_PORT); do
    # Progress indicator
    if [ $((port % 25)) -eq 0 ]; then
        echo "Progress: $port/$END_PORT ports scanned"
    fi
    
    # TODO: Add port scanning logic here
    # Example solution (uncomment to use):
    # timeout 1 bash -c "echo >/dev/tcp/$TARGET/$port" 2>/dev/null && {
    #     open_ports+=($port)
    #     echo "✅ Port $port is open"
    # }
done

scan_end=$(date +%s)
duration=$((scan_end - scan_start))

echo
echo "Scan Results:"
echo "- Duration: ${duration} seconds"
echo "- Open ports: ${#open_ports[@]}"
echo "- Port list: ${open_ports[*]}"

# Verification questions
echo
echo "📝 Answer these questions:"
echo "1. Which ports were found open?"
echo "2. What services might be running on these ports?"
echo "3. How could you improve the scanning speed?"
```

**Exercise 2: Service Enumeration (Intermediate)**

```bash
#!/bin/bash
# exercise2_service_enum.sh - Service enumeration exercise

echo "🎯 Exercise 2: Service Enumeration"
echo "Objective: Identify services on open ports"
echo

TARGET=${1:-"demo1.ine.local"}
echo "Target: $TARGET"

# Step 1: Quick port discovery
echo "Step 1: Discovering open ports..."
common_ports="21 22 23 25 53 80 110 135 139 443 445 993 995 3389"
open_ports=()

for port in $common_ports; do
    timeout 1 bash -c "echo >/dev/tcp/$TARGET/$port" 2>/dev/null && {
        open_ports+=($port)
        echo "✅ Found open port: $port"
    }
done

if [ ${#open_ports[@]} -eq 0 ]; then
    echo "❌ No open ports found in common list"
    exit 1
fi

# Step 2: Service identification
echo
echo "Step 2: Service identification..."

identify_service() {
    local port=$1
    echo "--- Analyzing port $port ---"
    
    # TODO: Implement service-specific banner grabbing
    case $port in
        21)
            echo "Service: FTP"
            # TODO: Implement FTP banner grabbing
            ;;
        22)
            echo "Service: SSH" 
            # TODO: Implement SSH banner grabbing
            ;;
        25)
            echo "Service: SMTP"
            # TODO: Implement SMTP banner grabbing
            ;;
        80)
            echo "Service: HTTP"
            # TODO: Implement HTTP banner grabbing
            ;;
        443)
            echo "Service: HTTPS"
            # TODO: Implement HTTPS banner grabbing
            ;;
        *)
            echo "Service: Unknown"
            # TODO: Implement generic banner grabbing
            ;;
    esac
    echo
}

# Enumerate each open port
for port in "${open_ports[@]}"; do
    identify_service $port
done

# Step 3: Vulnerability assessment
echo "Step 3: Basic vulnerability checks..."

check_vulnerabilities() {
    # TODO: Implement basic vulnerability checks
    # Examples:
    # - Anonymous FTP access
    # - Default web pages
    # - Outdated service versions
    # - Open relay testing (SMTP)
    
    echo "Vulnerability assessment not implemented yet"
    echo "TODO: Add checks for:"
    echo "- Anonymous access"
    echo "- Default credentials"
    echo "- Information disclosure"
    echo "- Outdated versions"
}

check_vulnerabilities

echo
echo "📝 Exercise Questions:"
echo "1. What services were identified?"
echo "2. Which services might be misconfigured?"
echo "3. What additional enumeration would you perform?"
echo "4. How would you prioritize these findings?"
```

**Exercise 3: Advanced Stealth Scanning (Advanced)**

```bash
#!/bin/bash
# exercise3_stealth_scanning.sh - Advanced stealth techniques

echo "🎯 Exercise 3: Advanced Stealth Scanning"
echo "Objective: Implement stealth scanning techniques"
echo

TARGET=${1:-"demo1.ine.local"}
STEALTH_LEVEL=${2:-2}  # 1=low, 2=medium, 3=high

echo "Target: $TARGET"
echo "Stealth Level: $STEALTH_LEVEL"

# Stealth technique implementations
implement_timing_evasion() {
    local level=$1
    
    case $level in
        1) 
            MIN_DELAY=0.1
            MAX_DELAY=0.5
            echo "Low stealth: 0.1-0.5s delays"
            ;;
        2)
            MIN_DELAY=0.5
            MAX_DELAY=2.0
            echo "Medium stealth: 0.5-2.0s delays"
            ;;
        3)
            MIN_DELAY=2.0
            MAX_DELAY=10.0
            echo "High stealth: 2.0-10.0s delays"
            ;;
    esac
    
    # Random delay function
    random_delay() {
        local min_delay=$1
        local max_delay=$2
        local delay=$(echo "scale=2; $min_delay + ($RANDOM/32767) * ($max_delay - $min_delay)" | bc)
        sleep "$delay"
    }
    
    export -f random_delay
    export MIN_DELAY MAX_DELAY
}

implement_source_port_randomization() {
    echo "Implementing source port randomization..."
    
    scan_with_random_source() {
        local target=$1
        local port=$2
        local source_port=$((RANDOM % 60000 + 1024))
        
        # Use netcat with specific source port
        nc -p "$source_port" -w 1 -z "$target" "$port" 2>/dev/null
    }
    
    export -f scan_with_random_source
}

implement_decoy_scanning() {
    echo "Implementing decoy scanning simulation..."
    
    # Simulate multiple source IPs (conceptual - requires advanced networking)
    decoy_scan() {
        local target=$1
        local port=$2
        
        # In practice, this would require:
        # - Raw socket programming
        # - IP spoofing capabilities
        # - Advanced networking tools
        
        echo "Decoy scan simulation for $target:$port"
        echo "Note: Real implementation requires raw sockets"
        
        # Fallback to regular scan with random timing
        random_delay "$MIN_DELAY" "$MAX_DELAY"
        timeout 1 bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null
    }
    
    export -f decoy_scan
}

implement_fragmented_scanning() {
    echo "Implementing fragmented packet simulation..."
    
    # Conceptual implementation
    fragmented_scan() {
        local target=$1
        local port=$2
        
        # In practice, this would use:
        # - Custom packet crafting
        # - Tools like hping3 or scapy
        # - IP fragmentation techniques
        
        echo "Fragmented scan simulation for $target:$port"
        echo "Note: Real implementation requires packet crafting"
        
        # Fallback to multiple small probes
        for i in {1..3}; do
            timeout 0.3 bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null &
            sleep 0.1
        done
        wait
    }
    
    export -f fragmented_scan
}

# Main stealth scanning function
perform_stealth_scan() {
    local target=$1
    local stealth_level=$2
    
    echo "Performing stealth scan..."
    
    # Initialize stealth techniques
    implement_timing_evasion "$stealth_level"
    implement_source_port_randomization
    implement_decoy_scanning
    implement_fragmented_scanning
    
    # Port list for scanning
    local ports=(21 22 23 25 53 80 110 143 443 993 995 3389)
    
    # Randomize port order
    local randomized_ports=($(printf '%s\n' "${ports[@]}" | shuf))
    
    echo "Scanning ${#randomized_ports[@]} ports with stealth techniques..."
    
    local open_ports=()
    local scan_start=$(date +%s)
    
    for port in "${randomized_ports[@]}"; do
        echo -n "Scanning port $port... "
        
        # Apply random delay
        random_delay "$MIN_DELAY" "$MAX_DELAY"
        
        # Choose random scanning technique
        local technique=$((RANDOM % 3))
        local success=false
        
        case $technique in
            0) # Standard scan with random source
                scan_with_random_source "$target" "$port" && success=true
                ;;
            1) # Decoy scan
                decoy_scan "$target" "$port" && success=true
                ;;
            2) # Fragmented scan
                fragmented_scan "$target" "$port" && success=true
                ;;
        esac
        
        if $success; then
            open_ports+=($port)
            echo "OPEN"
        else
            echo "closed/filtered"
        fi
        
        # Additional random delay between ports
        random_delay 0.1 1.0
    done
    
    local scan_end=$(date +%s)
    local duration=$((scan_end - scan_start))
    
    echo
    echo "Stealth Scan Results:"
    echo "- Duration: ${duration} seconds"
    echo "- Open ports: ${open_ports[*]}"
    echo "- Detection probability: $(calculate_detection_probability $stealth_level)"
}

calculate_detection_probability() {
    local level=$1
    case $level in
        1) echo "High (60-80%)" ;;
        2) echo "Medium (30-50%)" ;;
        3) echo "Low (10-20%)" ;;
    esac
}

# Execute stealth scanning
perform_stealth_scan "$TARGET" "$STEALTH_LEVEL"

echo
echo "📝 Advanced Exercise Questions:"
echo "1. What stealth techniques were most effective?"
echo "2. How does timing affect detection probability?"
echo "3. What additional evasion techniques could be used?"
echo "4. How would you validate stealth effectiveness?"
```

### Real-World Simulation Scripts

**Corporate Network Assessment Simulation:**

```bash
#!/bin/bash
# corporate_network_sim.sh - Realistic corporate network assessment

echo "🏢 Corporate Network Assessment Simulation"
echo "Simulating real-world penetration testing scenario"
echo

# Network configuration
CORPORATE_NETWORK="192.168.100"
TARGETS=("$CORPORATE_NETWORK.10" "$CORPORATE_NETWORK.20" "$CORPORATE_NETWORK.30" "$CORPORATE_NETWORK.50")
SERVICES=("web_server" "file_server" "database_server" "domain_controller")

# Assessment phases
phase1_network_discovery() {
    echo "=== Phase 1: Network Discovery ==="
    
    # Ping sweep
    echo "Performing ping sweep of $CORPORATE_NETWORK.0/24..."
    local live_hosts=()
    
    for i in {1..254}; do
        local ip="$CORPORATE_NETWORK.$i"
        timeout 1 ping -c 1 "$ip" >/dev/null 2>&1 && {
            live_hosts+=("$ip")
            echo "✅ Live host: $ip"
        }
    done
    
    echo "Found ${#live_hosts[@]} live hosts"
    printf '%s\n' "${live_hosts[@]}" > live_hosts.txt
}

phase2_port_scanning() {
    echo
    echo "=== Phase 2: Port Scanning ==="
    
    while IFS= read -r host; do
        echo "Scanning $host..."
        
        # Corporate-focused port list
        local corp_ports="21 22 23 25 53 80 135 139 389 443 445 636 993 995 1433 3389 5432"
        local host_open_ports=()
        
        for port in $corp_ports; do
            timeout 2 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null && {
                host_open_ports+=("$port")
            }
        done
        
        if [ ${#host_open_ports[@]} -gt 0 ]; then
            echo "$host: ${host_open_ports[*]}" >> port_scan_results.txt
            echo "✅ $host - Open ports: ${host_open_ports[*]}"
        fi
        
    done < live_hosts.txt
}

phase3_service_enumeration() {
    echo
    echo "=== Phase 3: Service Enumeration ==="
    
    while IFS=': ' read -r host ports_str; do
        IFS=' ' read -ra ports <<< "$ports_str"
        echo "Enumerating services on $host..."
        
        for port in "${ports[@]}"; do
            enumerate_corporate_service "$host" "$port"
        done
        
    done < port_scan_results.txt
}

enumerate_corporate_service() {
    local host=$1
    local port=$2
    
    echo "--- $host:$port ---"
    
    case $port in
        21) # FTP - Common in corporate file transfers
            timeout 5 nc "$host" "$port" <<< "USER anonymous" | head -3
            ;;
        22) # SSH - Remote administration
            timeout 3 nc "$host" "$port" </dev/null | head -1
            ;;
        25) # SMTP - Corporate mail
            timeout 5 nc "$host" "$port" <<< "EHLO corporate.local" | head -10
            ;;
        53) # DNS - Internal DNS servers
            echo "DNS service detected - corporate domain queries possible"
            ;;
        80|443) # Web services - Intranets, applications
            if [ "$port" == "443" ]; then
                curl -k -I "https://$host/" 2>/dev/null | head -5
            else
                curl -I "http://$host/" 2>/dev/null | head -5
            fi
            ;;
        135|445) # Windows services - File sharing, RPC
            echo "Windows services detected - SMB/RPC enumeration possible"
            ;;
        389|636) # LDAP - Active Directory
            echo "LDAP service detected - Active Directory enumeration possible"
            ;;
        1433) # MSSQL - Corporate databases
            echo "MSSQL service detected - database enumeration possible"
            ;;
        3389) # RDP - Remote desktop
            echo "RDP service detected - remote access possible"
            ;;
        5432) # PostgreSQL - Alternative database
            echo "PostgreSQL service detected - database enumeration possible"
            ;;
    esac
}

phase4_vulnerability_assessment() {
    echo
    echo "=== Phase 4: Vulnerability Assessment ==="
    
    # Common corporate vulnerabilities
    echo "Checking for common corporate vulnerabilities..."
    
    # Anonymous FTP access
    echo "- Testing anonymous FTP access..."
    grep ":21" port_scan_results.txt | while IFS=':' read -r host _; do
        timeout 10 nc "$host" 21 <<EOF | grep -q "230" && echo "⚠️  Anonymous FTP: $host"
USER anonymous
PASS anonymous
QUIT
EOF
    done
    
    # Default web pages
    echo "- Testing for default/admin web pages..."
    grep -E ":(80|443)" port_scan_results.txt | while IFS=':' read -r host port; do
        local protocol="http"
        [ "$port" == "443" ] && protocol="https"
        
        for path in admin login.asp default.htm iisstart.htm; do
            local response=$(curl -s -o /dev/null -w "%{http_code}" "$protocol://$host/$path")
            [ "$response" == "200" ] && echo "⚠️  Found: $protocol://$host/$path"
        done
    done
    
    # SMB null sessions
    echo "- Testing SMB null sessions..."
    grep ":445" port_scan_results.txt | while IFS=':' read -r host _; do
        timeout 5 nc "$host" 445 </dev/null >/dev/null 2>&1 && \
        echo "ℹ️  SMB accessible: $host (requires specialized tools for null session test)"
    done
}

generate_corporate_report() {
    echo
    echo "=== Generating Corporate Assessment Report ==="
    
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local report_file="corporate_assessment_$timestamp.md"
    
    cat > "$report_file" << EOF
# Corporate Network Assessment Report

**Assessment Date:** $(date)  
**Network Range:** $CORPORATE_NETWORK.0/24  
**Methodology:** Manual scanning techniques  

## Executive Summary

This assessment identified multiple systems and services within the corporate network that require attention.

## Network Discovery Results

**Live Hosts:** $(wc -l < live_hosts.txt 2>/dev/null || echo "0")
$(cat live_hosts.txt 2>/dev/null | sed 's/^/- /' || echo "No live hosts file found")

## Port Scanning Results

**Systems with Open Ports:**
$(cat port_scan_results.txt 2>/dev/null | sed 's/^/- /' || echo "No port scan results found")

## Service Enumeration Summary

Key services identified:
- Web services (HTTP/HTTPS) - Corporate applications
- SSH services - Administrative access
- SMB services - File sharing
- Database services - Corporate data
- RDP services - Remote access

## Security Recommendations

1. **Immediate Actions:**
   - Disable unnecessary services
   - Update service versions
   - Implement proper access controls

2. **Short-term Actions:**
   - Deploy network segmentation
   - Implement monitoring solutions
   - Conduct security awareness training

3. **Long-term Actions:**
   - Regular security assessments
   - Incident response planning
   - Security policy development

## Technical Details

**Scanning Methodology:**
- ICMP ping sweep for host discovery
- TCP connect scans for port identification
- Banner grabbing for service enumeration
- Basic vulnerability assessment

**Tools Used:**
- Custom bash scripts
- Netcat for banner grabbing
- Curl for HTTP analysis
- Manual enumeration techniques

EOF

    echo "✅ Report generated: $report_file"
}

# Main execution
main_corporate_simulation() {
    echo "Starting corporate network assessment simulation..."
    echo "Note: This simulation uses local network ranges"
    echo
    
    # Create results directory
    local results_dir="corporate_assessment_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$results_dir"
    cd "$results_dir"
    
    # Execute assessment phases
    phase1_network_discovery
    phase2_port_scanning  
    phase3_service_enumeration
    phase4_vulnerability_assessment
    generate_corporate_report
    
    echo
    echo "🎯 Corporate Assessment Simulation Complete!"
    echo "Results available in: $results_dir"
}

# Execute simulation
main_corporate_simulation
```

---

## 🔗 Advanced Techniques

### Custom Protocol Analysis

**Advanced Banner Grabbing Techniques:**

```bash
#!/bin/bash
# advanced_banner_analysis.sh - Advanced service fingerprinting

# HTTP/HTTPS advanced analysis
advanced_http_analysis() {
    local target=$1
    local port=${2:-80}
    local protocol="http"
    
    [ "$port" == "443" ] && protocol="https"
    
    echo "=== Advanced HTTP Analysis: $target:$port ==="
    
    # Multiple HTTP methods testing
    local methods=("GET" "POST" "PUT" "DELETE" "OPTIONS" "HEAD" "TRACE" "CONNECT")
    
    for method in "${methods[@]}"; do
        echo "Testing $method method:"
        curl -X "$method" -v "$protocol://$target:$port/" 2>&1 | \
        grep -E "(< HTTP|< Allow|< Server)" | head -3
        echo
    done
    
    # HTTP header analysis
    echo "--- HTTP Headers Analysis ---"
    local headers=$(curl -I "$protocol://$target:$port/" 2>/dev/null)
    
    # Security headers check
    local security_headers=("X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection" 
                           "Strict-Transport-Security" "Content-Security-Policy")
    
    for header in "${security_headers[@]}"; do
        echo -n "$header: "
        echo "$headers" | grep -i "$header:" | cut -d' ' -f2- || echo "MISSING"
    done
    
    # Technology stack detection
    echo "--- Technology Stack ---"
    echo "$headers" | grep -iE "(Server|X-Powered-By|X-AspNet-Version|X-Technology)" | \
    while IFS=':
