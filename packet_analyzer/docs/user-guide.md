# IDS User Guide

## Table of Contents
1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Configuration](#configuration)
4. [Rule Management](#rule-management)
5. [Logging and Monitoring](#logging-and-monitoring)
6. [Performance Tuning](#performance-tuning)
7. [Troubleshooting](#troubleshooting)
8. [Advanced Usage](#advanced-usage)

## Installation

### System Requirements
- Linux kernel 3.0 or higher
- CMake 3.10 or higher
- C++17 compatible compiler (GCC 7+, Clang 5+)
- Root privileges for packet capture
- Minimum 2GB RAM, 4GB recommended
- Network interface in promiscuous mode support

### Dependencies
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install build-essential cmake git
sudo apt-get install linux-headers-$(uname -r)

# CentOS/RHEL/Fedora
sudo yum groupinstall "Development Tools"
sudo yum install cmake git kernel-headers

# Arch Linux
sudo pacman -S base-devel cmake git linux-headers
```

### Building from Source
```bash
# Clone the repository
git clone https://github.com/yourusername/ids.git
cd ids

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build
make -j$(nproc)

# Run tests
make test

# Install
sudo make install
```

### Installation Paths
- Binary: `/usr/local/bin/ids`
- Configuration: `/etc/ids/`
- Rules: `/etc/ids/rules/`
- Documentation: `/usr/local/share/doc/ids/`
- Plugins: `/usr/local/lib/ids/plugins/`

## Quick Start

### Basic Usage
```bash
# Run with default configuration
sudo ids

# Run with custom configuration
sudo ids -c /path/to/config.yaml

# Run in debug mode
sudo ids -c config.yaml --debug

# Show version
ids --version

# Show help
ids --help
```

### First Time Setup
1. **Check network interfaces**:
```bash
ip link show
```

2. **Create basic configuration**:
```yaml
# /etc/ids/ids.yaml
ids:
  capture:
    interface: "eth0"  # Change to your interface
    promiscuous: true
    buffer_size: 65536
    
  logging:
    level: "INFO"
    format: "tcpdump"
    output: "console"
    
  rules:
    rule_files:
      - "/etc/ids/rules/local.rules"
```

3. **Create basic rule**:
```bash
# /etc/ids/rules/local.rules
alert tcp any any -> any 80 (msg:"HTTP traffic detected"; sid:1;)
alert tcp any any -> any 443 (msg:"HTTPS traffic detected"; sid:2;)
```

4. **Test the setup**:
```bash
sudo ids -c /etc/ids/ids.yaml
```

## Configuration

### Main Configuration File
The main configuration file uses YAML format and is organized into sections:

```yaml
ids:
  version: "1.0"
  
  capture:
    interface: "eth0"              # Network interface to monitor
    buffer_size: 65536            # Packet buffer size
    timeout_ms: 1000              # Capture timeout in milliseconds
    snaplen: 65535                # Maximum bytes per packet
    promiscuous: true             # Enable promiscuous mode
    filter: ""                    # BPF filter expression (optional)
    
  protocols:
    enabled:
      - ethernet
      - ipv4
      - tcp
      - udp
      - icmp
    plugins_path: "/usr/local/lib/ids/plugins"
    
  logging:
    level: "INFO"                 # DEBUG, INFO, WARNING, ERROR, ALERT
    format: "tcpdump"             # tcpdump, json, csv
    output: "console"             # console, file, syslog
    file_path: "/var/log/ids.log"
    max_file_size: 10485760       # 10MB
    max_files: 10                 # Number of rotated files
    enable_packet_dump: true
    enable_hex_dump: true
    
  rules:
    rule_files:
      - "/etc/ids/rules/local.rules"
      - "/etc/ids/rules/community.rules"
    auto_reload: true
    reload_interval: 300          # seconds
    
  performance:
    worker_threads: 4
    queue_size: 10000
    batch_size: 100
    cpu_affinity: true
```

### Configuration Sections

#### Capture Configuration
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| interface | string | "eth0" | Network interface to monitor |
| buffer_size | integer | 65536 | Kernel buffer size for packets |
| timeout_ms | integer | 1000 | Read timeout in milliseconds |
| snaplen | integer | 65535 | Maximum bytes to capture per packet |
| promiscuous | boolean | true | Enable promiscuous mode |
| filter | string | "" | BPF filter expression |

#### Protocol Configuration
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| enabled | array | [ethernet, ipv4, tcp, udp, icmp] | Enabled protocol parsers |
| plugins_path | string | "/usr/local/lib/ids/plugins" | Path to protocol plugins |

#### Logging Configuration
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| level | string | "INFO" | Minimum log level (DEBUG, INFO, WARNING, ERROR, ALERT) |
| format | string | "tcpdump" | Log format (tcpdump, json, csv) |
| output | string | "console" | Output destination (console, file, syslog) |
| file_path | string | "/var/log/ids.log" | Log file path |
| max_file_size | integer | 10485760 | Maximum log file size in bytes |
| max_files | integer | 10 | Number of rotated log files |
| enable_packet_dump | boolean | true | Include packet data in logs |
| enable_hex_dump | boolean | true | Include hex dump in logs |

#### Rule Configuration
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| rule_files | array | [] | List of rule files to load |
| auto_reload | boolean | true | Automatically reload rules when files change |
| reload_interval | integer | 300 | Rule reload check interval in seconds |

#### Performance Configuration
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| worker_threads | integer | 4 | Number of worker threads |
| queue_size | integer | 10000 | Event queue size |
| batch_size | integer | 100 | Packet batch size |
| cpu_affinity | boolean | true | Enable CPU affinity for threads |

### Environment Variables
```bash
# Set configuration file path
export MINIIDS_CONFIG=/path/to/config.yaml

# Set log level
export MINIIDS_LOG_LEVEL=DEBUG

# Set interface
export MINIIDS_INTERFACE=eth0

# Enable debug mode
export MINIIDS_DEBUG=1
```

## Rule Management

### Rule Syntax
IDS uses a Snort-like rule syntax:

```
action protocol src_ip src_port -> dst_ip dst_port (options)
```

#### Actions
- `alert` - Generate alert and log
- `log` - Log only
- `pass` - Allow packet
- `drop` - Drop packet (requires firewall integration)
- `reject` - Reject packet (requires firewall integration)

#### Protocols
- `ip` - Any IP protocol
- `tcp` - TCP protocol
- `udp` - UDP protocol
- `icmp` - ICMP protocol

#### IP Addresses
- `any` - Any IP address
- `192.168.1.0/24` - CIDR notation
- `192.168.1.1` - Single IP
- `[$HOME_NET]` - Variable (defined in configuration)

#### Ports
- `any` - Any port
- `80` - Single port
- `1:1024` - Port range
- `[80,443,8080]` - Port list

#### Rule Options
- `msg:"message"` - Alert message
- `sid:1` - Rule ID (required)
- `content:"pattern"` - Content matching
- `depth:10` - Search depth
- `offset:5` - Search offset
- `nocase` - Case-insensitive matching
- `pcre:"/regex/"` - Regular expression matching

### Rule Examples

#### Basic Detection Rules
```bash
# Detect HTTP traffic
alert tcp any any -> any 80 (msg:"HTTP traffic detected"; sid:1;)

# Detect HTTPS traffic
alert tcp any any -> any 443 (msg:"HTTPS traffic detected"; sid:2;)

# Detect SSH traffic
alert tcp any any -> any 22 (msg:"SSH traffic detected"; sid:3;)

# Detect DNS queries
alert udp any any -> any 53 (msg:"DNS query detected"; sid:4;)
```

#### Content-based Rules
```bash
# Detect SQL injection attempts
alert tcp any any -> any 80 (msg:"SQL injection attempt"; content:"SELECT"; nocase; sid:100;)
alert tcp any any -> any 80 (msg:"SQL injection attempt"; content:"DROP TABLE"; nocase; sid:101;)

# Detect XSS attempts
alert tcp any any -> any 80 (msg:"XSS attempt"; content:"<script>"; nocase; sid:102;)

# Detect directory traversal
alert tcp any any -> any 80 (msg:"Directory traversal attempt"; content:"../"; sid:103;)
```

#### Advanced Rules
```bash
# Detect port scanning
alert tcp any any -> any any (msg:"Port scan detected"; flags:S; threshold:type both,track by_src,count 10,seconds 60; sid:200;)

# Detect suspicious user agents
alert tcp any any -> any 80 (msg:"Suspicious user agent"; content:"User-Agent|3a|"; content:"sqlmap"; nocase; sid:201;)

# Detect binary downloads
alert tcp any any -> any 80 (msg:"Binary download detected"; content:"Content-Type|3a 20|application/octet-stream"; nocase; sid:202;)
```

### Rule Organization

#### Directory Structure
```
/etc/ids/rules/
├── local.rules          # Local custom rules
├── community.rules      # Community rules
├── emerging-threats.rules  # Emerging threats
├── malware.rules        # Malware detection
├── exploit.rules        # Exploit detection
└── policy.rules         # Policy violations
```

#### Rule Categories
- **local.rules** - Site-specific rules
- **community.rules** - General community rules
- **emerging-threats.rules** - New threats
- **malware.rules** - Malware detection
- **exploit.rules** - Exploit detection
- **policy.rules** - Policy violations

### Rule Testing

#### Test Individual Rules
```bash
# Test rule syntax
ids --test-rule "alert tcp any any -> any 80 (msg:'Test'; sid:1;)"

# Test rule file
ids --test-rules /etc/ids/rules/local.rules

# Validate all rules
ids --validate-rules
```

#### Rule Performance Testing
```bash
# Test rule performance
ids --benchmark-rules --duration 60

# Profile rule matching
ids --profile-rules --pcap-file traffic.pcap
```

## Logging and Monitoring

### Log Formats

#### Tcpdump Format
```
15:30:45.123456 IP 192.168.1.100.54321 > 192.168.1.1.80: Flags [S], seq 123456, win 65535, length 0
    0x0000:  4500 003c 1234 4000 4006 1234 c0a8 0164
    0x0010:  c0a8 0101 d431 0050 1234 5678 0000 0000
```

#### JSON Format
```json
{
  "timestamp": "2023-12-01T15:30:45.123456",
  "level": "ALERT",
  "source": "rule_engine",
  "message": "Suspicious activity detected",
  "packet": {
    "length": 60,
    "protocols": ["Ethernet", "IPv4", "TCP"],
    "src_ip": "192.168.1.100",
    "dst_ip": "192.168.1.1",
    "src_port": 54321,
    "dst_port": 80
  },
  "rule": {
    "id": "100",
    "message": "SQL injection attempt"
  }
}
```

#### CSV Format
```csv
timestamp,level,source,message,src_ip,dst_ip,src_port,dst_port,protocol
2023-12-01T15:30:45.123456,ALERT,rule_engine,SQL injection attempt,192.168.1.100,192.168.1.1,54321,80,TCP
```

### Log Management

#### Log Rotation
Logs are automatically rotated based on size and count settings:
```yaml
logging:
  max_file_size: 10485760  # 10MB
  max_files: 10            # Keep 10 rotated files
```

#### Log Analysis
```bash
# View real-time logs
tail -f /var/log/ids.log

# Search for alerts
grep "ALERT" /var/log/ids.log

# Filter by rule ID
grep "sid:100" /var/log/ids.log

# Count alerts by type
grep "ALERT" /var/log/ids.log | cut -d' ' -f5 | sort | uniq -c

# Extract unique source IPs
grep "ALERT" /var/log/ids.log | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq
```

### Monitoring Integration

#### Syslog Integration
```yaml
logging:
  output: "syslog"
  syslog_facility: "local0"
```

#### External Monitoring
```bash
# Send alerts to SIEM
tail -f /var/log/ids.log | grep "ALERT" | while read line; do
    curl -X POST -d "$line" http://siem.example.com/api/alerts
done

# Email alerts
tail -f /var/log/ids.log | grep "ALERT" | while read line; do
    echo "$line" | mail -s "IDS Alert" security@example.com
done
```

## Performance Tuning

### System Optimization

#### Kernel Parameters
```bash
# Increase network buffers
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.netdev_max_backlog = 5000' >> /etc/sysctl.conf

# Apply changes
sysctl -p
```

#### CPU Affinity
```yaml
performance:
  cpu_affinity: true
  worker_threads: 4  # Match number of CPU cores
```

#### Memory Optimization
```yaml
capture:
  buffer_size: 131072  # Increase for high traffic
  snaplen: 1500       # Reduce for lower memory usage

performance:
  queue_size: 20000   # Increase queue size
  batch_size: 200     # Increase batch size
```

### Rule Optimization

#### Performance Guidelines
1. **Order rules by frequency** - Most common rules first
2. **Use specific protocols** - Avoid "ip" when possible
3. **Limit content searches** - Use depth and offset
4. **Avoid expensive options** - Use simple content matches
5. **Group similar rules** - Combine related detections

#### Rule Profiling
```bash
# Enable rule profiling
ids --profile-rules --pcap-file test.pcap

# Analyze rule performance
ids --analyze-performance --duration 300
```

### Network Optimization

#### Interface Tuning
```bash
# Increase ring buffer
ethtool -G eth0 rx 4096 tx 4096

# Enable offloading features
ethtool -K eth0 gro on gso on tso on

# Set interrupt affinity
echo 2 > /proc/irq/24/smp_affinity
```

#### Traffic Filtering
```bash
# Use BPF filters to reduce traffic
capture:
  filter: "not port 22 and not port 53"
```

## Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Error: "Permission denied opening capture device"
# Solution: Run with sudo
sudo ids -c config.yaml
```

#### Interface Not Found
```bash
# Error: "Interface eth0 not found"
# Solution: Check available interfaces
ip link show
# Update configuration with correct interface
```

#### High CPU Usage
```yaml
# Solution: Reduce processing load
performance:
  worker_threads: 2  # Reduce threads
  batch_size: 50     # Reduce batch size

rules:
  # Disable expensive rules
  rule_files:
    - "/etc/ids/rules/local.rules"
    # - "/etc/ids/rules/community.rules"
```

#### Memory Issues
```yaml
# Solution: Reduce memory usage
capture:
  buffer_size: 32768  # Reduce buffer size
  snaplen: 512        # Reduce packet capture size

performance:
  queue_size: 5000    # Reduce queue size
```

#### No Alerts Generated
```bash
# Check if rules are loaded
ids --validate-rules

# Test with known traffic
# Generate test traffic
curl http://example.com

# Check logs
tail -f /var/log/ids.log

# Enable debug logging
logging:
  level: "DEBUG"
```

### Debug Mode

#### Enable Debug Logging
```bash
# Run in debug mode
ids -c config.yaml --debug

# Or set environment variable
export MINIIDS_DEBUG=1
ids -c config.yaml
```

#### Verbose Output
```bash
# Show detailed packet information
ids -c config.yaml --verbose

# Show rule evaluation
ids -c config.yaml --debug-rules
```

### Performance Debugging

#### System Resources
```bash
# Monitor CPU usage
top -p $(pidof ids)

# Monitor memory usage
ps aux | grep ids

# Monitor network interface
iftop -i eth0

# Monitor packet drops
netstat -i
```

#### Packet Capture Statistics
```bash
# Get capture statistics
kill -USR1 $(pidof ids)

# View statistics in logs
grep "STATS" /var/log/ids.log
```

### Log Analysis

#### Common Log Messages
```
[INFO] Capture started on interface eth0
[WARNING] High packet drop rate detected: 5%
[ERROR] Rule file not found: /etc/ids/rules/local.rules
[ALERT] SQL injection attempt detected from 192.168.1.100
```

#### Debug Log Messages
```
[DEBUG] Parsed Ethernet header
[DEBUG] Parsed IPv4 header: src=192.168.1.100 dst=192.168.1.1
[DEBUG] Parsed TCP header: sport=54321 dport=80 flags=S
[DEBUG] Rule evaluation: 10 rules checked, 1 matched
```

## Advanced Usage

### Custom Protocol Plugins

#### Plugin Development
```cpp
#include <ids/protocol/protocol_interface.h>

class CustomProtocolPlugin : public IProtocolPlugin {
public:
    std::string getName() const override { return "CustomProtocol"; }
    ProtocolLayer getLayer() const override { return ProtocolLayer::APPLICATION_LAYER; }
    int getPriority() const override { return 100; }
    
    bool canParse(const Packet& packet, int offset) override {
        // Check if packet contains custom protocol
        if (offset + 4 > packet.length) return false;
        return packet.data[offset] == 0xFF && packet.data[offset + 1] == 0xAA;
    }
    
    std::shared_ptr<ProtocolData> parse(const Packet& packet, int offset) override {
        auto data = std::make_shared<CustomProtocolData>();
        // Parse custom protocol
        return data;
    }
};
```

#### Plugin Registration
```cpp
// Register plugin
ProtocolManager::getInstance().registerPlugin(
    std::make_unique<CustomProtocolPlugin>()
);
```

### Custom Log Formatters

#### Formatter Development
```cpp
#include <ids/log/log_interface.h>

class CustomFormatter : public ILogFormatter {
public:
    std::string format(const LogMessage& message) override {
        std::stringstream ss;
        ss << "[" << message.timestamp_sec << "] "
           << "[" << message.level << "] "
           << message.message;
        return ss.str();
    }
    
    std::string getName() const override { return "custom"; }
};
```

### Integration Examples

#### SIEM Integration
```python
#!/usr/bin/env python3
import json
import syslog
import requests

def process_ids_log(log_line):
    try:
        # Parse log line
        if "ALERT" in log_line:
            # Extract relevant information
            alert_data = {
                "timestamp": extract_timestamp(log_line),
                "severity": "high",
                "source_ip": extract_source_ip(log_line),
                "dest_ip": extract_dest_ip(log_line),
                "rule_id": extract_rule_id(log_line),
                "message": extract_message(log_line)
            }
            
            # Send to SIEM
            response = requests.post(
                "https://siem.example.com/api/alerts",
                json=alert_data,
                headers={"Authorization": "Bearer TOKEN"}
            )
            
            # Log to syslog
            syslog.syslog(syslog.LOG_ALERT, json.dumps(alert_data))
            
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR, f"Error processing log: {e}")

# Monitor log file
with open("/var/log/ids.log", "r") as f:
    while True:
        line = f.readline()
        if line:
            process_ids_log(line)
```

#### Automated Response
```bash
#!/bin/bash
# Block suspicious IPs automatically

tail -f /var/log/ids.log | while read line; do
    if echo "$line" | grep -q "ALERT.*Port scan detected"; then
        # Extract source IP
        src_ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        
        # Block IP with iptables
        iptables -A INPUT -s "$src_ip" -j DROP
        
        # Log action
        logger "Blocked suspicious IP: $src_ip"
        
        # Send notification
        echo "Blocked IP: $src_ip" | mail -s "IDS Auto-block" admin@example.com
    fi
done
```

### High Availability Setup

#### Multiple Instance Configuration
```yaml
# Instance 1 - External traffic
capture:
  interface: "eth1"
  
logging:
  file_path: "/var/log/ids-external.log"

# Instance 2 - Internal traffic  
capture:
  interface: "eth2"
  
logging:
  file_path: "/var/log/ids-internal.log"
```

#### Load Balancing
```bash
# Run multiple instances for different subnets
ids -c external.yaml --instance external
ids -c internal.yaml --instance internal
ids -c dmz.yaml --instance dmz
```

### Performance Monitoring

#### Metrics Collection
```bash
# Collect performance metrics
while true; do
    # Get process stats
    pid=$(pidof ids)
    if [ -n "$pid" ]; then
        cpu=$(ps -p $pid -o %cpu --no-headers)
        mem=$(ps -p $pid -o %mem --no-headers)
        rss=$(ps -p $pid -o rss --no-headers)
        
        # Get packet stats
        packets=$(grep "packets_processed" /var/log/ids.log | tail -1 | awk '{print $2}')
        drops=$(grep "packets_dropped" /var/log/ids.log | tail -1 | awk '{print $2}')
        
        # Send to monitoring system
        curl -X POST http://monitoring.example.com/metrics \
            -d "cpu=$cpu&mem=$mem&rss=$rss&packets=$packets&drops=$drops"
    fi
    
    sleep 60
done
```

#### Health Checks
```bash
#!/bin/bash
# Health check script

# Check if process is running
if ! pgrep ids > /dev/null; then
    echo "CRITICAL: IDS process not running"
    exit 2
fi

# Check if capturing packets
if ! tail -n 100 /var/log/ids.log | grep -q "packet"; then
    echo "WARNING: No recent packet activity"
    exit 1
fi

# Check packet drop rate
drops=$(grep "packets_dropped" /var/log/ids.log | tail -1 | awk '{print $2}')
if [ "$drops" -gt 1000 ]; then
    echo "WARNING: High packet drop rate: $drops"
    exit 1
fi

echo "OK: IDS running normally"
exit 0
```

This comprehensive user guide provides detailed information for installing, configuring, and using IDS effectively. The guide covers everything from basic setup to advanced usage scenarios, troubleshooting, and performance optimization.