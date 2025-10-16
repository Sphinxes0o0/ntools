# IDS Implementation Plan

## Project Structure

```
ids/
├── CMakeLists.txt
├── src/
│   ├── core/
│   │   ├── packet.h
│   │   ├── packet.cpp
│   │   ├── event.h
│   │   ├── event.cpp
│   │   ├── config.h
│   │   ├── config.cpp
│   │   ├── exception.h
│   │   └── exception.cpp
│   ├── capture/
│   │   ├── capture_interface.h
│   │   ├── af_packet_capture.h
│   │   ├── af_packet_capture.cpp
│   │   ├── capture_factory.h
│   │   └── capture_factory.cpp
│   ├── protocol/
│   │   ├── protocol_interface.h
│   │   ├── protocol_data.h
│   │   ├── protocol_manager.h
│   │   ├── protocol_manager.cpp
│   │   ├── plugins/
│   │   │   ├── ethernet_plugin.h
│   │   │   ├── ethernet_plugin.cpp
│   │   │   ├── ipv4_plugin.h
│   │   │   ├── ipv4_plugin.cpp
│   │   │   ├── tcp_plugin.h
│   │   │   ├── tcp_plugin.cpp
│   │   │   ├── udp_plugin.h
│   │   │   └── udp_plugin.cpp
│   ├── log/
│   │   ├── log_interface.h
│   │   ├── log_manager.h
│   │   ├── log_manager.cpp
│   │   ├── formatters/
│   │   │   ├── tcpdump_formatter.h
│   │   │   └── tcpdump_formatter.cpp
│   ├── rule/
│   │   ├── rule.h
│   │   ├── rule.cpp
│   │   ├── rule_parser.h
│   │   ├── rule_parser.cpp
│   │   ├── rule_matcher.h
│   │   └── rule_matcher.cpp
│   ├── main.cpp
│   └── ids.cpp
├── include/
│   └── ids/
│       ├── common.h
│       └── export.h
├── plugins/
│   └── protocols/
├── tests/
│   ├── test_main.cpp
│   ├── test_capture.cpp
│   ├── test_protocol.cpp
│   ├── test_log.cpp
│   └── test_rule.cpp
├── config/
│   ├── ids.yaml
│   └── rules/
│       ├── local.rules
│       └── example.rules
├── docs/
│   ├── architecture.md
│   ├── module-specifications.md
│   ├── implementation-plan.md
│   ├── api-reference.md
│   └── user-guide.md
└── scripts/
    ├── build.sh
    ├── run.sh
    └── install.sh
```

## Implementation Phases

### Phase 1: Core Framework (Week 1)
**Objective**: Establish the foundational framework and interfaces

**Tasks**:
1. Set up CMake build system
2. Implement core data structures (Packet, Event, Config)
3. Create exception handling system
4. Implement basic logging infrastructure
5. Create module interface base classes

**Deliverables**:
- Working build system
- Core framework with basic functionality
- Unit tests for core components

### Phase 2: Traffic Capture Module (Week 2)
**Objective**: Implement packet capture with AF_PACKET

**Tasks**:
1. Implement AF_PACKET capture interface
2. Create packet buffer management
3. Implement capture configuration
4. Add basic packet filtering support
5. Create capture factory for extensibility

**Deliverables**:
- Working packet capture on specified interface
- Configuration-driven capture settings
- Basic performance metrics

### Phase 3: Protocol Parsing Module (Week 3-4)
**Objective**: Implement layered protocol parsing with plugin architecture

**Tasks**:
1. Implement protocol plugin interface
2. Create Ethernet protocol parser
3. Implement IPv4 protocol parser
4. Create TCP protocol parser
5. Implement UDP protocol parser
6. Create protocol plugin manager
7. Add ICMP protocol parser

**Deliverables**:
- Multi-layer protocol parsing
- Plugin system for extensibility
- Protocol data structures
- Comprehensive protocol support

### Phase 4: Logging Module (Week 5)
**Objective**: Implement tcpdump-compatible logging

**Tasks**:
1. Create log formatter interface
2. Implement tcpdump-style formatter
3. Add multiple output support (console, file)
4. Implement log rotation and management
5. Create packet hex dump functionality

**Deliverables**:
- Tcpdump-compatible output
- Configurable logging levels
- Multiple output formats
- Log file management

### Phase 5: Rule Engine Module (Week 6)
**Objective**: Implement rule parsing and matching

**Tasks**:
1. Create rule data structures
2. Implement rule parser
3. Create rule matcher engine
4. Add rule action execution
5. Implement rule file management

**Deliverables**:
- Snort-like rule syntax support
- Rule matching engine
- Rule file management
- Action execution system

### Phase 6: Integration and Testing (Week 7)
**Objective**: Integrate all modules and comprehensive testing

**Tasks**:
1. Integrate all modules
2. Create main application loop
3. Implement event management
4. Add comprehensive unit tests
5. Create integration tests
6. Performance testing and optimization

**Deliverables**:
- Fully integrated IDS system
- Comprehensive test suite
- Performance benchmarks
- Documentation updates

## Detailed Implementation Steps

### Step 1: CMake Build System
```cmake
cmake_minimum_required(VERSION 3.10)
project(IDS VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find packages
find_package(Threads REQUIRED)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)

# Source files
file(GLOB_RECURSE SOURCES 
    src/*.cpp
    src/capture/*.cpp
    src/protocol/*.cpp
    src/log/*.cpp
    src/rule/*.cpp
)

# Create executable
add_executable(ids ${SOURCES})

# Link libraries
target_link_libraries(ids 
    Threads::Threads
)

# Compiler flags
target_compile_options(ids PRIVATE 
    -Wall -Wextra -Wpedantic -O2
)

# Install targets
install(TARGETS ids DESTINATION bin)
install(DIRECTORY config/ DESTINATION /etc/ids)
install(DIRECTORY docs/ DESTINATION share/doc/ids)
```

### Step 2: Core Packet Structure
```cpp
// src/core/packet.h
#pragma once

#include <cstdint>
#include <vector>
#include <memory>

namespace ids {

struct Packet {
    std::vector<uint8_t> data;
    size_t length;
    uint32_t capture_time_sec;
    uint32_t capture_time_usec;
    uint32_t interface_index;
    uint16_t protocol;
    
    Packet() : length(0), capture_time_sec(0), capture_time_usec(0), 
               interface_index(0), protocol(0) {}
               
    Packet(const uint8_t* raw_data, size_t len) 
        : data(raw_data, raw_data + len), length(len),
          capture_time_sec(0), capture_time_usec(0), 
          interface_index(0), protocol(0) {}
};

} // namespace ids
```

### Step 3: AF_PACKET Implementation
```cpp
// src/capture/af_packet_capture.cpp
#include "af_packet_capture.h"
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

namespace ids {

bool AFPacketCapture::initialize(const CaptureConfig& config) {
    config_ = config;
    buffer_.resize(config.buffer_size);
    
    if (!createSocket()) {
        return false;
    }
    
    if (!bindToInterface()) {
        close(socket_fd_);
        return false;
    }
    
    if (!setSocketOptions()) {
        close(socket_fd_);
        return false;
    }
    
    return true;
}

bool AFPacketCapture::createSocket() {
    socket_fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socket_fd_ == -1) {
        throw CaptureException(ErrorCode::SOCKET_ERROR, 
                              "Failed to create AF_PACKET socket");
    }
    return true;
}

Packet* AFPacketCapture::capturePacket() {
    struct sockaddr_ll addr;
    socklen_t addr_len = sizeof(addr);
    
    ssize_t received = recvfrom(socket_fd_, buffer_.data(), 
                               buffer_.size(), 0,
                               (struct sockaddr*)&addr, &addr_len);
    
    if (received == -1) {
        if (errno == EAGAIN || errno == EINTR) {
            return nullptr; // Timeout or interrupt
        }
        throw CaptureException(ErrorCode::PACKET_CAPTURE_ERROR,
                              "Failed to receive packet");
    }
    
    auto packet = new Packet(buffer_.data(), received);
    packet->interface_index = addr.sll_ifindex;
    packet->protocol = addr.sll_protocol;
    
    // Set timestamp
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    packet->capture_time_sec = tv.tv_sec;
    packet->capture_time_usec = tv.tv_usec;
    
    return packet;
}

} // namespace ids
```

### Step 4: Protocol Plugin System
```cpp
// src/protocol/protocol_interface.h
#pragma once

#include "core/packet.h"
#include <memory>
#include <string>

namespace ids {

enum class ProtocolLayer {
    LINK_LAYER = 1,
    NETWORK_LAYER = 2,
    TRANSPORT_LAYER = 3,
    APPLICATION_LAYER = 4
};

class ProtocolData {
public:
    virtual ~ProtocolData() = default;
    virtual std::string toString() const = 0;
    virtual ProtocolLayer getLayer() const = 0;
    virtual std::string getProtocolName() const = 0;
    
    std::shared_ptr<ProtocolData> next_layer;
    size_t header_length = 0;
    size_t payload_length = 0;
};

class IProtocolPlugin {
public:
    virtual ~IProtocolPlugin() = default;
    virtual bool canParse(const Packet& packet, int offset) = 0;
    virtual std::shared_ptr<ProtocolData> parse(const Packet& packet, int offset) = 0;
    virtual int getPriority() const = 0;
    virtual std::string getName() const = 0;
};

} // namespace ids
```

### Step 5: Tcpdump Formatter
```cpp
// src/log/formatters/tcpdump_formatter.cpp
#include "tcpdump_formatter.h"
#include <iomanip>
#include <sstream>

namespace ids {

std::string TcpdumpFormatter::formatPacket(const Packet& packet,
                                         const std::vector<std::shared_ptr<ProtocolData>>& protocols) {
    std::stringstream ss;
    
    // Format timestamp
    ss << formatTimestamp(packet.capture_time_sec, packet.capture_time_usec) << " ";
    
    // Format protocols
    for (const auto& proto : protocols) {
        ss << proto->toString() << " ";
    }
    
    // Add packet length
    ss << "len " << packet.length;
    
    // Add hex dump if enabled
    if (config_.enable_hex_dump) {
        ss << "\n" << formatHexDump(packet.data.data(), packet.length);
    }
    
    return ss.str();
}

std::string TcpdumpFormatter::formatHexDump(const uint8_t* data, size_t length) {
    std::stringstream ss;
    const size_t bytes_per_line = 16;
    
    for (size_t i = 0; i < length; i += bytes_per_line) {
        // Offset
        ss << std::hex << std::setw(4) << std::setfill('0') << i << "  ";
        
        // Hex bytes
        for (size_t j = 0; j < bytes_per_line && i + j < length; ++j) {
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(data[i + j]) << " ";
            if (j == 7) ss << " ";
        }
        
        // ASCII representation
        ss << " |";
        for (size_t j = 0; j < bytes_per_line && i + j < length; ++j) {
            char c = static_cast<char>(data[i + j]);
            ss << (isprint(c) ? c : '.');
        }
        ss << "|\n";
    }
    
    return ss.str();
}

} // namespace ids
```

### Step 6: Rule Parser
```cpp
// src/rule/rule_parser.cpp
#include "rule_parser.h"
#include <regex>
#include <sstream>

namespace ids {

Rule RuleParser::parseRule(const std::string& rule_text) {
    Rule rule;
    
    // Basic rule format: action protocol src_ip src_port -> dst_ip dst_port (options)
    std::regex rule_regex(R"(^(\w+)\s+(\w+)\s+([^\s]+)\s+([^\s]+)\s+->\s+([^\s]+)\s+([^\s]+)\s*\((.*)\)$)");
    std::smatch match;
    
    if (!std::regex_match(rule_text, match, rule_regex)) {
        throw RuleException(ErrorCode::RULE_PARSE_ERROR,
                           "Invalid rule format: " + rule_text);
    }
    
    // Parse action
    std::string action_str = match[1];
    if (action_str == "alert") rule.action = RuleAction::ALERT;
    else if (action_str == "log") rule.action = RuleAction::LOG;
    else if (action_str == "drop") rule.action = RuleAction::DROP;
    else if (action_str == "pass") rule.action = RuleAction::PASS;
    else if (action_str == "reject") rule.action = RuleAction::REJECT;
    else {
        throw RuleException(ErrorCode::RULE_PARSE_ERROR,
                           "Invalid action: " + action_str);
    }
    
    // Parse protocol and addresses
    rule.protocol = match[2];
    rule.src_ip = match[3];
    rule.src_port = parsePort(match[4]);
    rule.dst_ip = match[5];
    rule.dst_port = parsePort(match[6]);
    
    // Parse options
    std::string options_str = match[7];
    rule.options = parseOptions(options_str);
    
    return rule;
}

std::vector<Rule> RuleParser::parseRuleFile(const std::string& file_path) {
    std::vector<Rule> rules;
    std::ifstream file(file_path);
    
    if (!file.is_open()) {
        throw RuleException(ErrorCode::FILE_NOT_FOUND,
                           "Cannot open rule file: " + file_path);
    }
    
    std::string line;
    while (std::getline(file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;
        
        try {
            Rule rule = parseRule(line);
            rules.push_back(rule);
        } catch (const RuleException& e) {
            // Log error but continue parsing
            std::cerr << "Error parsing rule: " << e.what() << std::endl;
        }
    }
    
    return rules;
}

} // namespace ids
```

## Testing Strategy

### Unit Tests
- Core data structures (Packet, Event, Config)
- Individual protocol parsers
- Rule parsing and matching
- Log formatting
- Exception handling

### Integration Tests
- End-to-end packet processing
- Module interaction testing
- Configuration loading
- Plugin system testing

### Performance Tests
- Packet capture throughput
- Protocol parsing speed
- Rule matching performance
- Memory usage profiling

### Security Tests
- Malformed packet handling
- Rule injection prevention
- Buffer overflow protection
- Resource exhaustion prevention

## Deployment Considerations

### System Requirements
- Linux kernel 3.0+ (for AF_PACKET)
- Root privileges for packet capture
- Sufficient memory for packet buffering
- CPU cores for multi-threading

### Installation
```bash
# Build
mkdir build && cd build
cmake ..
make

# Install
sudo make install

# Configure
sudo cp config/ids.yaml /etc/ids/
sudo cp config/rules/* /etc/ids/rules/

# Run
sudo ids -c /etc/ids/ids.yaml
```

### Performance Tuning
- CPU affinity for capture threads
- NUMA-aware memory allocation
- Interrupt coalescing settings
- Network interface optimization

## Future Enhancements

1. **Advanced Protocols**: HTTP, DNS, SSL/TLS parsing
2. **Machine Learning**: Anomaly detection integration
3. **Clustering**: Distributed IDS deployment
4. **GUI Interface**: Web-based management interface
5. **Cloud Integration**: Cloud-based rule updates
6. **Container Support**: Docker and Kubernetes integration

## 3. Protocol Parsing Enhancement

### 3.1 Current State Analysis
Currently, the TCP parser directly handles Ethernet and IP headers, which violates the principle of layered protocol parsing. This approach leads to code duplication and makes it difficult to extend to other protocols.

The current TCP parser implementation:
1. Checks if the packet contains an Ethernet frame
2. Verifies the EtherType indicates an IPv4 packet
3. Confirms the IP protocol field indicates TCP
4. Parses the TCP header fields

This approach works for basic TCP parsing but has limitations:
- Code duplication across different protocol parsers
- Difficulty in extending to other protocols (UDP, ICMP, etc.)
- Violation of separation of concerns principle
- Harder to test individual protocol layers

### 3.2 Refactoring Plan
1. **Create Ethernet Parser**:
   - Implement Ethernet frame header parsing
   - Extract MAC addresses and EtherType
   - Identify next layer protocol

2. **Create IP Parser**:
   - Implement IPv4 header parsing
   - Extract source and destination IP addresses
   - Identify transport layer protocol (TCP/UDP/ICMP)
   - Calculate header length for payload offset

3. **Refactor TCP Parser**:
   - Modify to only parse TCP segment
   - Remove direct Ethernet and IP header handling
   - Work with parsed IP information

4. **Implement Protocol Manager**:
   - Coordinate layered parsing process
   - Manage parser registration and execution
   - Build complete protocol stack information

### 3.3 Implementation Steps
1. Create Ethernet parser class with appropriate interfaces
2. Create IP parser class with IPv4 support
3. Refactor TCP parser to work in layered fashion
4. Implement protocol manager to coordinate parsing
5. Update IDS core to use new layered parsing approach
6. Test with various packet types to ensure compatibility
