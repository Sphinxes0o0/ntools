# TCP Packet and Rule Matching Implementation Design

## Overview
This document outlines the implementation plan for enhancing TCP packet parsing and rule matching functionality based on the layered architecture design.

## Current State Analysis

### Existing TCP Parser ([`tcp_parser.h`](include/parsing/tcp_parser.h), [`tcp_parser.cpp`](src/parsing/tcp_parser.cpp))
[text](../tests)- ✅ Parses TCP headers and extracts port numbers, flags, sequence numbers
- ✅ Implements protocol detection and validation
- ✅ Returns structured parsing results with detailed findings

### Current Rule Matcher ([`rule_matcher.h`](include/parsing/rule_matcher.h), [`rule_matcher.cpp`](src/parsing/rule_matcher.cpp))
- ❌ Uses hardcoded IP addresses and ports (simulated data)
- ❌ Basic protocol detection based on packet size
- ❌ Limited TCP-specific rule matching capabilities

## Implementation Strategy

### Phase 1: Packet Information Extraction

#### 1.1 Create PacketInfoExtractor Class
```cpp
// include/parsing/packet_info_extractor.h
class PacketInfoExtractor {
public:
    PacketInfo extractInfo(const Packet& packet);
    bool isTCP(const Packet& packet) const;
    std::string getSourceIP(const Packet& packet) const;
    std::string getDestinationIP(const Packet& packet) const;
    uint16_t getSourcePort(const Packet& packet) const;
    uint16_t getDestinationPort(const Packet& packet) const;
    TCPFlags getTCPFlags(const Packet& packet) const;
    RuleProtocol getProtocol(const Packet& packet) const;
    
private:
    TCPParser tcp_parser_;
    // Helper methods for IP extraction
    std::string extractIPv4Address(const uint8_t* data, size_t offset) const;
    uint8_t getIPProtocol(const Packet& packet) const;
    size_t getIPHeaderLength(const Packet& packet) const;
};
```

#### 1.2 PacketInfo Data Structure
```cpp
struct PacketInfo {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    RuleProtocol protocol;
    TCPFlags tcp_flags;
    uint32_t seq_number;
    uint32_t ack_number;
    uint16_t window_size;
    const Packet* raw_packet;
    
    PacketInfo() : src_port(0), dst_port(0), protocol(RuleProtocol::ANY),
                  seq_number(0), ack_number(0), window_size(0), raw_packet(nullptr) {}
};
```

### Phase 2: Enhanced Rule Matcher

#### 2.1 Enhanced RuleMatcher Interface
```cpp
class EnhancedRuleMatcher : public IRuleMatcher {
public:
    bool initialize(const Config& config) override;
    std::vector<RuleMatch> matchPacket(const Packet& packet) override;
    void addRules(const std::vector<Rule>& rules) override;
    
    // TCP-specific matching methods
    bool matchTCPFlags(const Rule& rule, const TCPFlags& packet_flags);
    bool matchTCPContent(const Rule& rule, const Packet& packet);
    bool matchTCPFlow(const Rule& rule, const PacketInfo& packet_info);
    
private:
    PacketInfoExtractor extractor_;
    std::vector<Rule> rules_;
    std::unordered_map<std::string, uint64_t> stats_;
    
    // Enhanced matching methods
    bool checkProtocol(const PacketInfo& packet_info, const Rule& rule);
    bool checkIPAddress(const PacketInfo& packet_info, const Rule& rule);
    bool checkPort(const PacketInfo& packet_info, const Rule& rule);
    bool checkTCPOptions(const PacketInfo& packet_info, const Rule& rule, RuleMatch& match);
};
```

### Phase 3: TCP-Specific Rule Matching

#### 3.1 TCP Flag Matching
```cpp
enum class TCPFlagCondition {
    ANY,
    SYN_ONLY,
    SYN_ACK,
    ACK_ONLY,
    FIN,
    RST,
    URGENT,
    PUSH
};

struct TCPRuleOptions {
    std::vector<TCPFlagCondition> flag_conditions;
    bool established_only;
    uint32_t min_window_size;
    uint32_t max_window_size;
    std::string content_pattern;
    bool content_case_sensitive;
    
    TCPRuleOptions() : established_only(false), min_window_size(0),
                      max_window_size(65535), content_case_sensitive(true) {}
};
```

#### 3.2 Flow State Tracking
```cpp
class TCPFlowTracker {
public:
    struct ConnectionState {
        std::string src_ip;
        std::string dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        bool syn_sent;
        bool syn_ack_received;
        bool established;
        std::chrono::steady_clock::time_point last_activity;
    };
    
    void updateConnectionState(const PacketInfo& packet_info);
    bool isEstablished(const PacketInfo& packet_info) const;
    void cleanupExpiredConnections();
    
private:
    std::unordered_map<std::string, ConnectionState> connections_;
    std::chrono::seconds connection_timeout_;
};
```

## Implementation Steps

### Step 1: Create PacketInfoExtractor
1. Implement IP address extraction from packet data
2. Extract TCP-specific information using existing TCPParser
3. Handle packet validation and error cases
4. Add unit tests for extraction accuracy

### Step 2: Enhance RuleMatcher
1. Replace simulated data with real packet extraction
2. Implement protocol-specific matching logic
3. Add TCP flag and flow state matching
4. Update threshold tracking with real packet data

### Step 3: Add TCP-Specific Rule Options
1. Extend rule parsing for TCP-specific options
2. Implement TCP flag condition matching
3. Add content pattern matching in TCP payload
4. Implement flow state-based matching

### Step 4: Integration and Testing
1. Integrate with existing IDS processing pipeline
2. Create comprehensive test cases
3. Performance optimization
4. Validation against real network traffic

## Key Interfaces and Data Structures

### Enhanced Packet Processing
```cpp
// Main processing flow in IDS::processPacket
void IDS::processPacket(const Packet& packet) {
    PacketInfo packet_info = extractor_.extractInfo(packet);
    std::vector<RuleMatch> matches = rule_matcher_.matchPacket(packet, packet_info);
    
    for (const auto& match : matches) {
        handleAlert(match, packet_info);
    }
}
```

### TCP-Specific Rule Format
```
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 \
    (msg:"TCP SYN flood attempt"; flags:S; threshold:type both, track by_src, count 100, seconds 10; sid:1000001;)

alert tcp any any -> any any \
    (msg:"TCP Christmas tree scan"; flags:FPU; sid:1000002;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any \
    (msg:"Established connection data exfiltration"; flow:established; content:"sensitive_data"; sid:1000003;)
```

## Performance Considerations

### Optimization Strategies
1. **Pre-compilation**: Compile rule patterns during rule loading
2. **Early Termination**: Check most common conditions first
3. **Connection Caching**: Cache connection states for flow matching
4. **Pattern Matching**: Use efficient string search algorithms for content matching

### Memory Management
1. **Zero-copy**: Use packet offsets instead of copying data
2. **Object Pooling**: Reuse PacketInfo objects
3. **Efficient Data Structures**: Use appropriate containers for rule storage

## Testing Strategy

### Unit Tests
- PacketInfoExtractor accuracy tests
- TCP flag matching validation
- Flow state tracking correctness
- Rule matching edge cases

### Integration Tests
- End-to-end packet processing
- Real packet capture analysis
- Performance under load
- Memory usage validation

### Validation Tests
- Comparison with known IDS systems
- Real attack pattern detection
- False positive rate measurement

## Integration with Existing Architecture

### Data Flow
```
Network Interface → Capture Layer → PacketInfoExtractor → EnhancedRuleMatcher → Alert Manager
                                                                   ↑
                                                            Rule Parser (TCP-specific rules)
```

### Configuration Updates
```yaml
ids:
  tcp_matching:
    enable_flow_tracking: true
    connection_timeout: 300
    max_connections: 10000
    enable_content_matching: true
    content_match_limit: 1024
```

This implementation plan provides a clear path to enhance TCP packet and rule matching while maintaining compatibility with the existing layered architecture.