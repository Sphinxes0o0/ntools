# Module Specifications

This document provides detailed specifications for each module in the packet analyzer system.

## 1. Core Module

### 1.1 Overview
The core module is the main entry point and orchestrator for the entire IDS system. It manages the initialization of all other modules, controls the main processing loop, and handles system shutdown.

### 1.2 Responsibilities
- System initialization and configuration loading
- Module coordination and lifecycle management
- Main packet processing loop
- Signal handling for graceful shutdown
- Statistics collection and reporting

### 1.3 Interface Design
```cpp
class IDS {
public:
    IDS();
    ~IDS();
    
    bool initialize(const std::string& config_file);
    bool initialize(const Config& config);
    void run();
    void shutdown();
    bool isRunning() const;
    void handleSignal(int signal);
    
private:
    std::atomic<bool> running_;
    std::atomic<bool> paused_;
    std::atomic<bool> shutdown_called_;
    std::chrono::steady_clock::time_point start_time_;
    Config config_;
    
    // Capture module
    std::unique_ptr<ids::ICaptureModule> capture_module_;
    
    // Protocol parsers
    std::vector<std::unique_ptr<ids::ProtocolParser>> protocol_parsers_;

    // Rule components
    ids::RuleMatcher rule_matcher_;
    ids::RuleParser rule_parser_;

    bool initializeModules();
    void processingLoop();
    void processPacket(const Packet& packet);
    
    // Protocol parsing functions
    void initializeProtocolParsers();
    std::vector<ids::ParsingResult> parsePacket(const Packet& packet);
};
```

### 1.4 Implementation Requirements
- Must handle system signals gracefully (SIGINT, SIGTERM)
- Must provide clean shutdown mechanism
- Must support configuration reloading
- Must collect and report system statistics

## 2. Capture Module

### 2.1 Overview
The capture module is responsible for capturing raw network packets from network interfaces. It provides a standardized interface that can be implemented with different capture mechanisms.

### 2.2 Design Principles
- Support multiple capture backends (AF_PACKET, libpcap, eBPF)
- Provide unified interface for packet capture
- Handle capture errors gracefully
- Support configuration-based initialization

### 2.3 Interface Design
```cpp
class ICaptureModule {
public:
    virtual bool initialize(const CaptureConfig& config) = 0;
    virtual std::unique_ptr<Packet> capturePacket() = 0;
    virtual void shutdown() = 0;
    virtual ~ICaptureModule() = default;
};
```

### 2.4 Implementation Requirements
- Must handle network interface binding
- Must support promiscuous mode configuration
- Must provide packet metadata (timestamps, interface info)
- Must handle capture buffer management
- Must support packet filtering

## 3. Protocol Parsing Module

### 3.1 Overview
The protocol parsing module is responsible for dissecting network packets according to the TCP/IP protocol stack. It follows a layered approach where each protocol layer is parsed independently, and the results are combined to form a complete protocol stack view.

### 3.2 Design Principles
1. **Layered Parsing**: Each protocol layer is parsed by a dedicated parser
2. **Modularity**: Each parser is implemented as a separate class
3. **Extensibility**: New protocol parsers can be added without modifying existing code
4. **Independence**: Each parser only handles its specific protocol layer
5. **Consistency**: All parsers implement the same interface for uniform handling

### 3.3 Current Implementation Status
The current implementation uses a simplified approach where parsers directly work on raw packets. 
Each parser is responsible for identifying and parsing its specific protocol within the packet.

For example, the TCP parser currently:
1. Checks if the packet contains an Ethernet frame
2. Verifies the EtherType indicates an IPv4 packet
3. Confirms the IP protocol field indicates TCP
4. Parses the TCP header fields

This approach will be refactored to follow a strict layered parsing model where:
1. Ethernet parser extracts Ethernet frame information
2. IP parser extracts IP header information
3. TCP parser works with parsed IP information to extract TCP fields

### 3.4 Future Layered Architecture
1. **Link Layer (Ethernet)**:
   - Parse Ethernet frame headers
   - Extract source and destination MAC addresses
   - Identify EtherType for next layer protocol

2. **Network Layer (IP)**:
   - Parse IP headers based on EtherType
   - Extract source and destination IP addresses
   - Identify transport layer protocol
   - Calculate header length and payload offset

3. **Transport Layer (TCP/UDP)**:
   - Parse transport layer headers
   - Extract source and destination ports
   - Parse protocol-specific fields (TCP flags, sequence numbers, etc.)

4. **Application Layer (Optional)**:
   - Parse application layer data when available
   - Handle protocol-specific parsing (HTTP headers, DNS records, etc.)

### 3.5 Interface Design
```cpp
class IProtocolParser {
public:
    virtual ProtocolType getProtocolType() const = 0;
    virtual bool canParse(const Packet& packet) const = 0;
    virtual ParsingResult parse(const Packet& packet) const = 0;
    virtual ~IProtocolParser() = default;
};
```

### 3.6 Implementation Requirements
1. Each parser must only access its own protocol layer data
2. Parsers must not modify the original packet data
3. Parsers should handle malformed packets gracefully
4. Parsing results should include all relevant protocol information
5. Parsers must be thread-safe if used in multi-threaded environments

## 4. Rule Engine Module

### 4.1 Overview
The rule engine module is responsible for parsing rule definitions and matching them against parsed packet data. It provides alerting capabilities when rules are matched.

### 4.2 Design Principles
- Support Snort-like rule syntax
- Provide efficient rule matching algorithms
- Support rule categorization and grouping
- Enable dynamic rule reloading

### 4.3 Interface Design
```cpp
class IRuleMatcher {
public:
    virtual bool initialize(const Config& config) = 0;
    virtual std::vector<RuleMatch> matchPacket(const PacketInfo& packet_info) = 0;
    virtual void addRules(const std::vector<Rule>& rules) = 0;
    virtual ~IRuleMatcher() = default;
};
```

### 4.4 Implementation Requirements
- Must support rule parsing from files
- Must provide efficient pattern matching
- Must handle rule compilation and optimization
- Must support rule metadata (SID, revision, classification)
- Must provide alert generation capabilities

## 5. Logging Module

### 5.1 Overview
The logging module is responsible for recording system events, packet information, and alerts. It supports multiple output formats and destinations.

### 5.2 Design Principles
- Support multiple log levels (DEBUG, INFO, WARN, ERROR)
- Provide configurable output formats
- Support multiple output destinations (console, file, network)
- Ensure thread-safe logging operations

### 5.3 Interface Design
```cpp
class ILogger {
public:
    virtual void log(LogLevel level, const std::string& message) = 0;
    virtual void debug(const std::string& message) = 0;
    virtual void info(const std::string& message) = 0;
    virtual void warn(const std::string& message) = 0;
    virtual void error(const std::string& message) = 0;
    virtual ~ILogger() = default;
};
```

### 5.4 Implementation Requirements
- Must support tcpdump-style packet output
- Must provide configurable log rotation
- Must handle concurrent logging from multiple threads
- Must support structured logging formats
- Must provide performance-efficient logging operations