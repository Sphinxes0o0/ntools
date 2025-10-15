# IDS Module Specifications

## Core Framework Interfaces

### Packet Structure
```cpp
struct Packet {
    uint8_t* data;          // Raw packet data
    size_t length;          // Packet length in bytes
    uint32_t capture_time;  // Capture timestamp (seconds)
    uint32_t capture_usec;  // Capture timestamp (microseconds)
    uint32_t interface_index; // Network interface index
    uint16_t protocol;      // Link layer protocol type
};
```

### Event System
```cpp
enum class EventType {
    PACKET_CAPTURED,
    PROTOCOL_DETECTED,
    RULE_MATCHED,
    ALERT_GENERATED,
    ERROR_OCCURRED
};

struct Event {
    EventType type;
    uint32_t timestamp;
    std::string source;
    std::shared_ptr<void> data;
};
```

## Traffic Capture Module Specification

### CaptureConfig Structure
```cpp
struct CaptureConfig {
    std::string interface;      // Network interface name
    size_t buffer_size;         // Capture buffer size
    int timeout_ms;             // Capture timeout in milliseconds
    int snaplen;               // Maximum bytes per packet
    bool promiscuous;          // Promiscuous mode
    std::string filter;        // BPF filter expression
};
```

### AF_PACKET Implementation
```cpp
class AFPacketCapture : public ICaptureModule {
private:
    int socket_fd_;
    CaptureConfig config_;
    std::vector<uint8_t> buffer_;
    
public:
    bool initialize(const CaptureConfig& config) override;
    Packet* capturePacket() override;
    void shutdown() override;
    
private:
    bool createSocket();
    bool bindToInterface();
    bool setSocketOptions();
};
```

### Extensibility Interface
```cpp
class CaptureFactory {
public:
    static std::unique_ptr<ICaptureModule> create(const std::string& type);
    
    // Future extensions:
    // - LibpcapCapture
    // - EBpfCapture
    // - DPDKCapture
};
```

## Protocol Parsing Module Specification

### Protocol Layer Enumeration
```cpp
enum class ProtocolLayer {
    LINK_LAYER = 1,
    NETWORK_LAYER = 2,
    TRANSPORT_LAYER = 3,
    APPLICATION_LAYER = 4
};
```

### Protocol Data Base Class
```cpp
class ProtocolData {
public:
    virtual ~ProtocolData() = default;
    virtual std::string toString() const = 0;
    virtual ProtocolLayer getLayer() const = 0;
    virtual std::string getProtocolName() const = 0;
    
    std::shared_ptr<ProtocolData> next_layer;
    size_t header_length;
    size_t payload_length;
};
```

### Ethernet Protocol Implementation
```cpp
class EthernetData : public ProtocolData {
public:
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
    
    std::string toString() const override;
    ProtocolLayer getLayer() const override { return ProtocolLayer::LINK_LAYER; }
    std::string getProtocolName() const override { return "Ethernet"; }
};
```

### IP Protocol Implementation
```cpp
class IPv4Data : public ProtocolData {
public:
    uint8_t version;
    uint8_t header_length;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint8_t flags;
    uint16_t fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
    
    std::string toString() const override;
    ProtocolLayer getLayer() const override { return ProtocolLayer::NETWORK_LAYER; }
    std::string getProtocolName() const override { return "IPv4"; }
};
```

### TCP Protocol Implementation
```cpp
class TCPData : public ProtocolData {
public:
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
    
    // TCP flags
    bool fin, syn, rst, psh, ack, urg;
    
    std::string toString() const override;
    ProtocolLayer getLayer() const override { return ProtocolLayer::TRANSPORT_LAYER; }
    std::string getProtocolName() const override { return "TCP"; }
};
```

### Protocol Plugin Manager
```cpp
class ProtocolPluginManager {
private:
    std::vector<std::unique_ptr<IProtocolPlugin>> plugins_;
    
public:
    void registerPlugin(std::unique_ptr<IProtocolPlugin> plugin);
    std::shared_ptr<ProtocolData> parsePacket(const Packet& packet);
    void loadDefaultPlugins();
    
    // Plugin discovery and loading
    void loadPluginsFromDirectory(const std::string& path);
};
```

## Logging Module Specification

### Log Levels
```cpp
enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    ALERT = 4
};
```

### Log Configuration
```cpp
struct LogConfig {
    LogLevel level;
    std::string format;        // "tcpdump", "json", "csv"
    std::string output;        // "console", "file", "syslog"
    std::string file_path;
    bool enable_packet_dump;
    bool enable_hex_dump;
    size_t max_file_size;
    int max_files;
};
```

### Tcpdump-style Formatter
```cpp
class TcpdumpFormatter : public ILogFormatter {
public:
    std::string formatPacket(const Packet& packet, 
                           const std::vector<std::shared_ptr<ProtocolData>>& protocols) override;
    
private:
    std::string formatTimestamp(uint32_t sec, uint32_t usec);
    std::string formatEthernet(const EthernetData& eth);
    std::string formatIPv4(const IPv4Data& ip);
    std::string formatTCP(const TCPData& tcp);
    std::string formatHexDump(const uint8_t* data, size_t length);
};
```

### Log Message Structure
```cpp
struct LogMessage {
    LogLevel level;
    uint32_t timestamp_sec;
    uint32_t timestamp_usec;
    std::string source;
    std::string message;
    std::shared_ptr<Packet> packet;
    std::vector<std::shared_ptr<ProtocolData>> protocols;
    std::unordered_map<std::string, std::string> metadata;
};
```

## Rule Engine Module Specification

### Rule Structure
```cpp
struct Rule {
    std::string id;
    std::string description;
    std::string protocol;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::string direction;  // "->", "<-", "<>"
    std::vector<RuleOption> options;
    RuleAction action;
    bool enabled;
};
```

### Rule Options
```cpp
struct RuleOption {
    std::string keyword;    // "content", "depth", "offset", "pcre", etc.
    std::string value;
    bool negated;          // "!" prefix
};

enum class RuleAction {
    ALERT,
    LOG,
    DROP,
    PASS,
    REJECT
};
```

### Rule Parser
```cpp
class RuleParser {
public:
    std::vector<Rule> parseRuleFile(const std::string& file_path);
    Rule parseRule(const std::string& rule_text);
    
private:
    Rule parseRuleLine(const std::string& line);
    std::vector<RuleOption> parseOptions(const std::string& options_str);
    bool validateRule(const Rule& rule);
};
```

### Rule Matcher
```cpp
class RuleMatcher {
private:
    std::vector<Rule> rules_;
    
public:
    void loadRules(const std::vector<Rule>& rules);
    std::vector<RuleMatch> match(const std::vector<std::shared_ptr<ProtocolData>>& protocols);
    
private:
    bool matchProtocol(const Rule& rule, const ProtocolData& proto);
    bool matchIP(const std::string& rule_ip, uint32_t packet_ip);
    bool matchPort(uint16_t rule_port, uint16_t packet_port);
    bool matchContent(const Rule& rule, const Packet& packet);
};
```

### Rule Match Result
```cpp
struct RuleMatch {
    const Rule* rule;
    double confidence;
    std::string matched_content;
    std::unordered_map<std::string, std::string> details;
};
```

## Event Manager Specification

### Event Manager Interface
```cpp
class EventManager {
private:
    std::vector<std::shared_ptr<IModule>> modules_;
    std::queue<Event> event_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    bool running_;
    
public:
    void registerModule(std::shared_ptr<IModule> module);
    void publishEvent(const Event& event);
    void start();
    void stop();
    
private:
    void eventLoop();
    void processEvent(const Event& event);
};
```

### Module Interface
```cpp
class IModule {
public:
    virtual std::string getName() const = 0;
    virtual bool initialize(const Config& config) = 0;
    virtual void handleEvent(const Event& event) = 0;
    virtual void shutdown() = 0;
    virtual ~IModule() = default;
};
```

## Configuration System Specification

### Configuration Structure
```cpp
class Config {
private:
    std::unordered_map<std::string, std::any> settings_;
    
public:
    template<typename T>
    T get(const std::string& key, const T& default_value) const;
    
    template<typename T>
    void set(const std::string& key, const T& value);
    
    bool loadFromFile(const std::string& file_path);
    bool loadFromString(const std::string& json_str);
    std::string toString() const;
};
```

### Configuration Schema
```yaml
ids:
  version: "1.0"
  
  capture:
    interface: "eth0"
    buffer_size: 65536
    timeout_ms: 1000
    snaplen: 65535
    promiscuous: true
    filter: ""
    
  protocols:
    enabled:
      - ethernet
      - ipv4
      - tcp
      - udp
      - icmp
    plugins_path: "/usr/lib/ids/plugins"
    
  logging:
    level: "INFO"
    format: "tcpdump"
    output: "console"
    file_path: "/var/log/ids.log"
    max_file_size: 10485760  # 10MB
    max_files: 10
    enable_packet_dump: true
    enable_hex_dump: true
    
  rules:
    rule_files:
      - "/etc/ids/rules/local.rules"
    auto_reload: true
    reload_interval: 300  # seconds
    
  performance:
    worker_threads: 4
    queue_size: 10000
    batch_size: 100
    cpu_affinity: true
```

## Error Handling Strategy

### Error Codes
```cpp
enum class ErrorCode {
    SUCCESS = 0,
    INVALID_CONFIG = 100,
    PERMISSION_DENIED = 101,
    INTERFACE_NOT_FOUND = 102,
    SOCKET_ERROR = 103,
    PACKET_CAPTURE_ERROR = 104,
    PROTOCOL_PARSE_ERROR = 105,
    RULE_PARSE_ERROR = 106,
    MEMORY_ALLOCATION_ERROR = 107,
    FILE_NOT_FOUND = 108,
    PLUGIN_LOAD_ERROR = 109
};
```

### Exception Classes
```cpp
class IDSException : public std::exception {
protected:
    ErrorCode code_;
    std::string message_;
    
public:
    IDSException(ErrorCode code, const std::string& message);
    const char* what() const noexcept override;
    ErrorCode getCode() const { return code_; }
};

class CaptureException : public IDSException {
public:
    CaptureException(ErrorCode code, const std::string& message);
};

class ProtocolException : public IDSException {
public:
    ProtocolException(ErrorCode code, const std::string& message);
};

class RuleException : public IDSException {
public:
    RuleException(ErrorCode code, const std::string& message);
};
```

## Performance Metrics

### Metrics Collection
```cpp
struct PerformanceMetrics {
    uint64_t packets_captured;
    uint64_t packets_processed;
    uint64_t packets_dropped;
    uint64_t alerts_generated;
    uint64_t rules_evaluated;
    uint64_t bytes_processed;
    double average_processing_time;
    double packets_per_second;
    double bytes_per_second;
    std::chrono::steady_clock::time_point start_time;
};
```

### Metrics Reporter
```cpp
class MetricsReporter {
public:
    void update(const std::string& metric, double value);
    void increment(const std::string& metric);
    PerformanceMetrics getSnapshot() const;
    std::string getReport() const;
};