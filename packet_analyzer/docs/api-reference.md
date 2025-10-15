# IDS API Reference

## Core API

### Packet Structure
```cpp
namespace ids {

struct Packet {
    std::vector<uint8_t> data;          // Raw packet data
    size_t length;                      // Packet length in bytes
    uint32_t capture_time_sec;          // Capture timestamp (seconds)
    uint32_t capture_time_usec;         // Capture timestamp (microseconds)
    uint32_t interface_index;           // Network interface index
    uint16_t protocol;                  // Link layer protocol type
    
    // Constructors
    Packet();
    Packet(const uint8_t* raw_data, size_t len);
    
    // Utility methods
    std::string toHexString() const;
    std::string getInfo() const;
};

} // namespace ids
```

### Event System
```cpp
namespace ids {

enum class EventType {
    PACKET_CAPTURED,     // New packet captured
    PROTOCOL_DETECTED,   // Protocol identified
    RULE_MATCHED,        // Rule matched
    ALERT_GENERATED,     // Alert generated
    ERROR_OCCURRED       // Error occurred
};

class Event {
public:
    Event(EventType type, const std::string& source);
    
    EventType getType() const;
    uint32_t getTimestamp() const;
    const std::string& getSource() const;
    
    template<typename T>
    void setData(std::shared_ptr<T> data);
    
    template<typename T>
    std::shared_ptr<T> getData() const;
    
    std::string toString() const;
};

class EventManager {
public:
    static EventManager& getInstance();
    
    void publishEvent(const Event& event);
    void subscribe(EventType type, std::function<void(const Event&)> handler);
    void start();
    void stop();
};

} // namespace ids
```

### Configuration API
```cpp
namespace ids {

class Config {
public:
    Config();
    explicit Config(const std::string& file_path);
    
    // Generic getter/setter
    template<typename T>
    T get(const std::string& key, const T& default_value) const;
    
    template<typename T>
    void set(const std::string& key, const T& value);
    
    // Load from various sources
    bool loadFromFile(const std::string& file_path);
    bool loadFromYAML(const std::string& yaml_content);
    bool loadFromJSON(const std::string& json_content);
    
    // Save configuration
    bool saveToFile(const std::string& file_path) const;
    std::string toString() const;
    
    // Validation
    bool validate() const;
    std::vector<std::string> getValidationErrors() const;
};

// Configuration sections
struct CaptureConfig {
    std::string interface;
    size_t buffer_size;
    int timeout_ms;
    int snaplen;
    bool promiscuous;
    std::string filter;
    
    static CaptureConfig fromConfig(const Config& config);
};

struct LogConfig {
    std::string level;
    std::string format;
    std::string output;
    std::string file_path;
    bool enable_packet_dump;
    bool enable_hex_dump;
    
    static LogConfig fromConfig(const Config& config);
};

struct RuleConfig {
    std::vector<std::string> rule_files;
    bool auto_reload;
    int reload_interval;
    
    static RuleConfig fromConfig(const Config& config);
};

} // namespace ids
```

## Capture Module API

### Capture Interface
```cpp
namespace ids {

class ICaptureModule {
public:
    virtual ~ICaptureModule() = default;
    
    // Lifecycle methods
    virtual bool initialize(const CaptureConfig& config) = 0;
    virtual void shutdown() = 0;
    
    // Capture methods
    virtual std::unique_ptr<Packet> capturePacket() = 0;
    virtual std::vector<std::unique_ptr<Packet>> captureBatch(size_t max_packets) = 0;
    
    // Statistics
    virtual CaptureStats getStats() const = 0;
    virtual void resetStats() = 0;
    
    // Configuration
    virtual bool isRunning() const = 0;
    virtual const CaptureConfig& getConfig() const = 0;
};

struct CaptureStats {
    uint64_t packets_captured;
    uint64_t packets_dropped;
    uint64_t bytes_captured;
    double capture_rate;  // packets per second
    std::chrono::steady_clock::time_point start_time;
};

// Factory for creating capture modules
class CaptureFactory {
public:
    static std::unique_ptr<ICaptureModule> create(const std::string& type);
    
    // Available types: "af_packet", "libpcap", "ebpf"
    static std::vector<std::string> getAvailableTypes();
    static bool isTypeAvailable(const std::string& type);
};

// AF_PACKET implementation
class AFPacketCapture : public ICaptureModule {
public:
    AFPacketCapture();
    ~AFPacketCapture();
    
    bool initialize(const CaptureConfig& config) override;
    void shutdown() override;
    std::unique_ptr<Packet> capturePacket() override;
    std::vector<std::unique_ptr<Packet>> captureBatch(size_t max_packets) override;
    CaptureStats getStats() const override;
    void resetStats() override;
    bool isRunning() const override;
    const CaptureConfig& getConfig() const override;
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ids
```

### Capture Usage Example
```cpp
#include <ids/capture/capture_interface.h>
#include <ids/core/config.h>

using namespace ids;

int main() {
    // Create capture configuration
    CaptureConfig config;
    config.interface = "eth0";
    config.buffer_size = 65536;
    config.timeout_ms = 1000;
    config.promiscuous = true;
    
    // Create capture module
    auto capture = CaptureFactory::create("af_packet");
    
    // Initialize
    if (!capture->initialize(config)) {
        std::cerr << "Failed to initialize capture" << std::endl;
        return 1;
    }
    
    // Capture packets
    while (true) {
        auto packet = capture->capturePacket();
        if (packet) {
            std::cout << "Captured packet: " << packet->length << " bytes" << std::endl;
            // Process packet...
        }
    }
    
    capture->shutdown();
    return 0;
}
```

## Protocol Module API

### Protocol Plugin Interface
```cpp
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
    
    // Layer chaining
    std::shared_ptr<ProtocolData> next_layer;
    size_t header_length = 0;
    size_t payload_length = 0;
    
    // Utility methods
    virtual std::string toJSON() const;
    virtual std::map<std::string, std::string> getFields() const;
};

class IProtocolPlugin {
public:
    virtual ~IProtocolPlugin() = default;
    
    // Plugin identification
    virtual std::string getName() const = 0;
    virtual std::string getVersion() const = 0;
    virtual ProtocolLayer getLayer() const = 0;
    virtual int getPriority() const = 0;  // Higher priority = parsed first
    
    // Parsing capabilities
    virtual bool canParse(const Packet& packet, int offset) = 0;
    virtual std::shared_ptr<ProtocolData> parse(const Packet& packet, int offset) = 0;
    
    // Plugin lifecycle
    virtual bool initialize(const Config& config) = 0;
    virtual void shutdown() = 0;
};

// Protocol Manager
class ProtocolManager {
public:
    static ProtocolManager& getInstance();
    
    // Plugin management
    void registerPlugin(std::unique_ptr<IProtocolPlugin> plugin);
    void unregisterPlugin(const std::string& name);
    std::vector<std::string> getLoadedPlugins() const;
    
    // Packet parsing
    std::vector<std::shared_ptr<ProtocolData>> parsePacket(const Packet& packet);
    std::shared_ptr<ProtocolData> parseLayer(const Packet& packet, 
                                            ProtocolLayer layer, 
                                            int offset = 0);
    
    // Configuration
    bool loadPluginsFromDirectory(const std::string& path);
    void setLayerEnabled(ProtocolLayer layer, bool enabled);
    bool isLayerEnabled(ProtocolLayer layer) const;
    
private:
    ProtocolManager();
    ~ProtocolManager();
    
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ids
```

### Protocol Data Implementations
```cpp
namespace ids {

// Ethernet protocol data
class EthernetData : public ProtocolData {
public:
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
    
    // ProtocolData implementation
    std::string toString() const override;
    ProtocolLayer getLayer() const override { return ProtocolLayer::LINK_LAYER; }
    std::string getProtocolName() const override { return "Ethernet"; }
    
    // MAC address utilities
    static std::string macToString(const uint8_t mac[6]);
    bool isBroadcast() const;
    bool isMulticast() const;
};

// IPv4 protocol data
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
    
    // ProtocolData implementation
    std::string toString() const override;
    ProtocolLayer getLayer() const override { return ProtocolLayer::NETWORK_LAYER; }
    std::string getProtocolName() const override { return "IPv4"; }
    
    // IP utilities
    static std::string ipToString(uint32_t ip);
    static uint32_t stringToIP(const std::string& ip);
    bool isFragment() const;
    bool isFirstFragment() const;
    bool isLastFragment() const;
};

// TCP protocol data
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
    
    // ProtocolData implementation
    std::string toString() const override;
    ProtocolLayer getLayer() const override { return ProtocolLayer::TRANSPORT_LAYER; }
    std::string getProtocolName() const override { return "TCP"; }
    
    // TCP flag utilities
    bool isFIN() const { return flags & 0x01; }
    bool isSYN() const { return flags & 0x02; }
    bool isRST() const { return flags & 0x04; }
    bool isPSH() const { return flags & 0x08; }
    bool isACK() const { return flags & 0x10; }
    bool isURG() const { return flags & 0x20; }
    
    std::string getFlagsString() const;
};

// UDP protocol data
class UDPData : public ProtocolData {
public:
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
    
    // ProtocolData implementation
    std::string toString() const override;
    ProtocolLayer getLayer() const override { return ProtocolLayer::TRANSPORT_LAYER; }
    std::string getProtocolName() const override { return "UDP"; }
};

} // namespace ids
```

### Protocol Usage Example
```cpp
#include <ids/protocol/protocol_interface.h>
#include <ids/core/packet.h>

using namespace ids;

int main() {
    // Create a sample packet
    uint8_t raw_data[] = {
        // Ethernet header
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // DST MAC
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // SRC MAC
        0x08, 0x00,                            // EtherType (IPv4)
        // IP header would follow...
    };
    
    Packet packet(raw_data, sizeof(raw_data));
    
    // Parse protocols
    auto protocols = ProtocolManager::getInstance().parsePacket(packet);
    
    // Process parsed protocols
    for (const auto& proto : protocols) {
        std::cout << "Layer: " << static_cast<int>(proto->getLayer()) 
                  << ", Protocol: " << proto->getProtocolName() << std::endl;
        std::cout << "Data: " << proto->toString() << std::endl;
    }
    
    return 0;
}
```

## Logging Module API

### Log Interface
```cpp
namespace ids {

enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    ALERT = 4
};

class LogMessage {
public:
    LogLevel level;
    uint32_t timestamp_sec;
    uint32_t timestamp_usec;
    std::string source;
    std::string message;
    std::shared_ptr<Packet> packet;
    std::vector<std::shared_ptr<ProtocolData>> protocols;
    std::unordered_map<std::string, std::string> metadata;
    
    LogMessage(LogLevel level, const std::string& source, const std::string& message);
    
    std::string toString() const;
    std::string toJSON() const;
};

class ILogFormatter {
public:
    virtual ~ILogFormatter() = default;
    virtual std::string format(const LogMessage& message) = 0;
    virtual std::string getName() const = 0;
};

class ILogOutput {
public:
    virtual ~ILogOutput() = default;
    virtual bool initialize(const LogConfig& config) = 0;
    virtual void write(const std::string& formatted_message) = 0;
    virtual void flush() = 0;
    virtual void shutdown() = 0;
    virtual std::string getName() const = 0;
};

// Log Manager
class LogManager {
public:
    static LogManager& getInstance();
    
    // Configuration
    bool initialize(const LogConfig& config);
    void shutdown();
    
    // Logging methods
    void log(LogLevel level, const std::string& source, const std::string& message);
    void logPacket(LogLevel level, const std::string& source, 
                   const Packet& packet, const std::vector<std::shared_ptr<ProtocolData>>& protocols);
    void logAlert(const std::string& source, const std::string& message, 
                  const RuleMatch& match);
    
    // Formatter management
    void setFormatter(std::unique_ptr<ILogFormatter> formatter);
    void addOutput(std::unique_ptr<ILogOutput> output);
    
    // Level management
    void setLevel(LogLevel level);
    LogLevel getLevel() const;
    bool shouldLog(LogLevel level) const;
    
private:
    LogManager();
    ~LogManager();
    
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Convenience logging macros
#define LOG_DEBUG(source, message) \
    if (ids::LogManager::getInstance().shouldLog(ids::LogLevel::DEBUG)) \
        ids::LogManager::getInstance().log(ids::LogLevel::DEBUG, source, message)

#define LOG_INFO(source, message) \
    if (ids::LogManager::getInstance().shouldLog(ids::LogLevel::INFO)) \
        ids::LogManager::getInstance().log(ids::LogLevel::INFO, source, message)

#define LOG_WARNING(source, message) \
    if (ids::LogManager::getInstance().shouldLog(ids::LogLevel::WARNING)) \
        ids::LogManager::getInstance().log(ids::LogLevel::WARNING, source, message)

#define LOG_ERROR(source, message) \
    if (ids::LogManager::getInstance().shouldLog(ids::LogLevel::ERROR)) \
        ids::LogManager::getInstance().log(ids::LogLevel::ERROR, source, message)

#define LOG_ALERT(source, message) \
    if (ids::LogManager::getInstance().shouldLog(ids::LogLevel::ALERT)) \
        ids::LogManager::getInstance().log(ids::LogLevel::ALERT, source, message)

} // namespace ids
```

### Built-in Formatters
```cpp
namespace ids {

// Tcpdump-style formatter
class TcpdumpFormatter : public ILogFormatter {
public:
    std::string format(const LogMessage& message) override;
    std::string getName() const override { return "tcpdump"; }
    
    void setShowHexDump(bool enable) { show_hex_dump_ = enable; }
    void setShowTimestamp(bool enable) { show_timestamp_ = enable; }
    
private:
    bool show_hex_dump_ = true;
    bool show_timestamp_ = true;
    
    std::string formatTimestamp(uint32_t sec, uint32_t usec) const;
    std::string formatHexDump(const uint8_t* data, size_t length) const;
};

// JSON formatter
class JSONFormatter : public ILogFormatter {
public:
    std::string format(const LogMessage& message) override;
    std::string getName() const override { return "json"; }
    
    void setPrettyPrint(bool enable) { pretty_print_ = enable; }
    void setIncludePacket(bool enable) { include_packet_ = enable; }
    
private:
    bool pretty_print_ = false;
    bool include_packet_ = true;
};

// CSV formatter
class CSVFormatter : public ILogFormatter {
public:
    std::string format(const LogMessage& message) override;
    std::string getName() const override { return "csv"; }
    
    void setHeader(const std::vector<std::string>& header) { header_ = header; }
    std::vector<std::string> getHeader() const { return header_; }
    
private:
    std::vector<std::string> header_;
};

} // namespace ids
```

### Built-in Outputs
```cpp
namespace ids {

// Console output
class ConsoleOutput : public ILogOutput {
public:
    bool initialize(const LogConfig& config) override;
    void write(const std::string& formatted_message) override;
    void flush() override;
    void shutdown() override;
    std::string getName() const override { return "console"; }
    
private:
    std::mutex mutex_;
    bool use_colors_ = true;
    
    std::string colorize(LogLevel level, const std::string& message) const;
};

// File output
class FileOutput : public ILogOutput {
public:
    bool initialize(const LogConfig& config) override;
    void write(const std::string& formatted_message) override;
    void flush() override;
    void shutdown() override;
    std::string getName() const override { return "file"; }
    
    void setMaxFileSize(size_t size) { max_file_size_ = size; }
    void setMaxFiles(int count) { max_files_ = count; }
    
private:
    std::ofstream file_;
    std::mutex mutex_;
    size_t max_file_size_ = 10 * 1024 * 1024; // 10MB
    int max_files_ = 10;
    size_t current_size_ = 0;
    int current_file_index_ = 0;
    std::string base_file_path_;
    
    void rotateIfNeeded();
    std::string getCurrentFileName() const;
};

// Syslog output
class SyslogOutput : public ILogOutput {
public:
    bool initialize(const LogConfig& config) override;
    void write(const std::string& formatted_message) override;
    void flush() override;
    void shutdown() override;
    std::string getName() const override { return "syslog"; }
    
private:
    int facility_;
    std::string ident_;
    
    int convertLevelToSyslog(LogLevel level) const;
};

} // namespace ids
```

### Logging Usage Example
```cpp
#include <ids/log/log_interface.h>
#include <ids/core/config.h>

using namespace ids;

int main() {
    // Configure logging
    LogConfig config;
    config.level = "INFO";
    config.format = "tcpdump";
    config.output = "console";
    
    // Initialize logging
    LogManager::getInstance().initialize(config);
    
    // Set custom formatter and output
    auto formatter = std::make_unique<TcpdumpFormatter>();
    auto output = std::make_unique<ConsoleOutput>();
    
    LogManager::getInstance().setFormatter(std::move(formatter));
    LogManager::getInstance().addOutput(std::move(output));
    
    // Log messages
    LOG_INFO("main", "Application started");
    LOG_DEBUG("main", "Debug information");
    LOG_WARNING("main", "This is a warning");
    LOG_ERROR("main", "An error occurred");
    LOG_ALERT("main", "ALERT: Security event detected");
    
    // Log with packet data
    Packet packet(/* packet data */);
    std::vector<std::shared_ptr<ProtocolData>> protocols;
    LogManager::getInstance().logPacket(LogLevel::INFO, "main", packet, protocols);
    
    return 0;
}
```

## Rule Engine API

### Rule Structures
```cpp
namespace ids {

enum class RuleAction {
    ALERT,    // Generate alert and log
    LOG,      // Log only
    DROP,     // Drop packet (future: firewall integration)
    PASS,     // Allow packet
    REJECT    // Reject packet (future: firewall integration)
};

enum class RuleDirection {
    UNIDIRECTIONAL,  // -> (src to dst)
    BIDIRECTIONAL,   // <> (src to dst or dst to src)
    REVERSE          // <- (dst to src)
};

struct RuleOption {
    std::string keyword;    // "content", "depth", "offset", "pcre", etc.
    std::string value;
    bool negated;          // "!" prefix
    
    RuleOption() : negated(false) {}
    RuleOption(const std::string& keyword, const std::string& value, bool negated = false)
        : keyword(keyword), value(value), negated(negated) {}
};

class Rule {
public:
    std::string id;
    std::string description;
    std::string protocol;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    RuleDirection direction;
    std::vector<RuleOption> options;
    RuleAction action;
    bool enabled;
    std::unordered_map<std::string, std::string> metadata;
    
    Rule();
    
    // Validation
    bool validate() const;
    std::vector<std::string> getValidationErrors() const;
    
    // Utilities
    std::string toString() const;
    std::string toSnortFormat() const;
    
    // Matching helpers
    bool matchesProtocol(const std::string& proto) const;
    bool matchesIP(const std::string& rule_ip, uint32_t packet_ip) const;
    bool matchesPort(uint16_t rule_port, uint16_t packet_port) const;
};

struct RuleMatch {
    const Rule* rule;
    double confidence;
    std::string matched_content;
    std::unordered_map<std::string, std::string> details;
    std::chrono::steady_clock::time_point match_time;
    
    RuleMatch() : rule(nullptr), confidence(0.0) {}
    RuleMatch(const Rule* r, double conf) : rule(r), confidence(conf) {}
};

} // namespace ids
```

### Rule Parser Interface
```cpp
namespace ids {

class RuleParser {
public:
    RuleParser();
    ~RuleParser();
    
    // Rule parsing
    Rule parseRule(const std::string& rule_text);
    std::vector<Rule> parseRuleFile(const std::string& file_path);
    std::vector<Rule> parseRuleString(const std::string& rule_content);
    
    // Rule file management
    std::vector<Rule> loadRuleFiles(const std::vector<std::string>& file_paths);
    std::vector<Rule> loadRuleDirectory(const std::string& directory_path);
    
    // Validation
    bool validateRule(const Rule& rule);
    std::vector<std::string> getRuleErrors(const Rule& rule);
    
    // Configuration
    void setStrictMode(bool strict) { strict_mode_ = strict; }
    bool getStrictMode() const { return strict_mode_; }
    
    // Statistics
    struct ParseStats {
        size_t rules_parsed;
        size_t rules_valid;
        size_t rules_invalid;
        size_t parse_errors;
        std::chrono::steady_clock::time_point start_time;
    };
    
    ParseStats getStats() const;
    void resetStats();
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    bool strict_mode_ = false;
};

// Rule syntax validation
class RuleSyntaxValidator {
public:
    static bool isValidAction(const std::string& action);
    static bool isValidProtocol(const std::string& protocol);
    static bool isValidIP(const std::string& ip);
    static bool isValidPort(const std::string& port);
    static bool isValidDirection(const std::string& direction);
    static bool isValidOption(const RuleOption& option);
};

} // namespace ids
```

### Rule Matcher Interface
```cpp
namespace ids {

class RuleMatcher {
public:
    RuleMatcher();
    ~RuleMatcher();
    
    // Rule management
    void loadRules(const std::vector<Rule>& rules);
    void addRule(const Rule& rule);
    void removeRule(const std::string& rule_id);
    void clearRules();
    
    // Matching
    std::vector<RuleMatch> match(const Packet& packet,
                                const std::vector<std::shared_ptr<ProtocolData>>& protocols);
    
    RuleMatch matchSingle(const Packet& packet,
                         const std::vector<std::shared_ptr<ProtocolData>>& protocols,
                         const Rule& rule);
    
    // Configuration
    void setMatchAll(bool match_all) { match_all_ = match_all; }
    bool getMatchAll() const { return match_all_; }
    
    void setMaxMatches(size_t max_matches) { max_matches_ = max_matches; }
    size_t getMaxMatches() const { return max_matches_; }
    
    // Statistics
    struct MatchStats {
        uint64_t packets_checked;
        uint64_t rules_evaluated;
        uint64_t matches_found;
        uint64_t alerts_generated;
        double average_match_time;
        std::chrono::steady_clock::time_point start_time;
    };
    
    MatchStats getStats() const;
    void resetStats();
    
    // Performance optimization
    void optimizeRules();
    void rebuildIndex();
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    bool match_all_ = false;
    size_t max_matches_ = 100;
};

// Rule option matchers
class IOptionMatcher {
public:
    virtual ~IOptionMatcher() = default;
    virtual bool match(const RuleOption& option, const Packet& packet, int offset) = 0;
    virtual std::string getName() const = 0;
    virtual bool isValid(const RuleOption& option) const = 0;
};

// Built-in option matchers
class ContentMatcher : public IOptionMatcher {
public:
    bool match(const RuleOption& option, const Packet& packet, int offset) override;
    std::string getName() const override { return "content"; }
    bool isValid(const RuleOption& option) const override;
    
private:
    std::vector<uint8_t> parseContent(const std::string& content) const;
};

class DepthMatcher : public IOptionMatcher {
public:
    bool match(const RuleOption& option, const Packet& packet, int offset) override;
    std::string getName() const override { return "depth"; }
    bool isValid(const RuleOption& option) const override;
};

class OffsetMatcher : public IOptionMatcher {
public:
    bool match(const RuleOption& option, const Packet& packet, int offset) override;
    std::string getName() const override { return "offset"; }
    bool isValid(const RuleOption& option) const override;
};

} // namespace ids
```

### Rule Usage Example
```cpp
#include <ids/rule/rule_parser.h>
#include <ids/rule/rule_matcher.h>
#include <ids/core/packet.h>
#include <ids/protocol/protocol_interface.h>

using namespace ids;

int main() {
    // Parse rules
    RuleParser parser;
    std::vector<Rule> rules = parser.parseRuleFile("/etc/ids/rules/local.rules");
    
    // Create rule matcher
    RuleMatcher matcher;
    matcher.loadRules(rules);
    
    // Create sample packet and protocols
    Packet packet(/* packet data */);
    std::vector<std::shared_ptr<ProtocolData>> protocols = 
        ProtocolManager::getInstance().parsePacket(packet);
    
    // Match rules
    std::vector<RuleMatch> matches = matcher.match(packet, protocols);
    
    // Process matches
    for (const auto& match : matches) {
        std::cout << "Rule matched: " << match.rule->id << std::endl;
        std::cout << "Confidence: " << match.confidence << std::endl;
        std::cout << "Content: " << match.matched_content << std::endl;
        
        // Generate alert
        if (match.rule->action == RuleAction::ALERT) {
            // Handle alert...
        }
    }
    
    return 0;
}
```

## Exception Handling API

### Exception Hierarchy
```cpp
namespace ids {

enum class ErrorCode {
    SUCCESS = 0,
    
    // Configuration errors
    INVALID_CONFIG = 100,
    CONFIG_FILE_NOT_FOUND = 101,
    CONFIG_PARSE_ERROR = 102,
    
    // Capture errors
    PERMISSION_DENIED = 200,
    INTERFACE_NOT_FOUND = 201,
    SOCKET_ERROR = 202,
    PACKET_CAPTURE_ERROR = 203,
    CAPTURE_TIMEOUT = 204,
    
    // Protocol errors
    PROTOCOL_PARSE_ERROR = 300,
    UNKNOWN_PROTOCOL = 301,
    INVALID_PROTOCOL_DATA = 302,
    PLUGIN_LOAD_ERROR = 303,
    
    // Rule errors
    RULE_PARSE_ERROR = 400,
    INVALID_RULE_SYNTAX = 401,
    RULE_FILE_NOT_FOUND = 402,
    RULE_VALIDATION_ERROR = 403,
    
    // Logging errors
    LOG_INIT_ERROR = 500,
    LOG_WRITE_ERROR = 501,
    LOG_FILE_ERROR = 502,
    
    // General errors
    MEMORY_ALLOCATION_ERROR = 600,
    INVALID_ARGUMENT = 601,
    NOT_IMPLEMENTED = 602,
    INTERNAL_ERROR = 603
};

class IDSException : public std::exception {
public:
    IDSException(ErrorCode code, const std::string& message);
    IDSException(ErrorCode code, const std::string& message, 
                    const std::string& details);
    
    const char* what() const noexcept override;
    ErrorCode getCode() const { return code_; }
    const std::string& getMessage() const { return message_; }
    const std::string& getDetails() const { return details_; }
    std::string getFullMessage() const;
    
    // Stack trace (if available)
    const std::string& getStackTrace() const { return stack_trace_; }
    
private:
    ErrorCode code_;
    std::string message_;
    std::string details_;
    std::string stack_trace_;
    mutable std::string full_message_;
};

// Specific exception types
class CaptureException : public IDSException {
public:
    CaptureException(ErrorCode code, const std::string& message);
    CaptureException(ErrorCode code, const std::string& message, 
                    const std::string& details);
};

class ProtocolException : public IDSException {
public:
    ProtocolException(ErrorCode code, const std::string& message);
    ProtocolException(ErrorCode code, const std::string& message, 
                     const std::string& details);
};

class RuleException : public IDSException {
public:
    RuleException(ErrorCode code, const std::string& message);
    RuleException(ErrorCode code, const std::string& message, 
                 const std::string& details);
};

class LogException : public IDSException {
public:
    LogException(ErrorCode code, const std::string& message);
    LogException(ErrorCode code, const std::string& message, 
                const std::string& details);
};

class ConfigException : public IDSException {
public:
    ConfigException(ErrorCode code, const std::string& message);
    ConfigException(ErrorCode code, const std::string& message, 
                   const std::string& details);
};

} // namespace ids
```

### Exception Usage Example
```cpp

#include <ids/capture/capture_interface.h>

using namespace ids;

int main() {
    try {
        auto capture = CaptureFactory::create("af_packet");
        CaptureConfig config;
        config.interface = "invalid_interface";
        
        if (!capture->initialize(config)) {
            throw CaptureException(ErrorCode::INTERFACE_NOT_FOUND,
                                  "Failed to initialize capture",
                                  "Interface 'invalid_interface' not found");
        }
        
    } catch (const CaptureException& e) {
        std::cerr << "Capture error: " << e.what() << std::endl;
        std::cerr << "Error code: " << static_cast<int>(e.getCode()) << std::endl;
        std::cerr << "Details: " << e.getDetails() << std::endl;
        return 1;
    } catch (const IDSException& e) {
        std::cerr << "IDS error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Standard error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
```

## Main Application API

### IDS Class
```cpp
namespace ids {

class IDS {
public:
    IDS();
    ~IDS();
    
    // Lifecycle
    bool initialize(const std::string& config_file);
    bool initialize(const Config& config);
    void run();
    void shutdown();
    bool isRunning() const;
    
    // Configuration
    const Config& getConfig() const;
    void reloadConfig();
    
    // Module access
    ICaptureModule* getCaptureModule() const;
    ProtocolManager* getProtocolManager() const;
    LogManager* getLogManager() const;
    RuleMatcher* getRuleMatcher() const;
    
    // Statistics
    struct SystemStats {
        uint64_t packets_processed;
        uint64_t alerts_generated;
        uint64_t rules_matched;
        double uptime_seconds;
        double packets_per_second;
        double average_processing_time;
        std::map<std::string, uint64_t> protocol_counts;
        std::map<std::string, uint64_t> alert_counts;
    };
    
    SystemStats getStats() const;
    std::string getStatsJSON() const;
    void resetStats();
    
    // Control
    void pause();
    void resume();
    bool isPaused() const;
    
    // Signal handling
    void handleSignal(int signal);
    static void setupSignalHandlers();
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ids
```

### Main Application Usage
```cpp
#include <ids/ids.h>
#include <iostream>

using namespace ids;

int main(int argc, char* argv[]) {
    // Setup signal handlers
    IDS::setupSignalHandlers();
    
    // Create IDS instance
    IDS ids;
    
    try {
        // Initialize with configuration
        std::string config_file = "/etc/ids/ids.yaml";
        if (argc > 1) {
            config_file = argv[1];
        }
        
        if (!ids.initialize(config_file)) {
            std::cerr << "Failed to initialize IDS" << std::endl;
            return 1;
        }
        
        std::cout << "IDS started successfully" << std::endl;
        
        // Run main loop
        ids.run();
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    // Cleanup
    ids.shutdown();
    std::cout << "IDS stopped" << std::endl;
    
    return 0;
}
```

## Utility APIs

### Network Utilities
```cpp
namespace ids {
namespace utils {

// IP address utilities
std::string ipToString(uint32_t ip);
uint32_t stringToIP(const std::string& ip);
bool isValidIP(const std::string& ip);
bool isPrivateIP(uint32_t ip);
bool isBroadcastIP(uint32_t ip);
bool isMulticastIP(uint32_t ip);

// MAC address utilities
std::string macToString(const uint8_t mac[6]);
bool isValidMAC(const std::string& mac);
bool isBroadcastMAC(const uint8_t mac[6]);
bool isMulticastMAC(const uint8_t mac[6]);

// Port utilities
bool isValidPort(uint16_t port);
bool isWellKnownPort(uint16_t port);
bool isRegisteredPort(uint16_t port);
std::string getServiceName(uint16_t port);

// Protocol utilities
std::string getProtocolName(uint8_t protocol);
uint8_t getProtocolNumber(const std::string& name);
bool isValidProtocol(const std::string& protocol);

// Checksum utilities
uint16_t calculateChecksum(const uint8_t* data, size_t length);
uint16_t calculateIPChecksum(const uint8_t* ip_header, size_t length);
bool verifyChecksum(const uint8_t* data, size_t length, uint16_t checksum);

// Time utilities
std::string formatTimestamp(uint32_t sec, uint32_t usec);
std::string formatDuration(double seconds);
std::string getCurrentTimestamp();

// String utilities
std::vector<std::string> split(const std::string& str, char delimiter);
std::string trim(const std::string& str);
std::string toLower(const std::string& str);
std::string toUpper(const std::string& str);
bool startsWith(const std::string& str, const std::string& prefix);
bool endsWith(const std::string& str, const std::string& suffix);

// Hex utilities
std::string toHex(const uint8_t* data, size_t length);
std::vector<uint8_t> fromHex(const std::string& hex);
std::string formatHexDump(const uint8_t* data, size_t length, 
                         size_t bytes_per_line = 16);

} // namespace utils
} // namespace ids
```

### Performance Utilities
```cpp
namespace ids {
namespace performance {

// Timer for performance measurement
class Timer {
public:
    Timer();
    void start();
    void stop();
    void reset();
    
    double getElapsedSeconds() const;
    double getElapsedMilliseconds() const;
    double getElapsedMicroseconds() const;
    
    bool isRunning() const;
    
private:
    std::chrono::steady_clock::time_point start_time_;
    std::chrono::steady_clock::time_point end_time_;
    bool running_;
};

// Rate limiter
class RateLimiter {
public:
    RateLimiter(size_t max_requests, double time_window_seconds);
    
    bool allow();
    void reset();
    size_t getRemainingRequests() const;
    double getTimeUntilReset() const;
    
private:
    size_t max_requests_;
    double time_window_seconds_;
    std::queue<std::chrono::steady_clock::time_point> requests_;
    std::mutex mutex_;
};

// Memory pool for packet allocation
class PacketPool {
public:
    PacketPool(size_t initial_size = 1000, size_t max_size = 10000);
    ~PacketPool();
    
    std::unique_ptr<Packet> acquire();
    void release(std::unique_ptr<Packet> packet);
    
    size_t getSize() const;
    size_t getAvailable() const;
    size_t getInUse() const;
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// CPU affinity management
class CPUAffinity {
public:
    static bool setAffinity(int cpu_id);
    static bool setAffinity(const std::vector<int>& cpu_ids);
    static std::vector<int> getAffinity();
    static int getCurrentCPU();
    static size_t getCPUCount();
};

} // namespace performance
} // namespace ids