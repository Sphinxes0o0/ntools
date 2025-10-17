#ifndef PROTOCOLS_PROTOCOL_PARSER_H
#define PROTOCOLS_PROTOCOL_PARSER_H

#include <string>
#include <vector>
#include <memory>
#include <utility>
#include <sstream>
#include <iomanip>

namespace ids {

/**
 * @brief Protocol types following IANA assigned numbers
 * @see https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
 */
enum class ProtocolType {
    UNKNOWN = 0,
    ETHERNET = 1,  // Custom value for Ethernet layer
    IP = 2,        // Custom value for IP layer
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    ARP = 63,      // Custom value for ARP (not in IANA standard)
    HTTP = 80,     // Custom value for HTTP (not in IANA standard)
    DNS = 53,      // Custom value for DNS (not in IANA standard)
    DHCP = 67,     // Using BOOTP/DHCP value
    FTP = 21,      // Custom value for FTP (not in IANA standard)
    SMTP = 25,     // Custom value for SMTP (not in IANA standard)
    POP3 = 110,    // Custom value for POP3 (not in IANA standard)
    IMAP = 143,    // Custom value for IMAP (not in IANA standard)
    SSL = 443,     // Using HTTPS/SSL value
    TLS = 12345    // Custom value for TLS (not in IANA standard)
};

// Structure to hold parsing results with detailed findings
struct ParsingResult {
    ProtocolType protocol_type;
    bool is_valid;
    std::string description;
    std::vector<std::pair<std::string, std::string>> findings;
    
    // Constructor
    explicit ParsingResult(ProtocolType type = ProtocolType::UNKNOWN, bool valid = false)
        : protocol_type(type), is_valid(valid), description("") {}
    
    // Add a finding to the result
    void add_finding(const std::string& key, const std::string& value) {
        findings.emplace_back(key, value);
    }
    
    // Clear all findings
    void clear_findings() {
        findings.clear();
        description.clear();
        is_valid = false;
    }
    
    // Get finding by key
    std::string get_finding(const std::string& key) const {
        for (const auto& finding : findings) {
            if (finding.first == key) {
                return finding.second;
            }
        }
        return "";
    }
    
    // Check if finding exists
    bool has_finding(const std::string& key) const {
        for (const auto& finding : findings) {
            if (finding.first == key) {
                return true;
            }
        }
        return false;
    }
};

// Base interface for all protocol parsers
class ProtocolParser {
public:
    // Virtual destructor for proper polymorphism
    virtual ~ProtocolParser() = default;
    
    // Parse packet data and return parsing results
    virtual ParsingResult parse(const std::vector<uint8_t>& packet_data) = 0;
    
    // Get the protocol type this parser handles
    virtual ProtocolType get_protocol_type() const = 0;
    
    // Get parser name for identification
    virtual std::string get_name() const = 0;
    
    // Check if this parser can handle the given packet data
    virtual bool can_parse(const std::vector<uint8_t>& packet_data) const = 0;
    
    // Get parser version information
    virtual std::string get_version() const { return "1.0.0"; }
    
    // Get parser description
    virtual std::string get_description() const { return "Protocol parser"; }
    
    // Check if parser is enabled (can be used to disable parsers dynamically)
    virtual bool is_enabled() const { return true; }
    
    // Enable/disable parser
    virtual void set_enabled(bool enabled) { 
        // Default implementation does nothing 
        (void)enabled; // Prevent unused parameter warning
    }
    
    // Get minimum packet size required for parsing
    virtual size_t get_min_packet_size() const { return 0; }
    
    // Get parser priority (higher priority parsers are tried first)
    virtual int get_priority() const { return 0; }
    
protected:
    // Helper method to validate packet size
    bool validate_packet_size(const std::vector<uint8_t>& packet_data, size_t required_size) const {
        return packet_data.size() >= required_size;
    }
    
    // Helper method to extract 16-bit value (big-endian)
    uint16_t extract_uint16_be(const uint8_t* data) const {
        return (static_cast<uint16_t>(data[0]) << 8) | static_cast<uint16_t>(data[1]);
    }
    
    // Helper method to extract 32-bit value (big-endian)
    uint32_t extract_uint32_be(const uint8_t* data) const {
        return (static_cast<uint32_t>(data[0]) << 24) |
               (static_cast<uint32_t>(data[1]) << 16) |
               (static_cast<uint32_t>(data[2]) << 8) |
               static_cast<uint32_t>(data[3]);
    }
    
    // Helper method to format hex values
    std::string format_hex(uint32_t value, int width = 4) const {
        std::stringstream ss;
        ss << "0x" << std::uppercase << std::hex << std::setfill('0') << std::setw(width) << value;
        return ss.str();
    }
};

// Factory function to create protocol parsers
std::unique_ptr<ProtocolParser> create_protocol_parser(ProtocolType type);

// Utility function to get protocol name from type
std::string protocol_type_to_string(ProtocolType type);

// Utility function to get protocol type from name
ProtocolType string_to_protocol_type(const std::string& name);

} // namespace ids

#endif // PARSING_PROTOCOL_PARSER_H