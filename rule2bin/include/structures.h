#ifndef RULE2BIN_STRUCTURES_H
#define RULE2BIN_STRUCTURES_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <ctime>

namespace rule2bin {

// Magic number for file identification
constexpr uint32_t FILE_MAGIC = 0x534E5254; // "SNRT" in hex

// File format version
constexpr uint32_t FILE_VERSION = 0x00010000; // Version 1.0

// Enumerations
enum class Action : uint8_t {
    ALERT = 0,
    LOG = 1,
    PASS = 2,
    DROP = 3
};

enum class Protocol : uint8_t {
    TCP = 0,
    UDP = 1,
    ICMP = 2,
    IP = 3
};

enum class Direction : uint8_t {
    UNI = 0,  // Unidirectional
    BI = 1    // Bidirectional
};

// Option types
enum class OptionType : uint32_t {
    CONTENT = 0,
    MSG = 1,
    SID = 2,
    REV = 3,
    CLASSTYPE = 4,
    PRIORITY = 5,
    METADATA = 6,
    FLOW = 7,
    FLAGS = 8
};

// File header structure
struct FileHeader {
    uint32_t magic;        // Magic number: 0x534E5254
    uint32_t version;      // File format version
    uint64_t timestamp;    // Creation time (Unix timestamp)
    uint32_t rule_count;   // Number of rules in file
    uint32_t header_size;  // Total header size in bytes
    uint32_t data_size;    // Total rules data size in bytes
    uint32_t checksum;     // CRC32 checksum of rules data

    FileHeader() 
        : magic(FILE_MAGIC)
        , version(FILE_VERSION)
        , timestamp(std::time(nullptr))
        , rule_count(0)
        , header_size(sizeof(FileHeader))
        , data_size(0)
        , checksum(0) {}
};

// Rule option structure
struct RuleOption {
    OptionType type;       // Option type
    uint32_t value_len;    // Length of value data
    // Note: value data follows in binary stream
    
    RuleOption(OptionType t, uint32_t len) 
        : type(t), value_len(len) {}
};

// Rule header structure
struct RuleHeader {
    Action action;         // Rule action
    Protocol protocol;     // Protocol
    char src_ip[16];       // Source IP (IPv4/IPv6 as string)
    char dst_ip[16];       // Destination IP
    uint16_t src_port;     // Source port (0 for any)
    uint16_t dst_port;     // Destination port (0 for any)
    Direction direction;   // Traffic direction
    uint32_t option_count; // Number of options
    uint32_t rule_size;    // Total size of this rule in bytes

    RuleHeader()
        : action(Action::ALERT)
        , protocol(Protocol::TCP)
        , src_port(0)
        , dst_port(0)
        , direction(Direction::UNI)
        , option_count(0)
        , rule_size(0) {
        std::memset(src_ip, 0, sizeof(src_ip));
        std::memset(dst_ip, 0, sizeof(dst_ip));
    }
};

// Complete rule representation
struct Rule {
    RuleHeader header;
    std::vector<RuleOption> options;
    std::vector<std::string> string_data; // String values for options
    
    Rule() = default;
    
    // Calculate total binary size for serialization
    uint32_t calculate_binary_size() const;
};

// Utility functions
const char* action_to_string(Action action);
const char* protocol_to_string(Protocol protocol);
const char* direction_to_string(Direction direction);
const char* option_type_to_string(OptionType type);

} // namespace rule2bin

#endif // RULE2BIN_STRUCTURES_H