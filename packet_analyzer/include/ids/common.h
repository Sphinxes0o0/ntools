#ifndef IDS_COMMON_H
#define IDS_COMMON_H

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <unordered_map>
#include <any>

namespace ids {

// Forward declarations
class Packet;
class Config;
class IDSException;

// Common type definitions
using byte_t = uint8_t;
using buffer_t = std::vector<byte_t>;
using timestamp_t = std::chrono::steady_clock::time_point;

// Error codes
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

// Protocol layers following TCP/IP model
enum class ProtocolLayer {
    LINK_LAYER = 1,
    NETWORK_LAYER = 2,
    TRANSPORT_LAYER = 3,
    APPLICATION_LAYER = 4
};


// Log levels - renamed to avoid DEBUG macro conflict
enum class LogLevel {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARNING = 2,
    LOG_ERROR = 3,
    LOG_ALERT = 4
};

// Rule actions
enum class RuleAction {
    ALERT,
    LOG,
    DROP,
    PASS,
    REJECT
};

// Rule direction
enum class RuleDirection {
    UNIDIRECTIONAL,  // -> (src to dst)
    BIDIRECTIONAL,   // <> (src to dst or dst to src)
    REVERSE          // <- (dst to src)
};

// Utility functions
namespace utils {

// Network utilities
std::string ipToString(uint32_t ip);
uint32_t stringToIP(const std::string& ip);
bool isValidIP(const std::string& ip);
bool isPrivateIP(uint32_t ip);
bool isBroadcastIP(uint32_t ip);
bool isMulticastIP(uint32_t ip);

std::string macToString(const uint8_t mac[6]);
bool isValidMAC(const std::string& mac);
bool isBroadcastMAC(const uint8_t mac[6]);
bool isMulticastMAC(const uint8_t mac[6]);

bool isValidPort(uint16_t port);
bool isWellKnownPort(uint16_t port);
bool isRegisteredPort(uint16_t port);
std::string getServiceName(uint16_t port);

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
std::string formatHexDump(const uint8_t* data, size_t length, size_t bytes_per_line = 16);

} // namespace utils

} // namespace ids

#endif // IDS_COMMON_H