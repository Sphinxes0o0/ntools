#ifndef MINIIDS_UTILS_UTILS_H
#define MINIIDS_UTILS_UTILS_H

#include <string>
#include <vector>
#include <cstdint>

namespace ids {
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
std::string formatHexDump(const uint8_t* data, size_t length, size_t bytes_per_line);

} // namespace utils
} // namespace ids

#endif // MINIIDS_UTILS_UTILS_H