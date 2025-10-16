#ifndef UTILS_UTILS_H
#define UTILS_UTILS_H

#include <string>
#include <vector>
#include <cstdint>
// Forward declaration to avoid circular dependency
namespace ids {
    class Config;
}

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

// Signal handling utilities
typedef void (*SignalHandler)(int signal);
void setupSignalHandler(int signal, SignalHandler handler);
void setupStandardSignalHandlers(SignalHandler handler);

/**
 * @brief Structure to hold command line options
 */
struct CommandLineOptions {
    std::string config_file = "/etc/ids/ids.yaml";
    std::string interface;
    std::vector<std::string> rule_files;
    std::string log_level;
    std::string output_format;
    bool debug_mode = false;
    bool save_config = false;  // Whether to save the config file after applying CLI options
};

/**
 * @brief Parse command line arguments
 * @param argc Argument count
 * @param argv Argument vector
 * @param options Parsed command line options
 * @return 0 on success, 1 on error, -1 to exit (help/version)
 */
int parseCommandLine(int argc, char* argv[], CommandLineOptions& options);

/**
 * @brief Process command line options and configuration
 * @param argc Argument count
 * @param argv Argument vector
 * @param config Configuration object to populate
 * @param options Command line options (output)
 * @return 0 on success, 1 on error, -1 to exit (help/version)
 */
int processConfiguration(int argc, char* argv[], ids::Config& config, CommandLineOptions& options);

/**
 * @brief Print usage information
 * @param program_name Program name
 */
void printUsage(const char* program_name);

/**
 * @brief Print version information
 */
void printVersion();

} // namespace utils
} // namespace ids

#endif // UTILS_UTILS_H