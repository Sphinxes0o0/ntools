#include "../../include/utils/utils.h"
#include "../../include/ids/config.h"
#include <iostream>
#include <getopt.h>
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
#include <cstdint>
#include <sys/time.h>
#include <arpa/inet.h>
#include <csignal>

namespace ids {
namespace utils {

// Signal handling utilities
void setupSignalHandler(int signal, SignalHandler handler) {
    std::signal(signal, handler);
}

void setupStandardSignalHandlers(SignalHandler handler) {
    setupSignalHandler(SIGINT, handler);
    setupSignalHandler(SIGTERM, handler);
    setupSignalHandler(SIGHUP, handler);
    setupSignalHandler(SIGUSR1, handler);
}

// Network utilities
std::string ipToString(uint32_t ip) {
    in_addr addr;
    addr.s_addr = ip;
    return inet_ntoa(addr);
}

uint32_t stringToIP(const std::string& ip) {
    return inet_addr(ip.c_str());
}

bool isValidIP(const std::string& ip) {
    return stringToIP(ip) != INADDR_NONE;
}

bool isPrivateIP(uint32_t ip) {
    // Convert to host byte order for checking
    uint32_t host_ip = ntohl(ip);
    
    // Check for private IP ranges:
    // 10.0.0.0/8
    if ((host_ip & 0xFF000000) == 0x0A000000) return true;
    // 172.16.0.0/12
    if ((host_ip & 0xFFF00000) == 0xAC100000) return true;
    // 192.168.0.0/16
    if ((host_ip & 0xFFFF0000) == 0xC0A80000) return true;
    
    return false;
}

bool isBroadcastIP(uint32_t ip) {
    return ip == 0xFFFFFFFF;
}

bool isMulticastIP(uint32_t ip) {
    uint32_t host_ip = ntohl(ip);
    return (host_ip & 0xF0000000) == 0xE0000000; // 224.0.0.0/4
}

std::string macToString(const uint8_t mac[6]) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; i++) {
        if (i > 0) ss << ":";
        ss << std::setw(2) << static_cast<int>(mac[i]);
    }
    return ss.str();
}

bool isValidMAC(const std::string& mac) {
    if (mac.length() != 17) return false;
    
    for (size_t i = 0; i < mac.length(); i++) {
        if (i % 3 == 2) {
            if (mac[i] != ':') return false;
        } else {
            if (!std::isxdigit(mac[i])) return false;
        }
    }
    return true;
}

bool isBroadcastMAC(const uint8_t mac[6]) {
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0xFF) return false;
    }
    return true;
}

bool isMulticastMAC(const uint8_t mac[6]) {
    // Multicast MAC addresses have the least significant bit of the first octet set to 1
    return (mac[0] & 0x01) == 0x01;
}

bool isValidPort(uint16_t port) {
    return port > 0 && port <= 65535;
}

bool isWellKnownPort(uint16_t port) {
    return port >= 1 && port <= 1023;
}

bool isRegisteredPort(uint16_t port) {
    return port >= 1024 && port <= 49151;
}

std::string getServiceName(uint16_t port) {
    switch (port) {
        case 20: case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        default: return "Unknown";
    }
}

std::string getProtocolName(uint8_t protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        default: return "Unknown";
    }
}

uint8_t getProtocolNumber(const std::string& name) {
    std::string upper_name = toUpper(name);
    if (upper_name == "ICMP") return 1;
    if (upper_name == "TCP") return 6;
    if (upper_name == "UDP") return 17;
    return 0;
}

bool isValidProtocol(const std::string& protocol) {
    return getProtocolNumber(protocol) != 0;
}

// Checksum utilities
uint16_t calculateChecksum(const uint8_t* data, size_t length) {
    uint32_t sum = 0;
    const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);
    
    // Sum all 16-bit words
    for (size_t i = 0; i < length / 2; i++) {
        sum += ntohs(ptr[i]);
    }
    
    // Add odd byte if present
    if (length % 2) {
        uint16_t tmp = 0;
        *reinterpret_cast<uint8_t*>(&tmp) = data[length - 1];
        sum += ntohs(tmp);
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // Return one's complement
    return ~static_cast<uint16_t>(sum);
}

uint16_t calculateIPChecksum(const uint8_t* ip_header, size_t length) {
    return calculateChecksum(ip_header, length);
}

bool verifyChecksum(const uint8_t* data, size_t length, uint16_t checksum) {
    uint32_t sum = 0;
    const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);
    
    // Sum all 16-bit words
    for (size_t i = 0; i < length / 2; i++) {
        sum += ntohs(ptr[i]);
    }
    
    // Add odd byte if present
    if (length % 2) {
        uint16_t tmp = 0;
        *reinterpret_cast<uint8_t*>(&tmp) = data[length - 1];
        sum += ntohs(tmp);
    }
    
    // Add the checksum itself
    sum += ntohs(checksum);
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // Check if result is all ones (0xFFFF)
    return (sum == 0xFFFF);
}

// Time utilities
std::string formatTimestamp(uint32_t sec, uint32_t usec) {
    struct timeval tv;
    tv.tv_sec = sec;
    tv.tv_usec = usec;
    
    struct tm* tm_info = localtime(&tv.tv_sec);
    char buffer[64];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    
    std::stringstream ss;
    ss << buffer << "." << std::setfill('0') << std::setw(6) << tv.tv_usec;
    return ss.str();
}

std::string formatDuration(double seconds) {
    std::stringstream ss;
    if (seconds < 60) {
        ss << std::fixed << std::setprecision(2) << seconds << "s";
    } else if (seconds < 3600) {
        ss << std::fixed << std::setprecision(2) << seconds/60 << "m";
    } else {
        ss << std::fixed << std::setprecision(2) << seconds/3600 << "h";
    }
    return ss.str();
}

std::string getCurrentTimestamp() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return formatTimestamp(tv.tv_sec, tv.tv_usec);
}

// String utilities
std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    
    return tokens;
}

std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(' ');
    if (first == std::string::npos) {
        return "";
    }
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

std::string toLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return result;
}

std::string toUpper(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c){ return std::toupper(c); });
    return result;
}

bool startsWith(const std::string& str, const std::string& prefix) {
    return str.substr(0, prefix.length()) == prefix;
}

bool endsWith(const std::string& str, const std::string& suffix) {
    if (str.length() < suffix.length()) return false;
    return str.substr(str.length() - suffix.length()) == suffix;
}

// Hex utilities
std::string toHex(const uint8_t* data, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::vector<uint8_t> fromHex(const std::string& hex) {
    std::vector<uint8_t> result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

std::string formatHexDump(const uint8_t* data, size_t length, size_t bytes_per_line) {
    std::stringstream ss;
    for (size_t i = 0; i < length; i += bytes_per_line) {
        // Offset
        ss << std::hex << std::setw(8) << std::setfill('0') << i << "  ";
        
        // Hex bytes
        for (size_t j = 0; j < bytes_per_line; j++) {
            if (i + j < length) {
                ss << std::hex << std::setw(2) << std::setfill('0') 
                   << static_cast<int>(data[i + j]) << " ";
            } else {
                ss << "   "; // Padding for missing bytes
            }
            
            // Extra space between groups of 8 bytes
            if (j == 7) ss << " ";
        }
        
        ss << " |";
        
        // ASCII representation
        for (size_t j = 0; j < bytes_per_line && i + j < length; j++) {
            uint8_t c = data[i + j];
            if (c >= 32 && c <= 126) { // Printable ASCII range
                ss << static_cast<char>(c);
            } else {
                ss << ".";
            }
        }
        
        ss << "|" << std::endl;
    }
    return ss.str();
}

void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "IDS - Intrusion Detection System\n\n"
              << "Options:\n"
              << "  -c, --config FILE       Configuration file path (default: /etc/ids/ids.yaml)\n"
              << "  -i, --interface IF      Network interface to monitor (overrides config)\n"
              << "  -r, --rules FILE        Rule file path (can be specified multiple times)\n"
              << "  -l, --log-level LEVEL   Log level (DEBUG, INFO, WARNING, ERROR, ALERT)\n"
              << "  -o, --output FORMAT     Output format (tcpdump, json, csv)\n"
              << "  -d, --debug             Enable debug mode\n"
              << "  -s, --save-config       Save command line options to config file\n"
              << "  -v, --version           Show version information\n"
              << "  -h, --help              Show this help message\n\n"
              << "Examples:\n"
              << "  " << program_name << " -c /path/to/config.yaml\n"
              << "  " << program_name << " -i eth0 -l DEBUG\n"
              << "  " << program_name << " -r local.rules -r community.rules\n\n"
              << "Signals:\n"
              << "  SIGINT, SIGTERM    Graceful shutdown\n"
              << "  SIGHUP             Reload configuration\n"
              << "  SIGUSR1            Print statistics\n";
}

void printVersion() {
    std::cout << "IDS version 1.0.0\n"
              << "Copyright (C) 2024 IDS Project\n"
              << "License: MIT\n"
              << "This is free software: you are free to change and redistribute it.\n";
}

int parseCommandLine(int argc, char* argv[], CommandLineOptions& options) {
    // Long options
    static struct option long_options[] = {
        {"config", required_argument, 0, 'c'},
        {"interface", required_argument, 0, 'i'},
        {"rules", required_argument, 0, 'r'},
        {"log-level", required_argument, 0, 'l'},
        {"output", required_argument, 0, 'o'},
        {"debug", no_argument, 0, 'd'},
        {"save-config", no_argument, 0, 's'},
        {"version", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    // Parse command line options
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "c:i:r:l:o:dsvh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'c':
                options.config_file = optarg;
                break;
            case 'i':
                options.interface = optarg;
                break;
            case 'r':
                options.rule_files.push_back(optarg);
                break;
            case 'l':
                options.log_level = optarg;
                break;
            case 'o':
                options.output_format = optarg;
                break;
            case 'd':
                options.debug_mode = true;
                break;
            case 's':
                options.save_config = true;
                break;
            case 'v':
                printVersion();
                return -1; // Indicates to exit
            case 'h':
                printUsage(argv[0]);
                return -1; // Indicates to exit
            case '?':
                // getopt_long already printed an error message
                return 1; // Indicates error
            default:
                printUsage(argv[0]);
                return 1; // Indicates error
        }
    }
    
    return 0; // Success
}

int processConfiguration(int argc, char* argv[], ids::Config& config, CommandLineOptions& options) {
    // Parse command line options
    int parse_result = parseCommandLine(argc, argv, options);
    
    // Handle special cases (help, version)
    if (parse_result == -1) {
        return -1; // Exit gracefully
    }
    
    // Handle parse errors
    if (parse_result == 1) {
        return 1; // Error occurred
    }

    // Load configuration from file
    if (!config.loadFromFile(options.config_file)) {
        std::cerr << "Error: Cannot load configuration file: " << options.config_file << std::endl;
        return 1;
    }

    // Override configuration with command line options
    config.applyCommandLineOptions(options);
    
    // Save config file if requested
    if (options.save_config) {
        if (config.saveConfig(options.config_file)) {
            std::cout << "Configuration saved to " << options.config_file << std::endl;
        } else {
            std::cerr << "Warning: Failed to save configuration to " << options.config_file << std::endl;
        }
    }
    
    // Validate configuration
    if (!config.validate()) {
        std::cerr << "Error: Invalid configuration" << std::endl;
        auto errors = config.getValidationErrors();
        for (const auto& error : errors) {
            std::cerr << "  - " << error << std::endl;
        }
        return 1;
    }
    
    return 0; // Success
}

} // namespace utils
} // namespace ids