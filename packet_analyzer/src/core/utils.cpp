#include "../../include/ids/common.h"
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace ids {
namespace utils {

// IP address utilities
std::string ipToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    return std::string(inet_ntoa(addr));
}

uint32_t stringToIP(const std::string& ip) {
    struct in_addr addr;
    if (inet_aton(ip.c_str(), &addr) == 0) {
        return 0;
    }
    return ntohl(addr.s_addr);
}

bool isValidIP(const std::string& ip) {
    struct in_addr addr;
    return inet_aton(ip.c_str(), &addr) != 0;
}

bool isPrivateIP(uint32_t ip) {
    // 10.0.0.0/8
    if ((ip & 0xFF000000) == 0x0A000000) return true;
    // 172.16.0.0/12
    if ((ip & 0xFFF00000) == 0xAC100000) return true;
    // 192.168.0.0/16
    if ((ip & 0xFFFF0000) == 0xC0A80000) return true;
    // 127.0.0.0/8 (loopback)
    if ((ip & 0xFF000000) == 0x7F000000) return true;
    return false;
}

bool isBroadcastIP(uint32_t ip) {
    return ip == 0xFFFFFFFF; // 255.255.255.255
}

bool isMulticastIP(uint32_t ip) {
    return (ip & 0xF0000000) == 0xE0000000; // 224.0.0.0/4
}

// MAC address utilities
std::string macToString(const uint8_t mac[6]) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i > 0) ss << ":";
        ss << std::setw(2) << static_cast<int>(mac[i]);
    }
    return ss.str();
}

bool isValidMAC(const std::string& mac) {
    // Simple MAC validation: XX:XX:XX:XX:XX:XX
    if (mac.length() != 17) return false;
    for (int i = 0; i < 17; ++i) {
        if (i % 3 == 2) {
            if (mac[i] != ':') return false;
        } else {
            if (!std::isxdigit(mac[i])) return false;
        }
    }
    return true;
}

bool isBroadcastMAC(const uint8_t mac[6]) {
    return mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF &&
           mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF;
}

bool isMulticastMAC(const uint8_t mac[6]) {
    return (mac[0] & 0x01) != 0; // I/G bit set
}

// Port utilities
bool isValidPort(uint16_t port) {
    return port != 0; // Port 0 is invalid, all others are valid for uint16_t
}

bool isWellKnownPort(uint16_t port) {
    return port >= 1 && port <= 1023;
}

bool isRegisteredPort(uint16_t port) {
    return port >= 1024 && port <= 49151;
}

std::string getServiceName(uint16_t port) {
    // Common service names
    switch (port) {
        case 20: return "FTP-DATA";
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "TELNET";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        default: return "unknown";
    }
}

// Protocol utilities
std::string getProtocolName(uint8_t protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        case 58: return "ICMPv6";
        default: return "unknown";
    }
}

uint8_t getProtocolNumber(const std::string& name) {
    std::string lower_name = toLower(name);
    if (lower_name == "icmp") return 1;
    if (lower_name == "tcp") return 6;
    if (lower_name == "udp") return 17;
    if (lower_name == "gre") return 47;
    if (lower_name == "esp") return 50;
    if (lower_name == "ah") return 51;
    if (lower_name == "icmpv6") return 58;
    return 0;
}

bool isValidProtocol(const std::string& protocol) {
    return getProtocolNumber(protocol) != 0;
}

// Checksum utilities
uint16_t calculateChecksum(const uint8_t* data, size_t length) {
    uint32_t sum = 0;
    
    // Add each 16-bit word
    while (length > 1) {
        sum += (data[0] << 8) + data[1];
        data += 2;
        length -= 2;
    }
    
    // Add left-over byte, if any
    if (length == 1) {
        sum += (data[0] << 8);
    }
    
    // Add carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // One's complement
    return static_cast<uint16_t>(~sum);
}

uint16_t calculateIPChecksum(const uint8_t* ip_header, size_t length) {
    return calculateChecksum(ip_header, length);
}

bool verifyChecksum(const uint8_t* data, size_t length, uint16_t checksum) {
    (void)checksum; // Unused parameter
    uint16_t calculated = calculateChecksum(data, length);
    return calculated == 0; // Checksum should be 0 if valid
}

// Time utilities
std::string formatTimestamp(uint32_t sec, uint32_t usec) {
    time_t time_sec = static_cast<time_t>(sec);
    struct tm* tm_info = localtime(&time_sec);
    
    char buffer[32];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    
    std::stringstream ss;
    ss << buffer << "." << std::setw(6) << std::setfill('0') << usec;
    return ss.str();
}

std::string formatDuration(double seconds) {
    if (seconds < 0.001) {
        return std::to_string(static_cast<int>(seconds * 1000000)) + "μs";
    } else if (seconds < 1.0) {
        return std::to_string(static_cast<int>(seconds * 1000)) + "ms";
    } else {
        return std::to_string(static_cast<int>(seconds)) + "s";
    }
}

std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration);
    
    return formatTimestamp(
        static_cast<uint32_t>(seconds.count()),
        static_cast<uint32_t>(microseconds.count() % 1000000)
    );
}

// String utilities
std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    
    while (std::getline(ss, token, delimiter)) {
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }
    
    return tokens;
}

std::string trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

std::string toLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::string toUpper(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

bool startsWith(const std::string& str, const std::string& prefix) {
    return str.size() >= prefix.size() && 
           str.compare(0, prefix.size(), prefix) == 0;
}

bool endsWith(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() && 
           str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
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
        std::string byte_string = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byte_string, nullptr, 16));
        result.push_back(byte);
    }
    
    return result;
}

std::string formatHexDump(const uint8_t* data, size_t length, size_t bytes_per_line) {
    std::stringstream ss;
    
    for (size_t i = 0; i < length; i += bytes_per_line) {
        // Offset
        ss << std::hex << std::setw(4) << std::setfill('0') << i << "  ";
        
        // Hex bytes
        for (size_t j = 0; j < bytes_per_line && i + j < length; ++j) {
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(data[i + j]) << " ";
            if (j == 7) ss << " ";
        }
        
        // Padding for incomplete lines
        if (i + bytes_per_line > length) {
            size_t remaining = bytes_per_line - (length - i);
            for (size_t j = 0; j < remaining; ++j) {
                ss << "   ";
                if (j == 7) ss << " ";
            }
        }
        
        // ASCII representation
        ss << " |";
        for (size_t j = 0; j < bytes_per_line && i + j < length; ++j) {
            char c = static_cast<char>(data[i + j]);
            ss << (isprint(c) ? c : '.');
        }
        ss << "|\n";
    }
    
    return ss.str();
}

} // namespace utils
} // namespace ids