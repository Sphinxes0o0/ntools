#ifndef MINIIDS_PARSING_PACKET_INFO_EXTRACTOR_H
#define MINIIDS_PARSING_PACKET_INFO_EXTRACTOR_H

#include "../../src/core/packet.h"
#include "tcp.h"
#include "parser.h"
#include "../ids/common.h"
#include <string>
#include <optional>

namespace ids {

/**
 * @brief Extracted packet information for rule matching
 */
struct PacketInfo {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    RuleProtocol protocol;
    TCPFlags tcp_flags;
    uint32_t seq_number;
    uint32_t ack_number;
    uint16_t window_size;
    const Packet* raw_packet;
    
    PacketInfo() : src_port(0), dst_port(0), protocol(RuleProtocol::ANY),
                  seq_number(0), ack_number(0), window_size(0), raw_packet(nullptr) {}
    
    /**
     * @brief Check if this is a TCP packet
     * @return true if TCP, false otherwise
     */
    bool isTCP() const { return protocol == RuleProtocol::TCP; }
    
    /**
     * @brief Check if this is a UDP packet
     * @return true if UDP, false otherwise
     */
    bool isUDP() const { return protocol == RuleProtocol::UDP; }
    
    /**
     * @brief Check if this is an ICMP packet
     * @return true if ICMP, false otherwise
     */
    bool isICMP() const { return protocol == RuleProtocol::ICMP; }
    
    /**
     * @brief Get protocol as string
     * @return Protocol name
     */
    std::string getProtocolName() const {
        switch (protocol) {
            case RuleProtocol::TCP: return "TCP";
            case RuleProtocol::UDP: return "UDP";
            case RuleProtocol::ICMP: return "ICMP";
            case RuleProtocol::IP: return "IP";
            case RuleProtocol::ANY: return "ANY";
            default: return "UNKNOWN";
        }
    }
};

/**
 * @brief Extracts structured information from raw packets for rule matching
 */
class PacketInfoExtractor {
public:
    /**
     * @brief Constructor
     */
    PacketInfoExtractor();
    
    /**
     * @brief Destructor
     */
    ~PacketInfoExtractor() = default;
    
    /**
     * @brief Extract structured information from packet
     * @param packet Packet to extract from
     * @return PacketInfo structure with extracted data
     */
    PacketInfo extractInfo(const Packet& packet);
    
    /**
     * @brief Check if packet is TCP
     * @param packet Packet to check
     * @return true if TCP, false otherwise
     */
    bool isTCP(const Packet& packet) const;
    
    /**
     * @brief Check if packet is UDP
     * @param packet Packet to check
     * @return true if UDP, false otherwise
     */
    bool isUDP(const Packet& packet) const;
    
    /**
     * @brief Check if packet is ICMP
     * @param packet Packet to check
     * @return true if ICMP, false otherwise
     */
    bool isICMP(const Packet& packet) const;
    
    /**
     * @brief Get source IP address from packet
     * @param packet Packet to extract from
     * @return Source IP address, empty string if not found
     */
    std::string getSourceIP(const Packet& packet) const;
    
    /**
     * @brief Get destination IP address from packet
     * @param packet Packet to extract from
     * @return Destination IP address, empty string if not found
     */
    std::string getDestinationIP(const Packet& packet) const;
    
    /**
     * @brief Get source port from packet
     * @param packet Packet to extract from
     * @return Source port, 0 if not found
     */
    uint16_t getSourcePort(const Packet& packet) const;
    
    /**
     * @brief Get destination port from packet
     * @param packet Packet to extract from
     * @return Destination port, 0 if not found
     */
    uint16_t getDestinationPort(const Packet& packet) const;
    
    /**
     * @brief Get TCP flags from packet
     * @param packet Packet to extract from
     * @return TCPFlags structure, empty if not TCP
     */
    TCPFlags getTCPFlags(const Packet& packet) const;
    
    /**
     * @brief Get protocol from packet
     * @param packet Packet to extract from
     * @return RuleProtocol enum value
     */
    RuleProtocol getProtocol(const Packet& packet) const {
        uint8_t ip_protocol = getIPProtocol(packet);
        return protocolToRuleProtocol(ip_protocol);
    }

private:
    TCPParser tcp_parser_;
    
    /**
     * @brief Extract IPv4 address from packet data
     * @param data Packet data pointer
     * @param offset Offset to IP header
     * @return IP address as string
     */
    std::string extractIPv4Address(const uint8_t* data, size_t offset) const;
    
    /**
     * @brief Get IP protocol number from packet
     * @param packet Packet to check
     * @return IP protocol number, 0 if not found
     */
    uint8_t getIPProtocol(const Packet& packet) const;
    
    /**
     * @brief Get IP header length from packet
     * @param packet Packet to check
     * @return IP header length in bytes, 0 if not found
     */
    size_t getIPHeaderLength(const Packet& packet) const;
    
    /**
     * @brief Get Ethernet header length
     * @param packet Packet to check
     * @return Ethernet header length in bytes
     */
    size_t getEthernetHeaderLength(const Packet& packet) const;
    
    /**
     * @brief Check if packet has valid IP header
     * @param packet Packet to check
     * @return true if valid IP header, false otherwise
     */
    bool hasValidIPHeader(const Packet& packet) const;
    
    /**
     * @brief Convert IP protocol number to RuleProtocol
     * @param protocol IP protocol number
     * @return RuleProtocol enum value
     */
    RuleProtocol protocolToRuleProtocol(uint8_t protocol) const {
        switch (protocol) {
            case 6:  return RuleProtocol::TCP;   // TCP
            case 17: return RuleProtocol::UDP;   // UDP
            case 1:  return RuleProtocol::ICMP;  // ICMP
            default: return RuleProtocol::IP;    // Treat other IP protocols as IP
        }
    }
};

} // namespace ids

#endif // MINIIDS_PARSING_PACKET_INFO_EXTRACTOR_H