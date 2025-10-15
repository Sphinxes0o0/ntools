#include "../../include/parsing/info_extractor.h"
#include <iostream>
#include <sstream>
#include <iomanip>

namespace ids {

PacketInfoExtractor::PacketInfoExtractor() {
    // Constructor - no special initialization needed
}

PacketInfo PacketInfoExtractor::extractInfo(const Packet& packet) {
    PacketInfo info;
    info.raw_packet = &packet;
    
    if (!packet.isValid()) {
        return info;
    }
    
    // Extract basic information
    info.protocol = getProtocol(packet);
    info.src_ip = getSourceIP(packet);
    info.dst_ip = getDestinationIP(packet);
    
    // Extract transport layer information
    if (info.isTCP()) {
        info.src_port = getSourcePort(packet);
        info.dst_port = getDestinationPort(packet);
        info.tcp_flags = getTCPFlags(packet);
        
        // For TCP, we can extract additional info using TCPParser
        auto tcp_result = tcp_parser_.parse(packet.data);
        if (tcp_result.is_valid) {
            // Extract sequence and acknowledgment numbers from TCP header
            // These would be available in the TCPParser result
        }
    } else if (info.isUDP()) {
        info.src_port = getSourcePort(packet);
        info.dst_port = getDestinationPort(packet);
    }
    
    return info;
}

bool PacketInfoExtractor::isTCP(const Packet& packet) const {
    return getProtocol(packet) == RuleProtocol::TCP;
}

bool PacketInfoExtractor::isUDP(const Packet& packet) const {
    return getProtocol(packet) == RuleProtocol::UDP;
}

bool PacketInfoExtractor::isICMP(const Packet& packet) const {
    return getProtocol(packet) == RuleProtocol::ICMP;
}

std::string PacketInfoExtractor::getSourceIP(const Packet& packet) const {
    if (!hasValidIPHeader(packet)) {
        return "";
    }
    
    size_t eth_len = getEthernetHeaderLength(packet);
    size_t ip_offset = eth_len + 12; // Source IP offset in IP header
    
    return extractIPv4Address(packet.data.data(), ip_offset);
}

std::string PacketInfoExtractor::getDestinationIP(const Packet& packet) const {
    if (!hasValidIPHeader(packet)) {
        return "";
    }
    
    size_t eth_len = getEthernetHeaderLength(packet);
    size_t ip_offset = eth_len + 16; // Destination IP offset in IP header
    
    return extractIPv4Address(packet.data.data(), ip_offset);
}

uint16_t PacketInfoExtractor::getSourcePort(const Packet& packet) const {
    if (!hasValidIPHeader(packet)) {
        return 0;
    }
    
    size_t eth_len = getEthernetHeaderLength(packet);
    size_t ip_len = getIPHeaderLength(packet);
    size_t transport_offset = eth_len + ip_len;
    
    if (transport_offset + 2 > packet.length) {
        return 0;
    }
    
    return packet.extractUint16(transport_offset);
}

uint16_t PacketInfoExtractor::getDestinationPort(const Packet& packet) const {
    if (!hasValidIPHeader(packet)) {
        return 0;
    }
    
    size_t eth_len = getEthernetHeaderLength(packet);
    size_t ip_len = getIPHeaderLength(packet);
    size_t transport_offset = eth_len + ip_len + 2; // Destination port offset
    
    if (transport_offset + 2 > packet.length) {
        return 0;
    }
    
    return packet.extractUint16(transport_offset);
}

TCPFlags PacketInfoExtractor::getTCPFlags(const Packet& packet) const {
    TCPFlags flags = {};
    
    if (!isTCP(packet)) {
        return flags;
    }
    
    // Parse TCP flags manually since TCPParser::parse is not const
    size_t eth_len = getEthernetHeaderLength(packet);
    size_t ip_len = getIPHeaderLength(packet);
    size_t tcp_offset = eth_len + ip_len;
    
    if (tcp_offset + 13 >= packet.length) {
        return flags;
    }
    
    // TCP flags are in byte 13 of TCP header
    uint8_t tcp_flags_byte = packet.data[tcp_offset + 13];
    
    flags.fin = (tcp_flags_byte & 0x01) != 0;
    flags.syn = (tcp_flags_byte & 0x02) != 0;
    flags.rst = (tcp_flags_byte & 0x04) != 0;
    flags.psh = (tcp_flags_byte & 0x08) != 0;
    flags.ack = (tcp_flags_byte & 0x10) != 0;
    flags.urg = (tcp_flags_byte & 0x20) != 0;
    flags.ece = (tcp_flags_byte & 0x40) != 0;
    flags.cwr = (tcp_flags_byte & 0x80) != 0;
    
    return flags;
}

std::string PacketInfoExtractor::extractIPv4Address(const uint8_t* data, size_t offset) const {
    std::stringstream ss;
    
    for (int i = 0; i < 4; i++) {
        if (i > 0) ss << ".";
        ss << static_cast<int>(data[offset + i]);
    }
    
    return ss.str();
}

uint8_t PacketInfoExtractor::getIPProtocol(const Packet& packet) const {
    if (!hasValidIPHeader(packet)) {
        return 0;
    }
    
    size_t eth_len = getEthernetHeaderLength(packet);
    size_t protocol_offset = eth_len + 9; // Protocol field in IP header
    
    if (protocol_offset >= packet.length) {
        return 0;
    }
    
    return packet.data[protocol_offset];
}

size_t PacketInfoExtractor::getIPHeaderLength(const Packet& packet) const {
    if (!hasValidIPHeader(packet)) {
        return 0;
    }
    
    size_t eth_len = getEthernetHeaderLength(packet);
    size_t ihl_offset = eth_len; // IP header length field
    
    if (ihl_offset >= packet.length) {
        return 0;
    }
    
    // IP header length is in the lower 4 bits of the first byte
    uint8_t ihl = packet.data[ihl_offset] & 0x0F;
    return ihl * 4; // Convert from 32-bit words to bytes
}

size_t PacketInfoExtractor::getEthernetHeaderLength(const Packet& packet) const {
    // Standard Ethernet header is 14 bytes
    // We could check for 802.1Q VLAN tags, but for now assume standard Ethernet
    return 14;
}

bool PacketInfoExtractor::hasValidIPHeader(const Packet& packet) const {
    size_t eth_len = getEthernetHeaderLength(packet);
    
    // Check if we have enough data for IP header
    if (packet.length < eth_len + 20) { // Minimum IP header is 20 bytes
        return false;
    }
    
    // Check IP version (should be 4 for IPv4)
    uint8_t version = (packet.data[eth_len] >> 4) & 0x0F;
    return version == 4;
}

} // namespace ids