#include "../../include/protocols/ethernet.h"
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>

namespace ids {

EthernetParser::EthernetParser() = default;

bool EthernetParser::can_parse(const std::vector<uint8_t>& packet_data) const {
    // For layered parsing, Ethernet parser should only check if it can parse Ethernet data
    // Ethernet header is at least 14 bytes (6 bytes dest MAC + 6 bytes src MAC + 2 bytes type)
    return packet_data.size() >= 14;
}

ParsingResult EthernetParser::parse(const std::vector<uint8_t>& packet_data) {
    ParsingResult result(ProtocolType::ETHERNET, false);
    
    if (!can_parse(packet_data)) {
        result.description = "Invalid or incomplete Ethernet packet";
        return result;
    }
    
    // Parse Ethernet header (assuming packet_data starts at Ethernet header)
    const EthernetHeader* eth_header = reinterpret_cast<const EthernetHeader*>(packet_data.data());
    
    // Mark result as valid
    result.is_valid = true;
    
    // Build description
    std::string src_mac = mac_address_to_string(eth_header->src_mac);
    std::string dst_mac = mac_address_to_string(eth_header->dest_mac);
    
    std::stringstream ss;
    ss << dst_mac << " > " << src_mac << ", ethertype " << get_protocol_type_name(ntohs(eth_header->ether_type));
    result.description = ss.str();
    
    // Add detailed findings
    result.findings.emplace_back("Destination MAC", dst_mac);
    result.findings.emplace_back("Source MAC", src_mac);
    result.findings.emplace_back("EtherType", "0x" + format_hex(ntohs(eth_header->ether_type), 4));
    result.findings.emplace_back("Protocol", get_protocol_type_name(ntohs(eth_header->ether_type)));
    
    return result;
}

std::string EthernetParser::mac_address_to_string(const uint8_t* mac) const {
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(mac[0]);
    for (int i = 1; i < 6; ++i) {
        ss << ":" << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(mac[i]);
    }
    return ss.str();
}

std::string EthernetParser::get_protocol_type_name(uint16_t ether_type) const {
    switch (ether_type) {
        case 0x0800:
            return "IPv4";
        case 0x0806:
            return "ARP";
        case 0x86DD:
            return "IPv6";
        case 0x8100:
            return "VLAN";
        case 0x88CC:
            return "LLDP";
        case 0x888E:
            return "EAP";
        default:
            return "Unknown";
    }
}

} // namespace ids