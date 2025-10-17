#include "../../include/protocols/ip.h"
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>

extern "C" {
    uint32_t ntohl(uint32_t netlong);
    uint16_t ntohs(uint16_t netshort);
}

namespace ids {

IPParser::IPParser() = default;

bool IPParser::can_parse(const std::vector<uint8_t>& packet_data) const {
    // For layered parsing, IP parser should only check if it can parse IP data
    // We assume the packet_data starts at the IP header (after Ethernet header)
    // Minimal IP header is 20 bytes
    if (packet_data.size() < 20) {
        return false;
    }

    // Check IP version
    uint8_t version = (packet_data[0] >> 4) & 0x0F;
    if (version != 4) { // IPv4
        return false;
    }

    return true;
}

ParsingResult IPParser::parse(const std::vector<uint8_t>& packet_data) {
    ParsingResult result(ProtocolType::IP, false);

    if (!can_parse(packet_data)) {
        result.description = "Invalid or incomplete IP packet";
        return result;
    }

    // IP header starts at the beginning of packet_data
    const IPv4Header* ip_header = reinterpret_cast<const IPv4Header*>(packet_data.data());

    // Validate IP header
    if (!is_valid_ip_header(ip_header)) {
        result.description = "Invalid IP header";
        return result;
    }

    // Mark result as valid
    result.is_valid = true;

    // Build description without protocol name to avoid duplication in logs
    std::string src_ip = ip_address_to_string(ntohl(ip_header->source_address));
    std::string dst_ip = ip_address_to_string(ntohl(ip_header->destination_address));

    std::stringstream ss;
    ss << "IP " << src_ip << " > " << dst_ip;
    result.description = ss.str();

    // Add detailed findings
    result.findings.emplace_back("Version", std::to_string((ip_header->version_ihl >> 4) & 0x0F));
    result.findings.emplace_back("Header Length", std::to_string(get_header_length(ip_header->version_ihl)) + " bytes");
    result.findings.emplace_back("Type of Service", std::to_string(ip_header->type_of_service));
    result.findings.emplace_back("Total Length", std::to_string(ntohs(ip_header->total_length)));
    result.findings.emplace_back("Identification", "0x" + format_hex(ntohs(ip_header->identification), 4));
    result.findings.emplace_back("Flags", std::to_string((ntohs(ip_header->flags_fragment) >> 13) & 0x07));
    result.findings.emplace_back("Fragment Offset", std::to_string(ntohs(ip_header->flags_fragment) & 0x1FFF));
    result.findings.emplace_back("Time to Live", std::to_string(ip_header->time_to_live));
    result.findings.emplace_back("Protocol", std::to_string(ip_header->protocol) + " (" + get_protocol_name(ip_header->protocol) + ")");
    result.findings.emplace_back("Header Checksum", "0x" + format_hex(ntohs(ip_header->header_checksum), 4));
    result.findings.emplace_back("Source Address", src_ip);
    result.findings.emplace_back("Destination Address", dst_ip);

    return result;
}

std::string IPParser::ip_address_to_string(uint32_t addr) const {
    std::stringstream ss;
    ss << ((addr >> 24) & 0xFF) << "."
       << ((addr >> 16) & 0xFF) << "."
       << ((addr >> 8) & 0xFF) << "."
       << (addr & 0xFF);
    return ss.str();
}

std::string IPParser::get_protocol_name(uint8_t protocol) const {
    switch (protocol) {
        case 1:
            return "ICMP";
        case 6:
            return "TCP";
        case 17:
            return "UDP";
        case 2:
            return "IGMP";
        case 89:
            return "OSPF";
        default:
            return "Unknown";
    }
}

uint8_t IPParser::get_header_length(uint8_t version_ihl) const {
    return (version_ihl & 0x0F) * 4;
}

bool IPParser::is_valid_ip_header(const IPv4Header* header) const {
    // Check IP version
    uint8_t version = (header->version_ihl >> 4) & 0x0F;
    if (version != 4) {
        return false;
    }

    // Check header length is valid (at least 20 bytes)
    uint8_t ihl = header->version_ihl & 0x0F;
    if (ihl < 5) {
        return false;
    }

    return true;
}

} // namespace ids