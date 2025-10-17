#include "../../include/protocols/tcp.h"
#include <sstream>
#include <iomanip>

namespace ids {

TCPParser::TCPParser() = default;

bool TCPParser::can_parse(const std::vector<uint8_t>& packet_data) const {
    // For layered parsing, TCP parser should only check if it can parse TCP data
    // We assume the packet_data starts at the TCP header (after Ethernet and IP headers)
    // Minimal TCP header is 20 bytes
    if (packet_data.size() < 20) {
        return false;
    }

    return true;
}

ParsingResult TCPParser::parse(const std::vector<uint8_t>& packet_data) {
    ParsingResult result(ProtocolType::TCP, false);
    
    if (!can_parse(packet_data)) {
        result.description = "Invalid or incomplete TCP packet";
        return result;
    }

    TCPHeader tcp_header = parse_tcp_header(packet_data.data());

    result.is_valid = true;
    result.description = "TCP";
    result.findings.emplace_back("Source Port", std::to_string(tcp_header.src_port));
    result.findings.emplace_back("Destination Port", std::to_string(tcp_header.dst_port));
    result.findings.emplace_back("Sequence Number", std::to_string(tcp_header.seq_number));
    result.findings.emplace_back("Acknowledgment Number", std::to_string(tcp_header.ack_number));
    result.findings.emplace_back("Header Length", std::to_string(tcp_header.data_offset * 4) + " bytes");

    TCPFlags flags = parse_tcp_flags(tcp_header.flags);
    result.findings.emplace_back("Flags", format_flags(flags));
    result.findings.emplace_back("Window Size", std::to_string(tcp_header.window_size));
    std::stringstream checksum_ss;
    checksum_ss << "0x" << std::uppercase << std::hex << std::setfill('0') << std::setw(4) << tcp_header.checksum;
    result.findings.emplace_back("Checksum", checksum_ss.str());
    result.findings.emplace_back("Urgent Pointer", std::to_string(tcp_header.urgent_pointer));
    return result;
}

TCPHeader TCPParser::parse_tcp_header(const uint8_t* data) {
    TCPHeader header;
    
    // 解析端口号
    header.src_port = (data[0] << 8) | data[1];
    header.dst_port = (data[2] << 8) | data[3];
    
    // 解析序列号和确认号
    header.seq_number = (static_cast<uint32_t>(data[4]) << 24) |
                       (static_cast<uint32_t>(data[5]) << 16) |
                       (static_cast<uint32_t>(data[6]) << 8) |
                       static_cast<uint32_t>(data[7]);
    
    header.ack_number = (static_cast<uint32_t>(data[8]) << 24) |
                       (static_cast<uint32_t>(data[9]) << 16) |
                       (static_cast<uint32_t>(data[10]) << 8) |
                       static_cast<uint32_t>(data[11]);
    
    // 解析数据偏移量和标志位
    header.data_offset = (data[12] >> 4) & 0x0F;
    header.flags = data[13];
    
    // 解析窗口大小、校验和和紧急指针
    header.window_size = (data[14] << 8) | data[15];
    header.checksum = (data[16] << 8) | data[17];
    header.urgent_pointer = (data[18] << 8) | data[19];
    
    return header;
}

TCPFlags TCPParser::parse_tcp_flags(uint8_t flags) {
    TCPFlags tcp_flags;
    tcp_flags.fin = (flags & 0x01) != 0;
    tcp_flags.syn = (flags & 0x02) != 0;
    tcp_flags.rst = (flags & 0x04) != 0;
    tcp_flags.psh = (flags & 0x08) != 0;
    tcp_flags.ack = (flags & 0x10) != 0;
    tcp_flags.urg = (flags & 0x20) != 0;
    tcp_flags.ece = (flags & 0x40) != 0;
    tcp_flags.cwr = (flags & 0x80) != 0;
    
    return tcp_flags;
}

std::string TCPParser::format_flags(const TCPFlags& flags) {
    std::stringstream ss;
    ss << "FIN=" << flags.fin << ", "
       << "SYN=" << flags.syn << ", "
       << "RST=" << flags.rst << ", "
       << "PSH=" << flags.psh << ", "
       << "ACK=" << flags.ack << ", "
       << "URG=" << flags.urg << ", "
       << "ECE=" << flags.ece << ", "
       << "CWR=" << flags.cwr;
    return ss.str();
}

} // namespace ids