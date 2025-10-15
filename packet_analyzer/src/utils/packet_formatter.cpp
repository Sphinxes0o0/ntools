#include "utils/packet_formatter.h"
#include <iomanip>
#include <sstream>
#include <arpa/inet.h>

namespace ids {

PacketFormatter::PacketFormatter() = default;
PacketFormatter::~PacketFormatter() = default;

std::string PacketFormatter::formatPacket(const Packet& packet, uint32_t packetNumber) {
    std::stringstream ss;
    ss << "========== 数据包 " << packetNumber << " ==========\n";
    
    // 显示数据包基本信息
    ss << "数据包长度: " << packet.length << " 字节\n";
    
    // Ethernet header解析
    if (packet.length >= 14) {
        formatEthernetHeader(packet, ss);
    } else {
        ss << "以太网头部: 数据包太短，无法解析以太网头部\n";
        return ss.str();
    }
    
    // IP header解析
    uint16_t etherType = (packet.data[12] << 8) | packet.data[13];
    if (etherType == 0x0800) {  // IPv4
        if (packet.length >= 20) {  // IP头部最小长度
            formatIPHeader(packet, ss);
            
            // 根据IP协议类型解析上层协议
            if (packet.length >= 34) {
                uint8_t ipProto = packet.data[23];
                switch (ipProto) {
                    case 6:  // TCP
                        formatTCPHeader(packet, ss);
                        break;
                    case 17:  // UDP
                        formatUDPHeader(packet, ss);
                        break;
                    case 1:  // ICMP
                        formatICMPHeader(packet, ss);
                        break;
                    default:
                        ss << "未知IP协议类型: " << static_cast<int>(ipProto) << "\n";
                        break;
                }
            } else {
                ss << "IP数据: 数据包太短，无法解析IP上层协议\n";
            }
        } else {
            ss << "IP头部: 数据包太短，无法解析IP头部\n";
        }
    } else if (etherType == 0x0806) {  // ARP
        formatARPHeader(packet, ss);
    } else {
        ss << "未知以太网类型: 0x" << std::hex << std::setfill('0') << std::setw(4) 
           << etherType << std::dec << "\n";
    }
    
    // 显示部分原始数据（前32字节）
    ss << "原始数据 (前32字节): ";
    size_t displayLength = std::min(static_cast<size_t>(32), packet.length);
    for (size_t i = 0; i < displayLength; ++i) {
        if (i % 16 == 0 && i > 0) {
            ss << "\n                  ";
        }
        ss << std::hex << std::setfill('0') << std::setw(2) 
           << static_cast<int>(packet.data[i]) << " ";
    }
    ss << std::dec << "\n";
    
    return ss.str();
}

void PacketFormatter::formatEthernetHeader(const Packet& packet, std::stringstream& ss) {
    ss << "以太网头部:\n";
    
    // 源MAC地址
    ss << "   源MAC地址: ";
    for (int i = 6; i < 12; i++) {
        if (i > 6) ss << ":";
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(packet.data[i]);
    }
    ss << "\n";
    
    // 目的MAC地址
    ss << "   目的MAC地址: ";
    for (int i = 0; i < 6; i++) {
        if (i > 0) ss << ":";
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(packet.data[i]);
    }
    ss << "\n";
    
    // 协议类型
    uint16_t etherType = (packet.data[12] << 8) | packet.data[13];
    ss << "   协议类型: 0x" << std::hex << std::setfill('0') << std::setw(4) << etherType << "\n";
    ss << std::dec;  // 重置为十进制
}

void PacketFormatter::formatIPHeader(const Packet& packet, std::stringstream& ss) {
    ss << "IP头部:\n";
    
    // 版本和首部长度
    uint8_t versionAndHeaderLength = packet.data[14];
    uint8_t version = versionAndHeaderLength >> 4;
    uint8_t headerLength = versionAndHeaderLength & 0x0F;
    ss << "   版本: " << static_cast<int>(version) << "\n";
    ss << "   首部长度: " << static_cast<int>(headerLength) << " DWORDS / " 
       << static_cast<int>(headerLength * 4) << " 字节\n";
    
    // 服务类型
    uint8_t tos = packet.data[15];
    ss << "   服务类型: " << static_cast<int>(tos) << "\n";
    
    // 总长度
    uint16_t totalLength = (packet.data[16] << 8) | packet.data[17];
    ss << "   总长度: " << totalLength << " 字节\n";
    
    // 标识符
    uint16_t identification = (packet.data[18] << 8) | packet.data[19];
    ss << "   标识符: " << identification << "\n";
    
    // 生存时间
    uint8_t ttl = packet.data[22];
    ss << "   生存时间: " << static_cast<int>(ttl) << "\n";
    
    // 协议
    uint8_t protocol = packet.data[23];
    ss << "   协议: " << static_cast<int>(protocol) << "\n";
    
    // 首部校验和
    uint16_t checksum = (packet.data[24] << 8) | packet.data[25];
    ss << "   首部校验和: " << checksum << "\n";
    
    // 源IP地址
    ss << "   源IP地址: " << static_cast<int>(packet.data[26]) << "."
       << static_cast<int>(packet.data[27]) << "."
       << static_cast<int>(packet.data[28]) << "."
       << static_cast<int>(packet.data[29]) << "\n";
    
    // 目的IP地址
    ss << "   目的IP地址: " << static_cast<int>(packet.data[30]) << "."
       << static_cast<int>(packet.data[31]) << "."
       << static_cast<int>(packet.data[32]) << "."
       << static_cast<int>(packet.data[33]) << "\n";
}

void PacketFormatter::formatTCPHeader(const Packet& packet, std::stringstream& ss) {
    // TCP头部从第34字节开始 (14 Ethernet + 20 IP)
    if (packet.length < 34) return;
    
    uint8_t ipHeaderLength = (packet.data[14] & 0x0F) * 4;
    size_t tcpOffset = 14 + ipHeaderLength;
    
    if (packet.length < tcpOffset + 20) return;  // Minimum TCP header size
    
    ss << "TCP头部:\n";
    
    // 源端口
    uint16_t srcPort = (packet.data[tcpOffset] << 8) | packet.data[tcpOffset + 1];
    ss << "   源端口: " << srcPort << "\n";
    
    // 目的端口
    uint16_t dstPort = (packet.data[tcpOffset + 2] << 8) | packet.data[tcpOffset + 3];
    ss << "   目的端口: " << dstPort << "\n";
    
    // 序列号
    uint32_t seqNumber = (static_cast<uint32_t>(packet.data[tcpOffset + 4]) << 24) |
                         (static_cast<uint32_t>(packet.data[tcpOffset + 5]) << 16) |
                         (static_cast<uint32_t>(packet.data[tcpOffset + 6]) << 8) |
                         static_cast<uint32_t>(packet.data[tcpOffset + 7]);
    ss << "   序列号: " << seqNumber << "\n";
    
    // 确认号
    uint32_t ackNumber = (static_cast<uint32_t>(packet.data[tcpOffset + 8]) << 24) |
                         (static_cast<uint32_t>(packet.data[tcpOffset + 9]) << 16) |
                         (static_cast<uint32_t>(packet.data[tcpOffset + 10]) << 8) |
                         static_cast<uint32_t>(packet.data[tcpOffset + 11]);
    ss << "   确认号: " << ackNumber << "\n";
    
    // 头部长度
    uint8_t dataOffset = (packet.data[tcpOffset + 12] >> 4) & 0x0F;
    ss << "   头部长度: " << static_cast<int>(dataOffset) << " DWORDS / " 
       << static_cast<int>(dataOffset * 4) << " 字节\n";
    
    // 标志位
    uint8_t flags = packet.data[tcpOffset + 13];
    ss << "   标志位: "
       << "URG=" << ((flags & 0x20) ? "1" : "0") << ","
       << "ACK=" << ((flags & 0x10) ? "1" : "0") << ","
       << "PSH=" << ((flags & 0x08) ? "1" : "0") << ","
       << "RST=" << ((flags & 0x04) ? "1" : "0") << ","
       << "SYN=" << ((flags & 0x02) ? "1" : "0") << ","
       << "FIN=" << ((flags & 0x01) ? "1" : "0") << "\n";
    
    // 窗口大小
    uint16_t windowSize = (packet.data[tcpOffset + 14] << 8) | packet.data[tcpOffset + 15];
    ss << "   窗口大小: " << windowSize << "\n";
    
    // 校验和
    uint16_t tcpChecksum = (packet.data[tcpOffset + 16] << 8) | packet.data[tcpOffset + 17];
    ss << "   校验和: " << tcpChecksum << "\n";
    
    // 紧急指针
    uint16_t urgentPointer = (packet.data[tcpOffset + 18] << 8) | packet.data[tcpOffset + 19];
    ss << "   紧急指针: " << urgentPointer << "\n";
}

void PacketFormatter::formatUDPHeader(const Packet& packet, std::stringstream& ss) {
    // UDP头部从第34字节开始 (14 Ethernet + 20 IP)
    if (packet.length < 34) return;
    
    uint8_t ipHeaderLength = (packet.data[14] & 0x0F) * 4;
    size_t udpOffset = 14 + ipHeaderLength;
    
    if (packet.length < udpOffset + 8) return;  // UDP header size
    
    ss << "UDP头部:\n";
    
    // 源端口
    uint16_t srcPort = (packet.data[udpOffset] << 8) | packet.data[udpOffset + 1];
    ss << "   源端口: " << srcPort << "\n";
    
    // 目的端口
    uint16_t dstPort = (packet.data[udpOffset + 2] << 8) | packet.data[udpOffset + 3];
    ss << "   目的端口: " << dstPort << "\n";
    
    // UDP长度
    uint16_t udpLength = (packet.data[udpOffset + 4] << 8) | packet.data[udpOffset + 5];
    ss << "   UDP长度: " << udpLength << " 字节\n";
    
    // 校验和
    uint16_t checksum = (packet.data[udpOffset + 6] << 8) | packet.data[udpOffset + 7];
    ss << "   校验和: " << checksum << "\n";
}

void PacketFormatter::formatICMPHeader(const Packet& packet, std::stringstream& ss) {
    // ICMP头部从第34字节开始 (14 Ethernet + 20 IP)
    if (packet.length < 34) return;
    
    uint8_t ipHeaderLength = (packet.data[14] & 0x0F) * 4;
    size_t icmpOffset = 14 + ipHeaderLength;
    
    if (packet.length < icmpOffset + 8) return;  // Minimum ICMP header size for echo
    
    ss << "ICMP头部:\n";
    
    // ICMP类型
    uint8_t type = packet.data[icmpOffset];
    ss << "   类型: " << static_cast<int>(type) << "\n";
    
    // ICMP代码
    uint8_t code = packet.data[icmpOffset + 1];
    ss << "   代码: " << static_cast<int>(code) << "\n";
    
    // 校验和
    uint16_t checksum = (packet.data[icmpOffset + 2] << 8) | packet.data[icmpOffset + 3];
    ss << "   校验和: " << checksum << "\n";
    
    // 标识符和序列号 (对于Echo类型)
    if (type == 0 || type == 8) {  // Echo Reply or Echo Request
        uint16_t identifier = (packet.data[icmpOffset + 4] << 8) | packet.data[icmpOffset + 5];
        uint16_t seqNumber = (packet.data[icmpOffset + 6] << 8) | packet.data[icmpOffset + 7];
        ss << "   标识符: " << identifier << "\n";
        ss << "   序列号: " << seqNumber << "\n";
    }
}

void PacketFormatter::formatARPHeader(const Packet& packet, std::stringstream& ss) {
    if (packet.length < 42) return;  // Minimum ARP packet size
    
    ss << "ARP头部:\n";
    
    // 硬件类型
    uint16_t hwType = (packet.data[14] << 8) | packet.data[15];
    ss << "   硬件类型: " << hwType << "\n";
    
    // 协议类型
    uint16_t protoType = (packet.data[16] << 8) | packet.data[17];
    ss << "   协议类型: 0x" << std::hex << std::setfill('0') << std::setw(4) << protoType << "\n";
    
    // 硬件地址长度
    uint8_t hwAddrLen = packet.data[18];
    ss << "   硬件地址长度: " << static_cast<int>(hwAddrLen) << "\n";
    
    // 协议地址长度
    uint8_t protoAddrLen = packet.data[19];
    ss << "   协议地址长度: " << static_cast<int>(protoAddrLen) << "\n";
    
    // 操作码
    uint16_t opcode = (packet.data[20] << 8) | packet.data[21];
    ss << "   操作码: " << opcode << "\n";
    
    ss << std::dec;  // 重置为十进制
}

} // namespace ids