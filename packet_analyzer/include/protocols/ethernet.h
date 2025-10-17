#ifndef PROTOCOLS_ETHERNET_H
#define PROTOCOLS_ETHERNET_H

#include "protocol_parser.h"
#include <cstdint>

namespace ids {

// Ethernet头部结构
struct EthernetHeader {
    uint8_t dest_mac[6];      // 目标MAC地址
    uint8_t src_mac[6];       // 源MAC地址
    uint16_t ether_type;      // 以太网类型
} __attribute__((packed));

class EthernetParser : public ProtocolParser {
public:
    EthernetParser();
    ~EthernetParser() override = default;
    
    // 实现ProtocolParser接口
    ParsingResult parse(const std::vector<uint8_t>& packet_data) override;
    ProtocolType get_protocol_type() const override { return ProtocolType::ETHERNET; }
    std::string get_name() const override { return "Ethernet"; }
    bool can_parse(const std::vector<uint8_t>& packet_data) const override;
    
private:
    // 将MAC地址转换为字符串
    std::string mac_address_to_string(const uint8_t* mac) const;
    
    // 获取协议类型名称
    std::string get_protocol_type_name(uint16_t ether_type) const;
};

} // namespace ids

#endif // PROTOCOLS_ETHERNET_H