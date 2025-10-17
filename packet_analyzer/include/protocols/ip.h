#ifndef PROTOCOLS_IP_H
#define PROTOCOLS_IP_H

#include "protocol_parser.h"
#include <cstdint>

namespace ids {

struct IPv4Header {
    uint8_t  version_ihl;        // 版本和头部长度 (4位版本 + 4位IHL)
    uint8_t  type_of_service;    // 服务类型
    uint16_t total_length;       // 总长度
    uint16_t identification;     // 标识符
    uint16_t flags_fragment;     // 标志和分片偏移
    uint8_t  time_to_live;       // 生存时间
    uint8_t  protocol;           // 协议类型
    uint16_t header_checksum;    // 头部校验和
    uint32_t source_address;     // 源地址
    uint32_t destination_address;// 目的地址
} __attribute__((packed));

class IPParser : public ProtocolParser {
public:
    IPParser();
    ~IPParser() override = default;
    ParsingResult parse(const std::vector<uint8_t>& packet_data) override;
    ProtocolType get_protocol_type() const override { return ProtocolType::IP; }
    std::string get_name() const override { return "IP"; }
    bool can_parse(const std::vector<uint8_t>& packet_data) const override;

private:
    std::string ip_address_to_string(uint32_t addr) const;
    std::string get_protocol_name(uint8_t protocol) const;
    uint8_t get_header_length(uint8_t version_ihl) const;
    bool is_valid_ip_header(const IPv4Header* header) const;
};

} // namespace ids

#endif // PROTOCOLS_IP_H