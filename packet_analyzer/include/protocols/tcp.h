#ifndef PROTOCOLS_TCP_PARSER_H
#define PROTOCOLS_TCP_PARSER_H

#include "protocol_parser.h"
#include <cstdint>
#include <vector>

namespace ids {

// TCP头部结构
struct TCPHeader {
    uint16_t src_port;          // 源端口
    uint16_t dst_port;          // 目标端口
    uint32_t seq_number;        // 序列号
    uint32_t ack_number;        // 确认号
    uint8_t data_offset;        // 数据偏移量（头部长度）
    uint8_t flags;              // 标志位
    uint16_t window_size;       // 窗口大小
    uint16_t checksum;          // 校验和
    uint16_t urgent_pointer;    // 紧急指针
};

// TCP标志位
struct TCPFlags {
    bool fin;  // 结束位
    bool syn;  // 同步位
    bool rst;  // 重置位
    bool psh;  // 推送位
    bool ack;  // 确认位
    bool urg;  // 紧急位
    bool ece;  // ECN-Echo
    bool cwr;  // 拥塞窗口减少
};

class TCPParser : public ProtocolParser {
public:
    TCPParser();
    ~TCPParser() override = default;
    
    // 实现ProtocolParser接口
    ParsingResult parse(const std::vector<uint8_t>& packet_data) override;
    ProtocolType get_protocol_type() const override { return ProtocolType::TCP; }
    std::string get_name() const override { return "TCP"; }
    bool can_parse(const std::vector<uint8_t>& packet_data) const override;
    
private:
    // 解析TCP头部
    TCPHeader parse_tcp_header(const uint8_t* data);
    
    // 解析TCP标志位
    TCPFlags parse_tcp_flags(uint8_t flags);
    
    // 格式化标志位为字符串
    std::string format_flags(const TCPFlags& flags);
};

} // namespace ids

#endif // PARSING_TCP_PARSER_H