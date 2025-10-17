#include "../../include/rule/matcher.h"
#include "../../include/protocols/ip.h"
#include "../../include/protocols/tcp.h"
#include <iostream>
#include <arpa/inet.h>

namespace ids {

std::vector<RuleMatch> RuleMatcher::match(const Packet& packet) const {
    std::vector<RuleMatch> matches;
    
    std::cout << "Matching packet: EtherType=0x" << std::hex << packet.protocol << std::dec << std::endl;
    
    // Check if we have IP header (assuming IPv4 for now)
    if (packet.length >= 14 + 20) { // Minimum Ethernet + IP header size
        // IP header starts after Ethernet header (14 bytes)
        size_t ip_offset = 14;
        
        // Extract basic IP information from raw packet data
        const uint8_t* ip_data = packet.data.data() + ip_offset;
        uint8_t version_ihl = ip_data[0];
        uint8_t ihl = version_ihl & 0x0F;  // IHL is in the lower 4 bits
        uint8_t protocol = ip_data[9];
        uint32_t src_ip = *reinterpret_cast<const uint32_t*>(ip_data + 12);
        uint32_t dst_ip = *reinterpret_cast<const uint32_t*>(ip_data + 16);
        
        // Convert to readable format
        char src_ip_str[INET_ADDRSTRLEN];
        char dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_ip, src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &dst_ip, dst_ip_str, INET_ADDRSTRLEN);
        
        std::cout << "IP Header: Protocol=" << static_cast<int>(protocol) 
                  << ", Src=" << src_ip_str << ", Dst=" << dst_ip_str << std::endl;
        
        // Check for transport layer header (TCP/UDP)
        if (protocol == 6 || protocol == 17) { // TCP or UDP
            size_t transport_offset = ip_offset + (ihl * 4);
            
            if (protocol == 6 && packet.length >= transport_offset + 20) { // TCP
                const uint8_t* tcp_data = packet.data.data() + transport_offset;
                uint16_t src_port = (static_cast<uint16_t>(tcp_data[0]) << 8) | 
                                    static_cast<uint16_t>(tcp_data[1]);
                uint16_t dst_port = (static_cast<uint16_t>(tcp_data[2]) << 8) | 
                                    static_cast<uint16_t>(tcp_data[3]);
                
                std::cout << "Transport: SrcPort=" << src_port 
                          << ", DstPort=" << dst_port << std::endl;
                
                // Now match against all rules
                for (const auto& rule : rules_) {
                    std::cout << "Checking rule: " << rule->id << " - " << rule->description << std::endl;
                    
                    // Check protocol
                    if (!rule->matchesProtocol(protocol == 6 ? "tcp" : "udp")) {
                        std::cout << "  Protocol mismatch: rule=" << rule->protocol << ", packet=" << (protocol == 6 ? "tcp" : "udp") << std::endl;
                        continue;
                    }

                    // Check source IP
                    if (!rule->matchesIP(rule->src_ip, src_ip)) {
                        std::cout << "  Source IP mismatch: rule=" << rule->src_ip << ", packet=" << src_ip_str << std::endl;
                        continue;
                    }

                    // Check destination IP
                    if (!rule->matchesIP(rule->dst_ip, dst_ip)) {
                        std::cout << "  Destination IP mismatch: rule=" << rule->dst_ip << ", packet=" << dst_ip_str << std::endl;
                        continue;
                    }

                    // Parse rule ports to numeric values
                    uint16_t rule_src_port = 0;
                    uint16_t rule_dst_port = 0;

                    try {
                        if (rule->src_port != "any") {
                            rule_src_port = static_cast<uint16_t>(std::stoi(rule->src_port));
                        }
                        
                        if (rule->dst_port != "any") {
                            rule_dst_port = static_cast<uint16_t>(std::stoi(rule->dst_port));
                        }
                    } catch (...) {
                        std::cout << "  Invalid port in rule" << std::endl;
                        continue;
                    }

                    // Check source port
                    if (rule_src_port != 0 && !rule->matchesPort(rule_src_port, src_port)) {
                        std::cout << "  Source port mismatch: rule=" << rule->src_port << ", packet=" << src_port << std::endl;
                        continue;
                    }

                    // Check destination port
                    if (rule_dst_port != 0 && !rule->matchesPort(rule_dst_port, dst_port)) {
                        std::cout << "  Destination port mismatch: rule=" << rule->dst_port << ", packet=" << dst_port << std::endl;
                        continue;
                    }

                    std::cout << "  Rule matched: " << rule->id << " - " << rule->description << std::endl;
                    matches.emplace_back(rule.get(), 1.0); // Confidence score of 1.0 for exact match
                }
            } else if (protocol == 17 && packet.length >= transport_offset + 8) { // UDP
                // For UDP, we'll use a simplified header parsing
                const uint8_t* udp_data = packet.data.data() + transport_offset;
                uint16_t src_port = (static_cast<uint16_t>(udp_data[0]) << 8) | 
                                    static_cast<uint16_t>(udp_data[1]);
                uint16_t dst_port = (static_cast<uint16_t>(udp_data[2]) << 8) | 
                                    static_cast<uint16_t>(udp_data[3]);

                std::cout << "Transport: SrcPort=" << src_port 
                          << ", DstPort=" << dst_port << std::endl;

                // Now match against all rules
                for (const auto& rule : rules_) {
                    std::cout << "Checking rule: " << rule->id << " - " << rule->description << std::endl;

                    // Check protocol
                    if (!rule->matchesProtocol(protocol == 17 ? "udp" : "tcp")) {
                        std::cout << "  Protocol mismatch: rule=" << rule->protocol << ", packet=" << (protocol == 17 ? "udp" : "tcp") << std::endl;
                        continue;
                    }

                    // Check source IP
                    if (!rule->matchesIP(rule->src_ip, src_ip)) {
                        std::cout << "  Source IP mismatch: rule=" << rule->src_ip << ", packet=" << src_ip_str << std::endl;
                        continue;
                    }

                    // Check destination IP
                    if (!rule->matchesIP(rule->dst_ip, dst_ip)) {
                        std::cout << "  Destination IP mismatch: rule=" << rule->dst_ip << ", packet=" << dst_ip_str << std::endl;
                        continue;
                    }

                    // Parse rule ports to numeric values
                    uint16_t rule_src_port = 0;
                    uint16_t rule_dst_port = 0;

                    try {
                        if (rule->src_port != "any") {
                            rule_src_port = static_cast<uint16_t>(std::stoi(rule->src_port));
                        }

                        if (rule->dst_port != "any") {
                            rule_dst_port = static_cast<uint16_t>(std::stoi(rule->dst_port));
                        }
                    } catch (...) {
                        std::cout << "  Invalid port in rule" << std::endl;
                        continue;
                    }

                    // Check source port
                    if (rule_src_port != 0 && !rule->matchesPort(rule_src_port, src_port)) {
                        std::cout << "  Source port mismatch: rule=" << rule->src_port << ", packet=" << src_port << std::endl;
                        continue;
                    }
                    
                    // Check destination port
                    if (rule_dst_port != 0 && !rule->matchesPort(rule_dst_port, dst_port)) {
                        std::cout << "  Destination port mismatch: rule=" << rule->dst_port << ", packet=" << dst_port << std::endl;
                        continue;
                    }

                    std::cout << "  Rule matched: " << rule->id << " - " << rule->description << std::endl;
                    matches.emplace_back(rule.get(), 1.0); // Confidence score of 1.0 for exact match
                }
            }
        } else {
            // Non-TCP/UDP protocols
            std::cout << "Non-TCP/UDP protocol: " << static_cast<int>(protocol) << std::endl;

            // Match against rules without port checking
            for (const auto& rule : rules_) {
                std::cout << "Checking rule: " << rule->id << " - " << rule->description << std::endl;
                // Check protocol
                if (!rule->matchesProtocol("ip")) {
                    std::cout << "  Protocol mismatch: rule=" << rule->protocol << ", packet=ip" << std::endl;
                    continue;
                }
                // Check source IP
                if (!rule->matchesIP(rule->src_ip, src_ip)) {
                    std::cout << "  Source IP mismatch: rule=" << rule->src_ip << ", packet=" << src_ip_str << std::endl;
                    continue;
                }
                // Check destination IP
                if (!rule->matchesIP(rule->dst_ip, dst_ip)) {
                    std::cout << "  Destination IP mismatch: rule=" << rule->dst_ip << ", packet=" << dst_ip_str << std::endl;
                    continue;
                }
                std::cout << "  Rule matched: " << rule->id << " - " << rule->description << std::endl;
                matches.emplace_back(rule.get(), 1.0); // Confidence score of 1.0 for exact match
            }
        }
    }

    std::cout << "Matched " << matches.size() << " rules" << std::endl;
    return matches;
}

void RuleMatcher::addRule(std::shared_ptr<Rule> rule) {
    rules_.push_back(rule);
}

void RuleMatcher::addRules(const std::vector<std::shared_ptr<Rule>>& rules) {
    for (const auto& rule : rules) {
        addRule(rule);
    }
}

std::vector<RuleMatch> RuleMatcher::match(const Packet& packet, RuleAction action) const {
    std::vector<RuleMatch> matches;

    // Filter matches by action
    std::vector<RuleMatch> all_matches = match(packet);
    for (const auto& match : all_matches) {
        if (match.rule && match.rule->action == action) {
            matches.push_back(match);
        }
    }

    return matches;
}

const std::vector<std::shared_ptr<Rule>>& RuleMatcher::getRules() const {
    return rules_;
}

void RuleMatcher::clear() {
    rules_.clear();
}

size_t RuleMatcher::size() const {
    return rules_.size();
}

} // namespace ids