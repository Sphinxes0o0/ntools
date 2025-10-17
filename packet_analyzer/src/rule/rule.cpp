#include "../../include/rule/rule.h"
#include <sstream>
#include <algorithm>
#include <cctype>

namespace ids {

Rule::Rule() : direction(RuleDirection::UNIDIRECTIONAL), action(RuleAction::ALERT), enabled(true) {
}

bool Rule::validate() const {
    // Basic validation
    return !protocol.empty() && !src_ip.empty() && !dst_ip.empty();
}

std::vector<std::string> Rule::getValidationErrors() const {
    std::vector<std::string> errors;
    
    if (protocol.empty()) {
        errors.push_back("Protocol is empty");
    }
    
    if (src_ip.empty()) {
        errors.push_back("Source IP is empty");
    }
    
    if (dst_ip.empty()) {
        errors.push_back("Destination IP is empty");
    }
    
    return errors;
}

std::string Rule::toString() const {
    std::ostringstream oss;
    
    // Action
    switch (action) {
        case RuleAction::ALERT:
            oss << "alert";
            break;
        case RuleAction::LOG:
            oss << "log";
            break;
        case RuleAction::DROP:
            oss << "drop";
            break;
        case RuleAction::PASS:
            oss << "pass";
            break;
        case RuleAction::REJECT:
            oss << "reject";
            break;
    }
    
    oss << " " << protocol << " " << src_ip << " " << src_port 
        << " -> " << dst_ip << " " << dst_port;
    
    oss << " (";
    for (size_t i = 0; i < options.size(); ++i) {
        if (i > 0) {
            oss << "; ";
        }
        if (options[i].negated) {
            oss << "!";
        }
        oss << options[i].keyword << ":" << options[i].value;
    }
    oss << ";)";
    
    return oss.str();
}

std::string Rule::toSnortFormat() const {
    return toString();
}

bool Rule::matchesProtocol(const std::string& proto) const {
    return protocol == "any" || protocol == proto;
}

bool Rule::matchesIP(const std::string& rule_ip, uint32_t packet_ip) const {
    // Simple implementation - in a real system, this would need to handle
    // IP ranges, CIDR notation, variables, etc.
    return rule_ip == "any" || rule_ip == "0.0.0.0" || 
           (rule_ip.find('/') == std::string::npos && rule_ip == utils::ipToString(packet_ip));
}

bool Rule::matchesPort(uint16_t rule_port, uint16_t packet_port) const {
    // Simple implementation - in a real system, this would need to handle
    // port ranges, lists, variables, etc.
    std::string rule_port_str = std::to_string(rule_port);
    std::string packet_port_str = std::to_string(packet_port);
    return src_port == "any" || dst_port == "any" || 
           src_port == rule_port_str || dst_port == packet_port_str;
}

} // namespace ids