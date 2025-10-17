#include "../../include/rule/rule.h"
#include "../../include/utils/utils.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <arpa/inet.h>

namespace ids {

Rule::Rule() : direction(RuleDirection::UNIDIRECTIONAL), 
               action(RuleAction::ALERT), 
               enabled(true) {
}

bool Rule::validate() const {
    std::vector<std::string> validation_errors;
    validation_errors.clear();

    if (id.empty()) {
        validation_errors.push_back("Rule must have an ID (sid option)");
    }

    if (description.empty()) {
        validation_errors.push_back("Rule must have a description (msg option)");
    }

    if (protocol.empty()) {
        validation_errors.push_back("Rule must specify a protocol");
    } else {
        // Check if protocol is valid
        std::string lower_protocol = protocol;
        std::transform(lower_protocol.begin(), lower_protocol.end(), lower_protocol.begin(), ::tolower);
        if (lower_protocol != "tcp" && lower_protocol != "udp" && lower_protocol != "icmp" && lower_protocol != "ip") {
            validation_errors.push_back("Invalid protocol: " + protocol);
        }
    }

    if (src_ip.empty()) {
        validation_errors.push_back("Rule must specify a source IP");
    }

    if (dst_ip.empty()) {
        validation_errors.push_back("Rule must specify a destination IP");
    }

    if (src_port.empty()) {
        validation_errors.push_back("Rule must specify a source port");
    }

    if (dst_port.empty()) {
        validation_errors.push_back("Rule must specify a destination port");
    }

    return validation_errors.empty();
}

std::vector<std::string> Rule::getValidationErrors() const {
    std::vector<std::string> validation_errors;

    if (id.empty()) {
        validation_errors.push_back("Rule must have an ID (sid option)");
    }

    if (description.empty()) {
        validation_errors.push_back("Rule must have a description (msg option)");
    }
    
    if (protocol.empty()) {
        validation_errors.push_back("Rule must specify a protocol");
    } else {
        // Check if protocol is valid
        std::string lower_protocol = protocol;
        std::transform(lower_protocol.begin(), lower_protocol.end(), lower_protocol.begin(), ::tolower);
        if (lower_protocol != "tcp" && lower_protocol != "udp" && lower_protocol != "icmp" && lower_protocol != "ip") {
            validation_errors.push_back("Invalid protocol: " + protocol);
        }
    }

    if (src_ip.empty()) {
        validation_errors.push_back("Rule must specify a source IP");
    }

    if (dst_ip.empty()) {
        validation_errors.push_back("Rule must specify a destination IP");
    }

    if (src_port.empty()) {
        validation_errors.push_back("Rule must specify a source port");
    }
 
    if (dst_port.empty()) {
        validation_errors.push_back("Rule must specify a destination port");
    }

    return validation_errors;
}

std::string Rule::toString() const {
    std::stringstream ss;
    ss << "Rule[" << id << "]: " << description 
       << " (" << protocol << " " << src_ip << " " << src_port 
       << " -> " << dst_ip << " " << dst_port << ")";
    return ss.str();
}

std::string Rule::toSnortFormat() const {
    std::stringstream ss;
    // Map action to string
    std::string action_str = "alert";
    switch (action) {
        case RuleAction::ALERT:
            action_str = "alert";
            break;
        case RuleAction::DROP:
            action_str = "drop";
            break;
        case RuleAction::LOG:
            action_str = "log";
            break;
        case RuleAction::PASS:
            action_str = "pass";
            break;
        case RuleAction::REJECT:
            action_str = "reject";
            break;
    }

    ss << action_str << " " << protocol << " " << src_ip << " " << src_port 
       << " -> " << dst_ip << " " << dst_port << " (";

    // Add options
    for (size_t i = 0; i < options.size(); ++i) {
        if (i > 0) ss << "; ";
        ss << options[i].keyword << ":" << options[i].value;
    }
    ss << ";)";

    return ss.str();
}

bool Rule::matchesProtocol(const std::string& proto) const {
    std::string lower_rule_proto = protocol;
    std::string lower_packet_proto = proto;
    std::transform(lower_rule_proto.begin(), lower_rule_proto.end(), lower_rule_proto.begin(), ::tolower);
    std::transform(lower_packet_proto.begin(), lower_packet_proto.end(), lower_packet_proto.begin(), ::tolower);

    return lower_rule_proto == "ip" || lower_rule_proto == lower_packet_proto;
}

bool Rule::matchesIP(const std::string& rule_ip, uint32_t packet_ip) const {
    // Handle special cases
    if (rule_ip == "any") {
        return true;
    }

    // Handle CIDR notation
    size_t slash_pos = rule_ip.find('/');
    if (slash_pos != std::string::npos) {
        // CIDR notation
        std::string network = rule_ip.substr(0, slash_pos);
        std::string prefix_length_str = rule_ip.substr(slash_pos + 1);
        uint32_t network_ip = inet_addr(network.c_str());
        if (network_ip == INADDR_NONE) {
            return false;
        }
        int prefix_length = std::stoi(prefix_length_str);
        if (prefix_length < 0 || prefix_length > 32) {
            return false;
        }
        // Calculate subnet mask
        uint32_t mask = (prefix_length == 0) ? 0 : (0xFFFFFFFF << (32 - prefix_length));
        // Convert to host byte order for comparison
        uint32_t host_packet_ip = ntohl(packet_ip);
        uint32_t host_network_ip = ntohl(network_ip);
        // Check if packet IP is in the network range
        return (host_packet_ip & mask) == (host_network_ip & mask);
    } else {
        // Simple IP address
        uint32_t rule_ip_addr = inet_addr(rule_ip.c_str());
        return rule_ip_addr == packet_ip;
    }
}

bool Rule::matchesPort(uint16_t rule_port, uint16_t packet_port) const {
    return rule_port == 0 || rule_port == packet_port; // 0 means "any"
}

} // namespace ids