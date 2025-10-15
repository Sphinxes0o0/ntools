#include "../../include/parsing/matcher.h"
#include "../../include/utils/utils.h"
#include <iostream>
#include <chrono>
#include <sstream>

namespace ids {

RuleMatcher::RuleMatcher() 
    : initialized_(false) {
}

RuleMatcher::~RuleMatcher() {
    shutdown();
}

bool RuleMatcher::initialize(const Config& config) {
    if (initialized_) {
        return true;
    }
    
    try {
        // Initialize statistics
        stats_["packets_processed"] = 0;
        stats_["rules_matched"] = 0;
        stats_["alerts_generated"] = 0;
        stats_["threshold_checks"] = 0;
        
        initialized_ = true;
        std::cout << "RuleMatcher initialized" << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "RuleMatcher initialization error: " << e.what() << std::endl;
        return false;
    }
}

void RuleMatcher::shutdown() {
    rules_.clear();
    threshold_counters_.clear();
    stats_.clear();
    initialized_ = false;
}

void RuleMatcher::addRules(const std::vector<Rule>& rules) {
    rules_.insert(rules_.end(), rules.begin(), rules.end());
    stats_["rules_loaded"] = rules_.size();
}

void RuleMatcher::clearRules() {
    rules_.clear();
    threshold_counters_.clear();
    stats_["rules_loaded"] = 0;
}

std::vector<RuleMatch> RuleMatcher::matchPacket(const Packet& packet) {
    std::vector<RuleMatch> matches;
    
    if (!initialized_ || rules_.empty()) {
        return matches;
    }
    
    stats_["packets_processed"]++;
    
    for (const auto& rule : rules_) {
        if (!rule.enabled) {
            continue;
        }
        
        auto match = matchRule(packet, rule);
        if (match) {
            matches.push_back(*match);
            stats_["rules_matched"]++;
            
            if (rule.action == RuleAction::ALERT) {
                stats_["alerts_generated"]++;
            }
        }
    }
    
    return matches;
}

std::optional<RuleMatch> RuleMatcher::matchRule(const Packet& packet, const Rule& rule) {
    RuleMatch match;
    match.rule = &rule;
    match.sid = rule.options.sid;
    match.rev = rule.options.rev;
    match.classtype = rule.options.classtype;
    
    // Extract real packet information using PacketInfoExtractor
    PacketInfo packet_info = packet_extractor_.extractInfo(packet);
    
    // Check protocol using real packet data
    if (!checkProtocol(packet_info, rule)) {
        return std::nullopt;
    }
    
    // Check source IP using real packet data
    if (!checkIPAddress(packet_info.src_ip, rule.src_ip, true)) {
        return std::nullopt;
    }
    
    // Check destination IP using real packet data
    if (!checkIPAddress(packet_info.dst_ip, rule.dst_ip, false)) {
        return std::nullopt;
    }
    
    // Check source port using real packet data
    if (!checkPort(packet_info.src_port, rule.src_port, true)) {
        return std::nullopt;
    }
    
    // Check destination port using real packet data
    if (!checkPort(packet_info.dst_port, rule.dst_port, false)) {
        return std::nullopt;
    }
    
    // Check flow direction using real packet data
    if (!checkFlow(packet_info, rule)) {
        return std::nullopt;
    }
    
    // Check content options
    if (!checkContent(packet, rule, match)) {
        return std::nullopt;
    }
    
    // Check threshold conditions using real IP addresses
    if (!checkThreshold(rule, packet_info.src_ip, packet_info.dst_ip)) {
        return std::nullopt;
    }
    
    // Set message
    match.message = rule.options.msg;
    
    return match;
}

bool RuleMatcher::checkProtocol(const PacketInfo& packet_info, const Rule& rule) {
    // Use real packet protocol information from PacketInfo
    switch (rule.protocol) {
        case RuleProtocol::ANY:
            return true;
        case RuleProtocol::IP:
            // IP matches any IP-based protocol (TCP, UDP, ICMP)
            return packet_info.protocol != RuleProtocol::ANY;
        case RuleProtocol::TCP:
            return packet_info.isTCP();
        case RuleProtocol::UDP:
            return packet_info.isUDP();
        case RuleProtocol::ICMP:
            return packet_info.isICMP();
        default:
            return false;
    }
}

bool RuleMatcher::checkIPAddress(const std::string& packet_ip, const std::string& rule_ip, bool is_source) {
    if (rule_ip == "any") {
        return true;
    }
    
    // Use actual packet IP address extracted from packet data
    return matchIPPattern(packet_ip, rule_ip);
}

bool RuleMatcher::checkPort(uint16_t packet_port, const std::string& rule_port, bool is_source) {
    if (rule_port == "any") {
        return true;
    }
    
    // Use actual packet port extracted from packet data
    return matchPortPattern(packet_port, rule_port);
}

bool RuleMatcher::checkFlow(const PacketInfo& packet_info, const Rule& rule) {
    if (rule.options.flow.empty()) {
        return true;
    }
    
    // Enhanced flow checking using real packet information
    for (const auto& flow : rule.options.flow) {
        if (flow == FlowDirection::ESTABLISHED) {
            // For now, we'll return true for established if ACK flag is set
            // In a real implementation, this would use connection tracking
            if (packet_info.isTCP() && packet_info.tcp_flags.ack) {
                return true;
            }
        }
        if (flow == FlowDirection::TO_SERVER) {
            // Check if packet is going to server (typically destination port < 1024)
            if (packet_info.dst_port < 1024) {
                return true;
            }
        }
        if (flow == FlowDirection::TO_CLIENT) {
            // Check if packet is going to client (typically source port < 1024)
            if (packet_info.src_port < 1024) {
                return true;
            }
        }
        if (flow == FlowDirection::BOTH) {
            return true;
        }
    }
    
    return false;
}

bool RuleMatcher::checkContent(const Packet& packet, const Rule& rule, RuleMatch& match) {
    if (rule.options.content_options.empty()) {
        return true;
    }
    
    for (const auto& [key, value] : rule.options.content_options) {
        if (!checkContentOption(packet, key, value, match)) {
            return false;
        }
    }
    
    return true;
}

bool RuleMatcher::checkContentOption(const Packet& packet, const std::string& key, 
                                   const std::string& value, RuleMatch& match) {
    // Simplified content checking - in a real implementation, this would
    // search for patterns in packet payload and handle various content modifiers
    
    // For now, we'll just check if the key exists and store it
    match.matched_content[key] = value;
    return true;
}

bool RuleMatcher::checkThreshold(const Rule& rule, const std::string& src_ip, const std::string& dst_ip) {
    if (rule.options.threshold.type.empty()) {
        return true; // No threshold configured
    }
    
    stats_["threshold_checks"]++;
    
    std::string counter_key;
    if (rule.options.threshold.track == "by_src") {
        counter_key = "src:" + src_ip + ":" + std::to_string(rule.options.sid);
    } else if (rule.options.threshold.track == "by_dst") {
        counter_key = "dst:" + dst_ip + ":" + std::to_string(rule.options.sid);
    } else {
        // Default to by_src if not specified
        counter_key = "src:" + src_ip + ":" + std::to_string(rule.options.sid);
    }
    
    updateThresholdCounters(rule, src_ip, dst_ip);
    
    auto it = threshold_counters_.find(counter_key);
    if (it != threshold_counters_.end()) {
        if (it->second.count >= rule.options.threshold.count) {
            // Check if within time window
            auto now = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second.last_update).count();
            
            if (duration <= rule.options.threshold.seconds) {
                return true; // Threshold condition met
            } else {
                // Reset counter if time window expired
                it->second.count = 0;
            }
        }
    }
    
    return false;
}

void RuleMatcher::updateThresholdCounters(const Rule& rule, const std::string& src_ip, const std::string& dst_ip) {
    std::string counter_key;
    if (rule.options.threshold.track == "by_src") {
        counter_key = "src:" + src_ip + ":" + std::to_string(rule.options.sid);
    } else if (rule.options.threshold.track == "by_dst") {
        counter_key = "dst:" + dst_ip + ":" + std::to_string(rule.options.sid);
    } else {
        counter_key = "src:" + src_ip + ":" + std::to_string(rule.options.sid);
    }
    
    auto now = std::chrono::steady_clock::now();
    auto& counter = threshold_counters_[counter_key];
    
    // Reset counter if it's the first time or if time window expired
    if (counter.count == 0) {
        counter.last_update = now;
    } else {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(
            now - counter.last_update).count();
        
        if (duration > rule.options.threshold.seconds) {
            counter.count = 0;
            counter.last_update = now;
        }
    }
    
    counter.count++;
}

bool RuleMatcher::matchIPPattern(const std::string& ip, const std::string& pattern) {
    if (pattern == "any") {
        return true;
    }
    
    // Check for CIDR notation
    if (pattern.find('/') != std::string::npos) {
        uint32_t network, mask;
        if (parseCIDR(pattern, network, mask)) {
            uint32_t ip_int = ipToInt(ip);
            if (ip_int == 0) return false; // Invalid IP
            return (ip_int & mask) == network;
        }
        return false;
    }
    
    // Exact match
    return ip == pattern;
}

bool RuleMatcher::matchPortPattern(uint16_t port, const std::string& pattern) {
    if (pattern == "any") {
        return true;
    }
    
    // Check for port range
    size_t colon_pos = pattern.find(':');
    if (colon_pos != std::string::npos) {
        try {
            uint16_t start_port = static_cast<uint16_t>(std::stoul(pattern.substr(0, colon_pos)));
            uint16_t end_port = static_cast<uint16_t>(std::stoul(pattern.substr(colon_pos + 1)));
            return port >= start_port && port <= end_port;
        } catch (...) {
            return false;
        }
    }
    
    // Exact port match
    try {
        uint16_t pattern_port = static_cast<uint16_t>(std::stoul(pattern));
        return port == pattern_port;
    } catch (...) {
        return false;
    }
}

bool RuleMatcher::parseCIDR(const std::string& cidr, uint32_t& network, uint32_t& mask) {
    size_t slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        return false;
    }
    
    std::string ip_str = cidr.substr(0, slash_pos);
    std::string mask_str = cidr.substr(slash_pos + 1);
    
    network = ipToInt(ip_str);
    if (network == 0) {
        return false;
    }
    
    try {
        int prefix_len = std::stoi(mask_str);
        if (prefix_len < 0 || prefix_len > 32) {
            return false;
        }
        
        mask = (0xFFFFFFFFUL << (32 - prefix_len)) & 0xFFFFFFFFUL;
        return true;
    } catch (...) {
        return false;
    }
}

uint32_t RuleMatcher::ipToInt(const std::string& ip) {
    std::vector<std::string> octets = utils::split(ip, '.');
    if (octets.size() != 4) {
        return 0;
    }
    
    try {
        uint32_t result = 0;
        for (int i = 0; i < 4; i++) {
            int octet = std::stoi(octets[i]);
            if (octet < 0 || octet > 255) {
                return 0;
            }
            result = (result << 8) | static_cast<uint32_t>(octet);
        }
        return result;
    } catch (...) {
        return 0;
    }
}

size_t RuleMatcher::getRuleCount() const {
    return rules_.size();
}

std::unordered_map<std::string, uint64_t> RuleMatcher::getStats() const {
    return stats_;
}

void RuleMatcher::resetStats() {
    stats_.clear();
    stats_["packets_processed"] = 0;
    stats_["rules_matched"] = 0;
    stats_["alerts_generated"] = 0;
    stats_["threshold_checks"] = 0;
}

} // namespace ids