#ifndef MINIIDS_PARSING_RULE_MATCHER_H
#define MINIIDS_PARSING_RULE_MATCHER_H

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <regex>
#include <optional>
#include "../ids/common.h"
#include "../../src/core/config.h"
#include "../../src/core/packet.h"
#include "parser.h"
#include "info_extractor.h"

namespace ids {

/**
 * @brief Rule match result
 */
struct RuleMatch {
    const Rule* rule;
    std::string message;
    uint32_t sid;
    uint32_t rev;
    std::string classtype;
    std::unordered_map<std::string, std::string> matched_content;
    
    RuleMatch() : rule(nullptr), sid(0), rev(0) {}
};

/**
 * @brief Rule matching engine for evaluating rules against packets
 */
class RuleMatcher {
public:
    /**
     * @brief Constructor
     */
    RuleMatcher();
    
    /**
     * @brief Destructor
     */
    ~RuleMatcher();
    
    /**
     * @brief Initialize rule matcher
     * @param config Configuration
     * @return true if successful, false otherwise
     */
    bool initialize(const Config& config);
    
    /**
     * @brief Shutdown rule matcher
     */
    void shutdown();
    
    /**
     * @brief Add rules to matcher
     * @param rules Vector of rules to add
     */
    void addRules(const std::vector<Rule>& rules);
    
    /**
     * @brief Clear all rules
     */
    void clearRules();
    
    /**
     * @brief Match packet against all rules
     * @param packet Packet to match
     * @return Vector of rule matches
     */
    std::vector<RuleMatch> matchPacket(const Packet& packet);
    
    /**
     * @brief Check if packet matches specific rule
     * @param packet Packet to check
     * @param rule Rule to match against
     * @return RuleMatch if matched, empty optional otherwise
     */
    std::optional<RuleMatch> matchRule(const Packet& packet, const Rule& rule);
    
    /**
     * @brief Get number of loaded rules
     * @return Rule count
     */
    size_t getRuleCount() const;
    
    /**
     * @brief Get statistics
     * @return Map of statistics
     */
    std::unordered_map<std::string, uint64_t> getStats() const;
    
    /**
     * @brief Reset statistics
     */
    void resetStats();

private:
    /**
     * @brief Check protocol match
     * @param packet_info Packet information to check
     * @param rule Rule with protocol condition
     * @return true if protocol matches, false otherwise
     */
    bool checkProtocol(const PacketInfo& packet_info, const Rule& rule);
    
    /**
     * @brief Check IP address match
     * @param packet_ip Packet IP address
     * @param rule_ip Rule IP pattern
     * @param is_source Whether this is source IP check
     * @return true if IP matches, false otherwise
     */
    bool checkIPAddress(const std::string& packet_ip, const std::string& rule_ip, bool is_source);
    
    /**
     * @brief Check port match
     * @param packet_port Packet port
     * @param rule_port Rule port pattern
     * @param is_source Whether this is source port check
     * @return true if port matches, false otherwise
     */
    bool checkPort(uint16_t packet_port, const std::string& rule_port, bool is_source);
    
    /**
     * @brief Check flow direction
     * @param packet_info Packet information to check
     * @param rule Rule with flow conditions
     * @return true if flow matches, false otherwise
     */
    bool checkFlow(const PacketInfo& packet_info, const Rule& rule);
    
    /**
     * @brief Check content options
     * @param packet Packet to check
     * @param rule Rule with content options
     * @param match Reference to match result for storing matched content
     * @return true if content matches, false otherwise
     */
    bool checkContent(const Packet& packet, const Rule& rule, RuleMatch& match);
    
    /**
     * @brief Check individual content option
     * @param packet Packet data
     * @param key Content key
     * @param value Content value
     * @param match Reference to match result
     * @return true if content matches, false otherwise
     */
    bool checkContentOption(const Packet& packet, const std::string& key, 
                           const std::string& value, RuleMatch& match);
    
    /**
     * @brief Check threshold conditions
     * @param rule Rule with threshold
     * @param src_ip Source IP for tracking
     * @param dst_ip Destination IP for tracking
     * @return true if threshold condition met, false otherwise
     */
    bool checkThreshold(const Rule& rule, const std::string& src_ip, const std::string& dst_ip);
    
    /**
     * @brief Update threshold counters
     * @param rule Rule with threshold
     * @param src_ip Source IP for tracking
     * @param dst_ip Destination IP for tracking
     */
    void updateThresholdCounters(const Rule& rule, const std::string& src_ip, const std::string& dst_ip);
    
    /**
     * @brief Check if IP matches rule pattern
     * @param ip IP address to check
     * @param pattern Rule pattern (e.g., "any", "192.168.1.0/24", "10.0.0.1")
     * @return true if matches, false otherwise
     */
    bool matchIPPattern(const std::string& ip, const std::string& pattern);
    
    /**
     * @brief Check if port matches rule pattern
     * @param port Port to check
     * @param pattern Rule pattern (e.g., "any", "80", "1024:65535")
     * @return true if matches, false otherwise
     */
    bool matchPortPattern(uint16_t port, const std::string& pattern);
    
    /**
     * @brief Parse CIDR notation
     * @param cidr CIDR string (e.g., "192.168.1.0/24")
     * @param network Output network address
     * @param mask Output network mask
     * @return true if parsed successfully, false otherwise
     */
    bool parseCIDR(const std::string& cidr, uint32_t& network, uint32_t& mask);
    
    /**
     * @brief Convert IP string to integer
     * @param ip IP address string
     * @return IP as 32-bit integer, 0 on error
     */
    uint32_t ipToInt(const std::string& ip);
    
    // Member variables
    std::vector<Rule> rules_;
    std::unordered_map<std::string, uint64_t> stats_;
    PacketInfoExtractor packet_extractor_;
    
    // Threshold tracking
    struct ThresholdCounter {
        uint64_t count;
        std::chrono::steady_clock::time_point last_update;
        
        ThresholdCounter() : count(0) {}
    };
    
    std::unordered_map<std::string, ThresholdCounter> threshold_counters_;
    bool initialized_;
};

} // namespace ids

#endif // MINIIDS_PARSING_RULE_MATCHER_H