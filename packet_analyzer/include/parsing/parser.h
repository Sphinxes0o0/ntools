#ifndef MINIIDS_PARSING_RULE_PARSER_H
#define MINIIDS_PARSING_RULE_PARSER_H

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <regex>
#include "../ids/common.h"
#include "../../src/core/config.h"
#include "../../src/core/packet.h"

namespace ids {

/**
 * @brief Protocol type for rules
 */
enum class RuleProtocol {
    TCP,
    UDP,
    ICMP,
    IP,
    ANY
};

/**
 * @brief Flow direction for Suricata rules
 */
enum class FlowDirection {
    TO_SERVER,
    TO_CLIENT,
    BOTH,
    ESTABLISHED
};

/**
 * @brief Rule threshold configuration
 */
struct RuleThreshold {
    std::string type;
    std::string track;  // by_src, by_dst
    uint32_t count;
    uint32_t seconds;
    
    RuleThreshold() : count(0), seconds(0) {}
};

/**
 * @brief Rule options container
 */
struct RuleOptions {
    std::string msg;
    std::vector<FlowDirection> flow;
    RuleThreshold threshold;
    std::string classtype;
    uint32_t sid;
    uint32_t rev;
    std::unordered_map<std::string, std::string> content_options;
    
    RuleOptions() : sid(0), rev(1) {}
};

/**
 * @brief Complete rule definition
 */
struct Rule {
    RuleAction action;
    RuleProtocol protocol;
    std::string src_ip;
    std::string src_port;
    std::string dst_ip;
    std::string dst_port;
    RuleOptions options;
    std::string raw_rule;
    bool enabled;
    
    Rule() : action(RuleAction::ALERT), protocol(RuleProtocol::ANY), enabled(true) {}
};

/**
 * @brief Suricata rule parser class
 */
class RuleParser {
public:
    /**
     * @brief Constructor
     */
    RuleParser();
    
    /**
     * @brief Destructor
     */
    ~RuleParser();
    
    /**
     * @brief Initialize rule parser
     * @param config Configuration
     * @return true if successful, false otherwise
     */
    bool initialize(const Config& config);
    
    /**
     * @brief Shutdown rule parser
     */
    void shutdown();
    
    /**
     * @brief Load rules from file
     * @param file_path Path to rule file
     * @return Vector of parsed rules
     */
    std::vector<Rule> loadRulesFromFile(const std::string& file_path);
    
    /**
     * @brief Load rules from directory
     * @param dir_path Path to rules directory
     * @return Vector of parsed rules
     */
    std::vector<Rule> loadRulesFromDirectory(const std::string& dir_path);
    
    /**
     * @brief Parse single rule string
     * @param rule_str Rule string to parse
     * @return Parsed rule object
     */
    Rule parseRule(const std::string& rule_str);
    
    /**
     * @brief Get loaded rules count
     * @return Number of loaded rules
     */
    size_t getRuleCount() const;
    
    /**
     * @brief Get all loaded rules
     * @return Vector of all rules
     */
    std::vector<Rule> getAllRules() const;
    
    /**
     * @brief Clear all loaded rules
     */
    void clearRules();
    
    /**
     * @brief Validate rule syntax
     * @param rule_str Rule string to validate
     * @return true if valid, false otherwise
     */
    bool validateRule(const std::string& rule_str);
    
    /**
     * @brief Get parsing statistics
     * @return Map of statistics
     */
    std::unordered_map<std::string, uint64_t> getStats() const;

private:
    /**
     * @brief Parse rule header (action, protocol, addresses, ports)
     * @param rule Reference to rule object
     * @param header_str Header string
     */
    void parseRuleHeader(Rule& rule, const std::string& header_str);
    
    /**
     * @brief Parse rule options
     * @param rule Reference to rule object
     * @param options_str Options string
     */
    void parseRuleOptions(Rule& rule, const std::string& options_str);
    
    /**
     * @brief Parse flow option
     * @param rule Reference to rule object
     * @param flow_str Flow string
     */
    void parseFlowOption(Rule& rule, const std::string& flow_str);
    
    /**
     * @brief Parse threshold option
     * @param rule Reference to rule object
     * @param threshold_str Threshold string
     */
    void parseThresholdOption(Rule& rule, const std::string& threshold_str);
    
    /**
     * @brief Parse key-value option
     * @param rule Reference to rule object
     * @param key Option key
     * @param value Option value
     */
    void parseKeyValueOption(Rule& rule, const std::string& key, const std::string& value);
    
    /**
     * @brief Convert string to rule action
     * @param action_str Action string
     * @return RuleAction enum
     */
    RuleAction stringToAction(const std::string& action_str);
    
    /**
     * @brief Convert string to protocol
     * @param protocol_str Protocol string
     * @return RuleProtocol enum
     */
    RuleProtocol stringToProtocol(const std::string& protocol_str);
    
    /**
     * @brief Convert string to flow direction
     * @param flow_str Flow string
     * @return FlowDirection enum
     */
    FlowDirection stringToFlowDirection(const std::string& flow_str);
    
    /**
     * @brief Clean and normalize rule string
     * @param rule_str Raw rule string
     * @return Cleaned rule string
     */
    std::string cleanRuleString(const std::string& rule_str);
    
    // Member variables
    std::vector<Rule> rules_;
    std::unordered_map<std::string, uint64_t> stats_;
    std::regex rule_pattern_;
    std::regex option_pattern_;
    bool initialized_;
};

} // namespace ids

#endif // MINIIDS_PARSING_RULE_PARSER_H