#ifndef RULE_H
#define RULE_H

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include "ids/common.h"

namespace ids {

/**
 * @brief Rule option structure
 */
struct RuleOption {
    std::string keyword;
    std::string value;
    bool negated;

    RuleOption() : negated(false) {}
    RuleOption(const std::string& keyword, const std::string& value, bool negated = false)
        : keyword(keyword), value(value), negated(negated) {}
};

/**
 * @brief Complete rule definition
 */
class Rule {
public:
    std::string id;
    std::string description;
    std::string protocol;
    std::string src_ip;
    std::string dst_ip;
    std::string src_port;
    std::string dst_port;
    RuleDirection direction;
    std::vector<RuleOption> options;
    RuleAction action;
    bool enabled;
    std::unordered_map<std::string, std::string> metadata;

    Rule();
    bool validate() const;
    std::vector<std::string> getValidationErrors() const;
    std::string toString() const;
    std::string toSnortFormat() const;
    bool matchesProtocol(const std::string& proto) const;
    bool matchesIP(const std::string& rule_ip, uint32_t packet_ip) const;
    bool matchesPort(uint16_t rule_port, uint16_t packet_port) const;
};

/**
 * @brief Rule match result
 */
struct RuleMatch {
    const Rule* rule;
    double confidence;
    std::string matched_content;
    std::unordered_map<std::string, std::string> details;
    std::chrono::steady_clock::time_point match_time;
    RuleMatch() : rule(nullptr), confidence(0.0) {}
    RuleMatch(const Rule* r, double conf) : rule(r), confidence(conf) {}
};

} // namespace ids

#endif // RULE_H