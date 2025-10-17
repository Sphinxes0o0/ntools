#include "../../include/rule/matcher.h"
#include <iostream>
#include <vector>
#include <memory>

namespace ids {

void RuleMatcher::addRule(std::shared_ptr<Rule> rule) {
    if (rule) {
        rules_.push_back(rule);
    }
}

void RuleMatcher::addRules(const std::vector<std::shared_ptr<Rule>>& rules) {
    for (const auto& rule : rules) {
        addRule(rule);
    }
}

std::vector<RuleMatch> RuleMatcher::match(const Packet& packet) const {
    std::vector<RuleMatch> matches;
    
    // For now, just return empty matches
    // In a real implementation, this would check the packet against all rules
    // and return matches with appropriate confidence scores
    
    // This is a simplified implementation for demonstration
    // A full implementation would:
    // 1. Parse the packet to extract protocol, IPs, ports, etc.
    // 2. Check each rule against the packet data
    // 3. Return matches with appropriate confidence scores
    
    // Suppress unused parameter warning
    (void)packet;

    return matches;
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