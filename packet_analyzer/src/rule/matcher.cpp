#include "../../include/rule/matcher.h"
#include <iostream>
#include <vector>
#include <memory>

namespace ids {

void RuleMatcher::addRule(std::shared_ptr<Rule> rule) {
    // Simplified implementation
}

void RuleMatcher::addRules(const std::vector<std::shared_ptr<Rule>>& rules) {
    // Simplified implementation
}

std::vector<std::shared_ptr<Rule>> RuleMatcher::match(const Packet& packet) const {
    // Simplified implementation
    return std::vector<std::shared_ptr<Rule>>();
}

} // namespace ids