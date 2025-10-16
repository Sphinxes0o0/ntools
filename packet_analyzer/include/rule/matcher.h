#ifndef RULE_MATCHER_H
#define RULE_MATCHER_H

#include "../../include/protocols/packet.h"
#include <vector>
#include <memory>
#include "ids/common.h"

namespace ids {

// Forward declarations
class Rule;

/**
 * @brief Matches packets against a set of rules
 * 
 * This class maintains a collection of rules and provides methods
 * to match incoming packets against these rules.
 */
class RuleMatcher {
public:
    /**
     * @brief Add a rule to the matcher
     * @param rule Shared pointer to Rule object
     */
    void addRule(std::shared_ptr<Rule> rule);
    
    /**
     * @brief Add multiple rules to the matcher
     * @param rules Vector of shared pointers to Rule objects
     */
    void addRules(const std::vector<std::shared_ptr<Rule>>& rules);
    
    /**
     * @brief Match a packet against all rules
     * @param packet The packet to match
     * @return Vector of matched rules
     */
    std::vector<std::shared_ptr<Rule>> match(const Packet& packet) const;
    
    /**
     * @brief Match a packet against rules of a specific action type
     * @param packet The packet to match
     * @param action The action type to filter by
     * @return Vector of matched rules with specified action
     */
    std::vector<std::shared_ptr<Rule>> match(const Packet& packet, RuleAction action) const;
    
    /**
     * @brief Get all rules
     * @return Vector of all rules
     */
    const std::vector<std::shared_ptr<Rule>>& getRules() const;
    
    /**
     * @brief Clear all rules
     */
    void clear();
    
    /**
     * @brief Get rule count
     * @return Number of rules
     */
    size_t size() const;
    
private:
    std::vector<std::shared_ptr<Rule>> rules_;  ///< Collection of rules to match against
};

} // namespace ids

#endif // RULE_MATCHER_H