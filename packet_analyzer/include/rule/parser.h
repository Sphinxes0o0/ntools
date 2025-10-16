#ifndef RULE_PARSER_H
#define RULE_PARSER_H

#include "../../include/protocols/packet.h"
#include <string>
#include <vector>
#include <memory>

namespace ids {

// Forward declaration
class Rule;

/**
 * @brief Parser for intrusion detection rules
 * 
 * This class is responsible for parsing rule definition strings into Rule objects.
 * It supports various rule options and conditions for matching network packets.
 */
class RuleParser {
public:
    /**
     * @brief Parse a rule string into a Rule object
     * @param rule_str The rule definition string
     * @return Shared pointer to parsed Rule object
     * @throws std::invalid_argument if rule string is invalid
     */
    std::shared_ptr<Rule> parseRule(const std::string& rule_str);
    
    /**
     * @brief Parse multiple rules from a vector of strings
     * @param rule_strings Vector of rule definition strings
     * @return Vector of shared pointers to Rule objects
     */
    std::vector<std::shared_ptr<Rule>> parseRules(const std::vector<std::string>& rule_strings);
    
    /**
     * @brief Validate a rule string without creating a Rule object
     * @param rule_str The rule definition string
     * @return true if valid, false otherwise
     */
    bool validateRule(const std::string& rule_str) const;
    
private:
    /**
     * @brief Parse rule header section
     * @param rule Reference to Rule object being constructed
     * @param header Header string part
     * @return true if successful, false otherwise
     */
    bool parseHeader(Rule& rule, const std::string& header);
    
    /**
     * @brief Parse rule options section
     * @param rule Reference to Rule object being constructed
     * @param options Options string part
     * @return true if successful, false otherwise
     */
    bool parseOptions(Rule& rule, const std::string& options);
    
    /**
     * @brief Parse individual option
     * @param rule Reference to Rule object being constructed
     * @param option Option string
     * @return true if successful, false otherwise
     */
    bool parseOption(Rule& rule, const std::string& option);
    
    /**
     * @brief Trim whitespace from string
     * @param str String to trim
     * @return Trimmed string
     */
    std::string trim(const std::string& str) const;
    
    /**
     * @brief Split string by delimiter
     * @param str String to split
     * @param delimiter Delimiter character
     * @return Vector of split parts
     */
    std::vector<std::string> split(const std::string& str, char delimiter) const;
};

} // namespace ids

#endif // RULE_PARSER_H