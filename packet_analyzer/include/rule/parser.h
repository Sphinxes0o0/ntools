#ifndef RULE_PARSER_H
#define RULE_PARSER_H

#include "../../include/protocols/packet.h"
#include "../../include/rule/rule.h"
#include <string>
#include <vector>
#include <memory>
#include <regex>
#include <unordered_map>

namespace ids {

/**
 * @brief Parser for Snort3 intrusion detection rules
 * 
 * This class is responsible for parsing Snort3 rule definition strings into Rule objects.
 * It supports various rule options and conditions for matching network packets.
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
     * @brief Parse rules from a file
     * @param file_path Path to the rule file
     * @return Vector of shared pointers to Rule objects
     */
    std::vector<std::shared_ptr<Rule>> parseRuleFile(const std::string& file_path);

    /**
     * @brief Validate a rule string without creating a Rule object
     * @param rule_str The rule definition string
     * @return true if valid, false otherwise
     */
    bool validateRule(const std::string& rule_str) const;
    
    /**
     * @brief Get parsing statistics
     * @return Map of statistics
     */
    const std::unordered_map<std::string, size_t>& getStats() const;

private:
    /**
     * @brief Parse rule header section
     * @param rule Reference to Rule object being constructed
     * @param tokens Header tokens
     * @return true if successful, false otherwise
     */
    bool parseHeader(Rule& rule, const std::vector<std::string>& tokens);

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

    /**
     * @brief Tokenize rule string
     * @param rule_str Rule string to tokenize
     * @return Vector of tokens
     */
    std::vector<std::string> tokenize(const std::string& rule_str) const;

    // Statistics
    std::unordered_map<std::string, size_t> stats_;
};

} // namespace ids

#endif // RULE_PARSER_H