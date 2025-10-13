#ifndef RULE2BIN_RULE_PARSER_H
#define RULE2BIN_RULE_PARSER_H

#include "structures.h"
#include <string>
#include <vector>
#include <memory>

namespace rule2bin {

class RuleParser {
public:
    RuleParser();
    ~RuleParser() = default;

    // Parse a single Snort3 rule string into a Rule object
    bool parse_rule(const std::string& rule_text, Rule& rule);

    // Parse multiple rules from a file
    bool parse_rules_from_file(const std::string& filename, std::vector<Rule>& rules);

    // Parse multiple rules from a string (one per line)
    bool parse_rules_from_string(const std::string& rules_text, std::vector<Rule>& rules);

    // Get last error message
    const std::string& get_last_error() const { return last_error_; }

private:
    std::string last_error_;

    // Internal parsing methods
    bool parse_rule_header(const std::string& header_part, Rule& rule);
    bool parse_rule_options(const std::string& options_part, Rule& rule);
    bool parse_ip_and_port(const std::string& ip_port, char* ip_array, uint16_t& port);
    bool parse_option(const std::string& option_str, Rule& rule);
    
    // Utility functions
    std::vector<std::string> split(const std::string& str, char delimiter);
    std::string trim(const std::string& str);
    bool is_valid_ip(const std::string& ip);
    bool is_valid_port(const std::string& port);
    uint16_t parse_port(const std::string& port_str);
    Action parse_action(const std::string& action_str);
    Protocol parse_protocol(const std::string& proto_str);
};

} // namespace rule2bin

#endif // RULE2BIN_RULE_PARSER_H