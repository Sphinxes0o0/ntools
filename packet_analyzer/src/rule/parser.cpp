#include "../../include/rule/parser.h"
#include <iostream>
#include <memory>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace ids {

RuleParser::RuleParser() {
    stats_["rules_parsed"] = 0;
    stats_["rules_invalid"] = 0;
}

RuleParser::~RuleParser() = default;

std::shared_ptr<Rule> RuleParser::parseRule(const std::string& rule_str) {
    if (rule_str.empty() || rule_str[0] == '#' || trim(rule_str).empty()) {
        return nullptr;
    }

    auto rule = std::make_shared<Rule>();

    try {
        // Tokenize the rule
        std::vector<std::string> tokens = tokenize(rule_str);
        if (tokens.size() < 7) {
            stats_["rules_invalid"]++;
            throw std::invalid_argument("Invalid rule format: insufficient tokens");
        }

        // Parse header
        if (!parseHeader(*rule, tokens)) {
            stats_["rules_invalid"]++;
            throw std::invalid_argument("Failed to parse rule header");
        }
        // Find the options part (between parentheses)
        size_t open_paren = rule_str.find('(');
        size_t close_paren = rule_str.rfind(')');
        if (open_paren != std::string::npos && close_paren != std::string::npos && open_paren < close_paren) {
            std::string options_str = rule_str.substr(open_paren + 1, close_paren - open_paren - 1);
            if (!parseOptions(*rule, options_str)) {
                stats_["rules_invalid"]++;
                throw std::invalid_argument("Failed to parse rule options");
            }
        }
        stats_["rules_parsed"]++;
        return rule;
    } catch (const std::exception& e) {
        std::cerr << "Error parsing rule: " << e.what() << std::endl;
        std::cerr << "Rule: " << rule_str << std::endl;
        return nullptr;
    }
}

std::vector<std::shared_ptr<Rule>> RuleParser::parseRules(const std::vector<std::string>& rule_strings) {
    std::vector<std::shared_ptr<Rule>> rules;
    for (const auto& rule_str : rule_strings) {
        auto rule = parseRule(rule_str);
        if (rule) {
            rules.push_back(rule);
        }
    }
    return rules;
}

std::vector<std::shared_ptr<Rule>> RuleParser::parseRuleFile(const std::string& file_path) {
    std::vector<std::shared_ptr<Rule>> rules;
    std::ifstream file(file_path);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open rule file: " + file_path);
    }
    
    std::string line;
    while (std::getline(file, line)) {
        auto rule = parseRule(line);
        if (rule) {
            rules.push_back(rule);
        }
    }
    
    file.close();
    return rules;
}

bool RuleParser::validateRule(const std::string& rule_str) const {
    try {
        RuleParser parser;
        auto rule = parser.parseRule(rule_str);
        return rule != nullptr && rule->validate();
    } catch (...) {
        return false;
    }
}

const std::unordered_map<std::string, size_t>& RuleParser::getStats() const {
    return stats_;
}

bool RuleParser::parseHeader(Rule& rule, const std::vector<std::string>& tokens) {
    if (tokens.size() < 7) {
        return false;
    }

    std::string action_str = tokens[0];
    std::transform(action_str.begin(), action_str.end(), action_str.begin(), ::tolower);

    if (action_str == "alert") {
        rule.action = RuleAction::ALERT;
    } else if (action_str == "log") {
        rule.action = RuleAction::LOG;
    } else if (action_str == "drop") {
        rule.action = RuleAction::DROP;
    } else if (action_str == "pass") {
        rule.action = RuleAction::PASS;
    } else if (action_str == "reject") {
        rule.action = RuleAction::REJECT;
    } else {
        return false; // Invalid action
    }

    rule.protocol = tokens[1];
    std::transform(rule.protocol.begin(), rule.protocol.end(), rule.protocol.begin(), ::tolower);
    rule.src_ip = tokens[2];
    rule.src_port = tokens[3];

    std::string direction_str = tokens[4];
    if (direction_str == "->") {
        rule.direction = RuleDirection::UNIDIRECTIONAL;
    } else if (direction_str == "<>") {
        rule.direction = RuleDirection::BIDIRECTIONAL;
    } else if (direction_str == "<-") {
        rule.direction = RuleDirection::REVERSE;
    } else {
        return false; // Invalid direction
    }

    rule.dst_ip = tokens[5];
    rule.dst_port = tokens[6];
    
    return true;
}

bool RuleParser::parseOptions(Rule& rule, const std::string& options) {
    // Split options by semicolon
    std::vector<std::string> option_list = split(options, ';');
    
    for (const auto& option_str : option_list) {
        std::string trimmed_option = trim(option_str);
        if (!trimmed_option.empty()) {
            if (!parseOption(rule, trimmed_option)) {
                return false;
            }
        }
    }
    
    return true;
}

bool RuleParser::parseOption(Rule& rule, const std::string& option) {
    // Check for negation
    bool negated = false;
    std::string option_content = option;

    if (!option_content.empty() && option_content[0] == '!') {
        negated = true;
        option_content = option_content.substr(1);
    }

    size_t colon_pos = option_content.find(':');
    if (colon_pos == std::string::npos) {
        // Option without value
        rule.options.emplace_back(option_content, "", negated);
        return true;
    }

    std::string keyword = trim(option_content.substr(0, colon_pos));
    std::string value = trim(option_content.substr(colon_pos + 1));

    if (!value.empty() && ((value.front() == '"' && value.back() == '"') ||
                           (value.front() == '\'' && value.back() == '\''))) {
        value = value.substr(1, value.length() - 2);
    }

    rule.options.emplace_back(keyword, value, negated);

    if (keyword == "msg") {
        rule.description = value;
    } else if (keyword == "sid") {
        rule.id = value;
    }

    return true;
}

std::string RuleParser::trim(const std::string& str) const {
    size_t first = str.find_first_not_of(' ');
    if (first == std::string::npos) {
        return "";
    }
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

std::vector<std::string> RuleParser::split(const std::string& str, char delimiter) const {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;

    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }

    return tokens;
}

std::vector<std::string> RuleParser::tokenize(const std::string& rule_str) const {
    std::vector<std::string> tokens;
    std::string cleaned = trim(rule_str);

    size_t open_paren = cleaned.find('(');
    std::string header_part = (open_paren != std::string::npos) ? cleaned.substr(0, open_paren) : cleaned;

    std::stringstream ss(header_part);
    std::string token;

    while (ss >> token) {
        tokens.push_back(token);
    }
    
    return tokens;
}

} // namespace ids