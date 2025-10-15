#include "../../include/parsing/parser.h"
#include "../../include/utils/utils.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <filesystem>

namespace ids {

RuleParser::RuleParser() 
    : initialized_(false),
      rule_pattern_(R"(^\s*(alert|pass|drop|reject|log)\s+(\w+)\s+([^\s]+)\s+([^\s]+)\s+->\s+([^\s]+)\s+([^\s]+)\s*\((.+)\)\s*$)"),
      option_pattern_(R"(\s*(\w+)\s*:\s*([^;]+);)") {
}

RuleParser::~RuleParser() {
    shutdown();
}

bool RuleParser::initialize(const Config& config) {
    if (initialized_) {
        return true;
    }
    
    try {
        // Load rules from configured directories
        RuleConfig rule_config = RuleConfig::fromConfig(config);
        
        // Load rules from default directory if specified
        if (!rule_config.rule_files.empty()) {
            for (const auto& rule_file : rule_config.rule_files) {
                if (std::filesystem::exists(rule_file)) {
                    auto rules = loadRulesFromFile(rule_file);
                    rules_.insert(rules_.end(), rules.begin(), rules.end());
                    stats_["files_loaded"]++;
                }
            }
        }
        
        // Load rules from rules directory if it exists
        std::string rules_dir = config.get<std::string>("rules.directory", "config/rules");
        if (std::filesystem::exists(rules_dir) && std::filesystem::is_directory(rules_dir)) {
            auto rules = loadRulesFromDirectory(rules_dir);
            rules_.insert(rules_.end(), rules.begin(), rules.end());
            stats_["directories_loaded"]++;
        }
        
        initialized_ = true;
        stats_["rules_loaded"] = rules_.size();
        std::cout << "RuleParser initialized with " << rules_.size() << " rules" << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "RuleParser initialization error: " << e.what() << std::endl;
        return false;
    }
}

void RuleParser::shutdown() {
    rules_.clear();
    stats_.clear();
    initialized_ = false;
}

std::vector<Rule> RuleParser::loadRulesFromFile(const std::string& file_path) {
    std::vector<Rule> rules;
    std::ifstream file(file_path);
    
    if (!file.is_open()) {
        throw std::runtime_error("RULE_FILE_NOT_FOUND: Cannot open rule file: " + file_path);
    }
    
    std::string line;
    uint32_t line_number = 0;
    
    while (std::getline(file, line)) {
        line_number++;
        
        // Skip empty lines and comments
        line = utils::trim(line);
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        try {
            Rule rule = parseRule(line);
            rule.raw_rule = line;
            rules.push_back(rule);
            stats_["rules_parsed"]++;
        } catch (const std::exception& e) {
            std::cerr << "Error parsing rule at line " << line_number 
                      << " in file " << file_path << ": " << e.what() << std::endl;
            stats_["parse_errors"]++;
        }
    }
    
    file.close();
    return rules;
}

std::vector<Rule> RuleParser::loadRulesFromDirectory(const std::string& dir_path) {
    std::vector<Rule> rules;
    
    try {
        for (const auto& entry : std::filesystem::directory_iterator(dir_path)) {
            if (entry.is_regular_file() && entry.path().extension() == ".rules") {
                auto file_rules = loadRulesFromFile(entry.path().string());
                rules.insert(rules.end(), file_rules.begin(), file_rules.end());
            }
        }
    } catch (const std::exception& e) {
        throw std::runtime_error("RULE_FILE_NOT_FOUND: Error loading rules from directory: " + dir_path + " - " + e.what());
    }
    
    return rules;
}

Rule RuleParser::parseRule(const std::string& rule_str) {
    Rule rule;
    std::string cleaned_rule = cleanRuleString(rule_str);
    
    std::smatch match;
    if (!std::regex_match(cleaned_rule, match, rule_pattern_)) {
        throw std::runtime_error("INVALID_RULE_SYNTAX: Invalid rule syntax: " + rule_str);
    }
    
    // Parse rule header (action, protocol, addresses, ports)
    std::string header_str = match[1].str() + " " + match[2].str() + " " + 
                           match[3].str() + " " + match[4].str() + " -> " +
                           match[5].str() + " " + match[6].str();
    parseRuleHeader(rule, header_str);
    
    // Parse rule options
    std::string options_str = match[7].str();
    parseRuleOptions(rule, options_str);
    
    rule.raw_rule = rule_str;
    return rule;
}

void RuleParser::parseRuleHeader(Rule& rule, const std::string& header_str) {
    std::vector<std::string> tokens = utils::split(header_str, ' ');
    
    if (tokens.size() < 7) {
        throw std::runtime_error("INVALID_RULE_SYNTAX: Invalid rule header: " + header_str);
    }
    
    // Parse action
    rule.action = stringToAction(tokens[0]);
    
    // Parse protocol
    rule.protocol = stringToProtocol(tokens[1]);
    
    // Parse source and destination
    rule.src_ip = tokens[2];
    rule.src_port = tokens[3];
    rule.dst_ip = tokens[5];
    rule.dst_port = tokens[6];
}

void RuleParser::parseRuleOptions(Rule& rule, const std::string& options_str) {
    std::string cleaned_options = options_str;
    
    // Remove outer parentheses if present
    if (!cleaned_options.empty() && cleaned_options.front() == '(' && cleaned_options.back() == ')') {
        cleaned_options = cleaned_options.substr(1, cleaned_options.length() - 2);
    }
    
    std::smatch match;
    std::string::const_iterator search_start(cleaned_options.cbegin());
    
    while (std::regex_search(search_start, cleaned_options.cend(), match, option_pattern_)) {
        std::string key = utils::trim(match[1].str());
        std::string value = utils::trim(match[2].str());
        
        parseKeyValueOption(rule, key, value);
        
        search_start = match.suffix().first;
    }
}

void RuleParser::parseFlowOption(Rule& rule, const std::string& flow_str) {
    std::vector<std::string> flow_tokens = utils::split(flow_str, ',');
    
    for (const auto& token : flow_tokens) {
        std::string clean_token = utils::trim(token);
        if (!clean_token.empty()) {
            rule.options.flow.push_back(stringToFlowDirection(clean_token));
        }
    }
}

void RuleParser::parseThresholdOption(Rule& rule, const std::string& threshold_str) {
    std::vector<std::string> tokens = utils::split(threshold_str, ',');
    
    for (const auto& token : tokens) {
        std::string clean_token = utils::trim(token);
        std::vector<std::string> key_value = utils::split(clean_token, ' ');
        
        if (key_value.size() == 2) {
            std::string key = utils::trim(key_value[0]);
            std::string value = utils::trim(key_value[1]);
            
            if (key == "type") {
                rule.options.threshold.type = value;
            } else if (key == "track") {
                rule.options.threshold.track = value;
            } else if (key == "count") {
                try {
                    rule.options.threshold.count = std::stoul(value);
                } catch (...) {
                    throw std::runtime_error("RULE_PARSE_ERROR: Invalid threshold count: " + value);
                }
            } else if (key == "seconds") {
                try {
                    rule.options.threshold.seconds = std::stoul(value);
                } catch (...) {
                    throw std::runtime_error("RULE_PARSE_ERROR: Invalid threshold seconds: " + value);
                }
            }
        }
    }
}

void RuleParser::parseKeyValueOption(Rule& rule, const std::string& key, const std::string& value) {
    std::string clean_key = utils::toLower(utils::trim(key));
    std::string clean_value = utils::trim(value);
    
    // Remove quotes if present
    if (clean_value.length() >= 2 && 
        ((clean_value.front() == '"' && clean_value.back() == '"') ||
         (clean_value.front() == '\'' && clean_value.back() == '\''))) {
        clean_value = clean_value.substr(1, clean_value.length() - 2);
    }
    
    if (clean_key == "msg") {
        rule.options.msg = clean_value;
    } else if (clean_key == "flow") {
        parseFlowOption(rule, clean_value);
    } else if (clean_key == "threshold") {
        parseThresholdOption(rule, clean_value);
    } else if (clean_key == "classtype") {
        rule.options.classtype = clean_value;
    } else if (clean_key == "sid") {
        try {
            rule.options.sid = std::stoul(clean_value);
        } catch (...) {
            throw std::runtime_error("RULE_PARSE_ERROR: Invalid SID: " + clean_value);
        }
    } else if (clean_key == "rev") {
        try {
            rule.options.rev = std::stoul(clean_value);
        } catch (...) {
            throw std::runtime_error("RULE_PARSE_ERROR: Invalid revision: " + clean_value);
        }
    } else {
        // Store as generic content option
        rule.options.content_options[clean_key] = clean_value;
    }
}

RuleAction RuleParser::stringToAction(const std::string& action_str) {
    std::string action = utils::toLower(utils::trim(action_str));
    
    if (action == "alert") return RuleAction::ALERT;
    if (action == "pass") return RuleAction::PASS;
    if (action == "drop") return RuleAction::DROP;
    if (action == "reject") return RuleAction::REJECT;
    if (action == "log") return RuleAction::LOG;
    
    throw std::runtime_error("INVALID_RULE_SYNTAX: Unknown rule action: " + action_str);
}

RuleProtocol RuleParser::stringToProtocol(const std::string& protocol_str) {
    std::string protocol = utils::toUpper(utils::trim(protocol_str));
    
    if (protocol == "TCP") return RuleProtocol::TCP;
    if (protocol == "UDP") return RuleProtocol::UDP;
    if (protocol == "ICMP") return RuleProtocol::ICMP;
    if (protocol == "IP") return RuleProtocol::IP;
    if (protocol == "ANY") return RuleProtocol::ANY;
    
    throw std::runtime_error("INVALID_RULE_SYNTAX: Unknown protocol: " + protocol_str);
}

FlowDirection RuleParser::stringToFlowDirection(const std::string& flow_str) {
    std::string flow = utils::toLower(utils::trim(flow_str));
    
    if (flow == "to_server") return FlowDirection::TO_SERVER;
    if (flow == "to_client") return FlowDirection::TO_CLIENT;
    if (flow == "established") return FlowDirection::ESTABLISHED;
    if (flow == "both") return FlowDirection::BOTH;
    
    throw std::runtime_error("INVALID_RULE_SYNTAX: Unknown flow direction: " + flow_str);
}

std::string RuleParser::cleanRuleString(const std::string& rule_str) {
    std::string cleaned = utils::trim(rule_str);
    
    // Remove extra whitespace
    std::regex whitespace_regex(R"(\s+)");
    cleaned = std::regex_replace(cleaned, whitespace_regex, " ");
    
    return cleaned;
}

size_t RuleParser::getRuleCount() const {
    return rules_.size();
}

std::vector<Rule> RuleParser::getAllRules() const {
    return rules_;
}

void RuleParser::clearRules() {
    rules_.clear();
    stats_.clear();
}

bool RuleParser::validateRule(const std::string& rule_str) {
    try {
        parseRule(rule_str);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::unordered_map<std::string, uint64_t> RuleParser::getStats() const {
    return stats_;
}

} // namespace ids