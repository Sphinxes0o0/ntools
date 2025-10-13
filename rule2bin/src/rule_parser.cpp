#include "../include/rule_parser.h"
#include <sstream>
#include <fstream>
#include <algorithm>
#include <regex>

namespace rule2bin {

RuleParser::RuleParser() : last_error_("") {}

bool RuleParser::parse_rule(const std::string& rule_text, Rule& rule) {
    last_error_.clear();
    
    // Remove comments and trim
    std::string clean_rule = rule_text;
    size_t comment_pos = clean_rule.find('#');
    if (comment_pos != std::string::npos) {
        clean_rule = clean_rule.substr(0, comment_pos);
    }
    clean_rule = trim(clean_rule);
    
    if (clean_rule.empty()) {
        return true; // Empty rule after comment removal is OK
    }
    
    // Split rule into header and options parts
    size_t options_start = clean_rule.find('(');
    size_t options_end = clean_rule.rfind(')');
    
    if (options_start == std::string::npos || options_end == std::string::npos) {
        last_error_ = "Invalid rule format: missing parentheses";
        return false;
    }
    
    std::string header_part = clean_rule.substr(0, options_start);
    std::string options_part = clean_rule.substr(options_start + 1, options_end - options_start - 1);
    
    // Parse header and options
    if (!parse_rule_header(header_part, rule)) {
        return false;
    }
    
    if (!parse_rule_options(options_part, rule)) {
        return false;
    }
    
    return true;
}

bool RuleParser::parse_rules_from_file(const std::string& filename, std::vector<Rule>& rules) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        last_error_ = "Cannot open file: " + filename;
        return false;
    }
    
    std::string line;
    int line_num = 0;
    
    while (std::getline(file, line)) {
        line_num++;
        Rule rule;
        if (parse_rule(line, rule)) {
            if (rule.header.option_count > 0) { // Only add non-empty rules
                rules.push_back(rule);
            }
        } else if (!last_error_.empty()) {
            last_error_ = "Error at line " + std::to_string(line_num) + ": " + last_error_;
            return false;
        }
    }
    
    return true;
}

bool RuleParser::parse_rules_from_string(const std::string& rules_text, std::vector<Rule>& rules) {
    std::istringstream stream(rules_text);
    std::string line;
    
    while (std::getline(stream, line)) {
        Rule rule;
        if (parse_rule(line, rule)) {
            if (rule.header.option_count > 0) { // Only add non-empty rules
                rules.push_back(rule);
            }
        } else if (!last_error_.empty()) {
            return false;
        }
    }
    
    return true;
}

bool RuleParser::parse_rule_header(const std::string& header_part, Rule& rule) {
    // Improved tokenization that handles Snort3 rule format better
    std::vector<std::string> parts;
    std::istringstream stream(header_part);
    std::string token;
    
    while (stream >> token) {
        parts.push_back(token);
    }
    
    // Expected format: action protocol src_ip src_port direction dst_ip dst_port
    if (parts.size() < 7) {
        last_error_ = "Invalid rule header: expected 7 parts, got " + std::to_string(parts.size());
        return false;
    }
    
    // Parse action
    rule.header.action = parse_action(parts[0]);
    
    // Parse protocol
    rule.header.protocol = parse_protocol(parts[1]);
    
    // Parse source IP and port (combine parts[2] and parts[3] if needed)
    std::string src = parts[2];
    if (parts[3] != "->" && parts[3] != "<>") {
        // parts[3] is source port, combine with IP
        src += ":" + parts[3];
    }
    
    if (!parse_ip_and_port(src, rule.header.src_ip, rule.header.src_port)) {
        last_error_ = "Invalid source IP/port: " + src;
        return false;
    }
    
    // Parse direction
    std::string direction;
    if (parts[3] == "->" || parts[3] == "<>") {
        direction = parts[3];
    } else if (parts[4] == "->" || parts[4] == "<>") {
        direction = parts[4];
    } else {
        last_error_ = "Invalid direction, expected '->' or '<>'";
        return false;
    }
    
    if (direction == "->") {
        rule.header.direction = Direction::UNI;
    } else if (direction == "<>") {
        rule.header.direction = Direction::BI;
    }
    
    // Parse destination IP and port (combine remaining parts)
    std::string dst = parts[parts.size() - 2];
    std::string dst_port = parts[parts.size() - 1];
    if (dst_port != "->" && dst_port != "<>") {
        dst += ":" + dst_port;
    }
    
    if (!parse_ip_and_port(dst, rule.header.dst_ip, rule.header.dst_port)) {
        last_error_ = "Invalid destination IP/port: " + dst;
        return false;
    }
    
    return true;
}

bool RuleParser::parse_rule_options(const std::string& options_part, Rule& rule) {
    auto options = split(options_part, ';');
    
    for (auto& option_str : options) {
        option_str = trim(option_str);
        if (option_str.empty()) continue;
        
        if (!parse_option(option_str, rule)) {
            return false;
        }
    }
    
    rule.header.option_count = rule.options.size();
    return true;
}

bool RuleParser::parse_ip_and_port(const std::string& ip_port, char* ip_array, uint16_t& port) {
    std::string ip_str;
    
    // Handle "any" case
    if (ip_port == "any") {
        ip_str = "0.0.0.0";
        port = 0;
    } else {
        // Check for port specification
        size_t colon_pos = ip_port.find(':');
        if (colon_pos != std::string::npos) {
            ip_str = ip_port.substr(0, colon_pos);
            std::string port_str = ip_port.substr(colon_pos + 1);
            port = parse_port(port_str);
        } else {
            ip_str = ip_port;
            port = 0;
        }
    }
    
    // Validate IP (basic validation)
    if (!is_valid_ip(ip_str)) {
        return false;
    }
    
    // Copy to char array
    std::strncpy(ip_array, ip_str.c_str(), 15);
    ip_array[15] = '\0'; // Ensure null termination
    
    return true;
}

bool RuleParser::parse_option(const std::string& option_str, Rule& rule) {
    size_t colon_pos = option_str.find(':');
    if (colon_pos == std::string::npos) {
        last_error_ = "Invalid option format: " + option_str;
        return false;
    }
    
    std::string key = trim(option_str.substr(0, colon_pos));
    std::string value = trim(option_str.substr(colon_pos + 1));
    
    // Remove quotes from value if present
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.size() - 2);
    }
    
    // Map option key to type
    if (key == "content") {
        rule.options.emplace_back(OptionType::CONTENT, value.size());
        rule.string_data.push_back(value);
    } else if (key == "msg") {
        rule.options.emplace_back(OptionType::MSG, value.size());
        rule.string_data.push_back(value);
    } else if (key == "sid") {
        rule.options.emplace_back(OptionType::SID, sizeof(uint32_t));
        // Store SID as string for now, will convert to uint32_t during serialization
        rule.string_data.push_back(value);
    } else if (key == "rev") {
        rule.options.emplace_back(OptionType::REV, sizeof(uint32_t));
        rule.string_data.push_back(value);
    } else if (key == "classtype") {
        rule.options.emplace_back(OptionType::CLASSTYPE, value.size());
        rule.string_data.push_back(value);
    } else if (key == "priority") {
        rule.options.emplace_back(OptionType::PRIORITY, sizeof(uint32_t));
        rule.string_data.push_back(value);
    } else if (key == "metadata") {
        rule.options.emplace_back(OptionType::METADATA, value.size());
        rule.string_data.push_back(value);
    } else if (key == "flow") {
        rule.options.emplace_back(OptionType::FLOW, value.size());
        rule.string_data.push_back(value);
    } else if (key == "flags") {
        rule.options.emplace_back(OptionType::FLAGS, value.size());
        rule.string_data.push_back(value);
    } else {
        // Skip unsupported options for now
        return true;
    }
    
    return true;
}

// Utility functions
std::vector<std::string> RuleParser::split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream token_stream(str);
    
    while (std::getline(token_stream, token, delimiter)) {
        tokens.push_back(token);
    }
    
    return tokens;
}

std::string RuleParser::trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    
    size_t end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
}

bool RuleParser::is_valid_ip(const std::string& ip) {
    // Basic IP validation - accept "any", CIDR notation, or simple IP patterns
    if (ip == "any" || ip == "0.0.0.0") return true;
    
    // Simple regex for IP validation (supports CIDR notation)
    std::regex ip_pattern(R"((\d{1,3}\.){3}\d{1,3}(/\d{1,2})?)");
    return std::regex_match(ip, ip_pattern);
}

bool RuleParser::is_valid_port(const std::string& port) {
    if (port == "any") return true;
    try {
        int p = std::stoi(port);
        return p >= 0 && p <= 65535;
    } catch (...) {
        return false;
    }
}

uint16_t RuleParser::parse_port(const std::string& port_str) {
    if (port_str == "any") return 0;
    try {
        return static_cast<uint16_t>(std::stoi(port_str));
    } catch (...) {
        return 0;
    }
}

Action RuleParser::parse_action(const std::string& action_str) {
    if (action_str == "alert") return Action::ALERT;
    if (action_str == "log") return Action::LOG;
    if (action_str == "pass") return Action::PASS;
    if (action_str == "drop") return Action::DROP;
    return Action::ALERT; // Default to alert
}

Protocol RuleParser::parse_protocol(const std::string& proto_str) {
    if (proto_str == "tcp") return Protocol::TCP;
    if (proto_str == "udp") return Protocol::UDP;
    if (proto_str == "icmp") return Protocol::ICMP;
    if (proto_str == "ip") return Protocol::IP;
    return Protocol::TCP; // Default to TCP
}

} // namespace rule2bin