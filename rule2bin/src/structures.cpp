#include "../include/structures.h"
#include <algorithm>
#include <cctype>

namespace rule2bin {

uint32_t Rule::calculate_binary_size() const {
    uint32_t size = sizeof(RuleHeader);
    
    // Add size for each option header
    size += options.size() * sizeof(RuleOption);
    
    // Add size for string data
    for (const auto& str : string_data) {
        size += sizeof(uint32_t); // length prefix
        size += str.size();       // string content
    }
    
    return size;
}

const char* action_to_string(Action action) {
    switch (action) {
        case Action::ALERT: return "alert";
        case Action::LOG:   return "log";
        case Action::PASS:  return "pass";
        case Action::DROP:  return "drop";
        default:            return "unknown";
    }
}

const char* protocol_to_string(Protocol protocol) {
    switch (protocol) {
        case Protocol::TCP:  return "tcp";
        case Protocol::UDP:  return "udp";
        case Protocol::ICMP: return "icmp";
        case Protocol::IP:   return "ip";
        default:             return "unknown";
    }
}

const char* direction_to_string(Direction direction) {
    switch (direction) {
        case Direction::UNI: return "uni";
        case Direction::BI:  return "bi";
        default:             return "unknown";
    }
}

const char* option_type_to_string(OptionType type) {
    switch (type) {
        case OptionType::CONTENT:   return "content";
        case OptionType::MSG:       return "msg";
        case OptionType::SID:       return "sid";
        case OptionType::REV:       return "rev";
        case OptionType::CLASSTYPE: return "classtype";
        case OptionType::PRIORITY:  return "priority";
        case OptionType::METADATA:  return "metadata";
        case OptionType::FLOW:      return "flow";
        case OptionType::FLAGS:     return "flags";
        default:                    return "unknown";
    }
}

} // namespace rule2bin