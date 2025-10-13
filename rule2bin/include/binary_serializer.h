#ifndef RULE2BIN_BINARY_SERIALIZER_H
#define RULE2BIN_BINARY_SERIALIZER_H

#include "structures.h"
#include <string>
#include <vector>
#include <fstream>

namespace rule2bin {

class BinarySerializer {
public:
    BinarySerializer();
    ~BinarySerializer() = default;

    // Serialize rules to binary file
    bool serialize_to_file(const std::vector<Rule>& rules, const std::string& filename);

    // Serialize rules to binary data in memory
    bool serialize_to_memory(const std::vector<Rule>& rules, std::vector<uint8_t>& output);

    // Get last error message
    const std::string& get_last_error() const { return last_error_; }

private:
    std::string last_error_;

    // Internal serialization methods
    bool write_file_header(std::ostream& stream, uint32_t rule_count, uint32_t data_size);
    bool write_rule(std::ostream& stream, const Rule& rule);
    bool write_rule_header(std::ostream& stream, const RuleHeader& header);
    bool write_rule_options(std::ostream& stream, const Rule& rule);
    bool write_string(std::ostream& stream, const std::string& str);
    
    // Utility functions
    uint32_t calculate_checksum(const std::vector<uint8_t>& data);
    uint32_t calculate_rule_binary_size(const Rule& rule);
    uint32_t calculate_rules_data_size(const std::vector<Rule>& rules);
};

} // namespace rule2bin

#endif // RULE2BIN_BINARY_SERIALIZER_H