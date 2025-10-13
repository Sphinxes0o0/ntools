#ifndef RULE2BIN_BINARY_DESERIALIZER_H
#define RULE2BIN_BINARY_DESERIALIZER_H

#include "structures.h"
#include <string>
#include <vector>
#include <fstream>

namespace rule2bin {

class BinaryDeserializer {
public:
    BinaryDeserializer();
    ~BinaryDeserializer() = default;

    // Deserialize rules from binary file
    bool deserialize_from_file(const std::string& filename, std::vector<Rule>& rules);

    // Deserialize rules from binary data in memory
    bool deserialize_from_memory(const std::vector<uint8_t>& data, std::vector<Rule>& rules);

    // Get last error message
    const std::string& get_last_error() const { return last_error_; }

private:
    std::string last_error_;

    // Internal deserialization methods
    bool read_file_header(std::istream& stream, FileHeader& header);
    bool read_rule(std::istream& stream, Rule& rule);
    bool read_rule_header(std::istream& stream, RuleHeader& header);
    bool read_rule_options(std::istream& stream, Rule& rule, uint32_t option_count);
    bool read_string(std::istream& stream, std::string& str, uint32_t length);
    bool read_string_with_length(std::istream& stream, std::string& str);
    
    // Validation and utility functions
    bool validate_file_header(const FileHeader& header);
    bool validate_checksum(std::istream& stream, const FileHeader& header);
    bool verify_magic(uint32_t magic);
    bool verify_version(uint32_t version);
};

} // namespace rule2bin

#endif // RULE2BIN_BINARY_DESERIALIZER_H