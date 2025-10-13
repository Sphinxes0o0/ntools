#include "../include/binary_serializer.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <zlib.h> // For CRC32 calculation

namespace rule2bin {

BinarySerializer::BinarySerializer() : last_error_("") {}

bool BinarySerializer::serialize_to_file(const std::vector<Rule>& rules, const std::string& filename) {
    last_error_.clear();
    
    // First serialize to memory to calculate checksum
    std::vector<uint8_t> data;
    if (!serialize_to_memory(rules, data)) {
        return false;
    }
    
    // Write to file
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        last_error_ = "Cannot open file for writing: " + filename;
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
    
    return true;
}

bool BinarySerializer::serialize_to_memory(const std::vector<Rule>& rules, std::vector<uint8_t>& output) {
    last_error_.clear();
    
    // Use stringstream to build the data
    std::stringstream stream(std::ios::binary | std::ios::out | std::ios::in);
    
    // Calculate total data size
    uint32_t data_size = calculate_rules_data_size(rules);
    
    // Write file header (without checksum initially)
    FileHeader header;
    header.rule_count = rules.size();
    header.data_size = data_size;
    
    if (!write_file_header(stream, header.rule_count, header.data_size)) {
        return false;
    }
    
    // Write rules data
    for (const auto& rule : rules) {
        if (!write_rule(stream, rule)) {
            return false;
        }
    }
    
    // Get the stream data
    std::string stream_str = stream.str();
    std::vector<uint8_t> stream_data(stream_str.begin(), stream_str.end());
    
    // Calculate checksum for rules data (skip header)
    size_t rules_data_offset = sizeof(FileHeader);
    size_t rules_data_size = stream_data.size() - rules_data_offset;
    uint32_t checksum = crc32(0L, Z_NULL, 0);
    checksum = crc32(checksum, stream_data.data() + rules_data_offset, rules_data_size);
    
    // Update checksum in stream data
    memcpy(stream_data.data() + offsetof(FileHeader, checksum), &checksum, sizeof(checksum));
    
    output = std::move(stream_data);
    return true;
}

bool BinarySerializer::write_file_header(std::ostream& stream, uint32_t rule_count, uint32_t data_size) {
    FileHeader header;
    header.rule_count = rule_count;
    header.data_size = data_size;
    
    if (!stream.write(reinterpret_cast<const char*>(&header), sizeof(FileHeader))) {
        last_error_ = "Failed to write file header";
        return false;
    }
    
    return true;
}

bool BinarySerializer::write_rule(std::ostream& stream, const Rule& rule) {
    // Write rule header
    if (!write_rule_header(stream, rule.header)) {
        return false;
    }
    
    // Write options
    if (!write_rule_options(stream, rule)) {
        return false;
    }
    
    return true;
}

bool BinarySerializer::write_rule_header(std::ostream& stream, const RuleHeader& header) {
    if (!stream.write(reinterpret_cast<const char*>(&header), sizeof(RuleHeader))) {
        last_error_ = "Failed to write rule header";
        return false;
    }
    
    return true;
}

bool BinarySerializer::write_rule_options(std::ostream& stream, const Rule& rule) {
    // Write each option header
    for (size_t i = 0; i < rule.options.size(); ++i) {
        const auto& option = rule.options[i];
        if (!stream.write(reinterpret_cast<const char*>(&option), sizeof(RuleOption))) {
            last_error_ = "Failed to write rule option";
            return false;
        }
        
        // Write option value
        const auto& value = rule.string_data[i];
        if (!write_string(stream, value)) {
            return false;
        }
    }
    
    return true;
}

bool BinarySerializer::write_string(std::ostream& stream, const std::string& str) {
    uint32_t length = str.size();
    if (!stream.write(reinterpret_cast<const char*>(&length), sizeof(length))) {
        last_error_ = "Failed to write string length";
        return false;
    }
    
    if (length > 0) {
        if (!stream.write(str.c_str(), length)) {
            last_error_ = "Failed to write string data";
            return false;
        }
    }
    
    return true;
}

uint32_t BinarySerializer::calculate_checksum(const std::vector<uint8_t>& data) {
    return crc32(0L, data.data(), data.size());
}

uint32_t BinarySerializer::calculate_rule_binary_size(const Rule& rule) {
    uint32_t size = sizeof(RuleHeader);
    
    // Add size for each option header and its value
    for (size_t i = 0; i < rule.options.size(); ++i) {
        size += sizeof(RuleOption);
        size += sizeof(uint32_t); // string length prefix
        size += rule.string_data[i].size();
    }
    
    return size;
}

uint32_t BinarySerializer::calculate_rules_data_size(const std::vector<Rule>& rules) {
    uint32_t total_size = 0;
    for (const auto& rule : rules) {
        total_size += calculate_rule_binary_size(rule);
    }
    return total_size;
}

} // namespace rule2bin