#include "../include/binary_deserializer.h"
#include <fstream>
#include <sstream>

namespace rule2bin {

BinaryDeserializer::BinaryDeserializer() : last_error_("") {}

bool BinaryDeserializer::deserialize_from_file(const std::string& filename, std::vector<Rule>& rules) {
    last_error_.clear();
    
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        last_error_ = "Cannot open file: " + filename;
        return false;
    }
    
    // Read file header
    FileHeader header;
    if (!read_file_header(file, header)) {
        return false;
    }
    
    // Validate file header
    if (!validate_file_header(header)) {
        return false;
    }
    
    // Validate checksum
    if (!validate_checksum(file, header)) {
        return false;
    }
    
    // Read rules
    rules.clear();
    rules.reserve(header.rule_count);
    
    for (uint32_t i = 0; i < header.rule_count; ++i) {
        Rule rule;
        if (!read_rule(file, rule)) {
            return false;
        }
        rules.push_back(rule);
    }
    
    file.close();
    return true;
}

bool BinaryDeserializer::deserialize_from_memory(const std::vector<uint8_t>& data, std::vector<Rule>& rules) {
    last_error_.clear();
    
    if (data.size() < sizeof(FileHeader)) {
        last_error_ = "Data too small for file header";
        return false;
    }
    
    // Create a stream from the data
    std::stringstream stream(std::ios::binary | std::ios::in | std::ios::out);
    stream.write(reinterpret_cast<const char*>(data.data()), data.size());
    stream.seekg(0);
    
    // Read file header
    FileHeader header;
    if (!read_file_header(stream, header)) {
        return false;
    }
    
    // Validate file header
    if (!validate_file_header(header)) {
        return false;
    }
    
    // Read rules
    rules.clear();
    rules.reserve(header.rule_count);
    
    for (uint32_t i = 0; i < header.rule_count; ++i) {
        Rule rule;
        if (!read_rule(stream, rule)) {
            return false;
        }
        rules.push_back(rule);
    }
    
    return true;
}

bool BinaryDeserializer::read_file_header(std::istream& stream, FileHeader& header) {
    if (!stream.read(reinterpret_cast<char*>(&header), sizeof(FileHeader))) {
        last_error_ = "Failed to read file header";
        return false;
    }
    return true;
}

bool BinaryDeserializer::read_rule(std::istream& stream, Rule& rule) {
    // Read rule header
    if (!read_rule_header(stream, rule.header)) {
        return false;
    }
    
    // Read options
    if (!read_rule_options(stream, rule, rule.header.option_count)) {
        return false;
    }
    
    return true;
}

bool BinaryDeserializer::read_rule_header(std::istream& stream, RuleHeader& header) {
    if (!stream.read(reinterpret_cast<char*>(&header), sizeof(RuleHeader))) {
        last_error_ = "Failed to read rule header";
        return false;
    }
    return true;
}

bool BinaryDeserializer::read_rule_options(std::istream& stream, Rule& rule, uint32_t option_count) {
    rule.options.clear();
    rule.string_data.clear();
    
    for (uint32_t i = 0; i < option_count; ++i) {
        // Read option header
        RuleOption option(OptionType::CONTENT, 0);
        if (!stream.read(reinterpret_cast<char*>(&option), sizeof(RuleOption))) {
            last_error_ = "Failed to read rule option";
            return false;
        }
        
        // Read option value (string with length prefix)
        std::string value;
        if (!read_string_with_length(stream, value)) {
            return false;
        }
        
        rule.options.push_back(option);
        rule.string_data.push_back(value);
    }
    
    return true;
}

bool BinaryDeserializer::read_string(std::istream& stream, std::string& str, uint32_t length) {
    if (length == 0) {
        str.clear();
        return true;
    }
    
    std::vector<char> buffer(length);
    if (!stream.read(buffer.data(), length)) {
        last_error_ = "Failed to read string data";
        return false;
    }
    
    str.assign(buffer.data(), length);
    return true;
}

bool BinaryDeserializer::read_string_with_length(std::istream& stream, std::string& str) {
    // Read length prefix (4 bytes)
    uint32_t length;
    if (!stream.read(reinterpret_cast<char*>(&length), sizeof(length))) {
        last_error_ = "Failed to read string length";
        return false;
    }
    
    // Read string data
    return read_string(stream, str, length);
}

bool BinaryDeserializer::validate_file_header(const FileHeader& header) {
    if (!verify_magic(header.magic)) {
        last_error_ = "Invalid file magic number";
        return false;
    }
    
    if (!verify_version(header.version)) {
        last_error_ = "Unsupported file version";
        return false;
    }
    
    if (header.header_size != sizeof(FileHeader)) {
        last_error_ = "Invalid header size";
        return false;
    }
    
    return true;
}

bool BinaryDeserializer::validate_checksum(std::istream& stream, const FileHeader& header) {
    // For POC, we'll skip checksum validation
    // In production, this would verify the CRC32 checksum
    return true;
}

bool BinaryDeserializer::verify_magic(uint32_t magic) {
    return magic == FILE_MAGIC;
}

bool BinaryDeserializer::verify_version(uint32_t version) {
    return version == FILE_VERSION;
}

} // namespace rule2bin