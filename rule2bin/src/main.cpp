#include "../include/rule_parser.h"
#include "../include/binary_serializer.h"
#include "../include/binary_deserializer.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

void print_usage(const char* program_name) {
    std::cout << "Snort3 Rule to Binary Translator\n";
    std::cout << "Usage: " << program_name << " <command> [options]\n";
    std::cout << "\nCommands:\n";
    std::cout << "  convert <input_file> <output_file>  Convert Snort3 rules to binary format\n";
    std::cout << "  info <binary_file>                  Display information about binary file\n";
    std::cout << "  help                                Show this help message\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program_name << " convert rules.txt rules.bin\n";
    std::cout << "  " << program_name << " info rules.bin\n";
}

void print_rule_info(const rule2bin::Rule& rule, int index) {
    std::cout << "Rule #" << index << ":\n";
    std::cout << "  Action: " << rule2bin::action_to_string(rule.header.action) << "\n";
    std::cout << "  Protocol: " << rule2bin::protocol_to_string(rule.header.protocol) << "\n";
    std::cout << "  Source: " << rule.header.src_ip << ":" << rule.header.src_port << "\n";
    std::cout << "  Destination: " << rule.header.dst_ip << ":" << rule.header.dst_port << "\n";
    std::cout << "  Direction: " << rule2bin::direction_to_string(rule.header.direction) << "\n";
    std::cout << "  Options: " << rule.header.option_count << "\n";
    
    for (size_t i = 0; i < rule.options.size(); ++i) {
        std::cout << "    - " << rule2bin::option_type_to_string(rule.options[i].type) 
                  << ": " << rule.string_data[i] << "\n";
    }
    std::cout << "\n";
}

int convert_rules(const std::string& input_file, const std::string& output_file) {
    rule2bin::RuleParser parser;
    std::vector<rule2bin::Rule> rules;
    
    std::cout << "Parsing rules from: " << input_file << "\n";
    
    if (!parser.parse_rules_from_file(input_file, rules)) {
        std::cerr << "Error parsing rules: " << parser.get_last_error() << "\n";
        return 1;
    }
    
    std::cout << "Successfully parsed " << rules.size() << " rules\n";
    
    rule2bin::BinarySerializer serializer;
    std::cout << "Serializing to binary: " << output_file << "\n";
    
    if (!serializer.serialize_to_file(rules, output_file)) {
        std::cerr << "Error serializing rules: " << serializer.get_last_error() << "\n";
        return 1;
    }
    
    std::cout << "Successfully created binary file: " << output_file << "\n";
    return 0;
}

int show_binary_info(const std::string& binary_file) {
    rule2bin::BinaryDeserializer deserializer;
    std::vector<rule2bin::Rule> rules;
    
    std::cout << "Reading binary file: " << binary_file << "\n";
    
    if (!deserializer.deserialize_from_file(binary_file, rules)) {
        std::cerr << "Error reading binary file: " << deserializer.get_last_error() << "\n";
        return 1;
    }
    
    std::cout << "File contains " << rules.size() << " rules\n\n";
    
    for (size_t i = 0; i < rules.size(); ++i) {
        print_rule_info(rules[i], i + 1);
    }
    
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    std::string command = argv[1];
    
    if (command == "convert") {
        if (argc != 4) {
            std::cerr << "Error: convert command requires input and output files\n";
            print_usage(argv[0]);
            return 1;
        }
        return convert_rules(argv[2], argv[3]);
    }
    else if (command == "info") {
        if (argc != 3) {
            std::cerr << "Error: info command requires a binary file\n";
            print_usage(argv[0]);
            return 1;
        }
        return show_binary_info(argv[2]);
    }
    else if (command == "help") {
        print_usage(argv[0]);
        return 0;
    }
    else {
        std::cerr << "Error: Unknown command '" << command << "'\n";
        print_usage(argv[0]);
        return 1;
    }
}