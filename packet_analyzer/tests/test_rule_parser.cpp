#include <iostream>
#include <memory>
#include "../include/rule/parser.h"

using namespace ids;

void testRuleParser() {
    std::cout << "=== Testing Suricata Rule Parser ===" << std::endl;
    
    // Create a rule parser
    RuleParser parser;
    
    // Test parsing the example rule from local.rules
    std::string test_rule = R"(alert tcp any any -> any any (msg:"Suricata: High TCP connection frequency from same source IP"; flow:established,to_server; threshold:type threshold,track by_src,count 10,seconds 60; classtype: network-scan; sid:1000001; rev:1;))";
    
    std::cout << "Parsing rule: " << test_rule << std::endl;
    
    try {
        Rule parsed_rule = parser.parseRule(test_rule);
        
        std::cout << "Successfully parsed rule!" << std::endl;
        std::cout << "Action: " << static_cast<int>(parsed_rule.action) << std::endl;
        std::cout << "Protocol: " << static_cast<int>(parsed_rule.protocol) << std::endl;
        std::cout << "Source IP: " << parsed_rule.src_ip << std::endl;
        std::cout << "Source Port: " << parsed_rule.src_port << std::endl;
        std::cout << "Destination IP: " << parsed_rule.dst_ip << std::endl;
        std::cout << "Destination Port: " << parsed_rule.dst_port << std::endl;
        std::cout << "Message: " << parsed_rule.options.msg << std::endl;
        std::cout << "SID: " << parsed_rule.options.sid << std::endl;
        std::cout << "Revision: " << parsed_rule.options.rev << std::endl;
        std::cout << "Classtype: " << parsed_rule.options.classtype << std::endl;
        
        // Print flow options
        std::cout << "Flow options: ";
        for (const auto& flow : parsed_rule.options.flow) {
            std::cout << static_cast<int>(flow) << " ";
        }
        std::cout << std::endl;
        
        // Print threshold options
        std::cout << "Threshold - Type: " << parsed_rule.options.threshold.type 
                  << ", Track: " << parsed_rule.options.threshold.track
                  << ", Count: " << parsed_rule.options.threshold.count
                  << ", Seconds: " << parsed_rule.options.threshold.seconds << std::endl;
                  
    } catch (const std::exception& e) {
        std::cerr << "Error parsing rule: " << e.what() << std::endl;
    }
}

void testRuleFileLoading() {
    std::cout << "\n=== Testing Rule File Loading ===" << std::endl;
    
    RuleParser parser;
    
    try {
        // Load rules from the local.rules file
        std::vector<Rule> rules = parser.loadRulesFromFile("config/rules/local.rules");
        
        std::cout << "Loaded " << rules.size() << " rules from file" << std::endl;
        
        for (const auto& rule : rules) {
            std::cout << "Rule SID " << rule.options.sid << ": " << rule.options.msg << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error loading rules from file: " << e.what() << std::endl;
    }
}

void testRuleValidation() {
    std::cout << "\n=== Testing Rule Validation ===" << std::endl;
    
    RuleParser parser;
    
    // Test valid rule
    std::string valid_rule = R"(alert tcp any any -> any any (msg:"Test Rule"; sid:1000002; rev:1;))";
    bool is_valid = parser.validateRule(valid_rule);
    std::cout << "Valid rule validation: " << (is_valid ? "PASS" : "FAIL") << std::endl;
    
    // Test invalid rule
    std::string invalid_rule = R"(invalid tcp any any -> any any (msg:"Test Rule"; sid:1000002; rev:1;))";
    bool is_invalid = parser.validateRule(invalid_rule);
    std::cout << "Invalid rule validation: " << (!is_invalid ? "PASS" : "FAIL") << std::endl;
}

int main() {
    std::cout << "IDS Rule Parser Test" << std::endl;
    std::cout << "=========================" << std::endl;
    
    testRuleParser();
    testRuleFileLoading();
    testRuleValidation();
    
    std::cout << "\n=== Test Complete ===" << std::endl;
    return 0;
}