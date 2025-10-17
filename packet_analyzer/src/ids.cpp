#include "ids.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <csignal>

#include "../include/ids/config.h"
#include "packetio/factory.h"
#include "../include/utils/utils.h"
#include "../include/protocols/ethernet.h"
#include "../include/protocols/ip.h"
#include "../include/protocols/tcp.h"

namespace ids {

static IDS* g_instance = nullptr;

IDS::IDS() 
    : running_(false), paused_(false), shutdown_called_(false),
      start_time_(std::chrono::steady_clock::now()) {
    g_instance = this;
}

IDS::~IDS() {
    shutdown();
    g_instance = nullptr;
}

bool IDS::initialize(const std::string& config_file) {
    try {
        Config config;
        if (!config.loadFromFile(config_file)) {
            std::cerr << "Failed to load configuration from " << config_file << std::endl;
            return false;
        }
        return initialize(config);
    } catch (const std::exception& e) {
        std::cerr << "Error initializing IDS: " << e.what() << std::endl;
        return false;
    }
}

bool IDS::initialize(const Config& config) {
    try {
        config_ = config;
        initializeProtocolParsers();
        rule_parser_ = std::make_unique<RuleParser>();
        loadRules();
        if (!initializeModules()) {
            std::cerr << "Failed to initialize modules" << std::endl;
            return false;
        }

        std::cout << "IDS initialized successfully" << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error initializing IDS: " << e.what() << std::endl;
        return false;
    }
}

void IDS::initializeProtocolParsers() {
    // 初始化协议解析器列表
    protocol_parsers_.push_back(std::make_unique<EthernetParser>());
    protocol_parsers_.push_back(std::make_unique<IPParser>());
    protocol_parsers_.push_back(std::make_unique<TCPParser>());
}

void IDS::loadRules() {
    std::cout << "Loading rules..." << std::endl;

    try {
        std::vector<std::string> rule_files = 
            config_.get<std::vector<std::string>>("ids.rules.rule_files", std::vector<std::string>());
        std::cout << "Found " << rule_files.size() << " rule files in configuration" << std::endl;
        std::vector<std::string> all_rule_strings;

        for (const auto& rule_file : rule_files) {
            std::cout << "Loading rules from file: " << rule_file << std::endl;

            std::ifstream file(rule_file);
            if (!file.is_open()) {
                std::cerr << "Warning: Cannot open rule file: " << rule_file << std::endl;
                continue;
            }

            std::string line;
            std::vector<std::string> rule_strings;
            std::string multi_line_rule;
            bool in_multiline_rule = false;

            while (std::getline(file, line)) {
                // Skip empty lines and comments
                if (line.empty() || line[0] == '#' || (line[0] == '/' && line[1] == '/')) {
                    continue;
                }

                // Trim whitespace from the beginning and end of the line
                line.erase(0, line.find_first_not_of(" \t"));
                line.erase(line.find_last_not_of(" \t") + 1);

                // Handle multi-line rules
                if (in_multiline_rule) {
                    multi_line_rule += " " + line;
                    if (line.find(')') != std::string::npos) {
                        rule_strings.push_back(multi_line_rule);
                        multi_line_rule.clear();
                        in_multiline_rule = false;
                    }
                } else if (line.find('(') != std::string::npos && line.find(')') == std::string::npos) {
                    multi_line_rule = line;
                    in_multiline_rule = true;
                } else {
                    // Single line rule
                    if (!line.empty()) {
                        rule_strings.push_back(line);
                    }
                }
            }

            // Handle case where file ends with an unclosed multiline rule
            if (in_multiline_rule && !multi_line_rule.empty()) {
                std::cerr << "Warning: Unclosed multiline rule in file: " << rule_file << std::endl;
            }

            file.close();

            std::cout << "Loaded " << rule_strings.size() << " rules from " << rule_file << std::endl;
            all_rule_strings.insert(all_rule_strings.end(), rule_strings.begin(), rule_strings.end());
        }

        std::cout << "Parsing " << all_rule_strings.size() << " rules" << std::endl;
        auto rules = rule_parser_->parseRules(all_rule_strings);
        rule_matcher_.addRules(rules);
        std::cout << "Loaded " << rules.size() << " rules" << std::endl;
        std::cout << "Rule matcher now contains " << rule_matcher_.size() << " rules" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error loading rules: " << e.what() << std::endl;
    }
}

bool IDS::initializeModules() {
    std::cout << "Initializing modules..." << std::endl;

    std::string capture_type = config_.get<std::string>("capture.type", "af_packet");
    capture_module_ = Factory::create(capture_type);

    if (!capture_module_) {
        std::cerr << "Failed to create capture module of type: " << capture_type << std::endl;
        return false;
    }

    // Initialize capture module with config
    CaptureConfig capture_config;
    capture_config.interface = config_.get<std::string>("capture.interface", "lo");
    capture_config.buffer_size = config_.get<int>("capture.buffer_size", 65536);
    capture_config.timeout_ms = config_.get<int>("capture.timeout_ms", 1000);
    capture_config.snaplen = config_.get<int>("capture.snaplen", 65535);
    capture_config.promiscuous = config_.get<bool>("capture.promiscuous", true);
    capture_config.filter = config_.get<std::string>("capture.filter", "");

    if (!capture_module_->initialize(capture_config)) {
        std::cerr << "Failed to initialize capture module" << std::endl;
        return false;
    }

    std::cout << "All modules initialized successfully" << std::endl;
    return true;
}

void IDS::run() {
    std::cout << "Running IDS..." << std::endl;
    running_ = true;

    while (running_) {
        // 1. capture packet
        std::unique_ptr<Packet> packet = nullptr;
        if (capture_module_) {
            packet = capture_module_->capturePacket();
        }

        if (packet) {
            processPacket(*packet);
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}

void IDS::shutdown() {
    if (shutdown_called_) {
        return;
    }

    shutdown_called_ = true;
    running_ = false;
    paused_ = false;

    if (capture_module_) {
        capture_module_->shutdown();
    }

    std::cout << "IDS shutdown complete" << std::endl;
}

bool IDS::isRunning() const {
    return running_;
}

std::vector<ParsingResult> IDS::parsePacket(const Packet& packet) {
    std::vector<ParsingResult> results;

    if (packet.data.size() < 14) {
        return results;
    }

    ParsingResult eth_result = parseEthernetLayer(packet);
    if (!eth_result.is_valid) {
        return results;
    }

    results.push_back(eth_result);

    uint16_t ether_type = (packet.data[12] << 8) | packet.data[13];

    if (ether_type != 0x0800) { // 只处理IPv4
        return results;
    }

    ParsingResult ip_result = parseIPLayer(packet);
    if (!ip_result.is_valid) {
        return results;
    }

    results.push_back(ip_result);

    ParsingResult transport_result = parseTransportLayer(packet);
    if (transport_result.is_valid) {
        results.push_back(transport_result);
    }

    return results;
}

ParsingResult IDS::parseEthernetLayer(const Packet& packet) {
    for (const auto& parser : protocol_parsers_) {
        if (parser && parser->can_parse(packet.data)) {
            ParsingResult result = parser->parse(packet.data);
            if (result.is_valid && result.protocol_type == ProtocolType::ETHERNET) {
                return result;
            }
        }
    }
    return ParsingResult(ProtocolType::UNKNOWN, false);
}

ParsingResult IDS::parseIPLayer(const Packet& packet) {
    // 提取IP数据（以太网头部之后的数据）
    if (packet.data.size() <= 14) {
        return ParsingResult(ProtocolType::UNKNOWN, false);
    }

    std::vector<uint8_t> ip_data(packet.data.begin() + 14, packet.data.end());

    for (const auto& parser : protocol_parsers_) {
        if (parser && parser->can_parse(ip_data)) {
            ParsingResult result = parser->parse(ip_data);
            if (result.is_valid && result.protocol_type == ProtocolType::IP) {
                return result;
            }
        }
    }
    return ParsingResult(ProtocolType::UNKNOWN, false);
}

ParsingResult IDS::parseTransportLayer(const Packet& packet) {
    // 从IP头部获取头部长度，计算传输层数据位置
    std::vector<uint8_t> ip_data(packet.data.begin() + 14, packet.data.end());

    if (ip_data.empty()) {
        return ParsingResult(ProtocolType::UNKNOWN, false);
    }

    uint8_t ihl = ip_data[0] & 0x0F;
    uint8_t ip_header_length = ihl * 4;

    if (ip_data.size() <= ip_header_length) {
        return ParsingResult(ProtocolType::UNKNOWN, false);
    }

    std::vector<uint8_t> transport_data(ip_data.begin() + ip_header_length, ip_data.end());

    uint8_t protocol = ip_data[9]; // IP头部第10个字节是协议字段
    for (const auto& parser : protocol_parsers_) {
        if (parser && parser->can_parse(transport_data)) {
            ParsingResult result = parser->parse(transport_data);
            if (result.is_valid) {
                // 检查协议是否匹配 (使用RFC定义的协议号: TCP=6, UDP=17)
                if ((protocol == 6 && result.protocol_type == ProtocolType::TCP) ||
                    (protocol == 17 && result.protocol_type == ProtocolType::UDP)) {
                    return result;
                }
            }
        }
    }
    return ParsingResult(ProtocolType::UNKNOWN, false);
}

void IDS::processPacket(const Packet& packet) {
    std::cout << "\n=== Processing new packet ===" << std::endl;
    std::cout << "Packet length: " << packet.length << " bytes" << std::endl;
    std::cout << "Packet data (first 32 bytes): " << packet.toHexString() << std::endl;
    // 1. Parse packet with all applicable parsers
    std::vector<ParsingResult> parsing_results = parsePacket(packet);

    // 2. Display parsing information
    std::cout << "Parsing results:" << std::endl;
    for (const auto& result : parsing_results) {
        if (result.is_valid) {
            std::cout << "  Protocol: " << static_cast<int>(result.protocol_type) 
                      << ", Description: " << result.description << std::endl;
            // Display detailed findings
            for (const auto& finding : result.findings) {
                std::cout << "    " << finding.first << ": " << finding.second << std::endl;
            }
        }
    }

    if (parsing_results.empty()) {
        std::cout << "  No valid parsing results" << std::endl;
    }

    // 3. Match rules against the packet
    std::cout << "Matching rules..." << std::endl;
    std::vector<RuleMatch> matches = rule_matcher_.match(packet);
    std::cout << "Found " << matches.size() << " matching rules" << std::endl;

    for (const auto& match : matches) {
        if (match.rule) {
            std::cout << "ALERT: Rule matched: " << match.rule->description 
                      << " (SID: " << match.rule->id << ")" << std::endl;

            // 根据规则动作执行相应操作
            switch (match.rule->action) {
                case RuleAction::ALERT:
                    std::cout << "  Action: ALERT - Generating alert" << std::endl;
                    break;
                case RuleAction::LOG:
                    std::cout << "  Action: LOG - Logging packet" << std::endl;
                    break;
                case RuleAction::DROP:
                    std::cout << "  Action: DROP - Dropping packet" << std::endl;
                    break;
                case RuleAction::PASS:
                    std::cout << "  Action: PASS - Passing packet without further inspection" << std::endl;
                    break;
                case RuleAction::REJECT:
                    std::cout << "  Action: REJECT - Rejecting packet" << std::endl;
                    break;
            }
        }
    }

    if (matches.empty()) {
        std::cout << "No rules matched for this packet" << std::endl;
    }

    std::cout << "=== End of packet processing ===\n" << std::endl;
}

void IDS::handleSignal(int signal) {
    std::cout << "\nReceived signal " << signal << ", shutting down...\n";
    if (g_instance) {
        g_instance->shutdown();
    }
}

} // namespace ids