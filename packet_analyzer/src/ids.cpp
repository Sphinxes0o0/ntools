#include "ids.h"
#include "packetio/factory.h"
#include "protocols/protocol_parser.h"
#include "protocols/tcp.h"
#include "ids/config.h"
#include <iostream>
#include <csignal>
#include <cstring>
#include <chrono>
#include <thread>
#include <memory>

namespace ids {

static volatile bool g_running = true;
static IDS* g_instance = nullptr;

void signalHandler(int signal) {
    std::cout << "\nReceived signal " << signal << ", shutting down...\n";
    g_running = false;
    if (g_instance) {
        g_instance->shutdown();
    }
}

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
    // Set up signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
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
        
        // Initialize protocol parsers
        initializeProtocolParsers();
        
        // Initialize rule components
        rule_parser_ = std::make_unique<RuleParser>();
        // rule_matcher_ is already declared in the class
        
        // Load rules
        loadRules();
        
        // Initialize capture module and other components
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
    protocol_parsers_.push_back(std::make_unique<EthernetParser>());
    protocol_parsers_.push_back(std::make_unique<IPParser>());
    protocol_parsers_.push_back(std::make_unique<TCPParser>());
}

void IDS::loadRules() {
    // Example of loading rules - in a real implementation this would load from files
    std::vector<std::string> rule_strings = {
        "alert tcp any any -> any any (msg:\"Test rule\"; sid:1000001; rev:1;)",
        "drop tcp any any -> any 80 (msg:\"Block HTTP\"; sid:1000002; rev:1;)"
    };

    auto rules = rule_parser_->parseRules(rule_strings);
    rule_matcher_.addRules(rules);

    std::cout << "Loaded " << rules.size() << " rules" << std::endl;
}

bool IDS::initializeModules() {
    std::cout << "Initializing modules..." << std::endl;

    std::string capture_type = config_.get<std::string>("capture.type", "af_packet");
    capture_module_ = ids::Factory::create(capture_type);

    if (!capture_module_) {
        std::cerr << "Failed to create capture module of type: " << capture_type << std::endl;
        return false;
    }

    std::cout << "All modules initialized successfully" << std::endl;
    return true;
}

void IDS::run() {
    std::string interface = config_.get<std::string>("capture.interface", "lo");
    std::cout << "IDS monitoring " << interface << std::endl;
    running_ = true;

    // Initialize capture module with config
    CaptureConfig capture_config;
    capture_config.interface = interface;
    capture_config.buffer_size = config_.get<int>("capture.buffer_size", 65536);
    capture_config.timeout_ms = config_.get<int>("capture.timeout_ms", 1000);
    capture_config.snaplen = config_.get<int>("capture.snaplen", 65535);
    capture_config.promiscuous = config_.get<bool>("capture.promiscuous", true);
    capture_config.filter = config_.get<std::string>("capture.filter", "");

    if (capture_module_ && !capture_module_->initialize(capture_config)) {
        std::cerr << "Failed to initialize capture module" << std::endl;
        return;
    }

    while (running_ && g_running) {
        // 1. capture packet
        std::unique_ptr<Packet> packet = nullptr;
        if (capture_module_) {
            packet = capture_module_->capturePacket();
        }

        // 2. process packet
        if (packet) {
            processPacket(*packet);
        }

        // Small delay to prevent busy waiting if no packet was captured
        if (!packet) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}

std::vector<ParsingResult> IDS::parsePacket(const Packet& packet) {
    std::vector<ParsingResult> results;

    // Start with the full packet data for Ethernet parsing
    std::vector<uint8_t> current_data = packet.data;

    // Try each parser to see if it can parse the packet
    for (const auto& parser : protocol_parsers_) {
        if (parser->can_parse(current_data)) {
            ParsingResult result = parser->parse(current_data);
            if (result.is_valid) {
                results.push_back(result);
                // Update current_data for the next layer based on the protocol type
                if (result.protocol_type == ProtocolType::ETHERNET) {
                    // After parsing Ethernet, move to IP header (14 bytes offset)
                    if (current_data.size() > 14) {
                        // Check EtherType to determine next protocol
                        uint16_t ether_type = (current_data[12] << 8) | current_data[13];
                        if (ether_type == 0x0800) { // IPv4
                            current_data = std::vector<uint8_t>(current_data.begin() + 14, current_data.end());
                        } else {
                            // For other types, we stop parsing
                            break;
                        }
                    } else {
                        break;
                    }
                } else if (result.protocol_type == ProtocolType::IP) {
                    // After parsing IP, move to transport layer header
                    if (!current_data.empty()) {
                        uint8_t ihl = current_data[0] & 0x0F;
                        uint8_t ip_header_length = ihl * 4;
                        if (current_data.size() > ip_header_length) {
                            // Move to transport layer (TCP/UDP/ICMP)
                            current_data = std::vector<uint8_t>(current_data.begin() + ip_header_length, current_data.end());
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                } else {
                    // For other protocols (TCP, UDP, etc.), we've reached the top of the stack
                    break;
                }
            }
        }
    }

    return results;
}

void IDS::processPacket(const Packet& packet) {
    // 1. Parse packet with all applicable parsers
    std::vector<ParsingResult> parsing_results = parsePacket(packet);

    // 2. Display parsing information
    if (!parsing_results.empty()) {
        for (const auto& result : parsing_results) {
            std::cout << "Protocol: " << result.description << std::endl;
            // Display detailed findings
            for (const auto& finding : result.findings) {
                std::cout << "  " << finding.first << ": " << finding.second << std::endl;
            }
        }
    } else {
        std::cout << "Unknown or unparsable packet (" << packet.data.size() << " bytes)" << std::endl;
    }

    // 3. Match against rules
    std::vector<RuleMatch> matched_rules = rule_matcher_.match(packet);

    // 4. Process rule matches
    if (!matched_rules.empty()) {
        std::cout << "Matched " << matched_rules.size() << " rules:" << std::endl;
        for (const auto& match : matched_rules) {
            // In a real implementation, we would take actions based on rule
            std::cout << "  Rule matched: " << match.rule->description << " (action would be taken)" << std::endl;
        }
    }
}

void IDS::shutdown() {
    // Only execute shutdown once
    if (shutdown_called_.exchange(true)) {
        return;
    }
    std::cout << "Shutting down IDS..." << std::endl;
    running_ = false;
    if (capture_module_) {
        capture_module_->shutdown();
    }
}

bool IDS::isRunning() const {
    return running_;
}

void IDS::handleSignal(int signal) {
    std::cout << "Received signal: " << signal << std::endl;
    switch (signal) {
        case SIGINT:
        case SIGTERM:
            if (g_instance) {
                g_instance->shutdown();
            }
            break;
        default:
            break;
    }
}

} // namespace ids