#include "ids.h"
#include "packetio/factory.h"
#include "protocols/protocol_parser.h"
#include "protocols/tcp.h"
#include <iostream>
#include <csignal>
#include <cstring>
#include <chrono>
#include <thread>
#include <memory>

#include "ids/config.h"

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
        
        // Initialize protocol parsers
        initializeProtocolParsers();
        
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
    // For now, just add TCP parser
    // In a full implementation, we would initialize parsers based on config
    protocol_parsers_.push_back(std::make_unique<TCPParser>());
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

    while (running_) {
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
    
    // Try each parser to see if it can parse the packet
    for (const auto& parser : protocol_parsers_) {
        if (parser->can_parse(packet.data)) {
            ParsingResult result = parser->parse(packet.data);
            if (result.is_valid) {
                results.push_back(result);
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
    std::vector<std::shared_ptr<Rule>> matched_rules = rule_matcher_.match(packet);

    // 4. Process rule matches
    if (!matched_rules.empty()) {
        std::cout << "Matched " << matched_rules.size() << " rules:" << std::endl;
        for (const auto& rule : matched_rules) {
            // In a real implementation, we would take actions based on rule
            std::cout << "  Rule matched (action would be taken)" << std::endl;
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