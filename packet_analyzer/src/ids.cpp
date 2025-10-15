#include "ids.h"
#include "core/utils.cpp"
#include "capture/factory.h"
#include "../include/parsing/tcp.h"
#include "../include/parsing/parser.h"
#include "../include/parsing/matcher.h"
#include "../include/utils/packet_formatter.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <signal.h>

namespace ids {

// Forward declarations for module classes (will be implemented later)
class ProtocolManager {
public:
    static ProtocolManager& getInstance() {
        static ProtocolManager instance;
        return instance;
    }
    bool initialize(const Config& config) {
        (void)config; // Unused parameter for now
        return true;
    }
    void shutdown() {}
};

IDS::IDS() 
    : running_(false), paused_(false), 
      start_time_(std::chrono::steady_clock::now()) {
}

IDS::~IDS() {
    shutdown();
}

bool IDS::initialize(const std::string& config_file) {
    Config config(config_file);
    return initialize(config);
}

bool IDS::initialize(const Config& config) {
    config_ = config;
    
    std::cout << "Initializing IDS with configuration..." << std::endl;
    
    // Initialize modules
    if (!initializeModules()) {
        std::cerr << "Failed to initialize modules" << std::endl;
        return false;
    }
    
    running_ = true;
    std::cout << "IDS initialized successfully" << std::endl;
    return true;
}
void IDS::run() {
    if (!running_) {
        std::cerr << "IDS not properly initialized or failed to start" << std::endl;
        return;
    }

    std::cout << "Starting packet processing..." << std::endl;
    processingLoop();
}

void IDS::shutdown() {
    if (!running_) {
        return;
    }
    
    std::cout << "Shutting down IDS..." << std::endl;
    
    running_ = false;
    
    // Stop capture module first to stop packet flow
    if (capture_module_) {
        capture_module_->shutdown();
    }
    
    
    // Shutdown other modules
    if (rule_matcher_) {
        rule_matcher_->shutdown();
    }
    
    if (rule_parser_) {
        rule_parser_->shutdown();
    }
    
    if (protocol_manager_) {
        protocol_manager_->shutdown();
    }

    std::cout << "IDS shutdown completed" << std::endl;
}

bool IDS::isRunning() const {
    return running_;
}

bool IDS::isPaused() const {
    return paused_;
}

void IDS::pause() {
    paused_ = true;
    std::cout << "IDS paused" << std::endl;
}

void IDS::resume() {
    paused_ = false;
    std::cout << "IDS resumed" << std::endl;
}

bool IDS::reloadConfig(const std::string& config_file) {
    try {
        Config new_config(config_file);
        config_ = new_config;
        std::cout << "Configuration reloaded from: " << config_file << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to reload configuration: " << e.what() << std::endl;
        return false;
    }
}

void IDS::handleSignal(int signal) {
    switch (signal) {
        case SIGINT:
        case SIGTERM:
            std::cout << "Received shutdown signal" << std::endl;
            shutdown();
            break;
        case SIGHUP:
            std::cout << "Received reload signal" << std::endl;
            reloadConfig("/etc/ids/ids.yaml");
            break;
        case SIGUSR1:
            std::cout << "Received stats signal" << std::endl;
            {
                auto stats = getStats();
                std::cout << "Packets processed: " << stats.packets_processed << std::endl;
                std::cout << "Alerts generated: " << stats.alerts_generated << std::endl;
                std::cout << "Rules matched: " << stats.rules_matched << std::endl;
                std::cout << "Uptime: " << stats.uptime_seconds << " seconds" << std::endl;
            }
            break;
        default:
            break;
    }
}

void IDS::setupSignalHandlers() {
    // This would be implemented in main.cpp
}

bool IDS::initializeModules() {
    std::cout << "Initializing modules..." << std::endl;
    
    try {
        // Initialize capture module
        std::string capture_type = config_.get<std::string>("capture.type", "af_packet");
        capture_module_ = ids::Factory::create(capture_type);
        
        CaptureConfig capture_config = CaptureConfig::fromConfig(config_);
        if (!capture_module_->initialize(capture_config)) {
            std::cerr << "Failed to initialize capture module" << std::endl;
            return false;
        }
        
        // Note: Removed log_manager initialization since we eliminated LogManager
        
        // Initialize rule parser
        rule_parser_ = std::make_unique<RuleParser>();
        if (!rule_parser_->initialize(config_)) {
            std::cerr << "Failed to initialize rule parser" << std::endl;
            return false;
        }
        
        // Initialize rule matcher
        rule_matcher_ = std::make_unique<RuleMatcher>();
        if (!rule_matcher_->initialize(config_)) {
            std::cerr << "Failed to initialize rule matcher" << std::endl;
            return false;
        }
        
        std::cout << "All modules initialized successfully" << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Module initialization error: " << e.what() << std::endl;
        return false;
    }
}

void IDS::processingLoop() {
    // Create packet formatter for unified output
    static PacketFormatter formatter;
    static uint32_t packet_counter = 0;
    
    while (running_) {
        if (paused_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        try {
            // Capture packet
            if (capture_module_) {
                auto packet = capture_module_->capturePacket();
                if (packet) {
                    processPacket(*packet);
                }
            } else {
                // Small delay to prevent busy waiting
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        } catch (const std::exception& e) {
            // Log error directly with std::cout instead of LogManager
            std::cerr << "[" << utils::getCurrentTimestamp() << "] [ERROR] capture: " << e.what() << std::endl;
        }
    }
}

void IDS::processPacket(const Packet& packet) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    try {
        static PacketFormatter formatter;
        static uint32_t packet_counter = 0;
        packet_counter++;

        // Format the entire packet with all protocols in one cohesive output
        if (false) {
            std::string formatted_packet = formatter.formatPacket(packet, packet_counter);
            std::cout << formatted_packet << std::endl;
        }
        // Perform rule matching on the packet
        if (rule_matcher_) {
            std::vector<RuleMatch> matches = rule_matcher_->matchPacket(packet);
            
            // Process rule matches and generate alerts
            for (const auto& match : matches) {
                handleAlert(match, packet);
            }
            
            // Update statistics
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.packets_processed++;
                stats_.rules_matched += matches.size();
                stats_.alerts_generated += matches.size();
            }
        } else {
            // Update packet count only if no rule matcher
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.packets_processed++;
            }
        }

    } catch (const std::exception& e) {
        // Log error directly with std::cout instead of LogManager
        std::cerr << "[" << utils::getCurrentTimestamp() << "] [ERROR] processing: Error in "
                  << "capture: " << e.what() << std::endl;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    // Update processing time statistics
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        double current_time = duration.count() / 1000.0; // Convert to milliseconds
        stats_.average_processing_time = (stats_.average_processing_time + current_time) / 2.0;
    }
}

IDS::SystemStats IDS::getStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    SystemStats current_stats = stats_;
    
    // Calculate uptime
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        now - start_time_).count();
    current_stats.uptime_seconds = duration;
    
    // Calculate packets per second
    if (duration > 0) {
        current_stats.packets_per_second = 
            static_cast<double>(stats_.packets_processed) / duration;
    }
    
    return current_stats;
}

std::string IDS::getStatsJSON() const {
    auto stats = getStats();
    
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"packets_processed\": " << stats.packets_processed << ",\n";
    ss << "  \"alerts_generated\": " << stats.alerts_generated << ",\n";
    ss << "  \"rules_matched\": " << stats.rules_matched << ",\n";
    ss << "  \"uptime_seconds\": " << std::fixed << std::setprecision(2) 
       << stats.uptime_seconds << ",\n";
    ss << "  \"packets_per_second\": " << std::fixed << std::setprecision(2) 
       << stats.packets_per_second << ",\n";
    ss << "  \"average_processing_time_ms\": " << std::fixed << std::setprecision(3) 
       << stats.average_processing_time << "\n";
    ss << "}";
    
    return ss.str();
}

void IDS::resetStats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = SystemStats();
    start_time_ = std::chrono::steady_clock::now();
}

void IDS::handleAlert(const RuleMatch& match, const Packet& packet) {
    // Format and output the alert
    std::cout << "[" << utils::getCurrentTimestamp() << "] [ALERT] "
              << "SID: " << match.sid
              << " - " << match.message
              << " [Classification: " << match.classtype << "]" << std::endl;
    
    // Optionally, we could log more details about the packet and match
    if (!match.matched_content.empty()) {
        std::cout << "    Matched content: ";
        for (const auto& [key, value] : match.matched_content) {
            std::cout << key << "=" << value << " ";
        }
        std::cout << std::endl;
    }
}

void IDS::initialize_components() {
    // Direct logging with std::cout instead of LogManager
    std::cout << "[" << utils::getCurrentTimestamp() << "] [INFO] IDS: Components initialized" << std::endl;
}

} // namespace ids