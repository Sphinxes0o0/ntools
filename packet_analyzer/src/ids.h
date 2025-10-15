#ifndef MINIIDS_MINIIDS_H
#define MINIIDS_MINIIDS_H

#include "core/config.h"
#include "capture/interface.h"
#include "../include/parsing/matcher.h"
#include <map>
#include <memory>
#include <atomic>
#include <thread>
#include <vector>
#include <mutex>

namespace ids {

// Forward declarations
class ProtocolManager;
class RuleParser;
class RuleMatcher;

/**
 * @brief Main IDS application class
 */
class IDS {
public:
    /**
     * @brief Constructor
     */
    IDS();
    
    /**
     * @brief Destructor
     */
    ~IDS();
    
    /**
     * @brief Initialize IDS with configuration
     * @param config_file Path to configuration file
     * @return true if initialization successful, false otherwise
     */
    bool initialize(const std::string& config_file);
    
    /**
     * @brief Initialize IDS with configuration object
     * @param config Configuration object
     * @return true if initialization successful, false otherwise
     */
    bool initialize(const Config& config);
    
    /**
     * @brief Run main processing loop
     */
    void run();
    
    /**
     * @brief Shutdown IDS
     */
    void shutdown();
    
    /**
     * @brief Check if IDS is running
     * @return true if running, false otherwise
     */
    bool isRunning() const;
    
    /**
     * @brief Check if IDS is paused
     * @return true if paused, false otherwise
     */
    bool isPaused() const;
    
    /**
     * @brief Pause processing
     */
    void pause();
    
    /**
     * @brief Resume processing
     */
    void resume();
    
    /**
     * @brief Reload configuration
     * @param config_file Path to new configuration file
     * @return true if reload successful, false otherwise
     */
    bool reloadConfig(const std::string& config_file);
    
    /**
     * @brief Handle system signal
     * @param signal Signal number
     */
    void handleSignal(int signal);
    
    /**
     * @brief Setup signal handlers
     */
    static void setupSignalHandlers();
    
    // Module access - removed LogManager for simplicity
    ICaptureModule* getCaptureModule() const { return capture_module_.get(); }
    ProtocolManager* getProtocolManager() const { return protocol_manager_.get(); }
    RuleMatcher* getRuleMatcher() const { return rule_matcher_.get(); }
    
    /**
     * @brief System statistics
     */
    struct SystemStats {
        uint64_t packets_processed;
        uint64_t alerts_generated;
        uint64_t rules_matched;
        double uptime_seconds;
        double packets_per_second;
        double average_processing_time;
        std::map<std::string, uint64_t> protocol_counts;
        std::map<std::string, uint64_t> alert_counts;
        
        SystemStats() 
            : packets_processed(0), alerts_generated(0), rules_matched(0),
              uptime_seconds(0.0), packets_per_second(0.0), average_processing_time(0.0) {}
    };
    
    /**
     * @brief Get system statistics
     * @return Current system statistics
     */
    SystemStats getStats() const;
    
    /**
     * @brief Get statistics as JSON string
     * @return JSON representation of statistics
     */
    std::string getStatsJSON() const;
    
    /**
     * @brief Reset statistics
     */
    void resetStats();
    
    /**
     * @brief Initialize components
     */
    void initialize_components();

private:
    /**
     * @brief Initialize modules
     * @return true if successful, false otherwise
     */
    bool initializeModules();
    
    /**
     * @brief Process a single packet
     * @param packet Packet to process
     */
    void processPacket(const Packet& packet);
    
    /**
     * @brief Handle rule match alert
     * @param match Rule match result
     * @param packet Original packet
     */
    void handleAlert(const RuleMatch& match, const Packet& packet);
    
    /**
     * @brief Main processing loop - single threaded for simplicity
     */
    void processingLoop();
    
    /**
     * @brief Update system statistics
     */
    void updateStats();
    
    // Configuration
    Config config_;
    
    // Module instances - removed LogManager for simplicity
    std::unique_ptr<ICaptureModule> capture_module_;
    std::unique_ptr<ProtocolManager> protocol_manager_;
    std::unique_ptr<RuleParser> rule_parser_;
    std::unique_ptr<RuleMatcher> rule_matcher_;
    
    // State
    std::atomic<bool> running_;
    std::atomic<bool> paused_;
    std::chrono::steady_clock::time_point start_time_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    SystemStats stats_;
};

} // namespace IDS

#endif // MINIIDS_MINIIDS_H