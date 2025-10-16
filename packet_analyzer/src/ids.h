#ifndef MINIIDS_IDS_H
#define MINIIDS_IDS_H

#include <memory>
#include <atomic>
#include <chrono>
#include <mutex>
#include <map>
#include <vector>

#include "ids/config.h"
#include "protocols/packet.h"
#include "capture/interface.h"
#include "capture/factory.h"
#include "protocols/protocol_parser.h"
#include "rule/matcher.h"
#include "rule/parser.h"

namespace ids {

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
     * @brief Start the IDS engine
     */
    void run();
    
    /**
     * @brief Shutdown the IDS engine
     */
    void shutdown();
    
    /**
     * @brief Check if IDS is running
     * @return true if running, false otherwise
     */
    bool isRunning() const;
    
    /**
     * @brief Handle system signals
     * @param signal Signal number
     */
    void handleSignal(int signal);
    
private:
    std::atomic<bool> running_;
    std::atomic<bool> paused_;
    std::atomic<bool> shutdown_called_;
    std::chrono::steady_clock::time_point start_time_;
    Config config_;
    
    // Capture module
    std::unique_ptr<ids::ICaptureModule> capture_module_;
    
    // Protocol parsers
    std::vector<std::unique_ptr<ids::ProtocolParser>> protocol_parsers_;

    // Rule components
    ids::RuleMatcher rule_matcher_;
    ids::RuleParser rule_parser_;

    bool initializeModules();
    void processingLoop();
    void processPacket(const Packet& packet);
    
    // Protocol parsing functions
    void initializeProtocolParsers();
    std::vector<ids::ParsingResult> parsePacket(const Packet& packet);
};

} // namespace ids

#endif // MINIIDS_IDS_H