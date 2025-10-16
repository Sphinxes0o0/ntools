#ifndef IDS_H
#define IDS_H

#include "ids/common.h"
#include "packetio/interface.h"
#include "packetio/factory.h"
#include "protocols/packet.h"
#include "protocols/protocol_parser.h"
#include "rule/matcher.h"
#include "utils/packet_formatter.h"
#include <memory>
#include <string>
#include <atomic>
#include <thread>
#include <vector>
#include <chrono>

namespace ids {

class IDS {
public:
    IDS();
    ~IDS();
    
    bool initialize(const std::string& config_file);
    bool initialize(const Config& config);
    void run();
    void shutdown();
    bool isRunning() const;
    
    static void handleSignal(int signal);

private:
    std::unique_ptr<ICaptureModule> capture_module_;
    std::vector<std::unique_ptr<ProtocolParser>> protocol_parsers_;
    RuleMatcher rule_matcher_;
    Config config_;
    std::atomic<bool> running_;
    std::atomic<bool> paused_;
    std::atomic<bool> shutdown_called_;
    std::chrono::steady_clock::time_point start_time_;
    std::thread capture_thread_;
    
    void initializeProtocolParsers();
    bool initializeModules();
    std::vector<ParsingResult> parsePacket(const Packet& packet);
    void captureLoop();
    void processPacket(const Packet& packet);
};

} // namespace ids

#endif // IDS_H