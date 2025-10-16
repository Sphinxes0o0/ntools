#ifndef PACKETIO_INTERFACE_H
#define PACKETIO_INTERFACE_H

#include "../../include/protocols/packet.h"
#include "../../include/ids/config.h"
#include <memory>
#include <string>

namespace ids {

/**
 * @brief Capture statistics structure
 */
struct CaptureStats {
    uint64_t packets_captured;
    uint64_t packets_dropped;
    uint64_t bytes_captured;
    double capture_rate;  // packets per second
    std::chrono::steady_clock::time_point start_time;
    
    CaptureStats() 
        : packets_captured(0), packets_dropped(0), bytes_captured(0), 
          capture_rate(0.0), start_time(std::chrono::steady_clock::now()) {}
};

/**
 * @brief Abstract interface for packet capture modules
 */
class ICaptureModule {
public:
    virtual ~ICaptureModule() = default;
    
    /**
     * @brief Initialize the capture module
     * @param config Capture configuration
     * @return true if initialization successful, false otherwise
     */
    virtual bool initialize(const CaptureConfig& config) = 0;
    
    /**
     * @brief Shutdown the capture module
     */
    virtual void shutdown() = 0;
    
    /**
     * @brief Capture a single packet
     * @return Unique pointer to captured packet, nullptr if timeout or error
     */
    virtual std::unique_ptr<Packet> capturePacket() = 0;
    
    /**
     * @brief Capture multiple packets in batch
     * @param max_packets Maximum number of packets to capture
     * @return Vector of captured packets
     */
    virtual std::vector<std::unique_ptr<Packet>> captureBatch(size_t max_packets) = 0;
    
    /**
     * @brief Get capture statistics
     * @return Current capture statistics
     */
    virtual CaptureStats getStats() const = 0;
    
    /**
     * @brief Reset capture statistics
     */
    virtual void resetStats() = 0;
    
    /**
     * @brief Check if capture module is running
     * @return true if running, false otherwise
     */
    virtual bool isRunning() const = 0;
    
    /**
     * @brief Get capture configuration
     * @return Current capture configuration
     */
    virtual const CaptureConfig& getConfig() const = 0;
    
    /**
     * @brief Set BPF filter
     * @param filter BPF filter expression
     * @return true if filter set successfully, false otherwise
     */
    virtual bool setFilter(const std::string& filter) = 0;
    
    /**
     * @brief Get module name
     * @return Module name
     */
    virtual std::string getName() const = 0;
    
    /**
     * @brief Get module version
     * @return Module version
     */
    virtual std::string getVersion() const = 0;
};

/**
 * @brief Factory for creating capture modules
 */
class CaptureFactory {
public:
    /**
     * @brief Create capture module by type
     * @param type Capture module type ("af_packet", "libpcap", "ebpf")
     * @return Unique pointer to capture module
     */
    static std::unique_ptr<ICaptureModule> create(const std::string& type);
    
    /**
     * @brief Get available capture module types
     * @return Vector of available types
     */
    static std::vector<std::string> getAvailableTypes();
    
    /**
     * @brief Check if capture module type is available
     * @param type Capture module type
     * @return true if available, false otherwise
     */
    static bool isTypeAvailable(const std::string& type);
    
private:
    // Static class - prevent instantiation
    CaptureFactory() = delete;
};

} // namespace ids

#endif // PACKETIO_INTERFACE_H