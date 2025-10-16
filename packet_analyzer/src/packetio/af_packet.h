#ifndef MINIIDS_PACKETIO_AF_PACKET_CAPTURE_H
#define MINIIDS_PACKETIO_AF_PACKET_CAPTURE_H

#include "interface.h"
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <string>
#include <mutex>
#include <chrono>

namespace ids {

/**
 * @brief AF_PACKET capture module implementation
 */
class AFPacketCapture : public ICaptureModule {
public:
    /**
     * @brief Constructor
     */
    AFPacketCapture();
    
    /**
     * @brief Destructor
     */
    ~AFPacketCapture() override;
    
    /**
     * @brief Initialize AF_PACKET capture
     * @param config Capture configuration
     * @return true if successful, false otherwise
     */
    bool initialize(const CaptureConfig& config) override;
    
    /**
     * @brief Shutdown capture module
     */
    void shutdown() override;
    
    /**
     * @brief Capture a single packet
     * @return Unique pointer to packet, nullptr if timeout
     */
    std::unique_ptr<Packet> capturePacket() override;
    
    /**
     * @brief Capture multiple packets in batch
     * @param max_packets Maximum number of packets to capture
     * @return Vector of captured packets
     */
    std::vector<std::unique_ptr<Packet>> captureBatch(size_t max_packets) override;
    
    /**
     * @brief Get capture statistics
     * @return Current capture statistics
     */
    CaptureStats getStats() const override;
    
    /**
     * @brief Reset capture statistics
     */
    void resetStats() override;
    
    /**
     * @brief Check if capture is running
     * @return true if running, false otherwise
     */
    bool isRunning() const override;
    
    /**
     * @brief Get capture configuration
     * @return Current capture configuration
     */
    const CaptureConfig& getConfig() const override { return config_; }
    
    /**
     * @brief Set BPF filter
     * @param filter BPF filter expression
     * @return true if filter set successfully, false otherwise
     */
    bool setFilter(const std::string& filter) override;
    
    /**
     * @brief Get module name
     * @return Module name
     */
    std::string getName() const override { return "AF_PACKET"; }
    
    /**
     * @brief Get module version
     * @return Module version
     */
    std::string getVersion() const override { return "1.0.0"; }

private:
    /**
     * @brief Create AF_PACKET socket
     * @return true if successful, false otherwise
     */
    bool createSocket();
    
    /**
     * @brief Bind socket to network interface
     * @return true if successful, false otherwise
     */
    bool bindToInterface();
    
    /**
     * @brief Set socket options
     * @return true if successful, false otherwise
     */
    bool setSocketOptions();
    
    /**
     * @brief Get interface index by name
     * @param interface_name Interface name
     * @return Interface index, or -1 if not found
     */
    int getInterfaceIndex(const std::string& interface_name);
    
    /**
     * @brief Compile and set BPF filter
     * @param filter_string BPF filter expression
     * @return true if successful, false otherwise
     */
    bool compileAndSetFilter(const std::string& filter_string);
    
    /**
     * @brief Update capture statistics
     * @param packet_len Length of captured packet
     */
    void updateStats(size_t packet_len);
    
    // Member variables
    int socket_fd_;
    CaptureConfig config_;
    std::vector<uint8_t> buffer_;
    bool running_;
    
    mutable std::mutex stats_mutex_;
    CaptureStats stats_;
    
    std::string interface_name_;
    int interface_index_;
};

} // namespace ids

#endif // MINIIDS_PACKETIO_AF_PACKET_CAPTURE_H