#include "af_packet.h"
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <chrono>
#include <cstring>

namespace ids {

AFPacketCapture::AFPacketCapture() 
    : socket_fd_(-1), running_(false), interface_index_(-1) {
}

AFPacketCapture::~AFPacketCapture() {
    shutdown();
}

bool AFPacketCapture::initialize(const CaptureConfig& config) {
    config_ = config;
    buffer_.resize(config.buffer_size);
    running_ = false;
    
    try {
        if (!createSocket()) {
            return false;
        }
        
        if (!bindToInterface()) {
            close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }
        
        if (!setSocketOptions()) {
            close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }
        
        // Set filter if provided
        if (!config.filter.empty()) {
            if (!setFilter(config.filter)) {
                close(socket_fd_);
                socket_fd_ = -1;
                return false;
            }
        }
        
        running_ = true;
        resetStats();
        
        return true;
    } catch (const std::exception& e) {
        if (socket_fd_ != -1) {
            close(socket_fd_);
            socket_fd_ = -1;
        }
        return false;
    }
}

void AFPacketCapture::shutdown() {
    running_ = false;
    
    if (socket_fd_ != -1) {
        close(socket_fd_);
        socket_fd_ = -1;
    }
}

std::unique_ptr<Packet> AFPacketCapture::capturePacket() {
    if (!running_ || socket_fd_ == -1) {

    }
    
    struct pollfd pfd;
    pfd.fd = socket_fd_;
    pfd.events = POLLIN;
    
    // Poll with timeout
    int ret = poll(&pfd, 1, config_.timeout_ms);
    if (ret < 0) {
        if (errno == EINTR) {
            return nullptr; // Interrupted by signal
        }
    } else if (ret == 0) {
        return nullptr; // Timeout
    }
    
    // Receive packet
    struct sockaddr_ll addr;
    socklen_t addr_len = sizeof(addr);
    
    ssize_t received = recvfrom(socket_fd_, buffer_.data(), 
                               buffer_.size(), 0,
                               (struct sockaddr*)&addr, &addr_len);
    
    if (received < 0) {
        if (errno == EAGAIN || errno == EINTR) {
            return nullptr; // Would block or interrupted
        }
    }
    
    if (received == 0) {
        return nullptr; // No data
    }
    
    // Create packet
    auto packet = std::make_unique<Packet>(buffer_.data(), received);
    packet->interface_index = addr.sll_ifindex;
    packet->protocol = addr.sll_protocol;
    packet->setCurrentTime();
    
    // Update statistics
    updateStats(received);
    
    return packet;
}

std::vector<std::unique_ptr<Packet>> AFPacketCapture::captureBatch(size_t max_packets) {
    std::vector<std::unique_ptr<Packet>> packets;
    packets.reserve(max_packets);
    
    for (size_t i = 0; i < max_packets; ++i) {
        auto packet = capturePacket();
        if (packet) {
            packets.push_back(std::move(packet));
        } else {
            break; // No more packets available
        }
    }
    
    return packets;
}

CaptureStats AFPacketCapture::getStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void AFPacketCapture::resetStats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = CaptureStats();
}

bool AFPacketCapture::isRunning() const {
    return running_ && socket_fd_ != -1;
}

bool AFPacketCapture::setFilter(const std::string& filter) {
    if (filter.empty()) {
        return true; // No filter to set
    }
    
    return compileAndSetFilter(filter);
}

bool AFPacketCapture::createSocket() {
    socket_fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socket_fd_ == -1) {
    }
    
    return true;
}

bool AFPacketCapture::bindToInterface() {
    interface_name_ = config_.interface;
    interface_index_ = getInterfaceIndex(interface_name_);
    
    if (interface_index_ == -1) {
    }
    
    struct sockaddr_ll addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = interface_index_;
    addr.sll_protocol = htons(ETH_P_ALL);
    
    if (bind(socket_fd_, (struct sockaddr*)&addr, sizeof(addr)) == -1) {

    }
    
    return true;
}

bool AFPacketCapture::setSocketOptions() {
    // Set receive buffer size
    int recv_buffer_size = config_.buffer_size;
    if (setsockopt(socket_fd_, SOL_SOCKET, SO_RCVBUF, 
                   &recv_buffer_size, sizeof(recv_buffer_size)) == -1) {
        // Non-fatal - continue with default buffer size
    }
    
    // Set timeout if specified
    if (config_.timeout_ms > 0) {
        struct timeval tv;
        tv.tv_sec = config_.timeout_ms / 1000;
        tv.tv_usec = (config_.timeout_ms % 1000) * 1000;
        
        if (setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, 
                       &tv, sizeof(tv)) == -1) {
            // Non-fatal - continue without timeout
        }
    }
    
    // Enable promiscuous mode if requested
    if (config_.promiscuous) {
        struct packet_mreq mreq;
        std::memset(&mreq, 0, sizeof(mreq));
        mreq.mr_ifindex = interface_index_;
        mreq.mr_type = PACKET_MR_PROMISC;
        
        if (setsockopt(socket_fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                       &mreq, sizeof(mreq)) == -1) {
            // Non-fatal - continue without promiscuous mode
        }
    }
    
    return true;
}

int AFPacketCapture::getInterfaceIndex(const std::string& interface_name) {
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);
    
    int temp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (temp_socket == -1) {
        return -1;
    }
    
    if (ioctl(temp_socket, SIOCGIFINDEX, &ifr) == -1) {
        close(temp_socket);
        return -1;
    }
    
    close(temp_socket);
    return ifr.ifr_ifindex;
}

bool AFPacketCapture::compileAndSetFilter(const std::string& filter_string) {
    (void)filter_string; // Unused parameter for now
    
    // For now, we'll skip BPF filter compilation
    // In a full implementation, you would use libpcap or implement BPF compilation
    // This is a placeholder that accepts the filter but doesn't apply it
    
    // Log warning that filter is not implemented
    // This would be logged if we had a logger available
    
    return true;
}

void AFPacketCapture::updateStats(size_t packet_len) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    stats_.packets_captured++;
    stats_.bytes_captured += packet_len;
    
    // Calculate capture rate
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
        now - stats_.start_time).count();
    
    if (duration > 0) {
        stats_.capture_rate = static_cast<double>(stats_.packets_captured) / duration;
    }
}

} // namespace ids