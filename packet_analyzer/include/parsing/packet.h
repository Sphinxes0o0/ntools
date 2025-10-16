#ifndef MINIIDS_CORE_PACKET_H
#define MINIIDS_CORE_PACKET_H

#include "../../include/ids/common.h"
#include <vector>
#include <memory>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace ids {

/**
 * @brief Represents a network packet with raw data and metadata
 */
struct Packet {
    std::vector<uint8_t> data;          // Raw packet data
    size_t length;                      // Packet length in bytes
    uint32_t capture_time_sec;          // Capture timestamp (seconds)
    uint32_t capture_time_usec;         // Capture timestamp (microseconds)
    uint32_t interface_index;           // Network interface index
    uint16_t protocol;                  // Link layer protocol type
    
    /**
     * @brief Default constructor
     */
    Packet() : length(0), capture_time_sec(0), capture_time_usec(0), 
               interface_index(0), protocol(0) {}
    
    /**
     * @brief Constructor with raw data
     * @param raw_data Pointer to raw packet data
     * @param len Length of packet data
     */
    Packet(const uint8_t* raw_data, size_t len) 
        : data(raw_data, raw_data + len), length(len),
          capture_time_sec(0), capture_time_usec(0), 
          interface_index(0), protocol(0) {}
    
    /**
     * @brief Copy constructor
     */
    Packet(const Packet& other) = default;
    
    /**
     * @brief Move constructor
     */
    Packet(Packet&& other) noexcept = default;
    
    /**
     * @brief Copy assignment operator
     */
    Packet& operator=(const Packet& other) = default;
    
    /**
     * @brief Move assignment operator
     */
    Packet& operator=(Packet&& other) noexcept = default;
    
    /**
     * @brief Destructor
     */
    ~Packet() = default;
    
    /**
     * @brief Get packet data at specific offset
     * @param offset Byte offset
     * @return Pointer to data at offset, nullptr if out of bounds
     */
    const uint8_t* getDataAt(size_t offset) const {
        if (offset >= length) return nullptr;
        return data.data() + offset;
    }
    
    /**
     * @brief Get packet data at specific offset with bounds checking
     * @param offset Byte offset
     * @param size Number of bytes to read
     * @return Pointer to data at offset, nullptr if out of bounds
     */
    const uint8_t* getDataAt(size_t offset, size_t size) const {
        if (offset + size > length) return nullptr;
        return data.data() + offset;
    }
    
    /**
     * @brief Extract 16-bit value from packet data
     * @param offset Byte offset
     * @return 16-bit value in host byte order
     */
    uint16_t extractUint16(size_t offset) const {
        if (offset + 2 > length) return 0;
        return (static_cast<uint16_t>(data[offset]) << 8) | 
               static_cast<uint16_t>(data[offset + 1]);
    }
    
    /**
     * @brief Extract 32-bit value from packet data
     * @param offset Byte offset
     * @return 32-bit value in host byte order
     */
    uint32_t extractUint32(size_t offset) const {
        if (offset + 4 > length) return 0;
        return (static_cast<uint32_t>(data[offset]) << 24) |
               (static_cast<uint32_t>(data[offset + 1]) << 16) |
               (static_cast<uint32_t>(data[offset + 2]) << 8) |
               static_cast<uint32_t>(data[offset + 3]);
    }
    
    /**
     * @brief Set capture timestamp to current time
     */
    void setCurrentTime() {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
        auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration);
        
        capture_time_sec = static_cast<uint32_t>(seconds.count());
        capture_time_usec = static_cast<uint32_t>(microseconds.count() % 1000000);
    }
    
    /**
     * @brief Convert packet to hex string representation
     * @return Hex string of packet data
     */
    std::string toHexString() const {
        std::stringstream ss;
        for (size_t i = 0; i < length && i < 32; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(data[i]) << " ";
        }
        if (length > 32) {
            ss << "...";
        }
        return ss.str();
    }
    
    /**
     * @brief Get packet information string
     * @return Formatted packet information
     */
    std::string getInfo() const {
        std::stringstream ss;
        ss << "Packet: " << length << " bytes, "
           << "Interface: " << interface_index << ", "
           << "Protocol: 0x" << std::hex << std::setw(4) << std::setfill('0') << protocol;
        return ss.str();
    }
    
    /**
     * @brief Check if packet has valid length
     * @return true if packet has data, false otherwise
     */
    bool isValid() const {
        return length > 0 && !data.empty();
    }
    
    /**
     * @brief Get remaining length from offset
     * @param offset Starting offset
     * @return Remaining bytes from offset
     */
    size_t getRemainingLength(size_t offset) const {
        return (offset < length) ? (length - offset) : 0;
    }
    
    /**
     * @brief Clear packet data
     */
    void clear() {
        data.clear();
        length = 0;
        capture_time_sec = 0;
        capture_time_usec = 0;
        interface_index = 0;
        protocol = 0;
    }
    
    /**
     * @brief Reserve space for packet data
     * @param size Number of bytes to reserve
     */
    void reserve(size_t size) {
        data.reserve(size);
    }
    
    /**
     * @brief Resize packet data
     * @param size New size
     */
    void resize(size_t size) {
        data.resize(size);
        length = size;
    }
    
    /**
     * @brief Append data to packet
     * @param new_data Pointer to data to append
     * @param size Number of bytes to append
     */
    void append(const uint8_t* new_data, size_t size) {
        data.insert(data.end(), new_data, new_data + size);
        length += size;
    }
};

} // namespace ids

#endif // MINIIDS_CORE_PACKET_H