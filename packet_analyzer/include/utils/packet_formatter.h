#ifndef MINIIDS_UTILS_PACKET_FORMATTER_H
#define MINIIDS_UTILS_PACKET_FORMATTER_H

#include "../../src/core/packet.h"
#include <string>

namespace ids {

/**
 * @brief Utility class for formatting packet data into human-readable format
 */
class PacketFormatter {
public:
    /**
     * @brief Constructor
     */
    PacketFormatter();
    
    /**
     * @brief Destructor
     */
    ~PacketFormatter();
    
    /**
     * @brief Format packet data into human-readable string
     * @param packet The packet to format
     * @param packetNumber The packet number for labeling
     * @return Formatted string representation of the packet
     */
    std::string formatPacket(const Packet& packet, uint32_t packetNumber);
    
private:
    /**
     * @brief Format Ethernet header information
     * @param packet The packet containing the header
     * @param ss String stream to append formatted data to
     */
    void formatEthernetHeader(const Packet& packet, std::stringstream& ss);
    
    /**
     * @brief Format IP header information
     * @param packet The packet containing the header
     * @param ss String stream to append formatted data to
     */
    void formatIPHeader(const Packet& packet, std::stringstream& ss);
    
    /**
     * @brief Format TCP header information
     * @param packet The packet containing the header
     * @param ss String stream to append formatted data to
     */
    void formatTCPHeader(const Packet& packet, std::stringstream& ss);
    
    /**
     * @brief Format UDP header information
     * @param packet The packet containing the header
     * @param ss String stream to append formatted data to
     */
    void formatUDPHeader(const Packet& packet, std::stringstream& ss);
    
    /**
     * @brief Format ICMP header information
     * @param packet The packet containing the header
     * @param ss String stream to append formatted data to
     */
    void formatICMPHeader(const Packet& packet, std::stringstream& ss);
    
    /**
     * @brief Format ARP header information
     * @param packet The packet containing the header
     * @param ss String stream to append formatted data to
     */
    void formatARPHeader(const Packet& packet, std::stringstream& ss);
};

} // namespace ids

#endif // MINIIDS_UTILS_PACKET_FORMATTER_H