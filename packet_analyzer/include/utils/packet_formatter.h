#ifndef PACKET_FORMATTER_H
#define PACKET_FORMATTER_H

#include "../protocols/packet.h"
#include <string>

namespace ids {

class PacketFormatter {
public:
    PacketFormatter();
    ~PacketFormatter();
    
    static std::string formatPacket(const Packet& packet, uint32_t packetNumber);
};

} // namespace ids

#endif // PACKET_FORMATTER_H