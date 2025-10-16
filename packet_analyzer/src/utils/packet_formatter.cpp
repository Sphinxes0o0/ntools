#include "utils/packet_formatter.h"
#include <sstream>
#include <iomanip>

namespace ids {

PacketFormatter::PacketFormatter() = default;
PacketFormatter::~PacketFormatter() = default;

std::string PacketFormatter::formatPacket(const Packet& packet, uint32_t packetNumber) {
    std::stringstream ss;
    ss << "Packet #" << packetNumber << "\n";
    ss << "  Size: " << packet.length << " bytes\n";
    
    return ss.str();
}

} // namespace ids