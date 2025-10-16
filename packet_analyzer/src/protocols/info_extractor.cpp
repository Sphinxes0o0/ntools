#include "../../include/protocols/info_extractor.h"
#include <sstream>

namespace ids {

InfoExtractor::InfoExtractor() = default;
InfoExtractor::~InfoExtractor() = default;

std::string InfoExtractor::extractInfo(const Packet& packet) {
    std::stringstream ss;
    ss << "Packet info extracted\n";
    ss << "Size: " << packet.data.size() << " bytes\n";
    return ss.str();
}

} // namespace ids