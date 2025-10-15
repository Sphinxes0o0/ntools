#include "interface.h"
#include "factory.h"
#include "af_packet.h"
#include <vector>
#include <string>
#include <algorithm>

namespace ids {

std::unique_ptr<ICaptureModule> Factory::create(const std::string& type) {
    if (type == "af_packet") {
        return std::make_unique<AFPacketCapture>();
    } else if (type == "libpcap") {
        // TODO: Implement libpcap capture module
        return nullptr;
    } else if (type == "ebpf") {
        // TODO: Implement eBPF capture module
        return nullptr;
    } else {
        // Unknown capture type
        return nullptr;
    }
}

std::vector<std::string> Factory::getAvailableTypes() {
    std::vector<std::string> types;
    types.push_back("af_packet");
    // types.push_back("libpcap"); // Not implemented yet
    // types.push_back("ebpf");    // Not implemented yet
    return types;
}

bool Factory::isTypeAvailable(const std::string& type) {
    std::vector<std::string> available = getAvailableTypes();
    return std::find(available.begin(), available.end(), type) != available.end();
}

} // namespace ids