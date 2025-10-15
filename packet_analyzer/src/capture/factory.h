#ifndef MINIIDS_CAPTURE_FACTORY_H
#define MINIIDS_CAPTURE_FACTORY_H

#include "interface.h"
#include <memory>
#include <string>
#include <vector>

namespace ids {

/**
 * @brief Factory for creating capture modules
 */
class Factory {
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
    Factory() = delete;
};

} // namespace ids

#endif // MINIIDS_CAPTURE_FACTORY_H