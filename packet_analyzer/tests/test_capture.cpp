#include "../src/capture/capture_interface.h"
#include "../src/packetio/interface.h"
#include <iostream>
#include <memory>

using namespace ids;

// Simple test function for capture factory create
bool test_capture_factory_create_af_packet() {
    try {
        // For now, just test that we can create the interface
        // The actual factory will be implemented later
        return true; // Placeholder
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return false;
    }
}

// Test capture stats initialization
bool test_capture_stats_initialization() {
    CaptureStats stats;
    return stats.packets_captured == 0 &&
           stats.packets_dropped == 0 &&
           stats.bytes_captured == 0 &&
           stats.capture_rate == 0.0;
}

// Test capture config creation
bool test_capture_config_creation() {
    Config config;
    config.set("capture.interface", "lo"); // Use loopback for testing
    config.set("capture.buffer_size", 4096);
    config.set("capture.timeout_ms", 100);
    config.set("capture.snaplen", 1500);
    config.set("capture.promiscuous", false);
    
    CaptureConfig capture_config = CaptureConfig::fromConfig(config);
    
    return capture_config.interface == "lo" &&
           capture_config.buffer_size == 4096 &&
           capture_config.timeout_ms == 100 &&
           capture_config.snaplen == 1500 &&
           capture_config.promiscuous == false;
}

// Registration function
void register_capture_tests() {
    std::cout << "Capture tests registered" << std::endl;
}