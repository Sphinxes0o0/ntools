#include <cstdlib>
#include <iostream>
#include <string>
#include <csignal>
#include "ids.h"
#include "utils/utils.h"
#include "ids/config.h"

using namespace ids;

// Global pointer to IDS instance for signal handler access
static IDS* g_ids_instance = nullptr;

void signalHandler(int signal) {
    if (g_ids_instance) {
        g_ids_instance->handleSignal(signal);
    }
}

int main(int argc, char* argv[]) {
    utils::CommandLineOptions options;
    Config config;

    if (utils::processConfiguration(argc, argv, config, options) != 0) {
        std::cout << "Configuration processing failed" << std::endl;
        exit(0);
    }

    utils::setupStandardSignalHandlers(signalHandler);

    // Create IDS instance
    IDS ids;
    g_ids_instance = &ids;
    if (!ids.initialize(config)) {
        std::cerr << "Error: Failed to initialize IDS" << std::endl;
        ids.shutdown();
        return 1;
    }

    std::cout << "IDS monitoring "
        << config.get<std::string>("capture.interface", "unknown") 
        << std::endl;

    ids.run();

    ids.shutdown();
    std::cout << "IDS stopped" << std::endl;

    return 0;
}