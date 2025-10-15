#include <iostream>
#include <string>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include "ids.h"

using namespace ids;

static IDS* g_ids = nullptr;

static volatile sig_atomic_t g_exit_flag = 0;

/**
 * @brief Signal handler for graceful shutdown
 * @param signal Signal number
 */
void signalHandler(int signal) {
    std::cout << "\nReceived signal " << signal << ", shutting down..." << std::endl;
    g_exit_flag = 1;
    if (g_ids != nullptr) {
        g_ids->handleSignal(signal);
    }
}

/**
 * @brief Print usage information
 * @param program_name Program name
 */
void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "IDS - Intrusion Detection System\n\n"
              << "Options:\n"
              << "  -c, --config FILE    Configuration file path (default: /etc/ids/ids.yaml)\n"
              << "  -i, --interface IF   Network interface to monitor (overrides config)\n"
              << "  -r, --rules FILE     Rule file path (can be specified multiple times)\n"
              << "  -l, --log-level LEVEL Log level (DEBUG, INFO, WARNING, ERROR, ALERT)\n"
              << "  -o, --output FORMAT  Output format (tcpdump, json, csv)\n"
              << "  -d, --debug          Enable debug mode\n"
              << "  -v, --version        Show version information\n"
              << "  -h, --help           Show this help message\n\n"
              << "Examples:\n"
              << "  " << program_name << " -c /path/to/config.yaml\n"
              << "  " << program_name << " -i eth0 -l DEBUG\n"
              << "  " << program_name << " -r local.rules -r community.rules\n\n"
              << "Signals:\n"
              << "  SIGINT, SIGTERM    Graceful shutdown\n"
              << "  SIGHUP             Reload configuration\n"
              << "  SIGUSR1            Print statistics\n";
}

/**
 * @brief Print version information
 */
void printVersion() {
    std::cout << "IDS version 1.0.0\n"
              << "Copyright (C) 2024 IDS Project\n"
              << "License: MIT\n"
              << "This is free software: you are free to change and redistribute it.\n";
}

/**
 * @brief Main function
 * @param argc Argument count
 * @param argv Argument vector
 * @return Exit code
 */
int main(int argc, char* argv[]) {
    // Default options
    std::string config_file = "/etc/ids/ids.yaml";
    std::string interface;
    std::vector<std::string> rule_files;
    std::string log_level;
    std::string output_format;
    bool debug_mode = false;
    
    // Long options
    static struct option long_options[] = {
        {"config", required_argument, 0, 'c'},
        {"interface", required_argument, 0, 'i'},
        {"rules", required_argument, 0, 'r'},
        {"log-level", required_argument, 0, 'l'},
        {"output", required_argument, 0, 'o'},
        {"debug", no_argument, 0, 'd'},
        {"version", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    // Parse command line options
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "c:i:r:l:o:dvh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'c':
                config_file = optarg;
                break;
            case 'i':
                interface = optarg;
                break;
            case 'r':
                rule_files.push_back(optarg);
                break;
            case 'l':
                log_level = optarg;
                break;
            case 'o':
                output_format = optarg;
                break;
            case 'd':
                debug_mode = true;
                break;
            case 'v':
                printVersion();
                return 0;
            case 'h':
                printUsage(argv[0]);
                return 0;
            case '?':
                // getopt_long already printed an error message
                return 1;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }
    
    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGHUP, signalHandler);
    signal(SIGUSR1, signalHandler);
    
    try {
        // Create IDS instance
        IDS ids;
        g_ids = &ids;
        
        // Load configuration
        Config config;
        if (!config.loadFromFile(config_file)) {
            std::cerr << "Error: Cannot load configuration file: " << config_file << std::endl;
            return 1;
        }
        
        // Override configuration with command line options
        if (!interface.empty()) {
            config.set("capture.interface", interface);
        }
        if (!log_level.empty()) {
            config.set("logging.level", log_level);
        }
        if (!output_format.empty()) {
            config.set("logging.format", output_format);
        }
        if (debug_mode) {
            config.set("logging.level", "DEBUG");
        }
        
        // Add rule files from command line
        if (!rule_files.empty()) {
            // Note: This would need special handling for arrays in the config system
            // For now, we'll just set the first rule file
            config.set("rules.rule_files.0", rule_files[0]);
        }
        
        // Validate configuration
        if (!config.validate()) {
            std::cerr << "Error: Invalid configuration" << std::endl;
            auto errors = config.getValidationErrors();
            for (const auto& error : errors) {
                std::cerr << "  - " << error << std::endl;
            }
            return 1;
        }

        if (!ids.initialize(config)) {
            std::cerr << "Error: Failed to initialize IDS" << std::endl;
            // Ensure proper cleanup even on initialization failure
            ids.shutdown();
            return 1;
        }
        
        std::cout << "IDS started successfully" << std::endl;
        std::cout << "Monitoring interface: " << config.get<std::string>("capture.interface", "unknown") << std::endl;
        std::cout << "Press Ctrl+C to stop" << std::endl;
        
        // Run main loop
        ids.run();
        
        // Cleanup
        ids.shutdown();
        std::cout << "IDS stopped" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}