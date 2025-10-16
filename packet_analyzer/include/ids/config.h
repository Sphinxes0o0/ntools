#ifndef MINIIDS_CORE_CONFIG_H
#define MINIIDS_CORE_CONFIG_H

#include "../../include/ids/common.h"
#include <unordered_map>
#include <any>
#include <fstream>
#include <sstream>
#include <iostream>
#include <typeinfo>
#include <algorithm>
#include <vector>
#include <string>
#include <limits>
#include <utility>
#include "../include/utils/utils.h"

namespace ids {

/**
 * @brief Configuration class for managing system settings
 */
class Config {
public:
    /**
     * @brief Default constructor
     */
    Config() = default;
    
    /**
     * @brief Constructor with config file path
     * @param file_path Path to configuration file
     * @throw ConfigException if file cannot be loaded
     */
    explicit Config(const std::string& file_path) {
        if (!loadFromFile(file_path)) {
            
        }
    }
    
    /**
     * @brief Destructor
     */
    ~Config() = default;
    
    /**
     * @brief Get configuration value with default
     * @tparam T Value type
     * @param key Configuration key
     * @param default_value Default value if key not found
     * @return Configuration value or default
     */
    template<typename T>
    T get(const std::string& key, const T& default_value) const {
        auto it = settings_.find(key);
        if (it == settings_.end()) {
            return default_value;
        }
        
        try {
            return std::any_cast<T>(it->second);
        } catch (const std::bad_any_cast& e) {
            // Debug: Print what type we actually have
            std::cout << "DEBUG: Type mismatch for key '" << key << "'. Expected type: "
                      << typeid(T).name() << ", Actual type: " << it->second.type().name() << std::endl;
            return default_value;
        }
    }
    
    /**
     * @brief Set configuration value
     * @tparam T Value type
     * @param key Configuration key
     * @param value Value to set
     */
    template<typename T>
    void set(const std::string& key, const T& value) {
        settings_[key] = value;
    }
    
    /**
     * @brief Check if key exists
     * @param key Configuration key
     * @return true if key exists, false otherwise
     */
    bool hasKey(const std::string& key) const {
        return settings_.find(key) != settings_.end();
    }
    
    /**
     * @brief Remove configuration key
     * @param key Configuration key to remove
     * @return true if key was removed, false if not found
     */
    bool remove(const std::string& key) {
        return settings_.erase(key) > 0;
    }
    
    /**
     * @brief Clear all configuration
     */
    void clear() {
        settings_.clear();
    }
    
    /**
     * @brief Load configuration from file
     * @param file_path Path to configuration file
     * @return true if loaded successfully, false otherwise
     */
    bool loadFromFile(const std::string& file_path) {
        std::ifstream file(file_path);
        if (!file.is_open()) {
            return false;
        }
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        file.close();
        
        return loadFromYAML(buffer.str());
    }
    
    /**
     * @brief Load configuration from YAML string
     * @param yaml_content YAML content
     * @return true if loaded successfully, false otherwise
     */
    bool loadFromYAML(const std::string& yaml_content) {
        // Simple YAML parser for basic configuration
        // This is a simplified implementation - for production, use a proper YAML library
        try {
            std::istringstream stream(yaml_content);
            std::string line;
            std::string current_section;
            
            while (std::getline(stream, line)) {
                line = utils::trim(line);
                
                // Skip empty lines and comments
                if (line.empty() || line[0] == '#') continue;
                
                // Section header
                if (line.back() == ':' && !line.empty()) {
                    current_section = line.substr(0, line.length() - 1);
                    continue;
                }
                
                // Key-value pair
                size_t colon_pos = line.find(':');
                if (colon_pos != std::string::npos) {
                    std::string key = utils::trim(line.substr(0, colon_pos));
                    std::string value = utils::trim(line.substr(colon_pos + 1));
                    
                    // Remove quotes if present
                    if (value.length() >= 2 && 
                        ((value.front() == '"' && value.back() == '"') ||
                         (value.front() == '\'' && value.back() == '\''))) {
                        value = value.substr(1, value.length() - 2);
                    }
                    
                    std::string full_key = current_section.empty() ? key : 
                                          current_section + "." + key;
                    
                    // Try to parse as different types
                    if (value == "true" || value == "false") {
                        set(full_key, value == "true");
                    } else if (value.find_first_of(".") != std::string::npos) {
                        try {
                            set(full_key, std::stod(value));
                        } catch (...) {
                            set(full_key, value);
                        }
                    } else {
                        try {
                            // Try to parse as different numeric types
                            // For specific keys that should be int, parse as int directly
                            if (key == "timeout_ms" || key == "snaplen" || key.find("timeout") != std::string::npos) {
                                long long val = std::stoll(value);
                                // Ensure it's within int range
                                if (val >= std::numeric_limits<int>::min() && 
                                    val <= std::numeric_limits<int>::max()) {
                                    set(full_key, static_cast<int>(val));
                                } else {
                                    set(full_key, val); // Store as long long if out of int range
                                }
                            } else if (key.find("size") != std::string::npos || 
                                      key.find("buffer") != std::string::npos ||
                                      key.find("length") != std::string::npos) {
                                set(full_key, static_cast<size_t>(std::stoull(value)));
                            } else {
                                // Default numeric parsing - try int first for small numbers
                                long long val = std::stoll(value);
                                if (val >= std::numeric_limits<int>::min() && 
                                    val <= std::numeric_limits<int>::max()) {
                                    set(full_key, static_cast<int>(val));
                                } else {
                                    set(full_key, val);
                                }
                            }
                        } catch (...) {
                            set(full_key, value);
                        }
                    }
                }
            }
            
            return true;
        } catch (const std::exception& e) {
            return false;
        }
    }
    
    /**
     * @brief Load configuration from JSON string
     * @param json_content JSON content
     * @return true if loaded successfully, false otherwise
     */
    bool loadFromJSON(const std::string& json_content) {
        // Simple JSON parser for basic configuration
        // This is a simplified implementation - for production, use a proper JSON library
        try {
            // Basic key-value extraction
            std::istringstream stream(json_content);
            std::string line;
            
            while (std::getline(stream, line)) {
                line = utils::trim(line);
                
                // Skip empty lines and comments
                if (line.empty() || line[0] == '/' || line[0] == '#') continue;
                
                // Key-value pair
                size_t colon_pos = line.find(':');
                if (colon_pos != std::string::npos) {
                    std::string key = utils::trim(line.substr(0, colon_pos));
                    std::string value = utils::trim(line.substr(colon_pos + 1));
                    
                    // Remove trailing comma if present
                    if (!value.empty() && value.back() == ',') {
                        value.pop_back();
                    }
                    
                    // Remove quotes if present
                    if (value.length() >= 2 && 
                        ((value.front() == '"' && value.back() == '"') ||
                         (value.front() == '\'' && value.back() == '\''))) {
                        value = value.substr(1, value.length() - 2);
                    }
                    
                    // Try to parse as different types
                    if (value == "true" || value == "false") {
                        set(key, value == "true");
                    } else if (value.find_first_of(".") != std::string::npos) {
                        try {
                            set(key, std::stod(value));
                        } catch (...) {
                            set(key, value);
                        }
                    } else {
                        try {
                            // Try to parse as size_t first for buffer sizes
                            if (key.find("size") != std::string::npos || 
                                key.find("buffer") != std::string::npos ||
                                key.find("length") != std::string::npos) {
                                set(key, static_cast<size_t>(std::stoull(value)));
                            } else {
                                set(key, std::stoll(value));
                            }
                        } catch (...) {
                            set(key, value);
                        }
                    }
                }
            }
            
            return true;
        } catch (const std::exception& e) {
            return false;
        }
    }
    
    /**
     * @brief Save configuration to file
     * @param file_path Path to save configuration
     * @return true if saved successfully, false otherwise
     */
    bool saveToFile(const std::string& file_path) const {
        std::ofstream file(file_path);
        if (!file.is_open()) {
            return false;
        }
        
        file << toYAML();
        file.close();
        return true;
    }
    
    /**
     * @brief Convert configuration to YAML string
     * @return YAML representation of configuration
     */
    std::string toYAML() const {
        std::stringstream ss;
        
        // Group by sections
        std::unordered_map<std::string, std::vector<std::pair<std::string, std::any>>> sections;
        
        for (const auto& [key, value] : settings_) {
            size_t dot_pos = key.find('.');
            if (dot_pos != std::string::npos) {
                std::string section = key.substr(0, dot_pos);
                std::string subkey = key.substr(dot_pos + 1);
                sections[section].emplace_back(subkey, value);
            } else {
                sections[""].emplace_back(key, value);
            }
        }
        
        // Output sections
        for (const auto& [section, pairs] : sections) {
            if (!section.empty()) {
                ss << section << ":\n";
            }
            
            for (const auto& [key, value] : pairs) {
                if (!section.empty()) {
                    ss << "  ";
                }
                ss << key << ": ";
                
                // Output value based on type
                if (value.type() == typeid(bool)) {
                    ss << (std::any_cast<bool>(value) ? "true" : "false");
                } else if (value.type() == typeid(int)) {
                    ss << std::any_cast<int>(value);
                } else if (value.type() == typeid(long)) {
                    ss << std::any_cast<long>(value);
                } else if (value.type() == typeid(long long)) {
                    ss << std::any_cast<long long>(value);
                } else if (value.type() == typeid(size_t)) {
                    ss << std::any_cast<size_t>(value);
                } else if (value.type() == typeid(double)) {
                    ss << std::any_cast<double>(value);
                } else if (value.type() == typeid(std::string)) {
                    ss << "\"" << std::any_cast<std::string>(value) << "\"";
                } else {
                    ss << "\"unknown\"";
                }
                ss << "\n";
            }
            
            if (!section.empty()) {
                ss << "\n";
            }
        }
        
        return ss.str();
    }
    
    /**
     * @brief Convert configuration to string
     * @return String representation of configuration
     */
    std::string toString() const {
        return toYAML();
    }
    
    /**
     * @brief Validate configuration
     * @return true if valid, false otherwise
     */
    bool validate() const {
        validation_errors_.clear();
        
        // Validate capture configuration
        if (hasKey("capture.interface")) {
            std::string interface = get<std::string>("capture.interface", "");
            if (interface.empty()) {
                validation_errors_.push_back("Capture interface cannot be empty");
            }
        }
        
        if (hasKey("capture.timeout_ms")) {
            int timeout = get<int>("capture.timeout_ms", 1000);
            if (timeout < 0) {
                validation_errors_.push_back("Capture timeout must be non-negative");
            }
        }
        
        if (hasKey("capture.snaplen")) {
            int snaplen = get<int>("capture.snaplen", 65535);
            if (snaplen <= 0 || snaplen > 65535) {
                validation_errors_.push_back("Capture snaplen must be between 1 and 65535");
            }
        }
        
        // Validate logging configuration
        if (hasKey("logging.level")) {
            std::string level = get<std::string>("logging.level", "");
            std::vector<std::string> valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "ALERT"};
            if (std::find(valid_levels.begin(), valid_levels.end(), level) == valid_levels.end()) {
                validation_errors_.push_back("Invalid logging level: " + level);
            }
        }
        
        if (hasKey("logging.format")) {
            std::string format = get<std::string>("logging.format", "");
            std::vector<std::string> valid_formats = {"tcpdump", "json", "csv"};
            if (std::find(valid_formats.begin(), valid_formats.end(), format) == valid_formats.end()) {
                validation_errors_.push_back("Invalid logging format: " + format);
            }
        }
        
        // Validate rules configuration
        // Note: rule_files would need special handling for arrays
        
        return validation_errors_.empty();
    }
    
    /**
     * @brief Get validation errors
     * @return Vector of validation error messages
     */
    std::vector<std::string> getValidationErrors() const {
        return validation_errors_;
    }
    
    /**
     * @brief Get all configuration keys
     * @return Vector of configuration keys
     */
    std::vector<std::string> getKeys() const {
        std::vector<std::string> keys;
        keys.reserve(settings_.size());
        
        for (const auto& [key, value] : settings_) {
            keys.push_back(key);
        }
        
        return keys;
    }
    
    /**
     * @brief Apply command line options to configuration
     * @param options Command line options to apply
     */
    void applyCommandLineOptions(const utils::CommandLineOptions& options) {
        if (!options.interface.empty()) {
            set("capture.interface", options.interface);
        }
        if (!options.log_level.empty()) {
            set("logging.level", options.log_level);
        }
        if (!options.output_format.empty()) {
            set("logging.format", options.output_format);
        }
        if (options.debug_mode) {
            set("logging.level", "DEBUG");
        }
        
        // Add rule files from command line
        if (!options.rule_files.empty()) {
            // Note: This would need special handling for arrays in the config system
            // For now, we'll just set the first rule file
            set("rules.rule_files.0", options.rule_files[0]);
        }
    }
    
    /**
     * @brief Save configuration to the specified file
     * @param filepath Path to save configuration file
     * @return true if saved successfully, false otherwise
     */
    bool saveConfig(const std::string& filepath) const {
        return saveToFile(filepath);
    }

private:
    std::unordered_map<std::string, std::any> settings_;
    mutable std::vector<std::string> validation_errors_;
};

// Configuration structures for specific components

/**
 * @brief Capture configuration
 */
struct CaptureConfig {
    std::string interface;
    size_t buffer_size;
    int timeout_ms;
    int snaplen;
    bool promiscuous;
    std::string filter;
    
    CaptureConfig() 
        : interface("eth0"), buffer_size(65536), timeout_ms(1000), 
          snaplen(65535), promiscuous(true), filter("") {}
    
    static CaptureConfig fromConfig(const Config& config) {
        CaptureConfig capture;
        capture.interface = config.get<std::string>("capture.interface", "eth0");
        
        // Handle buffer_size with flexible type casting - try multiple types
        try {
            capture.buffer_size = config.get<size_t>("capture.buffer_size", 65536);
        } catch (const std::bad_any_cast& e) {
            // Try long long first (most common from YAML parsing)
            try {
                long long buffer_size_ll = config.get<long long>("capture.buffer_size", 65536);
                capture.buffer_size = static_cast<size_t>(buffer_size_ll);
            } catch (...) {
                // Try int
                try {
                    int buffer_size_int = config.get<int>("capture.buffer_size", 65536);
                    capture.buffer_size = static_cast<size_t>(buffer_size_int);
                } catch (...) {
                    // Final fallback - use default
                    capture.buffer_size = 65536;
                }
            }
        }
        
        // Handle timeout_ms with flexible type casting
        try {
            capture.timeout_ms = config.get<int>("capture.timeout_ms", 1000);
        } catch (const std::bad_any_cast& e) {
            try {
                long long timeout_ll = config.get<long long>("capture.timeout_ms", 1000);
                capture.timeout_ms = static_cast<int>(timeout_ll);
            } catch (...) {
                // Try size_t
                try {
                    size_t timeout_size = config.get<size_t>("capture.timeout_ms", 1000);
                    capture.timeout_ms = static_cast<int>(timeout_size);
                } catch (...) {
                    // Final fallback - use default
                    capture.timeout_ms = 1000;
                }
            }
        }
        // Handle snaplen with flexible type casting
        try {
            capture.snaplen = config.get<int>("capture.snaplen", 65535);
        } catch (const std::bad_any_cast& e) {
            try {
                long long snaplen_ll = config.get<long long>("capture.snaplen", 65535);
                capture.snaplen = static_cast<int>(snaplen_ll);
            } catch (...) {
                // Try size_t
                try {
                    size_t snaplen_size = config.get<size_t>("capture.snaplen", 65535);
                    capture.snaplen = static_cast<int>(snaplen_size);
                } catch (...) {
                    // Final fallback - use default
                    capture.snaplen = 65535;
                }
            }
        }
        capture.promiscuous = config.get<bool>("capture.promiscuous", true);
        capture.filter = config.get<std::string>("capture.filter", "");
        return capture;
    }
};

/**
 * @brief Rule configuration
 */
struct RuleConfig {
    std::vector<std::string> rule_files;
    bool auto_reload;
    int reload_interval;
    
    RuleConfig() : auto_reload(true), reload_interval(300) {}
    
    static RuleConfig fromConfig(const Config& config) {
        RuleConfig rules;
        // Note: rule_files would need special handling for arrays
        rules.auto_reload = config.get<bool>("rules.auto_reload", true);
        // Handle reload_interval with flexible type casting
        try {
            rules.reload_interval = config.get<int>("rules.reload_interval", 300);
        } catch (const std::bad_any_cast& e) {
            try {
                long long reload_interval_ll = config.get<long long>("rules.reload_interval", 300);
                rules.reload_interval = static_cast<int>(reload_interval_ll);
            } catch (...) {
                // Try size_t
                try {
                    size_t reload_interval_size = config.get<size_t>("rules.reload_interval", 300);
                    rules.reload_interval = static_cast<int>(reload_interval_size);
                } catch (...) {
                    // Final fallback - use default
                    rules.reload_interval = 300;
                }
            }
        }
        return rules;
    }
};

/**
 * @brief Performance configuration
 */
struct PerformanceConfig {
    int worker_threads;
    size_t queue_size;
    size_t batch_size;
    bool cpu_affinity;
    
    PerformanceConfig()
        : worker_threads(4), queue_size(10000), batch_size(100), cpu_affinity(true) {}
    
    static PerformanceConfig fromConfig(const Config& config) {
        PerformanceConfig perf;
        // Note: worker_threads was removed since we simplified to single-threaded
        // Handle queue_size with flexible type casting
        try {
            perf.queue_size = config.get<size_t>("performance.queue_size", 10000);
        } catch (const std::bad_any_cast& e) {
            try {
                long long queue_size_ll = config.get<long long>("performance.queue_size", 10000);
                perf.queue_size = static_cast<size_t>(queue_size_ll);
            } catch (...) {
                int queue_size_int = config.get<int>("performance.queue_size", 10000);
                perf.queue_size = static_cast<size_t>(queue_size_int);
            }
        }
        
        // Handle batch_size with flexible type casting
        try {
            perf.batch_size = config.get<size_t>("performance.batch_size", 100);
        } catch (const std::bad_any_cast& e) {
            try {
                long long batch_size_ll = config.get<long long>("performance.batch_size", 100);
                perf.batch_size = static_cast<size_t>(batch_size_ll);
            } catch (...) {
                int batch_size_int = config.get<int>("performance.batch_size", 100);
                perf.batch_size = static_cast<size_t>(batch_size_int);
            }
        }
        
        perf.cpu_affinity = config.get<bool>("performance.cpu_affinity", true);
        return perf;
    }
};

} // namespace ids

#endif // MINIIDS_CORE_CONFIG_H