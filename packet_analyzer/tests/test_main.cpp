#include <iostream>
#include <vector>
#include <functional>
#include <string>

// Simple test framework
class TestFramework {
public:
    struct TestResult {
        std::string name;
        bool passed;
        std::string message;
    };

    static TestFramework& getInstance() {
        static TestFramework instance;
        return instance;
    }

    void addTest(const std::string& name, std::function<bool()> test) {
        tests_.push_back({name, test});
    }

    void runTests() {
        std::cout << "Running IDS Unit Tests..." << std::endl;
        std::cout << "================================" << std::endl;

        int passed = 0;
        int failed = 0;
        std::vector<TestResult> results;

        for (const auto& [name, test] : tests_) {
            try {
                bool result = test();
                results.push_back({name, result, result ? "PASSED" : "FAILED"});
                if (result) {
                    passed++;
                    std::cout << "[PASS] " << name << std::endl;
                } else {
                    failed++;
                    std::cout << "[FAIL] " << name << std::endl;
                }
            } catch (const std::exception& e) {
                failed++;
                results.push_back({name, false, std::string("EXCEPTION: ") + e.what()});
                std::cout << "[EXCEPTION] " << name << ": " << e.what() << std::endl;
            }
        }

        std::cout << "================================" << std::endl;
        std::cout << "Tests run: " << tests_.size() << std::endl;
        std::cout << "Passed: " << passed << std::endl;
        std::cout << "Failed: " << failed << std::endl;
        std::cout << "Success rate: " << (passed * 100 / tests_.size()) << "%" << std::endl;

        if (failed > 0) {
            std::cout << "\nFailed tests:" << std::endl;
            for (const auto& result : results) {
                if (!result.passed) {
                    std::cout << "  - " << result.name << ": " << result.message << std::endl;
                }
            }
        }
    }

private:
    std::vector<std::pair<std::string, std::function<bool()>>> tests_;
};

// Test registration macros
#define REGISTER_TEST(name) \
    static bool test_##name(); \
    static struct test_##name##_registrar { \
        test_##name##_registrar() { \
            TestFramework::getInstance().addTest(#name, test_##name); \
        } \
    } test_##name##_instance; \
    static bool test_##name()

// External test declarations
extern void register_capture_tests();
extern void register_protocol_tests();
extern void register_log_tests();
extern void register_rule_tests();

int main() {
    // Register all test suites
    register_capture_tests();
    register_protocol_tests();
    register_log_tests();
    register_rule_tests();

    // Run tests
    TestFramework::getInstance().runTests();

    return 0;
}