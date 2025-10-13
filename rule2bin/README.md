# Snort3 Rule to Binary Translator (rule2bin)

A C++ tool for converting Snort3 rules into a binary format for efficient loading and execution.

## Overview

This tool translates Snort3 rule syntax into a compact binary format consisting of:
- **File Header**: Magic number, version, timestamp, rule count, and checksum
- **Rules Data**: Serialized rule structures with options and string data

## Features

- ✅ Parse Snort3 rule syntax with common keywords
- ✅ Convert rules to optimized binary format
- ✅ Load and inspect binary rule files
- ✅ CRC32 checksum validation for data integrity
- ✅ Support for basic Snort3 rule actions and protocols

## Supported Snort3 Keywords

### Actions
- `alert` - Generate alerts
- `log` - Log packets
- `pass` - Ignore packets
- `drop` - Drop packets

### Protocols
- `tcp` - TCP protocol
- `udp` - UDP protocol
- `icmp` - ICMP protocol
- `ip` - IP protocol

### Rule Options
- `content` - Pattern matching
- `msg` - Rule description
- `sid` - Rule ID
- `rev` - Revision number
- `classtype` - Classification type
- `priority` - Priority level
- `metadata` - Key-value metadata
- `flow` - Session flow
- `flags` - TCP flags

## Binary File Format

### File Header (32 bytes)
```
Offset | Size | Field        | Description
-------|------|--------------|-------------
0x00   | 4    | magic        | Magic number: 0x534E5254 ("SNRT")
0x04   | 4    | version      | File format version (1.0)
0x08   | 8    | timestamp    | Creation time (Unix timestamp)
0x10   | 4    | rule_count   | Number of rules in file
0x14   | 4    | header_size  | Total header size in bytes
0x18   | 4    | data_size    | Total rules data size in bytes
0x1C   | 4    | checksum     | CRC32 checksum of rules data
```

### Rule Structure
Each rule consists of:
- **Rule Header**: Fixed-size structure with action, protocol, IPs, ports, direction
- **Rule Options**: Variable number of options with type and value data
- **String Data**: Length-prefixed string values for options

## Building

### Prerequisites
- CMake 3.10+
- C++17 compatible compiler
- zlib development libraries

### Build Instructions
```bash
mkdir build
cd build
cmake ..
make
```

## Usage

### Command Line Interface
```bash
# Convert Snort3 rules to binary format
./rule2bin_cli convert input_rules.txt output.bin

# Display information about binary file
./rule2bin_cli info rules.bin

# Show help
./rule2bin_cli help
```

### Example
```bash
# Convert test rules
./rule2bin_cli convert ../test_rules.txt test_rules.bin

# Display converted rules
./rule2bin_cli info test_rules.bin
```

### Example Snort3 Rule Format
```
alert tcp any any -> any 80 (msg:"HTTP traffic detected"; sid:1000001; rev:1;)
alert tcp 192.168.1.1 any -> any 443 (msg:"HTTPS from internal IP"; content:"GET"; sid:1000002; rev:1;)
```

## API Usage

### C++ Library
```cpp
#include "rule2bin/rule_parser.h"
#include "rule2bin/binary_serializer.h"
#include "rule2bin/binary_deserializer.h"

// Parse rules from file
rule2bin::RuleParser parser;
std::vector<rule2bin::Rule> rules;
parser.parse_rules_from_file("rules.txt", rules);

// Serialize to binary
rule2bin::BinarySerializer serializer;
serializer.serialize_to_file(rules, "rules.bin");

// Deserialize from binary
rule2bin::BinaryDeserializer deserializer;
deserializer.deserialize_from_file("rules.bin", rules);
```

## Testing

Run the integration test:
```bash
chmod +x test_integration.sh
./test_integration.sh
```

## Project Structure

```
rule2bin/
├── include/                 # Header files
│   ├── structures.h         # Data structures and enums
│   ├── rule_parser.h        # Rule parsing interface
│   ├── binary_serializer.h  # Binary serialization
│   └── binary_deserializer.h # Binary deserialization
├── rules                    # Test rules
├── src/                    # Implementation
│   ├── main.cpp            # CLI application
│   ├── structures.cpp      # Utility functions
│   ├── rule_parser.cpp     # Rule parsing logic
│   ├── binary_serializer.cpp # Serialization logic
│   └── binary_deserializer.cpp # Deserialization logic
├── CMakeLists.txt          # Build configuration
└── README.md              # This file
```

## Dependencies

- **zlib**: For CRC32 checksum calculation
- **C++17 Standard Library**

## Architecture

The system follows a modular architecture:

1. **Rule Parser**: Tokenizes and parses Snort3 rule syntax
2. **Binary Serializer**: Converts internal structures to binary format
3. **Binary Deserializer**: Reconstructs structures from binary data
4. **CLI Interface**: Command-line tool for end users

## License

This project is provided as a proof-of-concept implementation for educational purposes.

## Contributing

This is a proof-of-concept implementation. For production use, additional features and error handling would be required.