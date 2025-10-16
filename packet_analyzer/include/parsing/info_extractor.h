#ifndef MINIIDS_PARSING_INFO_EXTRACTOR_H
#define MINIIDS_PARSING_INFO_EXTRACTOR_H

#include <string>
#include <vector>
#include "packet.h"

namespace ids {

class InfoExtractor {
public:
    InfoExtractor();
    ~InfoExtractor();
    
    static std::string extractInfo(const Packet& packet);
};

} // namespace ids

#endif // MINIIDS_PARSING_INFO_EXTRACTOR_H