#include "tools.h"

namespace tools {

    std::string bytearray_to_MACstring(const uint8_t* byteArray, std::size_t size) {
        std::stringstream ss;

        for (std::size_t i = 0; i < size; i++) {
            if (i > 0) {
                ss << ":";
            }

            ss << std::uppercase << std::setfill('0') << std::setw(2)
                << std::hex << static_cast<int>(byteArray[i]);
        }

        return ss.str();
    }

    std::string bytearray_to_IPV4string(const uint8_t* byteArray, std::size_t size) {
        std::stringstream ss;

        for (std::size_t i = 0; i < size; i++) {
            if (i > 0) {
                ss << ".";
            }

            ss << static_cast<int>(byteArray[i]);
        }

        return ss.str();
    }

    std::string bytearray_to_separated_string(const uint8_t* byteArray, std::size_t size) {
        std::stringstream ss;

        for (std::size_t i = 0; i < size; i++) {
            if (i > 0) {
                ss << "-";
            }

            ss << std::uppercase << std::setfill('0') << std::setw(2)
                << std::hex << static_cast<int>(byteArray[i]);
        }

        return ss.str();
    }

} // namespace tools