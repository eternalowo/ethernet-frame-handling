#ifndef TOOLS_H_
#define TOOLS_H_

#include <string>
#include <cstdint>
#include <sstream>
#include <iomanip>

namespace tools {

	std::string bytearray_to_MACstring(const uint8_t* byteArray, std::size_t size);
	std::string bytearray_to_IPV4string(const uint8_t* byteArray, std::size_t size);
	std::string bytearray_to_separated_string(const uint8_t* byteArray, std::size_t size);

} // namespace tools

#endif