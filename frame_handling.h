#ifndef FRAME_HANDLING_H_
#define FRAME_HANDLING_H_

#include <fstream>
#include <bitset>
#include <cstdint>
#include <iostream>

#include "tools.h"

namespace ethernet {

	const uint16_t IPV4_CODE = 0x0800;
	const uint16_t MAX_FRAME_LENGTH = 0x05FE;
	const uint16_t RAW = 0xFFFF;
	const uint16_t SNAP = 0xAA;

	extern std::size_t RAWcnt, SNAPcnt, LLCcnt, IPV4cnt, ARPcnt;

	[[nodiscard]] bool handle_frame(std::ifstream& file);
	void handle_IPV4(std::ifstream& file);
	void handle_ARP(std::ifstream& file);
	void handle_STP(std::ifstream& file);
	void print_results(std::size_t cnt);

} // namespace ethernet

#endif