#include "frame_handling.h"

namespace ethernet {

    std::size_t RAWcnt = 0, SNAPcnt = 0, LLCcnt = 0, IPV4cnt = 0, ARPcnt = 0;

    [[nodiscard]] bool handle_frame(std::ifstream& file) {

        uint8_t DA[6], SA[6], OUI[3], LLC3, buffer2[2];
        uint16_t organization_type, data2bytes, type_length;

        file.read(reinterpret_cast<char*>(DA), 6);
        if (file.gcount() != 6)
            return false;
        std::cout << "Destination address: " << tools::bytearray_to_MACstring(DA, 6) << std::endl;

        file.read(reinterpret_cast<char*>(SA), 6);
        std::cout << "Source address: " << tools::bytearray_to_MACstring(SA, 6) << std::endl;

        file.read(reinterpret_cast<char*>(buffer2), 2);
        type_length = (buffer2[0] << 8) | buffer2[1];

        if (type_length > MAX_FRAME_LENGTH) {
            std::cout << "Frame type: Ethernet II (" << std::hex << std::setw(4) << std::setfill('0') << type_length << ")" << std::endl;
            if (type_length == IPV4_CODE) {
                handle_IPV4(file);
                ++IPV4cnt;
            }
            else if (type_length == 0x0806) {
                handle_ARP(file);
                ++ARPcnt;
            }
        }
        else {
            file.read(reinterpret_cast<char*>(buffer2), 2);
            data2bytes = (buffer2[0] << 8) | buffer2[1];
            if (data2bytes == RAW) {
                std::cout << "Frame type: Ethernet II 802.3 RAW" << std::endl;
                ++RAWcnt;
                handle_IPV4(file);
            }
            else if (buffer2[0] == SNAP && buffer2[1] == SNAP) {
                std::cout << "Frame type: Ethernet SNAP" << std::endl;

                file.read(reinterpret_cast<char*>(&LLC3), 1);
                std::cout << "LLC: " << std::hex << buffer2[0] << ":" << buffer2[1] << ":" << static_cast<int>(LLC3);
                file.seekg(1, std::ios::cur);

                file.read(reinterpret_cast<char*>(&OUI), 3);
                std::cout << "OUI: " << tools::bytearray_to_separated_string(OUI, 3);

                handle_IPV4(file);
                SNAPcnt++;
            }
            else {
                std::cout << "Frame type: Ethernet 802.3 LLC" << std::endl;
                file.read(reinterpret_cast<char*>(&LLC3), 1);
                std::cout << "LLC: " << std::hex << buffer2[0] << ":" << buffer2[1] << ":" << static_cast<int>(LLC3);
                if (buffer2[0] == 0x6 && buffer2[0] == 0x6)
                    handle_IPV4(file);
                if (buffer2[0] == 0x42 && buffer2[1] == 0x42)
                    handle_STP(file);
                ++LLCcnt;
            }
        }
        return true;
    }

    void handle_IPV4(std::ifstream& file) {

        uint8_t buffer1, buffer2[2], buffer4[4];
        uint8_t IPV4_ver, IPV4_hlen, IPV4_service, IPV4_time_to_live, IPV4_protocol;
        uint16_t IPV4_total_length, IPV4_identification, IPV4_flags, IPV4_header_checksum;
        uint8_t IPV4_source_address[4], IPV4_destination_address[4];

        file.read(reinterpret_cast<char*>(&buffer1), 1);
        IPV4_ver = (buffer1 & 0xF0) >> 4;
        IPV4_hlen = buffer1 & 0X0F;
        std::cout << "    Version: " << std::hex << static_cast<int>(IPV4_ver) << std::endl;
        std::cout << "    Header length: " << static_cast<int>(IPV4_hlen) << " bytes" << std::endl;

        file.read(reinterpret_cast<char*>(&buffer1), 1);
        IPV4_service = buffer1;
        std::cout << "    Service: " << static_cast<int>(IPV4_service) << std::endl;

        file.read(reinterpret_cast<char*>(&buffer2), 2);
        IPV4_total_length = (buffer2[0] << 8) | buffer2[1];
        std::cout << "    Total datagramm length: " << std::dec << static_cast<int>(IPV4_total_length) << " bytes" << std::endl;

        file.read(reinterpret_cast<char*>(&buffer2), 2);
        IPV4_identification = (buffer2[0] << 8) | buffer2[1];
        std::cout << "    Identification: " << std::hex << std::uppercase << static_cast<int>(IPV4_identification) << std::endl;

        file.read(reinterpret_cast<char*>(&buffer2), 2);
        IPV4_flags = (((buffer2[0] << 8) | buffer2[1]) & 0xE000) >> 13;
        std::cout << "    Flags: " << std::bitset<3>(IPV4_flags) << std::endl;

        file.read(reinterpret_cast<char*>(&buffer1), 1);
        IPV4_time_to_live = buffer1;
        std::cout << "    Time to live: " << std::dec << static_cast<int>(IPV4_time_to_live) << std::endl;

        file.read(reinterpret_cast<char*>(&buffer1), 1);
        IPV4_protocol = buffer1;
        std::cout << "    Protocol: " << std::dec << static_cast<int>(IPV4_protocol) << std::endl;

        file.read(reinterpret_cast<char*>(&buffer2), 2);
        IPV4_header_checksum = (buffer2[0] << 8) | buffer2[1];
        std::cout << "    Header checksum: " << std::dec << static_cast<int>(IPV4_header_checksum) << std::endl;

        file.read(reinterpret_cast<char*>(&IPV4_source_address), 4);
        std::cout << "    IPV4 source address: " << tools::bytearray_to_IPV4string(IPV4_source_address, 4) << std::endl;

        file.read(reinterpret_cast<char*>(&IPV4_destination_address), 4);
        std::cout << "    IPV4 source address: " << tools::bytearray_to_IPV4string(IPV4_destination_address, 4) << std::endl << std::endl;

        file.seekg(IPV4_total_length - 20, std::ios::cur);

    }

    void handle_ARP(std::ifstream& file) {

        uint8_t buffer1, buffer2[2], buffer4[4];
        uint8_t ARP_hlen, ARP_plen;
        uint16_t ARP_hardware_type, ARP_protocol_type, ARP_operation;
        uint8_t* ARP_sender_protocol_address, * ARP_target_protocol_address,
            * ARP_sender_hardware_address, * ARP_target_hardware_address;

        file.read(reinterpret_cast<char*>(&buffer2), 2);
        ARP_hardware_type = (buffer2[0] << 8) | buffer2[1];
        std::cout << "    Hardware type: " << std::hex << static_cast<int>(ARP_hardware_type) << std::endl;

        file.read(reinterpret_cast<char*>(&buffer2), 2);
        ARP_protocol_type = (buffer2[0] << 8) | buffer2[1];
        std::cout << "    Protocol type: " << std::hex << static_cast<int>(ARP_protocol_type) << std::endl;

        file.read(reinterpret_cast<char*>(&buffer1), 1);
        ARP_hlen = buffer1;
        std::cout << "    Hardware length: " << std::dec << static_cast<int>(ARP_hlen) << std::endl;

        file.read(reinterpret_cast<char*>(&buffer1), 1);
        ARP_plen = buffer1;
        std::cout << "    Protocol length: " << std::dec << static_cast<int>(ARP_plen) << std::endl;

        file.read(reinterpret_cast<char*>(&buffer2), 2);
        ARP_operation = (buffer2[0] << 8) | buffer2[1];
        std::cout << "    Operation: " << std::hex << static_cast<int>(ARP_operation) << std::endl;

        ARP_sender_protocol_address = new uint8_t[ARP_plen];
        ARP_target_protocol_address = new uint8_t[ARP_plen];

        ARP_sender_hardware_address = new uint8_t[ARP_hlen];
        ARP_target_hardware_address = new uint8_t[ARP_hlen];

        file.read(reinterpret_cast<char*>(ARP_sender_hardware_address), ARP_hlen);
        std::cout << "    Sender hardware address: " << tools::bytearray_to_MACstring(ARP_sender_hardware_address, ARP_hlen) << std::endl;

        file.read(reinterpret_cast<char*>(ARP_sender_protocol_address), ARP_plen);
        std::cout << "    Sender protocol address: " << tools::bytearray_to_IPV4string(ARP_sender_protocol_address, ARP_plen) << std::endl;

        file.read(reinterpret_cast<char*>(ARP_target_hardware_address), ARP_hlen);
        std::cout << "    Target hardware address: " << tools::bytearray_to_MACstring(ARP_target_hardware_address, ARP_hlen) << std::endl;

        file.read(reinterpret_cast<char*>(ARP_target_protocol_address), ARP_plen);
        std::cout << "    Target protocol address: " << tools::bytearray_to_IPV4string(ARP_target_protocol_address, ARP_plen) << std::endl;


        delete[] ARP_sender_protocol_address;
        delete[] ARP_target_protocol_address;

        delete[] ARP_sender_hardware_address;
        delete[] ARP_target_hardware_address;

    }

    void handle_STP(std::ifstream& file) {

        uint8_t buffer1, buffer2[2], buffer4[4], buffer8[8];
        uint8_t BPDU_version, BPDU_message_type, BPDU_flags;
        uint16_t BPDU_protocol_id, BPDU_port_id, BPDU_message_age,
            BPDU_maximum_age, BPDU_hello_time, BPDU_forward_delay;
        uint32_t BPDU_root_path_cost;

        file.read(reinterpret_cast<char*>(&buffer2), 2);
        BPDU_protocol_id = (buffer2[0] << 8) | buffer2[1];
        std::cout << "    Protocol identifier: " << std::hex << static_cast<int>(BPDU_protocol_id) << std::endl;

        file.read(reinterpret_cast<char*>(&BPDU_version), 1);
        std::cout << "    Protocol version: " << std::hex << static_cast<int>(BPDU_version) << std::endl;

        file.read(reinterpret_cast<char*>(&BPDU_message_type), 1);
        if (BPDU_message_type == 0x00) {
            std::cout << "    BPDU type: Configurational" << std::endl;
        }
        else
            std::cout << "    BPDU type: Topology changed" << std::endl;

        file.read(reinterpret_cast<char*>(&BPDU_flags), 1);
        std::cout << "    Flags: " << std::bitset<8>(BPDU_flags) << std::endl;

        file.read(reinterpret_cast<char*>(&buffer8), 8);
        std::cout << "    Root identifier: " << tools::bytearray_to_separated_string(buffer8, 8) << std::endl;

        file.read(reinterpret_cast<char*>(&buffer4), 4);
        BPDU_root_path_cost = (buffer4[0] << 32) | (buffer4[1] << 16) | (buffer4[2] << 8) | buffer4[3];
        std::cout << "    Root path cost: " << std::dec << static_cast<int>(BPDU_root_path_cost) << std::endl;

        file.read(reinterpret_cast<char*>(&buffer8), 8);
        std::cout << "    Bridge identifier: " << tools::bytearray_to_separated_string(buffer8, 8) << std::endl;

        file.read(reinterpret_cast<char*>(&buffer2), 2);
        BPDU_port_id = (buffer2[0] << 8) | buffer2[1];
        std::cout << "    Port identifier: " << std::dec << static_cast<int>(BPDU_port_id) << std::endl;

        file.read(reinterpret_cast<char*>(&buffer2), 2);
        BPDU_message_age = (buffer2[0] << 8) | buffer2[1];
        std::cout << "    Message age: " << std::dec << static_cast<int>(BPDU_message_age) << std::endl;

        file.read(reinterpret_cast<char*>(&buffer2), 2);
        BPDU_maximum_age = (buffer2[0] << 8) | buffer2[1];
        std::cout << "    Maximum age: " << std::dec << static_cast<int>(BPDU_maximum_age) << std::endl;

        file.read(reinterpret_cast<char*>(&buffer2), 2);
        BPDU_hello_time = (buffer2[0] << 8) | buffer2[1];
        std::cout << "    Hello time: " << std::dec << static_cast<int>(BPDU_hello_time) << std::endl;

        file.read(reinterpret_cast<char*>(&buffer2), 2);
        BPDU_forward_delay = (buffer2[0] << 8) | buffer2[1];
        std::cout << "    Forward delay: " << std::dec << static_cast<int>(BPDU_forward_delay) << std::endl;

    }

    void print_results(std::size_t cnt) {

        std::cout << "Total number of frames: " << cnt - 1 << std::endl;
        std::cout << "Total number of IPV4 frames: " << IPV4cnt << std::endl;
        std::cout << "Total number of LLC frames: " << LLCcnt << std::endl;
        std::cout << "Total number of ARP frames: " << ARPcnt << std::endl;
        std::cout << "Total number of RAW frames: " << RAWcnt << std::endl;
        std::cout << "Total number of SNAP frames: " << SNAPcnt << std::endl;

    }

} // namespace ethernet