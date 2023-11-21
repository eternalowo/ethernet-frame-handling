#include "frame_handling.h"

int main() {
    std::string file_name;
    std::size_t total_frames_cnt = 1;

    std::cout << "Enter the file name: ";
    std::cin >> file_name;
    std::ifstream file("./resources/" + file_name, std::ios::binary);

    if (!file.is_open()) {
        std::cerr << "Error opening file" << std::endl;
        return 1;
    }

    std::cout << std::endl << std::dec << "Frame " << total_frames_cnt << std::endl;

    while (ethernet::handle_frame(file)) {
        ++total_frames_cnt;
        if (!file.eof()) {
            std::cout << std::endl << std::dec << "Frame " << total_frames_cnt << std::endl;
        }
    }

    file.close();
    ethernet::print_results(total_frames_cnt);

    return 0;
}
