#include <iostream>
#include <string>
#include <fstream>
#include <filesystem>

int hexdump(std::string hex_pattern, std::string filepath) {
    int nombre = 0;
    char charact;
    std::stringstream hexa;
    std::string ligne;
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        std::cout << filepath << "This file does not exist" << std::endl;
    } else {
        while (file.get(charact)) {
            if (isprint(charact)) {
                ligne += charact;
            } else {
                ligne += '.';
            } 
            hexa << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)(charact & 0xff);
            if (ligne.size() % 2 == 0) {
                hexa << " ";
            }

            nombre += 1;
            if ((nombre % 16 == 0)) {
                std::cout << std::setfill('0') << std::setw(8) << std::hex << nombre - 16 << ": " << std::setw(16) << std::setfill('0') << hexa.str() << " " << std::setw(16) << ligne << std::endl;
                ligne.clear();
                hexa.str("");
            }
        }
    }
    file.close();
    return 0;
}