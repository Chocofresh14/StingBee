#include <iostream>
#include <fstream>
#include <regex>
#include <string>
#include "my_grep.hpp"
#include "my_hexdump.hpp"

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " rule.yar file" << std::endl;
        return 1;
    }

    std::string ligne;
    std::ifstream file_rule(argv[1]);
    std::string target_file = argv[2];

    if (!file_rule) {
        std::cout << argv[1] << " does not exist" << std::endl;
        return 1;
    }

    std::regex str_pattern("\"(.+)\"");
    std::regex hex_pattern("\\{(.+)\\}");
    std::regex regex_pattern("/(.+)/");
    std::smatch match;

    while (getline(file_rule, ligne)) {
        if (ligne.find('$') != std::string::npos) {
            if (std::regex_search(ligne, match, str_pattern)) {
                std::cout << "=== Searching str: " << match[1] << " ===" << std::endl;
                grep(match[1].str(), target_file);
            }
            else if (std::regex_search(ligne, match, regex_pattern)) {
                std::cout << "=== Searching regex: " << match[1] << " ===" << std::endl;
                grep(match[1].str(), target_file);
            }
            else if (std::regex_search(ligne, match, hex_pattern)) {
                std::string hex_str = match[1].str();
                hex_str.erase(0, hex_str.find_first_not_of(' '));
                hex_str.erase(hex_str.find_last_not_of(' ') + 1);
                std::cout << "=== Searching hex: " << hex_str << " ===" << std::endl;
                hexdump(hex_str, target_file);
            }
        }
    }

    return 0;
}