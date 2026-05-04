#include <iostream>
#include <string>
#include <fstream>
#include <filesystem>
#include <regex>

int grep(std::string pattern, std::string filepath) {
    int count = 0;
    std::string ligne;
    std::regex mot(pattern);
    std::ifstream file(filepath);
    if (!file) {
        std::cout << filepath << "This file does not exist" << std::endl;
    } else {
        while (getline(file, ligne)) {
            if(std::regex_search(ligne, mot)){
                std::cout << ligne << std::endl;
            } ligne.clear();
        } 
    }  
    file.close();
    return 0;
}