#include <iostream>
#include <regex>
#include <filesystem>
#include <fstream>
#include <sstream>

std::string intput_donne(std::string input)
{
    std::regex DOMAIN_REGEX(R"(^(?=.{1,253}$)(?:https?://)?(?:www\.)?[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$)");
    std::regex URL_REGEX(R"(^(?:https?://)?(?:www\.)?[A-Za-z0-9.-]+\.[A-Za-z]{2,6}(?:/.*)?$)");
    std::regex IP_REGEX(R"(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)");
    std::regex HASH_REGEX(R"(^[A-Fa-f0-9]{32,128}$)");
    std::regex Fichier_REGEX(R"(^/?[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$)");
    int max = 33554432;
    if (std::regex_match(input, DOMAIN_REGEX)){
        return "DOMAIN";
    }
    if (std::regex_match(input, URL_REGEX)){
        return "URL";
    }
    if (std::regex_match(input, IP_REGEX)){
        return "IP";
    }
    if (std::regex_match(input, HASH_REGEX)){
        return "HASH";
    }
    if (std::regex_match(input, Fichier_REGEX)){
        if (std::filesystem::file_size(input) > max){
            return "G-Fichier";
        }
        return "Fichier";
    }
    return "Rien ne match";
}

int request_choise(std::string input, std::string x)
{
    std::string API = "ee81daeaa483270ad43feebca18fd19223c88f659706961a2d026432a755fbd5";
    if (x == "URL"){
        system(("curl -s -X POST 'https://www.virustotal.com/api/v3/urls' -H 'x-apikey: " + API + "' --data-urlencode 'url=" + input + "' | grep -oE 'https://[A-Za-z0-9./_-]+' | tail -1 | tr -d '\n' > url_url_result.txt").c_str());
        
        std::stringstream url;
        url << std::ifstream("url_url_result.txt").rdbuf();
        std::string analysis_url = url.str();
        
        system(("curl -s -X GET '" + analysis_url + "' -H 'x-apikey: " + API + "' > url_result.txt").c_str());
        std::cout << std::ifstream("url_result.txt").rdbuf();
        return 0;
    }
    if (x == "DOMAIN"){
        system(("curl 'https://www.virustotal.com/api/v3/domains/" + input + "' -H 'x-apikey: " + API + "' > domain_result.txt").c_str());
        std::cout << std::ifstream("domain_result.txt").rdbuf();
        return 0;
    }
    if (x == "IP"){
        system(("curl 'https://www.virustotal.com/api/v3/ip_addresses/" + input + "' -H 'x-apikey: " + API + "' > ip_result.txt").c_str());
        std::cout << std::ifstream("ip_result.txt").rdbuf();
        return 0;
    }
    if (x == "HASH"){
        system(("curl -s -X GET 'https://www.virustotal.com/api/v3/files/" + input + "' -H 'x-apikey: " + API + "' > hash_result.txt").c_str());
        std::cout << std::ifstream("hash_result.txt").rdbuf();
        return 0;
    }
    if (x == "Fichier"){
        system(("curl -s -X POST 'https://www.virustotal.com/api/v3/files' -H 'x-apikey: " + API + "' -F 'file=@" + input + "' | grep -o 'https://[^\"]*' | tr -d '\n' > fichier_url_result.txt").c_str());
        std::cout << std::ifstream("fichier_url_result.txt").rdbuf();

        std::stringstream url;
        url << std::ifstream("fichier_url_result.txt").rdbuf();
        std::string analysis_url = url.str();

        system(("curl -s -X GET '" + analysis_url + "' -H 'x-apikey: " + API + "' > fichier_result.txt").c_str());
        std::cout << std::ifstream("fichier_result.txt").rdbuf();
        return 0;
    }
    if (x == "G-Fichier"){
        system(("curl -s -X GET 'https://www.virustotal.com/api/v3/files/upload_url' -H 'x-apikey: " + API + "' | grep -o 'https://[^\"]*' > GFichier_URL_Result.txt").c_str());

        std::stringstream convert;
        convert << std::ifstream("GFichier_URL_Result.txt").rdbuf();
        std::string upload_url = convert.str();

        system(("curl -s -X PUT '" + upload_url + "' -H 'x-apikey: " + API + "' -F 'file=@" + input + "' > GFichier_result.txt").c_str());
        std::cout << std::ifstream("GFichier_result.txt").rdbuf();
        return 0;
    }
    std::cout << "Le input n'a pas ete identifie" << std::endl;
    return 0;
}

int main(int argc, char** argv)
{
    std::cout << "Have " << argc-1 << " arguments:\n";
    for (int i = 1; i < argc; ++i){
        std::cout << argv[i] << " " << intput_donne(argv[i]) << "\n";
        request_choise(argv[i], intput_donne(argv[i]));
    }
    return 0;
}