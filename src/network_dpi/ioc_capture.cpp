#include <iostream>
#include <regex>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp>

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
        system(("curl -s -X POST 'https://www.virustotal.com/api/v3/urls' -H 'x-apikey: " + API + "' --data-urlencode 'url=" + input + "' | grep -oE 'https://[A-Za-z0-9./_-]+' | tail -1 | tr -d '\n' > /var/log/url_url_result.json").c_str());

        std::stringstream url;
        url << std::ifstream("/var/log/url_url_result.json").rdbuf();
        std::string analysis_url = url.str();

        system(("curl -s -X GET '" + analysis_url + "' -H 'x-apikey: " + API + "' > /var/log/result.json").c_str());
        std::cout << std::ifstream("/var/log/result.json").rdbuf();
        return 0;
    }
    if (x == "DOMAIN"){
        system(("curl -s -X GET 'https://www.virustotal.com/api/v3/domains/" + input + "' -H 'x-apikey: " + API + "' > /var/log/result.json").c_str());
        std::cout << std::ifstream("/var/log/result.json").rdbuf();
        return 0;
    }
    if (x == "IP"){
        system(("curl -s -X GET 'https://www.virustotal.com/api/v3/ip_addresses/" + input + "' -H 'x-apikey: " + API + "' > /var/log/result.json").c_str());
        std::cout << std::ifstream("/var/log/result.json").rdbuf();
        return 0;
    }
    if (x == "HASH"){
        system(("curl -X GET 'https://www.virustotal.com/api/v3/files/" + input + "' -H 'x-apikey: " + API + "' > /var/log/result.json").c_str());

        std::ifstream f("/var/log/result.json");
        std::cout << f.rdbuf();
        f.close();

        return 0;
    }
    if (x == "Fichier"){
        system(("curl -s -X POST 'https://www.virustotal.com/api/v3/files' -H 'x-apikey: " + API + "' -F 'file=@" + input + "' | grep -o 'https://[^\"]*' | tr -d '\n' > /var/log/fichier_url_result.json").c_str());
        std::cout << std::ifstream("/var/log/fichier_url_result.json").rdbuf();

        std::stringstream url;
        url << std::ifstream("/var/log/fichier_url_result.json").rdbuf();
        std::string analysis_url = url.str();

        system(("curl -s -X GET '" + analysis_url + "' -H 'x-apikey: " + API + "' > /var/log/result.json").c_str());
        std::cout << std::ifstream("/var/log/result.json").rdbuf();
        return 0;
    }
    if (x == "G-Fichier"){
        system(("curl -s -X GET 'https://www.virustotal.com/api/v3/files/upload_url' -H 'x-apikey: " + API + "' | grep -o 'https://[^\"]*' > /var/log/GFichier_URL_Result.json").c_str());

        std::stringstream convert;
        convert << std::ifstream("/var/log/GFichier_URL_Result.json").rdbuf();
        std::string upload_url = convert.str();

        system(("curl -s -X PUT '" + upload_url + "' -H 'x-apikey: " + API + "' -F 'file=@" + input + "' > /var/log/result.json").c_str());
        std::cout << std::ifstream("/var/log/result.json").rdbuf();
        return 0;
    }
    std::cout << "Le input n'a pas ete identifie" << std::endl;
    return 0;
}

int detector_status(std::string type){
    using json = nlohmann::json;
    std::ifstream file("result.json");
    json data = json::parse(file);
    file.close();

    int score_malicouis = 0;
    int score_suspicious = 0;
    int score_failure = 0;

    if(type == "URL" || type == "Fichier" || type == "G-Fichier"){
    score_malicouis  = data["data"]["attributes"]["stats"].value("malicious", 0);
    score_suspicious = data["data"]["attributes"]["stats"].value("suspicious", 0);
    score_failure    = data["data"]["attributes"]["stats"].value("failure", 0);
}
else{
    score_malicouis  = data["data"]["attributes"]["last_analysis_stats"].value("malicious", 0);
    score_suspicious = data["data"]["attributes"]["last_analysis_stats"].value("suspicious", 0);
    score_failure    = data["data"]["attributes"]["last_analysis_stats"].value("failure", 0);
}
    std::cout << "\nLes scores sont : " << score_malicouis << " " << score_suspicious << " " << score_failure << std::endl;
    return 0;
}

int collecte(std::string input)
{
  std::cout << input << " " << intput_donne(input) << "\n";
  request_choise(input, intput_donne(input));
  detector_status(intput_donne(input));
  return 0;
}