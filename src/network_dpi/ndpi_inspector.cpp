#include <iostream>
#include <vector>
#include "pcap_capture.h"
#include <unistd.h>
#include "ioc_capture.h"
#include <sys/time.h>
#include <chrono>
#include <ctime>
#include <fstream>

std::ofstream edr_log("/var/log/stingbee/edr.log", std::ios::app);
std::ofstream alert("/var/log/stingbee/alert.log", std::ios::app);

std::string timeToString(std::chrono::system_clock::time_point &t) {
  std::time_t time = std::chrono::system_clock::to_time_t(t);
  std::string time_str = std::ctime(&time);
  time_str.resize(time_str.size() - 1);
  return time_str;
}

void inspecter(std::vector<std::string> p) {

  if (std::stoi(p[1]) <= 10 && p[3] != "127.0.0.1") {
    edr_log << "[ALERTE] TTL très bas (" << p[1] << ") : " << p[3] << " -> possible scan" << std::endl;
    alert << "[ALERTE] TTL très bas (" << p[1] << ") : " << p[3] << std::endl;
    collecte(p[3]);
  }

  if (std::stoi(p[0]) > 1500) {
    edr_log << "[ALERTE] Paquet trop grand (" << p[0] << " octets) : " << p[3] << std::endl;
    alert << p[3] << std::endl;
    collecte(p[3]);
  }

  if (std::stoi(p[2]) == 1) {
    edr_log << "[INFO] ICMP détecté : " << p[3] << " -> " << p[4] << std::endl;
  }

  if (std::stoi(p[2]) == 17) {
    edr_log << "[INFO] UDP détecté : " << p[3] << " -> " << p[4] << std::endl;
  }

  if (p[4] == "127.0.0.1" && p[3] != "127.0.0.1") {
    edr_log << "[ALERTE] Trafic externe vers loopback : " << p[3] << " -> 127.0.0.1" << std::endl;
    alert<< "[ALERTE] Trafic externe vers loopback : " << p[3] << " -> 127.0.0.1" << std::endl;
    collecte(p[3]);
    }
  }

int execute() {
  while (true) {
    auto time_p = std::chrono::system_clock::now();
    edr_log << "Dormir maintenant " << timeToString(time_p) << std::endl;
    sleep(3);
    edr_log << "Reveille " << timeToString(time_p) << std::endl;
    paquets.clear();
    ecoute_dev();
    if (!paquets.empty()) {
      inspecter(paquets);
    }
  }
  return 0;
}
