#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <vector>
#include "pcap_capture.h"
#include <unistd.h>

void inspecter(std::vector<std::string> p) {

  if (std::stoi(p[1]) <= 10 && p[3] != "127.0.0.1")
    std::cout << "[ALERTE] TTL très bas (" << p[1] << ") : " << p[3] << " -> possible scan" << std::endl;

  if (std::stoi(p[0]) > 1500)
    std::cout << "[ALERTE] Paquet trop grand (" << p[0] << " octets) : " << p[3] << std::endl;

  if (std::stoi(p[2]) == 1)
    std::cout << "[INFO] ICMP détecté : " << p[3] << " -> " << p[4] << std::endl;

  if (std::stoi(p[2]) == 17)
    std::cout << "[INFO] UDP détecté : " << p[3] << " -> " << p[4] << std::endl;

  if (p[4] == "127.0.0.1" && p[3] != "127.0.0.1")
    std::cout << "[ALERTE] Trafic externe vers loopback : " << p[3] << " -> 127.0.0.1" << std::endl;
}

int main() {
  while (true) {
    std::cout << "Dormir maintenant" << std::endl;
    sleep(30);
    std::cout << "Reveille" << std::endl;
    paquets.clear();
    ecoute_dev();
    if (!paquets.empty()) {
      inspecter(paquets);
    }
  }
  return 0;
}
