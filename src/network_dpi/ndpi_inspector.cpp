#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <vector>
#include "pcap_capture.h"

int main() {
  std::string avant, apres;

  ecoute_dev();           // capture 1 paquet
  avant = dernier_paquet;

  ecoute_dev();           // capture 1 paquet
  apres = dernier_paquet;

  if (avant != apres)
    std::cout << "Nouveau paquet capturé" << std::endl;
  else
    std::cout << "Même paquet" << std::endl;

  return 0;
}