#pragma once
#include <string>
#include <vector>

extern std::vector<std::string> paquets;
void traitement(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
int ecoute_dev();