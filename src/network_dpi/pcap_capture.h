#pragma once
#include <string>

extern std::string dernier_paquet;
void traitement(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
int ecoute_dev();