#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <vector>
#include <string>
#include "pcap_capture.h"

std::vector<std::string> paquets;
void traitement(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {

  int ttl = packet[24];
  int protocol = packet[25];

  int total_len = (packet[18] << 8) + packet[19];

  std::string src_ip = std::to_string(packet[28]) + "." + std::to_string(packet[29]) + "." +std::to_string(packet[30]) + "." +std::to_string(packet[31]);

  std::string dst_ip = std::to_string(packet[32]) + "." +std::to_string(packet[33]) + "." + std::to_string(packet[34]) + "." + std::to_string(packet[35]);
  if (paquets.size() >= 3 && paquets[3] == "127.0.0.1") {
    std::cout << "Le paquet ne sera pas envoyé" << std::endl;
    return;
  }
  paquets.push_back(std::to_string(total_len));
  paquets.push_back(std::to_string(protocol));
  paquets.push_back(std::to_string(ttl));
  paquets.push_back(src_ip);
  paquets.push_back(dst_ip);
}

int ecoute_dev() {

  pcap_if_t *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  int result =0;

  result = pcap_findalldevs(&dev, errbuf);
  if (result == -1) {
    std::cout << "Error in pcap_findalldevs: " << errbuf << std::endl;
    return 0;
  }
  while (dev != NULL) {
    bool is_up = (dev->flags & PCAP_IF_UP) ;
    bool is_running = (dev->flags & PCAP_IF_RUNNING);

    if (is_up && is_running) {
      std::cout << "Interface active : " << dev->name << std::endl;
    }
    dev = dev->next;
  }

  pcap_t *handle = pcap_open_live("any", BUFSIZ, 0, -1, errbuf);

  if (handle == NULL) {
    std::cout << "Handel est Null : " <<  errbuf;
    return 1;
  }

  printf("Ecoute en cours...\n");
  pcap_loop(handle, 200, traitement, NULL);
  pcap_close(handle);
  return 0;
}

