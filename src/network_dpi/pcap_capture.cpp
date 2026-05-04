#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <vector>
#include <string>
#include "pcap_capture.h"
#include <sys/time.h>
#include <chrono>
#include <ctime>
#include <fstream>

auto time_p = std::chrono::system_clock::now();
std::ofstream edr_logs("/var/log/stingbee/edr.log", std::ios::app);

std::vector<std::string> paquets;
int nombre_paquet = 0;

std::string timeToStringg(std::chrono::system_clock::time_point &t) {
  std::time_t time = std::chrono::system_clock::to_time_t(t);
  std::string time_str = std::ctime(&time);
  time_str.resize(time_str.size() - 1);
  return time_str;
}

void traitement(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {

  int ttl = packet[24];
  int protocol = packet[25];

  int total_len = (packet[18] << 8) + packet[19];

  std::string src_ip = std::to_string(packet[28]) + "." + std::to_string(packet[29]) + "." +std::to_string(packet[30]) + "." +std::to_string(packet[31]);
  std::string dst_ip = std::to_string(packet[32]) + "." +std::to_string(packet[33]) + "." + std::to_string(packet[34]) + "." + std::to_string(packet[35]);

  if (src_ip.rfind("127.", 0) == 0 || dst_ip.rfind("127.", 0) == 0) {
    return;
  }

  paquets.push_back(std::to_string(total_len));
  paquets.push_back(std::to_string(protocol));
  paquets.push_back(std::to_string(ttl));
  paquets.push_back(src_ip);
  paquets.push_back(dst_ip);
  nombre_paquet ++;
}

int ecoute_dev() {

  pcap_if_t *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  int result =0;

  result = pcap_findalldevs(&dev, errbuf);
  if (result == -1) {
    edr_logs << "Error in pcap_findalldevs: " << errbuf << std::endl;
    return 0;
  }
  while (dev != NULL) {
    bool is_up = (dev->flags & PCAP_IF_UP) ;
    bool is_running = (dev->flags & PCAP_IF_RUNNING);

    if (is_up && is_running) {
      edr_logs << "Interface active : " << dev->name << timeToStringg(time_p) << std::endl;
    }
    dev = dev->next;
  }

  pcap_t *handle = pcap_open_live("any", BUFSIZ, 0, -1, errbuf);

  if (handle == NULL) {
    edr_logs << "Handel est Null : " << timeToStringg(time_p) <<  errbuf;
    return 1;
  }

  while (nombre_paquet < 200) {
    paquets.clear();
    pcap_loop(handle, 200, traitement, NULL);
  }
    pcap_close(handle);
    nombre_paquet = 0;
    return 0;

}

