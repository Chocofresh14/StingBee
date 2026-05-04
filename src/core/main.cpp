#include <QApplication>
#include <QLabel>
#include <QPixmap>
#include <QVBoxLayout>
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <thread>
#include "../network_dpi/ndpi_inspector.h"
#include "../static_memory/main.hpp"
#include "behavioral/main.hpp"

int main(int argc, char *argv[]){

  mkdir("/var/log/stingbee", 0755);
  std::ofstream("/var/log/stingbee/edr.log");
  std::ofstream("/var/log/stingbee/alert.log");
  system("curl -s https://cdn.discordapp.com/channel-icons/1493585495551250462/5ae2c8faeae774db1d28d69cc3c0cb9e.png?size=160 --output /var/log/image");

  std::thread ndpi(execute);
  ndpi.detach();
  std::thread yara_th([](){
    yara("../static_memory/hello.bin");
  });
  yara_th.detach();

  std::thread behavioral_thread([](){ run_behavioral_components(); });
  behavioral_thread.detach();

  QApplication app(argc, argv);
  QWidget window;
  QVBoxLayout *layout = new QVBoxLayout(&window);

  QLabel *texte = new QLabel("StingBee - Monitoring actif");
  QLabel *image = new QLabel();
  image->setPixmap(QPixmap("/var/log/image"));

  layout->addWidget(image);
  layout->addWidget(texte);

  window.show();
  return app.exec();
}