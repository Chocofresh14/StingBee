#include <iostream>
#include <string>
#include <sys/inotify.h>
#include <unistd.h>
#include "yara.hpp"

#define BUF_LEN 4096

int inotify(std::string parcours){
    bool monitor = true;
    std::string path;

    int fd = inotify_init1(0);
    int wd = inotify_add_watch(fd, path.c_str(), IN_CREATE | IN_MODIFY | IN_DELETE);

    char buffer[BUF_LEN];

    while(true){
        int length = read(fd, buffer, BUF_LEN);
        int i = 0;
        while(i < length){
            struct inotify_event* event = (struct inotify_event*)&buffer[i];
            if(event->len){
                std::string fullpath = path + "/" + event->name;

                if(event->mask & IN_CREATE) {
                    std::cout << "CREATE: " << fullpath << "\n";
                    yara(fullpath);
                }
                if(event->mask & IN_MODIFY) {
                    std::cout << "MODIFY: " << fullpath << "\n";
                    yara(fullpath);
                }
                if(event->mask & IN_DELETE) {
                    std::cout << "DELETE: " << fullpath << "\n";
                    // pas de yara ici, le fichier n'existe plus
                }
            }
        }
    }
    inotify_rm_watch(fd, wd);
    close(fd);
    return 0;
}