#!/bin/bash

. /etc/os-release

if [ "$EUID" -ne 0 ]; then
    echo "Ce script doit être exécuté en root (ou via sudo)."
    exit 1
fi

if echo "$ID $ID_LIKE" | grep -qiE "debian|ubuntu"; then
    echo "Debian based"
    apt update && apt install -y \
        libseccomp2 \
        libseccomp-dev \
        clang \
        libbpf-dev \
        llvm \
        libelf-dev \
        pkg-config \
        linux-tools-common \
        nlohmann-json3-dev \
        libcap-dev \
        qtbase5-dev 


elif echo "$ID $ID_LIKE" | grep -qiE "rhel|centos|fedora"; then
    echo "Red Hat based"
    dnf install -y \
        libseccomp \
        libseccomp-devel \
        clang \
        libbpf-devel \
        llvm \
        elfutils-libelf-devel \
        pkgconf-pkg-config \
        bpftool \
        nlohmann-json3-dev \
        libcap-dev \
        qtbase5-dev 

else
    echo "OS non reconnu : $ID"
    exit 1
fi