#!/bin/bash

bpftool btf dump file /sys/kernel/btf/vmlinux format c > /opt/stingbee/ebpf/vmlinux.h