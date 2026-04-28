cmake_minimum_required(VERSION 3.20)
project(stingbee VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


# Les fichiers cibles
file(GLOB_RECURSE SOURCES
    src/core/*.cpp
    src/alerts/*.cpp
    src/behavioral/*.cpp
    src/network_dpi/*.cpp
    src/static_memory/*.cpp
)

# Binaire créer a la sortie
add_executable(stingbee ${SOURCES})

# Tous les Headers de qui sont dans include
target_include_directories(stingbee PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

# Options
target_compile_options(stingbee PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    $<$<CONFIG:Debug>:-g -O0 -fsanitize=address>
    $<$<CONFIG:Release>:-O2>
)

# Linker
target_link_options(stingbee PRIVATE
    $<$<CONFIG:Debug>:-fsanitize=address>
)

# Dépendances à modifier si utilisé ou non

# libpcap
# libyara
# yaml-cpp

# Build les tests
option(BUILD_TESTS "Compiler les tests" ON)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# eBPF
find_program(CLANG_BIN clang)
if(CLANG_BIN)
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/ebpf)
    set(BPF_SRC ${CMAKE_SOURCE_DIR}/ebpf/syscall_hook.bpf.c)
    set(BPF_OUT ${CMAKE_BINARY_DIR}/ebpf/syscall_hook.bpf.o)

    add_custom_command(OUTPUT ${BPF_OUT}
        COMMAND ${CLANG_BIN} -O2 -target bpf -c ${BPF_SRC} -o ${BPF_OUT}
        DEPENDS ${BPF_SRC}
        COMMENT "Compiling BPF program ${BPF_SRC} -> ${BPF_OUT}"
        VERBATIM
    )
    add_custom_target(compile_bpf ALL DEPENDS ${BPF_OUT})
    add_dependencies(stingbee compile_bpf)
endif()

# Detect libbpf headers and link if present
include(CheckIncludeFileCXX)
check_include_file_cxx("bpf/libbpf.h" HAVE_LIBBPF_H)
if(HAVE_LIBBPF_H)
    add_compile_definitions(HAVE_LIBBPF=1)
    find_library(LIBBPF_LIBRARY NAMES bpf libbpf)
    if(LIBBPF_LIBRARY)
        target_link_libraries(stingbee PRIVATE ${LIBBPF_LIBRARY})
    endif()
endif()