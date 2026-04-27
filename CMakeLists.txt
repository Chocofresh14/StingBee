cmake_minimum_required(VERSION 3.20)
project(stingbee VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
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