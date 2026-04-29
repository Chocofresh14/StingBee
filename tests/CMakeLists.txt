add_executable(stingbee_ptrace_tracer_unit
    unit/test_ptrace_tracer.cpp
    ../src/behavioral/ptrace_tracer.cpp
)

target_include_directories(stingbee_ptrace_tracer_unit PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_compile_options(stingbee_ptrace_tracer_unit PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

target_link_libraries(stingbee_ptrace_tracer_unit PRIVATE pthread)

add_test(NAME ptrace_tracer_unit COMMAND stingbee_ptrace_tracer_unit)

add_executable(stingbee_ebpf_loader_unit
    unit/test_ebpf_loader.cpp
    ../src/behavioral/ebpf_loader.cpp
)

target_include_directories(stingbee_ebpf_loader_unit PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_compile_options(stingbee_ebpf_loader_unit PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

target_link_libraries(stingbee_ebpf_loader_unit PRIVATE pthread)

add_test(NAME ebpf_loader_unit COMMAND stingbee_ebpf_loader_unit)

add_executable(stingbee_auditd_event_analyzer_unit
    unit/test_auditd_event_analyzer.cpp
    ../src/behavioral/auditd_event_analyzer.cpp
)

target_include_directories(stingbee_auditd_event_analyzer_unit PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_compile_options(stingbee_auditd_event_analyzer_unit PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

target_link_libraries(stingbee_auditd_event_analyzer_unit PRIVATE pthread audit)

add_test(NAME auditd_event_analyzer_unit COMMAND stingbee_auditd_event_analyzer_unit)
