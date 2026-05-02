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

add_executable(stingbee_syscall_analyzer_unit
    unit/test_syscall_analyzer.cpp
    ../src/behavioral/syscall_analyzer.cpp
)

target_include_directories(stingbee_syscall_analyzer_unit PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_compile_options(stingbee_syscall_analyzer_unit PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

target_link_libraries(stingbee_syscall_analyzer_unit PRIVATE pthread)

add_test(NAME syscall_analyzer_unit COMMAND stingbee_syscall_analyzer_unit)

find_library(LIBSECCOMP_LIBRARY NAMES seccomp)

add_executable(stingbee_main_behavioral
    main_behavioral.cpp
    ../src/behavioral/ptrace_tracer.cpp
    ../src/behavioral/ebpf_loader.cpp
    ../src/behavioral/auditd_event_analyzer.cpp
    ../src/behavioral/seccomp_filter.cpp
    ../src/behavioral/syscall_analyzer.cpp
)

target_include_directories(stingbee_main_behavioral PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_compile_options(stingbee_main_behavioral PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

target_link_libraries(stingbee_main_behavioral PRIVATE pthread audit)

if(LIBSECCOMP_LIBRARY)
    target_compile_definitions(stingbee_main_behavioral PRIVATE STINGBEE_HAVE_SECCOMP=1)
    target_link_libraries(stingbee_main_behavioral PRIVATE ${LIBSECCOMP_LIBRARY})
endif()

add_executable(stingbee_seccomp_filter_unit
    unit/test_seccomp_filter.cpp
    ../src/behavioral/seccomp_filter.cpp
)

target_include_directories(stingbee_seccomp_filter_unit PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_compile_options(stingbee_seccomp_filter_unit PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

if(LIBSECCOMP_LIBRARY)
    target_compile_definitions(stingbee_seccomp_filter_unit PRIVATE STINGBEE_HAVE_SECCOMP=1)
    target_link_libraries(stingbee_seccomp_filter_unit PRIVATE pthread ${LIBSECCOMP_LIBRARY})
else()
    target_link_libraries(stingbee_seccomp_filter_unit PRIVATE pthread)
endif()

add_test(NAME seccomp_filter_unit COMMAND stingbee_seccomp_filter_unit)
