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
