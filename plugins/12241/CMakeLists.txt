cmake_minimum_required(VERSION 3.12)
project(12241-plugin C)

set(CMAKE_C_FLAGS "-fPIC -shared ${CMAKE_C_FLAGS}")

add_library(12241 SHARED
    12241.c
    12241_point.c
    12241_stack.c
    12241_standard_points.c
    12241_tcp.c
)

target_include_directories(12241 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
)

install(TARGETS 12241
    DESTINATION lib/neuron/plugins
)

set(LIBRARY_OUTPUT_PATH "${CMAKE_BINARY_DIR}/plugins")

set(TWELVE241_SRC 12241.c 12241_point.c 12241_req.c 12241_stack.c)

set(CMAKE_BUILD_RPATH ./)
file(COPY ${CMAKE_SOURCE_DIR}/plugins/12241/12241-tcp.json DESTINATION ${CMAKE_BINARY_DIR}/plugins/schema/)

# 12241 TCP plugin
set(TWELVE241_TCP_PLUGIN plugin-12241-tcp)
set(TWELVE241_TCP_PLUGIN_SOURCES  12241_tcp.c
                                ${TWELVE241_SRC})
add_library(${TWELVE241_TCP_PLUGIN} SHARED)
target_include_directories(${TWELVE241_TCP_PLUGIN} PRIVATE ${CMAKE_SOURCE_DIR}/include/neuron)
target_sources(${TWELVE241_TCP_PLUGIN} PRIVATE ${TWELVE241_TCP_PLUGIN_SOURCES})
target_link_libraries(${TWELVE241_TCP_PLUGIN} neuron-base) 