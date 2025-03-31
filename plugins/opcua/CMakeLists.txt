set(LIBRARY_OUTPUT_PATH "${CMAKE_BINARY_DIR}/plugins")

set(PLUGIN_NAME "plugin-opcua")

find_package(open62541 REQUIRED)

set(CMAKE_BUILD_RPATH ./)
file(COPY ${CMAKE_SOURCE_DIR}/plugins/opcua/opcua.json DESTINATION ${CMAKE_BINARY_DIR}/plugins/schema/)

set(OPCUA_PLUGIN_SOURCES
    opcua.c
    opcua_client.c
    opcua_point.c
)

add_library(${PLUGIN_NAME} SHARED)
target_include_directories(${PLUGIN_NAME} PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/neuron
    ${open62541_INCLUDE_DIRS}
)
target_sources(${PLUGIN_NAME} PRIVATE ${OPCUA_PLUGIN_SOURCES})
target_link_libraries(${PLUGIN_NAME} PRIVATE
    neuron-base
    open62541
) 