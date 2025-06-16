cmake_minimum_required(VERSION 3.12)

project(plugin-dmp-mqtt)

set(LIBRARY_OUTPUT_PATH "${CMAKE_BINARY_DIR}/plugins")

file(COPY ${CMAKE_SOURCE_DIR}/plugins/dmp_mqtt/dmp-mqtt.json DESTINATION ${CMAKE_BINARY_DIR}/plugins/schema/)

add_library(${PROJECT_NAME} SHARED
  mqtt_config.c
  mqtt_handle.c
  mqtt_plugin.c
  mqtt_plugin_intf.c
  schema.c
  ptformat.pb-c.c
)

target_include_directories(${PROJECT_NAME} PRIVATE 
  ${CMAKE_SOURCE_DIR}/include/neuron
  ${CMAKE_SOURCE_DIR}/plugins/dmp_mqtt
)

target_link_libraries(${PROJECT_NAME} neuron-base)
target_link_libraries(${PROJECT_NAME} ${CMAKE_THREAD_LIBS_INIT})
