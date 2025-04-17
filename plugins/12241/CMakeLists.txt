cmake_minimum_required(VERSION 3.13)

project(neuron-plugin-12241-tcp C)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/plugins)

set(CMAKE_C_FLAGS "-fPIC ${CMAKE_C_FLAGS}")

# 复制JSON配置文件
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/12241-tcp.json DESTINATION ${CMAKE_BINARY_DIR}/plugins/schema/)

# GB/T 12241 TCP 插件
set(GB_12241_TCP_PLUGIN plugin-12241-tcp)
set(GB_12241_TCP_SOURCES 12241_tcp.c 12241_point.c)
add_library(${GB_12241_TCP_PLUGIN} SHARED ${GB_12241_TCP_SOURCES})
target_compile_options(${GB_12241_TCP_PLUGIN} PRIVATE -fPIC)

# 包含路径设置
target_include_directories(${GB_12241_TCP_PLUGIN} PRIVATE ${CMAKE_SOURCE_DIR}/include/neuron )

# 安装规则
install(TARGETS ${GB_12241_TCP_PLUGIN}
        LIBRARY DESTINATION lib/neuron/plugins
        COMPONENT neuron-plugin-12241-tcp)

install(
    FILES 12241-tcp.json
    DESTINATION "${CMAKE_INSTALL_PREFIX}/config/plugins"
) 