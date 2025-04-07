/**
 * NEURON IIoT System for Industry 4.0
 * Copyright (C) 2020-2023 EMQ Technologies Co., Ltd All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **/
#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <neuron.h>

#include "12241.h"
#include "12241_point.h"
#include "12241_req.h"
#include "12241_stack.h"

// 帧头标识
#define GB_12241_FRAME_HEADER      0x68
// 最大帧长度
#define GB_12241_MAX_FRAME_SIZE    1024
// 最小帧长度 (帧头1B + 长度2B + 控制码1B + 序列号2B + CRC校验2B)
#define GB_12241_MIN_FRAME_SIZE    8
#define GB_12241_READ_DATA    0x01  // 读数据命令码
#define GB_12241_MAX_CACHED_CMDS 16    // 最大缓存命令数量

// 接收缓冲区结构
typedef struct {
    uint8_t  buffer[GB_12241_MAX_FRAME_SIZE * 2]; // 接收缓冲区
    uint32_t size;         // 缓冲区大小
    uint32_t used;         // 已使用大小
    uint32_t frame_start;  // 当前帧起始位置
    bool     frame_found;  // 是否找到帧头
} GB_12241_recv_buffer_t;

// 设备信息结构
typedef struct {
    GB_12241_recv_buffer_t recv_buffer;  // 接收缓冲区
    uint16_t               seq;          // 序列号
    bool                   waiting;      // 是否等待响应
    neu_reqresp_head_t     waiting_req;  // 等待的请求
    uint32_t               last_class1_time; // 上次一类数据时间
    uint32_t               last_class2_time; // 上次二类数据时间
    uint32_t               class1_timeout;   // 一类数据超时时间(ms)
    uint32_t               class2_timeout;   // 二类数据超时时间(ms)
    
    // 命令缓存队列
    struct {
        neu_reqresp_head_t queue[GB_12241_MAX_CACHED_CMDS];  // 命令队列
        int                count;                   // 队列中的命令数量
    } cmd_cache;
} GB_12241_device_t;

// 数据类型
typedef enum {
    GB_12241_DATA_CLASS_1 = 1,  // 一类数据（实时数据）
    GB_12241_DATA_CLASS_2 = 2,  // 二类数据（非实时数据）
} GB_12241_data_class_t;

static inline uint16_t get_group_interval(const neu_plugin_t *plugin)
{
    return neu_plugin_get_config_uint16(plugin, "group_interval", 1000);
}

static inline uint16_t get_max_retries(const neu_plugin_t *plugin)
{
    return neu_plugin_get_config_uint16(plugin, "max_retries", 0);
}

static inline uint16_t get_retry_interval(const neu_plugin_t *plugin)
{
    return neu_plugin_get_config_uint16(plugin, "retry_interval", 0);
}

static inline GB_12241_endianess get_endianess(const neu_plugin_t *plugin)
{
    return (GB_12241_endianess) neu_plugin_get_config_int(plugin, "endianess", 1);
}

static inline GB_12241_address_base get_address_base(const neu_plugin_t *plugin)
{
    return (GB_12241_address_base) neu_plugin_get_config_int(plugin, "address_base", 0);
}

static inline int get_device_degrade(const neu_plugin_t *plugin)
{
    return neu_plugin_get_config_int(plugin, "device_degrade", 0);
}

static inline uint16_t get_degrade_cycle(const neu_plugin_t *plugin)
{
    return neu_plugin_get_config_uint16(plugin, "degrade_cycle", 2);
}

static inline uint16_t get_degrade_time(const neu_plugin_t *plugin)
{
    return neu_plugin_get_config_uint16(plugin, "degrade_time", 600);
}

static inline int get_check_header(const neu_plugin_t *plugin)
{
    return neu_plugin_get_config_int(plugin, "check_header", 0);
}

static inline int get_connection_mode(const neu_plugin_t *plugin)
{
    return neu_plugin_get_config_int(plugin, "connection_mode", 0);
}

// 解析点位地址
static int parse_tag_addr(const neu_plugin_t *plugin, const neu_datatag_t *tag,
                           neu_datatag_addr_t *addr)
{
    GB_12241_point_t point  = { 0 };
    const char *      str    = tag->address;
    GB_12241_endianess endian = get_endianess(plugin);
    GB_12241_address_base base = get_address_base(plugin);

    return GB_12241_parse_point(str, addr, &point, base, endian);
}

// 添加点位
static int add_tag(const neu_plugin_t *plugin, const neu_datatag_t *tag)
{
    neu_datatag_addr_t addr = { 0 };
    GB_12241_point_t    point = { 0 };
    int                rc    = 0;

    GB_12241_endianess endian = get_endianess(plugin);
    GB_12241_address_base base = get_address_base(plugin);

    rc = GB_12241_parse_point(tag->address, &addr, &point, base, endian);
    if (rc != 0) {
        nlog_error("failed parse tag: %s, err: %d", tag->address, rc);
        return rc;
    }

    return GB_12241_req_add_point(plugin, tag);
}

// 写入点位值
static int write_tags(const neu_plugin_t *plugin, neu_req_value_t *value)
{
    uint16_t                  n_tag        = neu_req_value_get_n_tag(value);
    neu_req_tag_value_parse_t tag_value    = { 0 };
    int                       rc           = 0;
    neu_req_value_get_tag_value_begin(value, &tag_value);

    for (int i = 0; i < n_tag; i++) {
        GB_12241_point_t point      = { 0 };
        uint8_t           bytes[128] = { 0 };
        double            val        = 0;

        memcpy(&point, tag_value.tag_addr->value.opaques.bytes, sizeof(point));

        switch (tag_value.value.type) {
        case NEU_TYPE_UINT16:
            val = tag_value.value.value.u16;
            break;
        case NEU_TYPE_INT16:
            val = tag_value.value.value.i16;
            break;
        case NEU_TYPE_UINT32:
            val = tag_value.value.value.u32;
            break;
        case NEU_TYPE_INT32:
            val = tag_value.value.value.i32;
            break;
        case NEU_TYPE_UINT64:
            val = tag_value.value.value.u64;
            break;
        case NEU_TYPE_INT64:
            val = tag_value.value.value.i64;
            break;
        case NEU_TYPE_FLOAT:
            val = tag_value.value.value.f32;
            break;
        case NEU_TYPE_DOUBLE:
            val = tag_value.value.value.d64;
            break;
        case NEU_TYPE_BIT:
            val = tag_value.value.value.bit;
            break;
        case NEU_TYPE_BOOL:
            val = tag_value.value.value.boolean;
            break;
        default:
            nlog_error("unsupported value type: %d", tag_value.value.type);
            neu_req_value_get_tag_value_end(value, &tag_value);
            return -1;
        }

        rc = GB_12241_value_write(&point, val, bytes);
        if (rc < 0) {
            nlog_error("write value error: %d", rc);
            neu_req_value_get_tag_value_end(value, &tag_value);
            return rc;
        }

        // 根据区域选择写入功能码
        uint8_t function = 0;
        switch (point.area) {
        case GB_12241_AREA_DATA:
            function = GB_12241_WRITE_DATA;
            break;
        case GB_12241_AREA_PARAM:
            function = GB_12241_WRITE_PARAM;
            break;
        default:
            nlog_error("unsupported write area: %d", point.area);
            neu_req_value_get_tag_value_end(value, &tag_value);
            return -1;
        }

        rc = GB_12241_req_add_write(plugin, point.dev_addr, point.reg_addr,
                                  function, bytes,
                                  GB_12241_get_data_size(&point));
        if (rc < 0) {
            nlog_error("add write error: %d", rc);
            neu_req_value_get_tag_value_end(value, &tag_value);
            return rc;
        }

        rc = neu_req_value_get_tag_value_next(value, &tag_value);
        if (rc != 0) {
            break;
        }
    }

    neu_req_value_get_tag_value_end(value, &tag_value);
    return rc;
}

// 设置回调
static void set_callback(neu_plugin_t *plugin, neu_persist_driver_cb_t *cb)
{
    neu_plugin_set_owner(plugin, cb);
}

// 编码请求
static int GB_12241_encode_request(neu_plugin_t *plugin, neu_reqresp_head_t *head,
                                 uint8_t *buf, size_t size)
{
    GB_12241_device_t *device = neu_plugin_get_data(plugin);
    uint8_t *buffer = buf;
    size_t buf_size = size;
    int rc = 0;
    
    // 增加序列号
    device->seq++;
    
    switch (head->type) {
    case NEU_REQ_READ:
        // 编码读请求
        rc = GB_12241_req_build_read(plugin, head, buffer, buf_size);
        break;
        
    case NEU_REQ_WRITE:
        // 编码写请求
        rc = GB_12241_req_build_write(plugin, head, buffer, buf_size);
        break;
        
    default:
        plog_error("unsupported request type: %d", head->type);
        rc = -1;
        break;
    }
    
    if (rc > 0) {
        // 打印发送的数据帧
        plog_debug("GB_12241 TX[%d]: %02X %02X %02X %02X ...", 
                   rc, buffer[0], buffer[1], buffer[2], buffer[3]);
    
        // 打印详细的帧信息
        if (plog_get_level() <= NEU_PLOG_DEBUG) {
            char hex_buffer[1024] = {0};
            char *p = hex_buffer;
            for (int i = 0; i < rc && i < 32; i++) {
                p += snprintf(p, sizeof(hex_buffer) - (p - hex_buffer), 
                              "%02X ", buffer[i]);
            }
            if (rc > 32) {
                p += snprintf(p, sizeof(hex_buffer) - (p - hex_buffer), "...");
            }
            plog_debug("GB_12241 FRAME[%d]: %s", rc, hex_buffer);
        }
    
        // 检查通道是否连接
        if (GB_12241_is_connected(plugin) && !device->waiting) {
            // 通道已连接且没有等待的请求，直接发送
            uint8_t buf[GB_12241_MAX_FRAME_SIZE];
            int rc = GB_12241_encode_request(plugin, head, buf, sizeof(buf));
            if (rc > 0) {
                // 设置等待状态
                device->waiting = true;
                device->waiting_req = *head;
                
                // 发送请求
                neu_plugin_send(plugin, buf, rc);
                plog_debug("Sent query for %s data", 
                          head->type == NEU_REQ_READ ? "class 1" : "class 2");
            } else {
                plog_error("Failed to encode %s data query request", 
                          head->type == NEU_REQ_READ ? "class 1" : "class 2");
            }
        } else {
            // 通道未连接或有等待的请求，缓存命令
            GB_12241_cache_command(device, head);
            plog_debug("Cached query for %s data, channel %s", 
                      head->type == NEU_REQ_READ ? "class 1" : "class 2",
                      GB_12241_is_connected(plugin) ? "busy" : "disconnected");
        }
    }
    
    return rc;
}

// 处理已收到的响应
static void GB_12241_handle_response(neu_plugin_t *plugin, 
                                   GB_12241_device_t *device,
                                   uint8_t *frame_data, 
                                   uint16_t frame_len)
{
    // 获取序列号
    uint16_t seq = (frame_data[4] << 8) | frame_data[5];
    
    // 调用回调函数处理帧
    if (device->waiting_req.cb) {
        device->waiting_req.cb(&device->waiting_req, frame_data, frame_len);
    }
    
    // 清除等待状态
    device->waiting = false;
    
    // 尝试处理缓存的命令
    neu_plugin_t *plugin_ptr = neu_device_to_plugin(device);
    if (plugin_ptr != NULL) {
        GB_12241_process_cached_commands(plugin_ptr, device);
    }
}

// 响应处理函数，兼容原有API
static int GB_12241_handle_response_api(neu_plugin_t *plugin, neu_reqresp_head_t *head,
                                     uint8_t *buf, size_t size)
{
    GB_12241_device_t *device = neu_plugin_get_data(plugin);
    int rc = 0;
    
    // 处理接收到的数据
    rc = GB_12241_process_recv_data(device, buf, size);
    if (rc < 0) {
        plog_error("process receive data error: %d", rc);
        return rc;
    }
    
    return size;
}

// 处理TCP接收数据
static int GB_12241_tcp_recv(neu_plugin_t *plugin, uint8_t *buf, size_t size)
{
    GB_12241_device_t *device = neu_plugin_get_data(plugin);
    int rc = 0;
    
    // 处理接收到的数据
    rc = GB_12241_process_recv_data(device, buf, size);
    
    return rc;
}

// 读请求处理
static int GB_12241_read(neu_plugin_t *plugin, neu_reqresp_head_t *head,
                       neu_req_read_t *req)
{
    assert(NULL != plugin);
    assert(NULL != req);

    int rc = 0;
    rc = GB_12241_req_process_tags(plugin, req->tags);
    if (rc < 0) {
        plog_error("process tags error: %d", rc);
        return NEU_ERR_PLUGIN_REQUEST_BUILD_FAIL;
    }

    return NEU_ERR_SUCCESS;
}

// 写请求处理
static int GB_12241_write(neu_plugin_t *plugin, neu_reqresp_head_t *head,
                        neu_req_write_t *req)
{
    assert(NULL != plugin);
    assert(NULL != req);

    int rc = 0;
    rc = GB_12241_req_process_tags(plugin, req->tags);
    if (rc < 0) {
        plog_error("process tags error: %d", rc);
        return NEU_ERR_PLUGIN_REQUEST_BUILD_FAIL;
    }

    return NEU_ERR_SUCCESS;
}

// 释放插件资源
static void destroy(neu_plugin_t *plugin)
{
    GB_12241_req_destroy(plugin);
}

// 从设备指针获取插件指针的辅助函数
static neu_plugin_t *g_current_plugin = NULL;

static neu_plugin_t *neu_device_to_plugin(void *device_data)
{
    // 返回全局保存的插件指针
    return g_current_plugin;
}

// 检查是否需要主动查询数据
static void GB_12241_check_data_timeout(neu_plugin_t *plugin, 
                                       GB_12241_device_t *device)
{
    uint32_t now = neu_time_ms();
    
    // 检查一类数据超时
    if (device->last_class1_time > 0 && 
        now - device->last_class1_time > device->class1_timeout) {
        // 已超时，需要主动查询一类数据
        plog_debug("Class 1 data timeout, last received: %u ms ago", 
                  now - device->last_class1_time);
        
        // 如果正在等待响应，则不发送新请求
        if (device->waiting) {
            return;
        }
        
        // 这里需要实现主动查询一类数据的函数
        // 可以调用已有的查询函数，指定查询一类数据的点位
        GB_12241_query_class_data(plugin, GB_12241_DATA_CLASS_1);
    }
    
    // 检查二类数据超时
    if (device->last_class2_time > 0 && 
        now - device->last_class2_time > device->class2_timeout) {
        // 已超时，需要主动查询二类数据
        plog_debug("Class 2 data timeout, last received: %u ms ago", 
                  now - device->last_class2_time);
        
        // 如果正在等待响应，则不发送新请求
        if (device->waiting) {
            return;
        }
        
        // 这里需要实现主动查询二类数据的函数
        // 可以调用已有的查询函数，指定查询二类数据的点位
        GB_12241_query_class_data(plugin, GB_12241_DATA_CLASS_2);
    }
}

// 主动查询特定类别的数据
static void GB_12241_query_class_data(neu_plugin_t *plugin, 
                                    GB_12241_data_class_t data_class)
{
    GB_12241_device_t *device = neu_plugin_get_data(plugin);
    
    // 构造请求头
    neu_reqresp_head_t head = { 0 };
    head.type = NEU_REQ_READ;
    
    // 标记为主动查询的请求
    bool points_added = false;
    
    if (data_class == GB_12241_DATA_CLASS_1) {
        plog_debug("Actively querying class 1 data");
        
        // 添加一类数据点位到请求中 - 以电压和电流为例
        // 设备地址默认使用1，实际应根据配置调整
        uint8_t dev_addr = 1;
        
        // 添加点位：A相电压 (点位ID: 1000)
        if (GB_12241_req_add_read(plugin, dev_addr, 1000, GB_12241_READ_DATA, 4) == 0) {
            points_added = true;
        }
        
        // 添加点位：B相电压 (点位ID: 1001)
        if (GB_12241_req_add_read(plugin, dev_addr, 1001, GB_12241_READ_DATA, 4) == 0) {
            points_added = true;
        }
        
        // 添加点位：C相电压 (点位ID: 1002)
        if (GB_12241_req_add_read(plugin, dev_addr, 1002, GB_12241_READ_DATA, 4) == 0) {
            points_added = true;
        }
        
        // 添加点位：A相电流 (点位ID: 1020)
        if (GB_12241_req_add_read(plugin, dev_addr, 1020, GB_12241_READ_DATA, 4) == 0) {
            points_added = true;
        }
        
        // 更新一类数据最后查询时间
        device->last_class1_time = neu_time_ms();
        
    } else {
        plog_debug("Actively querying class 2 data");
        
        // 添加二类数据点位到请求中 - 以累计电量为例
        // 设备地址默认使用1，实际应根据配置调整
        uint8_t dev_addr = 1;
        
        // 添加点位：正向有功总电能 (点位ID: 2000)
        if (GB_12241_req_add_read(plugin, dev_addr, 2000, GB_12241_READ_DATA, 4) == 0) {
            points_added = true;
        }
        
        // 添加点位：反向有功总电能 (点位ID: 2010)
        if (GB_12241_req_add_read(plugin, dev_addr, 2010, GB_12241_READ_DATA, 4) == 0) {
            points_added = true;
        }
        
        // 更新二类数据最后查询时间
        device->last_class2_time = neu_time_ms();
    }
    
    // 如果没有添加任何点位，直接返回
    if (!points_added) {
        plog_warn("No points added for %s data query", 
                 data_class == GB_12241_DATA_CLASS_1 ? "class 1" : "class 2");
        return;
    }
    
    // 检查通道是否已连接
    if (GB_12241_is_connected(plugin) && !device->waiting) {
        // 通道已连接且没有等待的请求，直接发送
        uint8_t buf[GB_12241_MAX_FRAME_SIZE];
        int rc = GB_12241_encode_request(plugin, &head, buf, sizeof(buf));
        if (rc > 0) {
            // 设置等待状态
            device->waiting = true;
            device->waiting_req = head;
            
            // 发送请求
            neu_plugin_send(plugin, buf, rc);
            
            plog_debug("Sent query for %s data, %d bytes", 
                      data_class == GB_12241_DATA_CLASS_1 ? "class 1" : "class 2", rc);
        } else {
            plog_error("Failed to encode %s data query request", 
                      data_class == GB_12241_DATA_CLASS_1 ? "class 1" : "class 2");
        }
    } else {
        // 通道未连接或有等待的请求，缓存命令
        GB_12241_cache_command(device, &head);
        plog_debug("Cached query for %s data, channel %s", 
                  data_class == GB_12241_DATA_CLASS_1 ? "class 1" : "class 2",
                  GB_12241_is_connected(plugin) ? "busy" : "disconnected");
    }
}

// 周期性检查函数，根据需要主动查询数据
static void GB_12241_check_periodic(neu_plugin_t *plugin)
{
    GB_12241_device_t *device = neu_plugin_get_data(plugin);
    
    // 如果通道已连接，检查是否需要主动查询数据
    if (GB_12241_is_connected(plugin)) {
        // 检查是否需要主动查询数据
        GB_12241_check_data_timeout(plugin, device);
        
        // 如果没有等待的请求，尝试处理缓存的命令
        if (!device->waiting) {
            GB_12241_process_cached_commands(plugin, device);
        }
    } else {
        // 通道未连接，记录日志
        plog_debug("Channel disconnected, skipping data check");
    }
}

// 修改驱动启动函数，添加定时检查
static int driver_start(neu_plugin_t *plugin)
{
    GB_12241_device_t *device = neu_plugin_get_data(plugin);
    if (device == NULL) {
        plog_error("Device not initialized");
        return -1;
    }
    
    // 创建定时器，定期检查数据状态
    neu_plugin_timer_create(plugin, 1000, GB_12241_check_periodic);
    
    plog_info("GB_12241 driver started with data class monitoring");
    return 0;
}

// 驱动停止
static int driver_stop(neu_plugin_t *plugin)
{
    GB_12241_device_t *device = neu_plugin_get_data(plugin);
    if (device == NULL) {
        plog_error("Device not initialized");
        return -1;
    }
    
    plog_info("GB_12241 driver stopped");
    return 0;
}

// 设置回调函数
static int set_callback(neu_plugin_t *plugin, void *param)
{
    // 保存回调参数
    return 0;
}

// 初始化接收缓冲区
static void GB_12241_recv_buffer_init(GB_12241_recv_buffer_t *recv)
{
    memset(recv->buffer, 0, sizeof(recv->buffer));
    recv->size = sizeof(recv->buffer);
    recv->used = 0;
    recv->frame_start = 0;
    recv->frame_found = false;
}

// 检查报文帧头
static bool GB_12241_check_frame_header(const uint8_t *buf, size_t len)
{
    if (len < 1) {
        return false;
    }
    
    return buf[0] == GB_12241_FRAME_HEADER;
}

// 查找帧头
static bool GB_12241_find_frame_header(GB_12241_recv_buffer_t *recv)
{
    for (uint32_t i = 0; i < recv->used; i++) {
        if (recv->buffer[i] == GB_12241_FRAME_HEADER) {
            // 找到帧头，记录位置
            recv->frame_start = i;
            recv->frame_found = true;
            
            // 如果帧头不在开始位置，则移动缓冲区
            if (i > 0) {
                memmove(recv->buffer, recv->buffer + i, recv->used - i);
                recv->used -= i;
                recv->frame_start = 0;
            }
            
            return true;
        }
    }
    
    // 没有找到帧头，清空缓冲区
    recv->used = 0;
    recv->frame_found = false;
    return false;
}

// 检查报文是否完整
static bool GB_12241_check_frame_complete(GB_12241_recv_buffer_t *recv)
{
    // 最小帧长检查
    if (recv->used < GB_12241_MIN_FRAME_SIZE) {
        return false;
    }
    
    // 检查是否有足够的字节解析长度字段
    if (recv->used < recv->frame_start + 3) {
        return false;
    }
    
    // 获取帧长度
    uint16_t frame_len = (recv->buffer[recv->frame_start + 1] << 8) | 
                          recv->buffer[recv->frame_start + 2];
    
    // 检查长度是否合法
    if (frame_len < GB_12241_MIN_FRAME_SIZE || frame_len > GB_12241_MAX_FRAME_SIZE) {
        // 长度不合法，可能是错误的帧或者干扰数据
        plog_warn("Invalid frame length: %u", frame_len);
        
        // 尝试重新查找帧头
        recv->frame_found = false;
        return false;
    }
    
    // 检查是否接收到完整的帧
    if (recv->used < recv->frame_start + frame_len) {
        return false;
    }
    
    return true;
}

// 设置一类数据超时
static inline uint32_t get_class1_timeout(const neu_plugin_t *plugin)
{
    return neu_plugin_get_config_uint32(plugin, "class1_timeout", 10000); // 默认10秒
}

// 设置二类数据超时
static inline uint32_t get_class2_timeout(const neu_plugin_t *plugin)
{
    return neu_plugin_get_config_uint32(plugin, "class2_timeout", 60000); // 默认60秒
}

// 判断点位属于哪类数据
static GB_12241_data_class_t GB_12241_get_point_class(uint16_t point_id)
{
    // 根据点位ID范围判断数据类别
    if (point_id >= 1000 && point_id < 2000) {
        return GB_12241_DATA_CLASS_1;  // 一类数据
    } else {
        return GB_12241_DATA_CLASS_2;  // 二类数据
    }
}

// 处理带时标的二类数据
static void GB_12241_handle_class2_data(neu_plugin_t *plugin, 
    const GB_12241_timestamped_data_t* data) {
    
    // 转换时标为 time_t
    time_t timestamp;
    GB_12241_timestamp_to_time(&data->timestamp, &timestamp);
    
    // 构建带时标的数据值
    neu_data_val_t value = {
        .timestamp = timestamp,  // 使用数据自带的时标
        .type = data->data_type,
        .value = data->data,
        .len = data->data_len
    };
    
    // 上报数据
    neu_plugin_send_value(plugin, &value);
}

// 修改数据接收处理函数
static void GB_12241_handle_response(neu_plugin_t *plugin,
    const uint8_t *buf, size_t size) {
    
    // 判断数据类型
    if (buf[0] == GB_12241_DATA_CLASS_2) {
        // 二类数据，带时标
        const GB_12241_timestamped_data_t* data = 
            (const GB_12241_timestamped_data_t*)buf;
            
        GB_12241_handle_class2_data(plugin, data);
    } else {
        // 一类数据，实时处理
        // ... existing code ...
    }
}

// 驱动初始化
static neu_plugin_t *driver_init(neu_plugin_t *plugin)
{
    GB_12241_device_t *device = calloc(1, sizeof(GB_12241_device_t));
    if (device == NULL) {
        plog_error("Failed to allocate memory for device");
        return NULL;
    }
    
    // 初始化接收缓冲区
    GB_12241_recv_buffer_init(&device->recv_buffer);
    
    // 初始化设备参数
    device->seq = 0;
    device->waiting = false;
    memset(&device->waiting_req, 0, sizeof(neu_reqresp_head_t));
    
    // 初始化一类和二类数据超时时间
    device->class1_timeout = get_class1_timeout(plugin);
    device->class2_timeout = get_class2_timeout(plugin);
    device->last_class1_time = 0;
    device->last_class2_time = 0;
    
    // 初始化命令缓存
    device->cmd_cache.count = 0;
    
    // 设置私有数据
    neu_plugin_set_data(plugin, device);
    
    // 保存当前插件指针到全局变量
    g_current_plugin = plugin;
    
    plog_info("GB_12241 driver initialized, class1_timeout=%u ms, class2_timeout=%u ms",
              device->class1_timeout, device->class2_timeout);
    
    // 创建协议栈
    return GB_12241_stack_create();
}

// 驱动反初始化
static int driver_uninit(neu_plugin_t *plugin)
{
    GB_12241_device_t *device = neu_plugin_get_data(plugin);
    if (device != NULL) {
        free(device);
    }
    
    // 销毁协议栈
    GB_12241_stack_destroy(plugin);
    
    return 0;
}

// 插件接口定义
static neu_plugin_module_t gb12241_tcp_module = {
    .module_name = "gb12241-tcp",
    .module_info = {
        .slug        = "gb12241-tcp",
        .version     = "0.0.1",
        .description = "GB/T 12241 TCP driver",
        .connection  = "ethernet",
    },
    
    .init        = driver_start,
    .uninit      = driver_stop,
    .start       = driver_start,
    .stop        = driver_stop,
    .setting     = set_callback,
    .request     = GB_12241_encode_request,
    .reply       = GB_12241_handle_response_api,
    .write_req   = GB_12241_encode_request,  // 使用相同的编码函数
    .write_resp  = GB_12241_handle_response_api, // 使用相同的响应处理函数
    .tag_addr    = parse_tag_addr,
    .add_tag     = add_tag,
    .get_point   = NULL,
    .read        = GB_12241_read,
    .write       = GB_12241_write,
    .recv        = GB_12241_tcp_recv,
    .configure   = NULL,
};

// 插件接口导出
neu_plugin_intf_t *neu_plugin_interface()
{
    static neu_plugin_intf_t intf = {
        .name        = "12241-TCP",
        .version     = "1.0.0",
        .description = "12241 TCP Protocol Plugin",
        .funs        = &gb12241_tcp_module,
    };

    return &intf;
}

// 添加读请求点位
static int GB_12241_req_add_read(neu_plugin_t *plugin, 
                               uint8_t device_addr, 
                               uint16_t point_id, 
                               uint8_t func_code, 
                               uint16_t data_len)
{
    // 构建点位地址字符串
    char addr[32] = { 0 };
    snprintf(addr, sizeof(addr), "%u!D%u#BB", device_addr, point_id);
    
    // 使用Neuron的请求添加功能添加点位
    return neu_plugin_group_add_point(plugin, addr, func_code, data_len);
}

// 检查通道是否连接
static bool GB_12241_is_connected(neu_plugin_t *plugin)
{
    // Neuron可能不直接提供通道状态的API，使用以下方式代替
    // 1. 查看是否有socket连接
    void *socket = neu_plugin_get_socket(plugin);
    if (socket == NULL) {
        return false;
    }
    
    // 2. 检查最后通信时间，如果超过一定时间没有通信，认为不在线
    GB_12241_device_t *device = neu_plugin_get_data(plugin);
    uint32_t now = neu_time_ms();
    uint32_t comm_timeout = 30000; // 默认30秒超时
    
    // 如果从未通信，返回false
    if (device->last_class1_time == 0 && device->last_class2_time == 0) {
        return false;
    }
    
    // 使用最近的通信时间
    uint32_t last_comm_time = device->last_class1_time > device->last_class2_time ? 
                             device->last_class1_time : device->last_class2_time;
    
    // 如果最后通信时间太久，认为不在线
    if (now - last_comm_time > comm_timeout) {
        return false;
    }
    
    return true;
}

// 缓存召测命令
static void GB_12241_cache_command(GB_12241_device_t *device, neu_reqresp_head_t *head)
{
    // 检查缓存是否已满
    if (device->cmd_cache.count >= GB_12241_MAX_CACHED_CMDS) {
        plog_warn("Command cache full, dropping oldest command");
        // 移除最旧的命令
        for (int i = 0; i < GB_12241_MAX_CACHED_CMDS - 1; i++) {
            device->cmd_cache.queue[i] = device->cmd_cache.queue[i + 1];
        }
        device->cmd_cache.count--;
    }
    
    // 添加新命令到缓存
    device->cmd_cache.queue[device->cmd_cache.count++] = *head;
    plog_debug("Command cached, total cached commands: %d", device->cmd_cache.count);
}

// 处理缓存的命令
static void GB_12241_process_cached_commands(neu_plugin_t *plugin, GB_12241_device_t *device)
{
    // 如果通道未连接或当前有等待的请求，不处理缓存
    if (!GB_12241_is_connected(plugin) || device->waiting) {
        return;
    }
    
    // 处理排在最前面的命令
    if (device->cmd_cache.count > 0) {
        neu_reqresp_head_t cmd = device->cmd_cache.queue[0];
        
        // 发送命令
        uint8_t buf[GB_12241_MAX_FRAME_SIZE];
        int rc = GB_12241_encode_request(plugin, &cmd, buf, sizeof(buf));
        
        if (rc > 0) {
            // 发送请求
            neu_plugin_send(plugin, buf, rc);
            plog_debug("Sent cached command, type: %d", cmd.type);
            
            // 从缓存中移除已发送的命令
            for (int i = 0; i < device->cmd_cache.count - 1; i++) {
                device->cmd_cache.queue[i] = device->cmd_cache.queue[i + 1];
            }
            device->cmd_cache.count--;
        }
    }
} 