/**
 * NEURON IIoT System for Industry 4.0
 * Copyright (C) 2020-2022 EMQ Technologies Co., Ltd All rights reserved.
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

/* 包含标准库 */
#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Neuron核心头文件 */
#include <neuron.h>
#include <plugin.h>
#include <adapter.h>
#include <tag.h>
#include <utils/log.h>
#include <utils/utarray.h>
#include <utils/utlist.h>
#include <utils/utextend.h>
#include <utils/uthash.h>

/* 包含12241_point.h */
#include "12241_point.h"

/* 结构体前向声明 */
struct neu_plugin_group;
typedef struct neu_plugin_group neu_plugin_group_t;
struct DATA_UNIT_Flag;
/* 定义NEU_UNUSED宏 */
#define NEU_UNUSED(x) (void)(x)

// GB 12241 设备结构体
typedef struct {
    bool             connected;
    bool             waiting;
    uint8_t          seq;
    neu_reqresp_head_t waiting_req;
    UT_array        *cmd_queue;
    int              class1_timeout;
    int              class2_timeout;
    int              check_header;
    int              degrade_enabled;
    int              degrade_cycle;
    int              degrade_time;
    int              max_retries;
    int              retry_interval;
    int              endianess;
    int              address_base;
    int              group_interval;
    uint8_t          tx_code[2];       /* 保存发送功能码，用于校验 */
    void            *plugin;           /* 指向plugin的指针 */
} gb_12241_t;

// 添加连接回调函数定义
void gb_12241_conn_connected(void *data, int fd);
void gb_12241_conn_disconnected(void *data, int fd);
static bool is_valid_string(const char *str);
static const char *get_safe_group_name(neu_plugin_group_t *group);
static uint8_t gb_12241_make_crc(const uint8_t *buf, int16_t count);
// 特殊fn判断
static bool is_special_fn(uint16_t fn);

/* 定义neu_plugin_t结构 */
typedef struct neu_plugin {
    neu_plugin_common_t common;
    
    // 连接管理
    neu_conn_t *conn;
    
    // 设备参数 - 直接存储在plugin中
    bool             connected;
    bool             waiting;
    uint8_t          seq;
    neu_reqresp_head_t waiting_req;
    UT_array        *cmd_queue;
    int              class1_timeout;
    int              class2_timeout;
    int              check_header;
    int              degrade_enabled;
    int              degrade_cycle;
    int              degrade_time;
    int              max_retries;
    int              retry_interval;
    int              endianess;
    int              address_base;
    int              group_interval;
    
    // 组和标签
    UT_array *groups;
    UT_array *tags;
    
    // 状态标志
    bool running;
} neu_plugin_t;

// 获取DA1或DT1低4位的值
static int16_t GetDA1(uint8_t value) {
    switch(value) {
    case 0x01: return 1;
    case 0x02: return 2;
    case 0x04: return 3;
    case 0x08: return 4;
    case 0x10: return 5;
    case 0x20: return 6;
    case 0x40: return 7;
    case 0x80: return 8;
    default:   return 0;
    }
}


/* 函数前向声明 */
static neu_plugin_t *plugin_open(void);
static int plugin_close(neu_plugin_t *plugin);
static int driver_write(neu_plugin_t *plugin, void *req, neu_datatag_t *tag, neu_value_u value);
static int driver_group_timer(neu_plugin_t *plugin, neu_plugin_group_t *group);
static int neu_plugin_send(neu_plugin_t *plugin, neu_reqresp_head_t *head, void *data, size_t len);
static int neu_plugin_update_tag(neu_plugin_t *plugin, const char *group, neu_datatag_t *tag, neu_value_u *value);
static int gb_12241_add_tag_to_group(neu_plugin_t *plugin, const char *group_name, neu_datatag_t *tag);
// 新增函数前向声明
static int gb_12241_get_data_unit_size(uint16_t fn);
static int gb_12241_extract_data_value(neu_plugin_t *plugin, const uint8_t *data, int data_unit_size, 
                                     uint16_t fn, uint8_t data_index, neu_value_u *value);
static int gb_12241_parse_tag_address(neu_plugin_t *plugin, const char *addr_str, 
                                  uint16_t *device_addr, uint16_t *fn, 
                                  uint16_t *pn, uint16_t *data_index);
static int gb_12241_read_group(neu_plugin_t *plugin, neu_plugin_group_t *group);
// static int __attribute__((unused)) gb_12241_extract_value_from_response(neu_plugin_t *plugin, uint8_t *data, size_t data_len, 
//                                                uint16_t fn, uint8_t pn, uint8_t data_index, 
//                                                neu_value_u *value);
static size_t gb_12241_parse_frame(const uint8_t *frame, size_t frame_len, 
                      uint16_t *device_addr, uint8_t *afn, uint8_t *seq, 
                      uint8_t *control_field, uint8_t *data, size_t *data_len);
static int gb_12241_send_and_receive(neu_plugin_t *plugin, const uint8_t *request, size_t request_len, 
                                    uint8_t *response, size_t *response_len);

// GB 12241 帧结构定义
#define GB_12241_FRAME_HEADER_SIZE  17  // 从起始符到数据单元标识结束
#define GB_12241_MIN_FRAME_SIZE     12  // 帧头 + CRC16
#define GB_12241_MAX_FRAME_SIZE     1024
#define GB_12241_START_CODE         0x68
#define GB_12241_END_CODE           0x16

// GB 12241 命令码定义
typedef enum {
    GB_12241_CMD_CLASS1_DATA = 0x01, // 一类数据
    GB_12241_CMD_CLASS2_DATA = 0x02,  // 二类数据
    GB_12241_CMD_READ_TIME   = 0x03,  // 读时间
    GB_12241_CMD_WRITE_TIME  = 0x04,  // 写时间
    GB_12241_CMD_READ_ADDR   = 0x05,  // 读通信地址
    GB_12241_CMD_WRITE_ADDR  = 0x06   // 写通信地址
} GB_12241_cmd_e;

// 链路层帧长度定义
typedef struct {
    uint8_t PFLG:2;     // 协议标识
    uint8_t LUSERL:6;   // 用户数据长度低6位
    uint8_t LUSERH;     // 用户数据长度高8位
} LINK_LEN;

// 控制域
typedef struct {
    uint8_t FC:4;       // 功能码
    uint8_t FCV:1;      // 计数有效位
    uint8_t FCB:1;      // 计数位
    uint8_t PRM:1;      // 启动报文位
    uint8_t DIR:1;      // 方向位
} Sou_ControlField;

typedef struct {
    union {
        Sou_ControlField ControlField;
        uint8_t BControlField;
    } ControlField;
} S_ControlField;

// 地址域
typedef struct {
    uint8_t RA4:4;      // 区号段4
    uint8_t RA3:4;      // 区号段3
    uint8_t RA2:4;      // 区号段2
    uint8_t RA1:4;      // 区号段1
    uint8_t TAL;        // 终端地址低
    uint8_t TAH;        // 终端地址高
    uint8_t GAF:1;      // 终端组地址标志
    uint8_t MSA:7;      // 主站地址
} ADDR;

// 数据单元标识
typedef struct {
    uint8_t DA1;        // 信息点 pn
    uint8_t DA2;        
    uint8_t DT1;        // 信息类 Fn
    uint8_t DT2;        
} DATA_UNIT_Flag;

//static uint8_t gb_12241_dt_to_fn(const DATA_UNIT_Flag *ptDataUnitID, uint16_t *pwFn);
static uint8_t gb_12241_fn_to_dt(DATA_UNIT_Flag *ptDataUnitID, uint16_t wFn);
// 帧序列
typedef struct {
    uint8_t PSEQ:4;     // 启动帧序号
    uint8_t CON:1;      // 请求确认标志位
    uint8_t FIN:1;      // 末帧标志
    uint8_t FIR:1;      // 首帧标志
    uint8_t TpV:1;      // 帧时间标签有效标志
} SEQ;

typedef struct {
    union {
        SEQ     PSEQ;
        uint8_t RSEQ;
    } seq;
} S_SEQ;

// GB 12241 数据类型定义
typedef enum {
    GB_12241_TYPE_UNKNOWN,
    GB_12241_TYPE_INT8,
    GB_12241_TYPE_UINT8,
    GB_12241_TYPE_INT16,
    GB_12241_TYPE_UINT16,
    GB_12241_TYPE_INT32,
    GB_12241_TYPE_UINT32,
    GB_12241_TYPE_FLOAT,
    GB_12241_TYPE_DOUBLE,
    GB_12241_TYPE_STRING,
    GB_12241_TYPE_BOOL,
    GB_12241_TYPE_BIT
} GB_12241_data_type_e;

// GB 12241 字节序
typedef enum {
    GB_12241_BIG_ENDIAN = 0,
    GB_12241_LITTLE_ENDIAN = 1
} GB_12241_endianess;

// GB 12241 地址基准
typedef enum {
    GB_12241_ADDR_BASE_0 = 0,
    GB_12241_ADDR_BASE_1 = 1
} GB_12241_address_base;

// 自定义常量定义
#define GB_12241_FN_DEVICE_STATUS 0x01  // 设备状态功能码

// 帧头结构
#pragma pack(push, 1)
typedef struct {
    uint8_t  start_code[2];  // 起始码 0x68 0x68
    uint8_t  addr_code[4];   // 地址域
    uint8_t  afn;            // 应用功能码
    uint8_t  seq;            // 序列号
} GB_12241_header;

// 地址信息
typedef struct {
    uint16_t  device_addr;    // 设备地址
    uint16_t reg_addr;       // 寄存器地址
    uint8_t  reg_count;      // 寄存器数量，针对连续读取
} GB_12241_address;

// 点位数据
typedef struct {
    GB_12241_data_type_e type;    // 数据类型
    union {
        int8_t   i8;
        uint8_t  u8;
        int16_t  i16;
        uint16_t u16;
        int32_t  i32;
        uint32_t u32;
        float    f32;
        double   d64;
        bool     boolean;
    struct {
            uint8_t *bytes;
            uint16_t length;
        } str;
    struct {
            uint8_t *bytes;
            uint16_t length;
        } bytes;
    } value;
} GB_12241_data;

// 点位结构
typedef struct {
    char                 name[NEU_TAG_NAME_LEN];
    char                 address[NEU_TAG_ADDRESS_LEN];
    GB_12241_address     addr;
    GB_12241_data_type_e type;
    uint16_t             size;
    uint8_t              bit_offset;
    uint8_t              data_index;    // 新增：数据索引，表示读取的第几个数据
} GB_12241_point_t;

// 函数前向声明
static void gb_12241_free_group(neu_plugin_group_t *group);
static int add_tag(neu_plugin_t *plugin, void *req);
static GB_12241_point_t *gb_12241_find_tag(neu_plugin_t *plugin, const char *tag_name);
static int gb_12241_write_tag(neu_plugin_t *plugin, GB_12241_point_t *point, neu_value_u value);
static int gb_12241_read_group(neu_plugin_t *plugin, neu_plugin_group_t *group);
static int gb_12241_send_and_receive(neu_plugin_t *plugin, const uint8_t *request, size_t request_len, 
                                    uint8_t *response, size_t *response_len);
static size_t gb_12241_parse_frame(const uint8_t *frame, size_t frame_len, 
                       uint16_t *device_addr, uint8_t *afn, uint8_t *seq, 
                       uint8_t *control_field, uint8_t *data, size_t *data_len);
static int gb_12241_build_multi_request(neu_plugin_t *plugin, uint8_t *frame, size_t frame_size, 
                               uint16_t device_addr, uint8_t seq, 
                               uint16_t *fn_array, uint16_t *pn_array, int fn_pn_count,
                               size_t *request_length);
// static int gb_12241_extract_value_from_response(neu_plugin_t *plugin, uint8_t *data, size_t data_len, 
//                                               uint16_t fn, uint8_t pn, uint8_t data_index, 
//                                               neu_value_u *value);

static GB_12241_data_type_e gb_12241_neuron_type_to_type(neu_type_e type);
static int driver_start(neu_plugin_t *plugin);
static int driver_stop(neu_plugin_t *plugin);
static int driver_validate_tag(neu_plugin_t *plugin, neu_datatag_t *tag);
static int driver_group_timer(neu_plugin_t *plugin, neu_plugin_group_t *group);

// ==== 实用函数 ====

// CRC校验计算
static uint8_t gb_12241_make_crc(const uint8_t *buf, int16_t count)
{
    uint8_t crc = 0;
    int16_t i;
    
    if (buf == NULL || count <= 0) {
        return 0;
    }
    
    for (i = 0; i < count; i++) {
        crc += buf[i];
    }
    
    return crc;
}

// 从Neuron类型映射到GB12241类型
static GB_12241_data_type_e gb_12241_neuron_type_to_type(neu_type_e type)
{
    switch (type) {
    case NEU_TYPE_BOOL:
        return GB_12241_TYPE_BOOL;
    case NEU_TYPE_INT8:
        return GB_12241_TYPE_INT8;
    case NEU_TYPE_UINT8:
        return GB_12241_TYPE_UINT8;
    case NEU_TYPE_INT16:
        return GB_12241_TYPE_INT16;
    case NEU_TYPE_UINT16:
        return GB_12241_TYPE_UINT16;
    case NEU_TYPE_INT32:
        return GB_12241_TYPE_INT32;
    case NEU_TYPE_UINT32:
        return GB_12241_TYPE_UINT32;
    case NEU_TYPE_FLOAT:
        return GB_12241_TYPE_FLOAT;
    case NEU_TYPE_DOUBLE:
        return GB_12241_TYPE_DOUBLE;
    case NEU_TYPE_STRING:
        return GB_12241_TYPE_STRING;
    case NEU_TYPE_BIT:
        return GB_12241_TYPE_BIT;
    default:
        return GB_12241_TYPE_UNKNOWN;
    }
}

// ==== 插件接口实现 ====

static neu_plugin_t *plugin_open(void)
{
    neu_plugin_t *plugin = calloc(1, sizeof(neu_plugin_t));
    if (plugin == NULL) {
        return NULL;
    }
    
    // 初始化通用部分
    neu_plugin_common_init(&plugin->common);
    
    // 初始化内部状态
    plugin->running = false;
    plugin->connected = false;
    plugin->waiting = false;
    plugin->seq = 0;
    
    // 初始化默认参数值
    plugin->class1_timeout = 10000;
    plugin->class2_timeout = 60000;
    plugin->check_header = 0;
    plugin->degrade_enabled = 0;
    plugin->degrade_cycle = 2;
    plugin->degrade_time = 600;
    plugin->max_retries = 0;
    plugin->retry_interval = 0;
    plugin->endianess = 1;
    plugin->address_base = 0;
    plugin->group_interval = 1000;
    
    return plugin;
}

static int plugin_close(neu_plugin_t *plugin)
{
    if (plugin == NULL) {
        return -1;
    }
    
    // 关闭TCP连接
    if (plugin->conn != NULL) {
        neu_conn_stop(plugin->conn);
        neu_conn_destory(plugin->conn);
    }
    
    // 释放组和标签资源
    if (plugin->groups != NULL) {
        utarray_free(plugin->groups);
    }
    
    if (plugin->tags != NULL) {
        utarray_free(plugin->tags);
    }
    
    free(plugin);
    
    return 0;
}

static int plugin_init(neu_plugin_t *plugin, bool load)
{
    if (plugin == NULL) {
        return -1;
    }
    
    NEU_UNUSED(load);
    
    // 初始化连接为NULL
    plugin->conn = NULL;
    
    // 初始化组和标签
    plugin->groups = NULL;
    plugin->tags = NULL;
    
    utarray_new(plugin->groups, &ut_ptr_icd);
    utarray_new(plugin->tags, &ut_ptr_icd);
    
    // 初始化命令队列
    plugin->cmd_queue = NULL;
    utarray_new(plugin->cmd_queue, &ut_ptr_icd);
    
    return 0;
}

static int plugin_uninit(neu_plugin_t *plugin)
{
    if (plugin == NULL) {
            return -1;
        }

    plugin->running = false;
    
    // 释放连接资源
    if (plugin->conn != NULL) {
        neu_conn_destory(plugin->conn);
        plugin->conn = NULL;
    }
    
    // 释放命令队列
    if (plugin->cmd_queue) {
        utarray_free(plugin->cmd_queue);
        plugin->cmd_queue = NULL;
    }
    
    // 释放组
    if (plugin->groups != NULL) {
        neu_plugin_group_t **group = NULL;
        while ((group = (neu_plugin_group_t **) utarray_next(plugin->groups, group)) != NULL) {
            gb_12241_free_group(*group);
    }
    utarray_free(plugin->groups);
        plugin->groups = NULL;
    }
    
    // 释放标签
    if (plugin->tags != NULL) {
        neu_datatag_t **tag = NULL;
        while ((tag = (neu_datatag_t **) utarray_next(plugin->tags, tag)) != NULL) {
            free(*tag);
    }
    utarray_free(plugin->tags);
        plugin->tags = NULL;
    }
    
    plog_notice(plugin, "插件已卸载");
    
    return 0;
}

static int plugin_start(neu_plugin_t *plugin)
{
    if (plugin == NULL) {
        return -1;
    }
    
    return driver_start(plugin);
}

static int plugin_stop(neu_plugin_t *plugin)
{
    if (plugin == NULL) {
        return -1;
    }
    
    plugin->running = false;
    
    return driver_stop(plugin);
}

static int plugin_config(neu_plugin_t *plugin, const char *config)
{
    if (plugin == NULL || config == NULL) {
        return -1;
    }
    
    int              ret       = 0;
    char *           err_param = NULL;
    neu_json_elem_t  port      = { .name = "port", .t = NEU_JSON_INT };
    neu_json_elem_t  timeout   = { .name = "timeout", .t = NEU_JSON_INT };
    neu_json_elem_t  host      = { .name      = "host",
                             .t         = NEU_JSON_STR,
                             .v.val_str = NULL };
    neu_conn_param_t param = { 0 };
    neu_json_elem_t  class1_timeout = { .name = "class1_timeout", .t = NEU_JSON_INT };
    neu_json_elem_t  class2_timeout = { .name = "class2_timeout", .t = NEU_JSON_INT };
    neu_json_elem_t  connection_mode = { .name = "connection_mode", .t = NEU_JSON_INT };
    neu_json_elem_t  check_header = { .name = "check_header", .t = NEU_JSON_INT };
    neu_json_elem_t  device_degrade = { .name = "device_degrade", .t = NEU_JSON_INT };
    neu_json_elem_t  degrade_cycle = { .name = "degrade_cycle", .t = NEU_JSON_INT };
    neu_json_elem_t  degrade_time = { .name = "degrade_time", .t = NEU_JSON_INT };
    neu_json_elem_t  max_retries = { .name = "max_retries", .t = NEU_JSON_INT };
    neu_json_elem_t  retry_interval = { .name = "retry_interval", .t = NEU_JSON_INT };
    neu_json_elem_t  endianess = { .name = "endianess", .t = NEU_JSON_INT };
    neu_json_elem_t  address_base = { .name = "address_base", .t = NEU_JSON_INT };
    
    // 解析基本参数：host、port、timeout
    ret = neu_parse_param((char *) config, &err_param, 3, &host, &port, &timeout);
    if (ret != 0) {
        plog_error(plugin, "config: %s, decode error: %s", config, err_param);
        free(err_param);
        if (host.v.val_str != NULL) {
            free(host.v.val_str);
        }
        return -1;
    }
    
    // 验证必需参数
    if (host.v.val_str == NULL || port.v.val_int <= 0 || port.v.val_int > 65535) {
        plog_error(plugin, "缺少必需参数或参数无效: host或port");
        if (host.v.val_str != NULL) {
            free(host.v.val_str);
        }
        return -1;
    }
    
    // 解析可选参数
    ret = neu_parse_param((char *) config, &err_param, 1, &connection_mode);
    if (ret != 0) {
        free(err_param);
        connection_mode.v.val_int = 0; // 默认客户端模式
    }
    
    ret = neu_parse_param((char *) config, &err_param, 2, &class1_timeout, &class2_timeout);
    if (ret != 0) {
        free(err_param);
        class1_timeout.v.val_int = 10000; // 默认10秒
        class2_timeout.v.val_int = 60000; // 默认60秒
    }
    
    ret = neu_parse_param((char *) config, &err_param, 1, &check_header);
    if (ret != 0) {
        free(err_param);
        check_header.v.val_int = 0;
    }
    
    ret = neu_parse_param((char *) config, &err_param, 3, &device_degrade, &degrade_cycle, &degrade_time);
    if (ret != 0) {
        free(err_param);
        device_degrade.v.val_int = 0;
        degrade_cycle.v.val_int = 2;
        degrade_time.v.val_int = 600;
    }
    
    ret = neu_parse_param((char *) config, &err_param, 2, &max_retries, &retry_interval);
    if (ret != 0) {
        free(err_param);
        max_retries.v.val_int = 0;
        retry_interval.v.val_int = 0;
    }
    
    ret = neu_parse_param((char *) config, &err_param, 1, &endianess);
    if (ret != 0) {
        free(err_param);
        endianess.v.val_int = 1; // 默认ABCD
    }
    
    ret = neu_parse_param((char *) config, &err_param, 1, &address_base);
    if (ret != 0) {
        free(err_param);
        address_base.v.val_int = 0; // 默认从0开始
    }
    
    // 打印配置信息
    plog_notice(plugin, "配置参数 - host: %s, port: %" PRId64 ", timeout: %" PRId64 " ms", 
                host.v.val_str, port.v.val_int, timeout.v.val_int);
    plog_notice(plugin, "配置参数 - connection_mode: %" PRId64 ", class1_timeout: %" PRId64 " ms, class2_timeout: %" PRId64 " ms", 
                connection_mode.v.val_int, class1_timeout.v.val_int, class2_timeout.v.val_int);
    plog_notice(plugin, "配置参数 - check_header: %" PRId64 ", device_degrade: %" PRId64 "", 
                check_header.v.val_int, device_degrade.v.val_int);
    plog_notice(plugin, "配置参数 - degrade_cycle: %" PRId64 ", degrade_time: %" PRId64 "", 
                degrade_cycle.v.val_int, degrade_time.v.val_int);
    plog_notice(plugin, "配置参数 - max_retries: %" PRId64 ", retry_interval: %" PRId64 "", 
                max_retries.v.val_int, retry_interval.v.val_int);
    plog_notice(plugin, "配置参数 - endianess: %" PRId64 ", address_base: %" PRId64 "", 
                endianess.v.val_int, address_base.v.val_int);
    plog_notice(plugin, "配置参数 - group_interval: 1000 ms");
    
    // 根据连接模式配置连接参数
    param.log = plugin->common.log;
    
    if (connection_mode.v.val_int == 0) {
        // 客户端模式
    param.type = NEU_CONN_TCP_CLIENT;
        param.params.tcp_client.ip = strdup(host.v.val_str);
        param.params.tcp_client.port = port.v.val_int;
        param.params.tcp_client.timeout = timeout.v.val_int;
    
    // 配置或创建连接
    if (plugin->conn != NULL) {
        plugin->conn = neu_conn_reconfig(plugin->conn, &param);
            } else {
        plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
        plugin->conn = neu_conn_new(&param, (void *)plugin, 
                                   gb_12241_conn_connected,
                                   gb_12241_conn_disconnected);
    }
    
    free(param.params.tcp_client.ip);
    } else {
        // 服务器模式
        param.type = NEU_CONN_TCP_SERVER;
        param.params.tcp_server.ip = strdup(host.v.val_str);
        param.params.tcp_server.port = port.v.val_int;
        param.params.tcp_server.timeout = timeout.v.val_int;
        param.params.tcp_server.max_link = 5; // 最大连接数
        param.params.tcp_server.start_listen = NULL; // 暂不支持回调
        param.params.tcp_server.stop_listen = NULL;
        
        // 配置或创建连接
        if (plugin->conn != NULL) {
            plugin->conn = neu_conn_reconfig(plugin->conn, &param);
        } else {
            plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
            plugin->conn = neu_conn_new(&param, (void *)plugin, 
                                      gb_12241_conn_connected,
                                      gb_12241_conn_disconnected);
        }
        
        free(param.params.tcp_server.ip);
    }
    
    // 将所有参数存储到plugin结构
    plugin->class1_timeout = class1_timeout.v.val_int;
    plugin->class2_timeout = class2_timeout.v.val_int;
    plugin->check_header = check_header.v.val_int;
    plugin->degrade_enabled = device_degrade.v.val_int;
    plugin->degrade_cycle = degrade_cycle.v.val_int;
    plugin->degrade_time = degrade_time.v.val_int;
    plugin->max_retries = max_retries.v.val_int;
    plugin->retry_interval = retry_interval.v.val_int;
    plugin->endianess = endianess.v.val_int;
    plugin->address_base = address_base.v.val_int;
    plugin->group_interval = 1000; // 默认值
    
    // 释放资源
    if (host.v.val_str != NULL) {
        free(host.v.val_str);
        host.v.val_str = NULL;
    }
    
    return 0;
}

static int plugin_request(neu_plugin_t *plugin, neu_reqresp_head_t *head, void *data)
{
    if (plugin == NULL || head == NULL) {
        return -1;
    }
    
    plog_debug(plugin, "处理请求: %d", head->type);
    
    int ret = 0;
    
    switch (head->type) {
    case NEU_REQ_ADD_TAG:
        ret = add_tag(plugin, data);
        break;
    case NEU_REQ_UPDATE_TAG:
        plog_warn(plugin, "暂不支持更新标签");
        ret = -1;
        break;
    case NEU_REQ_DEL_TAG:
        plog_warn(plugin, "暂不支持删除标签");
        ret = -1;
        break;
    case NEU_REQ_READ_GROUP:
        {
            neu_req_read_group_t *req = (neu_req_read_group_t *)data;
            bool found = false;
            
            if (req == NULL) {
                return -1;
            }
            
            // 查找组并读取数据
            unsigned int n_groups = utarray_len(plugin->groups);
            
            for (unsigned int i = 0; i < n_groups; i++) {
                neu_plugin_group_t **pp_group = (neu_plugin_group_t **)utarray_eltptr(plugin->groups, i);
                
                if (pp_group != NULL && *pp_group != NULL) {
                    if (strcmp((*pp_group)->group_name, req->group) == 0) {
                        // 读取组
                        plog_debug(plugin, "读取组: %s", req->group);
                        ret = gb_12241_read_group(plugin, *pp_group);
                        found = true;
                        break;
                    }
                }
            }
            
            if (!found) {
                plog_error(plugin, "找不到组: %s", req->group);
                ret = -1;
            }
        }
        break;
    case NEU_REQ_WRITE_TAG:
        {
            neu_req_write_tag_t *req = (neu_req_write_tag_t *)data;
            neu_resp_error_t resp = { 0 };
            
            if (req == NULL) {
                return -1;
            }
            
            // 查找标签
            GB_12241_point_t *point = gb_12241_find_tag(plugin, req->tag);
            
            if (point == NULL) {
                plog_error(plugin, "找不到标签: %s", req->tag);
                resp.error = NEU_ERR_TAG_NOT_EXIST;
                neu_plugin_send(plugin, head, &resp, sizeof(resp));
                return -1;
            }
            
            // 写入标签值
            int result = gb_12241_write_tag(plugin, point, req->value.value);
            
            if (result != 0) {
                plog_error(plugin, "写入标签值失败: %s, 错误: %d", req->tag, result);
                resp.error = NEU_ERR_PLUGIN_WRITE_FAILURE;
            } else {
                resp.error = NEU_ERR_SUCCESS;
            }
            
            // 发送响应
            neu_plugin_send(plugin, head, &resp, sizeof(resp));
            
            // 释放资源
            if (point != NULL) {
            free(point);
            }
        }
        break;
    default:
        plog_warn(plugin, "不支持的请求类型: %d", head->type);
        ret = -1;
        break;
    }
    
    return ret;
}

// 解析标签地址
static int gb_12241_parse_tag_address(neu_plugin_t *plugin, const char *addr_str, 
                                  uint16_t *device_addr, uint16_t *fn, 
                                  uint16_t *pn, uint16_t *data_index)
{
    NEU_UNUSED(plugin);
    
    if (addr_str == NULL) {
        plog_error(plugin, "标签地址为空");
        return -1;
    }
    
    // 地址格式1：device,fn[,pn[,dtype]] - 逗号分隔的旧格式
    // 地址格式2：device!fn[.pn] - 兼容Modbus风格的格式
    // 地址格式3：device!FfnPpn[.x] - 新格式，明确功能码和参数号
    unsigned int dev = 0;
    unsigned int fun = 0;
    unsigned int param = 0;
    unsigned int idx = 0;
    char func_type = 0;
    int ret = 0;
    
    // 首先尝试解析新的FfnPpn[.x]格式
    ret = sscanf(addr_str, "%u!F%uP%u.%u", &dev, &fun, &param, &idx);
    if (ret == 4) {
        *device_addr = (uint16_t)dev;
        *fn = (uint16_t)fun;
        *pn = (uint16_t)param;
        if (data_index) {
            *data_index = (uint8_t)idx;
        }
        plog_notice(plugin, "解析地址成功(新格式4): %s -> 设备号=%u, 功能码=%u, 参数号=%u, 数据索引=%u", 
                  addr_str, dev, fun, param, data_index ? *data_index : 0);
        return 0;
    }
    
    // 尝试解析没有数据索引的新格式
    ret = sscanf(addr_str, "%u!F%uP%u", &dev, &fun, &param);
    if (ret == 3) {
        *device_addr = (uint16_t)dev;
        *fn = (uint16_t)fun;
        *pn = (uint8_t)param;
        if (data_index) {
            *data_index = 0;
        }
        plog_notice(plugin, "解析地址成功(新格式3): %s -> 设备号=%u, 功能码=%u, 参数号=%u, 数据索引=%u", 
                  addr_str, dev, fun, param, data_index ? *data_index : 0);
        return 0;
    }
    
    // 尝试解析逗号分隔的原始格式
    unsigned int dtype = 0;  // 仍然需要这个变量来正确解析格式，但不再使用其值
    ret = sscanf(addr_str, "%u,%u,%u,%u", &dev, &fun, &param, &dtype);
    
    if (ret >= 2) {
        // 逗号格式解析成功
        *device_addr = (uint16_t)dev;
        *fn = (uint16_t)fun;
        if (data_index) {
            *data_index = 0;
        }
    
    // 设置可选参数
    if (ret >= 3) {
        *pn = (uint16_t)param;
    } else {
            *pn = 0;
        }
        
        plog_notice(plugin, "解析地址成功(逗号格式): %s -> 设备号=%u, 功能码=%u, 参数号=%u, 数据索引=%u", 
                  addr_str, dev, fun, *pn, data_index ? *data_index : 0);
        return 0;
    }
    
    // 尝试解析带字母功能码且带参数的格式 (例如 "1!F25.1")
    ret = sscanf(addr_str, "%u!%c%u.%u", &dev, &func_type, &fun, &param);
    if (ret == 4) {
        *device_addr = (uint16_t)dev;
        *fn = (uint16_t)fun;
        *pn = (uint16_t)param;
        if (data_index) {
            *data_index = 0;
        }
        plog_notice(plugin, "解析地址成功(字母格式带参数): %s -> 设备号=%u, 功能码=%u, 参数号=%u, 数据索引=%u", 
                  addr_str, dev, fun, param, data_index ? *data_index : 0);
    return 0;
}

    // 尝试解析带字母功能码的格式 (例如 "1!F25")
    ret = sscanf(addr_str, "%u!%c%u", &dev, &func_type, &fun);
    if (ret == 3) {
        *device_addr = (uint16_t)dev;
        *fn = (uint16_t)fun;
        *pn = 0;
        if (data_index) {
            *data_index = 0;
        }
        plog_notice(plugin, "解析地址成功(字母格式): %s -> 设备号=%u, 功能码=%u, 参数号=%u, 数据索引=%u", 
                  addr_str, dev, fun, *pn, data_index ? *data_index : 0);
        return 0;
    }
    
    // 尝试解析纯数字功能码带参数格式 (例如 "1!25.1")
    ret = sscanf(addr_str, "%u!%u.%u", &dev, &fun, &param);
    if (ret == 3) {
        *device_addr = (uint16_t)dev;
        *fn = (uint16_t)fun;
        *pn = (uint16_t)param;
        if (data_index) {
            *data_index = 0;
        }
        plog_notice(plugin, "解析地址成功(纯数字带参数): %s -> 设备号=%u, 功能码=%u, 参数号=%u, 数据索引=%u", 
                  addr_str, dev, fun, param, data_index ? *data_index : 0);
        return 0;
    }
    
    // 尝试解析纯数字功能码格式 (例如 "1!25")
    ret = sscanf(addr_str, "%u!%u", &dev, &fun);
    if (ret == 2) {
        *device_addr = (uint16_t)dev;
        *fn = (uint16_t)fun;
        *pn = 0;
        if (data_index) {
            *data_index = 0;
        }
        plog_notice(plugin, "解析地址成功(纯数字): %s -> 设备号=%u, 功能码=%u, 参数号=%u, 数据索引=%u", 
                  addr_str, dev, fun, *pn, data_index ? *data_index : 0);
        return 0;
    }
    
    plog_error(plugin, "无效的标签地址格式: %s, 支持格式: 设备号,功能码[,参数[,类型]] 或 设备号!功能码[.参数] 或 设备号!F功能码P参数[.索引]", addr_str);
    return -1;
}

// 查找标签 - 模拟ModbusTCP的实现方式，直接从传入的标签创建点位
static GB_12241_point_t *gb_12241_find_tag(neu_plugin_t *plugin, const char *tag_name)
{
    if (plugin == NULL || tag_name == NULL) {
        return NULL;
    }
    
    // 在组中查找标签
    neu_datatag_t *found_tag = NULL;
    unsigned int n_groups = utarray_len(plugin->groups);
    
    // 遍历所有组
    for (unsigned int i = 0; n_groups > 0 && i < n_groups; i++) {
        neu_plugin_group_t **pp_group = (neu_plugin_group_t **)utarray_eltptr(plugin->groups, i);
        if (pp_group == NULL || *pp_group == NULL) {
            continue;
        }
        
        // 遍历组内所有标签
        neu_plugin_group_t *group = *pp_group;
        utarray_foreach(group->tags, neu_datatag_t *, tag) {
            if (tag && strcmp(tag->name, tag_name) == 0) {
                found_tag = tag;
                break;
            }
        }
        
        if (found_tag) {
            break;
        }
    }
    
    // 如果未找到标签，返回NULL
    if (found_tag == NULL) {
        return NULL;
    }
    
            // 创建点位
    GB_12241_point_t *point = (GB_12241_point_t *)calloc(1, sizeof(GB_12241_point_t));
            if (point == NULL) {
                return NULL;
            }
            
            // 复制名称和地址
    strncpy(point->name, found_tag->name, NEU_TAG_NAME_LEN - 1);
    strncpy(point->address, found_tag->address, NEU_TAG_ADDRESS_LEN - 1);
            
            // 解析地址
            uint16_t device_addr = 0;
            uint16_t fn = 0;
            uint16_t pn = 0;
            uint16_t data_index = 0;
            
            int ret = gb_12241_parse_tag_address(plugin, 
                                found_tag->address, 
                                &device_addr, &fn, &pn, &data_index);
            if (ret != 0) {
                free(point);
                return NULL;
            }
            
            // 设置地址参数
            point->addr.device_addr = device_addr;
            point->addr.reg_addr = fn;
            point->addr.reg_count = 1;
            
            // 设置类型
    point->type = gb_12241_neuron_type_to_type(found_tag->type);
            
            // 设置大小
            point->size = 0;
            
            // 设置位偏移
            point->bit_offset = pn;
            
    // 设置数据索引
    point->data_index = data_index;
    
    return point;
}

// 驱动实现函数
static int driver_validate_tag(neu_plugin_t *plugin, neu_datatag_t *tag)
{
    if (plugin == NULL || tag == NULL) {
        return -1;
    }
    
    plog_debug(plugin, "验证标签: %s, 地址: %s", tag->name, tag->address);
    
    // 解析地址
    uint16_t device_addr = 0;
    uint16_t fn = 0;
    uint16_t pn = 0;
    
    if (gb_12241_parse_tag_address(plugin, tag->address, &device_addr, &fn, &pn, NULL) != 0) {
        return -1;
    }
    
    // 验证数据类型
    GB_12241_data_type_e gb_type = gb_12241_neuron_type_to_type(tag->type);
    if (gb_type == GB_12241_TYPE_UNKNOWN) {
        plog_error(plugin, "不支持的数据类型: %d", tag->type);
        return -1;
    }
    
    // 验证设备地址范围 - 允许0(采集器自身)
    if ((unsigned int)device_addr > 128U) {
        plog_error(plugin, "设备地址超出允许范围(0-128): %d", device_addr);
        return -1;
    }
    
    // 验证功能码范围
    if (fn == 0) {
        plog_error(plugin, "无效的功能码: %d", fn);
        return -1;
    }
    
    return 0;
}

// 读取标签值
static int gb_12241_write_tag(neu_plugin_t *plugin, GB_12241_point_t *point, neu_value_u value)
{
    NEU_UNUSED(value);
    if (plugin == NULL || point == NULL) {
        return -1;
    }
    
    plog_debug(plugin, "写入标签: %s, 地址: %s", point->name, point->address);
    
    // GB/T 12241协议通常是只读的，如果需要支持写入操作，需要实现此功能
    plog_warn(plugin, "写入操作暂不支持: %s", point->name);
    return -1;
}

// 读取组内所有标签
static int gb_12241_read_group(neu_plugin_t *plugin, neu_plugin_group_t *group)
{
    if (plugin == NULL || group == NULL) {
        return -1;
    }
    
    int ret = 0;
    int success_count = 0;
    int error_count = 0;
    int64_t rtt = 0;  // 响应时间
    int total_count = 0; // 总请求数量
    uint64_t read_start_time = neu_time_ms();
    unsigned int tag_count = utarray_len(group->tags);
    const char *safe_group_name = get_safe_group_name(group);
    
    plog_debug((neu_plugin_t *)plugin, "读取组 '%s' 中的 %d 个标签", safe_group_name, tag_count);
    
    // 如果组中没有标签，直接返回
    if (tag_count == 0) {
        plog_debug(plugin, "组 '%s' 中没有标签", safe_group_name);
        return 0;
    }
    
    // 确保TCP连接正常
    if (!neu_conn_is_connected(plugin->conn)) {
        plog_info(plugin, "尝试连接服务器...");
        neu_conn_connect(plugin->conn);
        
        if (!neu_conn_is_connected(plugin->conn)) {
            plog_error(plugin, "连接服务器失败，无法读取组: '%s'", safe_group_name);
        return -1;
        }
    }
    
    // 1. 遍历标签，按设备地址和FN+PN进行分组，最多4个FN+PN一组
    typedef struct {
        uint16_t device_addr;
        uint16_t fn;
        uint16_t pn;
        uint16_t data_index;
        bool processed;
    } tag_key_t;
    
    tag_key_t *tag_keys = (tag_key_t *)malloc(tag_count * sizeof(tag_key_t));
    if (tag_keys == NULL) {
        plog_error(plugin, "内存分配失败");
        // 释放之前分配的内存
        free(tag_keys);
        return -1;
    }
    
    memset(tag_keys, 0, tag_count * sizeof(tag_key_t));
    
    // 创建设备地址集合
    uint16_t unique_devices[tag_count];
    int unique_device_count = 0;
    
    // 提取所有标签的设备地址、FN和PN，同时收集唯一设备地址
    int tag_idx = 0;
    utarray_foreach(group->tags, neu_datatag_t *, tag) {
        // 解析标签地址
        uint16_t device_addr = 0;
        uint16_t fn = 0;
        uint16_t pn = 0;
        uint16_t data_index = 0;
        
        if (gb_12241_parse_tag_address(plugin, tag->address, 
                                     &device_addr, &fn, &pn, &data_index) != 0) {
            plog_error(plugin, "无法解析标签地址: %s", tag->address);
            continue;
        }
        
        // 保存解析结果
        tag_keys[tag_idx].device_addr = device_addr;
        tag_keys[tag_idx].fn = fn;
        tag_keys[tag_idx].pn = pn;
        tag_keys[tag_idx].data_index = data_index;
        tag_keys[tag_idx].processed = false;
        tag_idx++;
        
        // 检查是否是新的设备地址，如果是则添加到唯一设备列表
        bool device_exists = false;
        for (int j = 0; j < unique_device_count; j++) {
            if (unique_devices[j] == device_addr) {
                device_exists = true;
                break;
            }
        }
        
        if (!device_exists) {
            unique_devices[unique_device_count++] = device_addr;
        }
    }
    
    plog_debug(plugin, "解析成功 %d 个标签，检测到 %d 个唯一设备地址", tag_idx, unique_device_count);
    
    // 2. 按设备地址分组，每组最多4个FN+PN
    const int max_fn_per_request = 4;  // 每个请求最多包含4个FN+PN
    
    // 只处理实际存在的设备
    for (int i = 0; i < unique_device_count; i++) {
        uint16_t current_device = unique_devices[i];
        
        // 处理当前设备的标签，每批最多max_fn_per_request个FN+PN
        while (true) {
            uint16_t fn_array[max_fn_per_request];
            uint16_t pn_array[max_fn_per_request];
            int batch_size = 0;
            bool has_special_fn = false;
            
            // 收集一批未处理的FN+PN
            for (unsigned int tag_idx_loop = 0; tag_idx_loop < tag_count && batch_size < max_fn_per_request; tag_idx_loop++) {
                if (tag_keys[tag_idx_loop].device_addr == current_device && !tag_keys[tag_idx_loop].processed) {
                    // 检查是否是特殊功能码
                    bool current_is_special = is_special_fn(tag_keys[tag_idx_loop].fn);
                    
                    // 如果当前批次已有特殊功能码或当前是特殊功能码但批次已有其他功能码，则跳过
                    if ((has_special_fn || current_is_special) && batch_size > 0) {
                        continue;
                    }
                    
                    // 检查此FN+PN是否已在批次中
                    bool already_in_batch = false;
                    for (int j = 0; j < batch_size; j++) {
                        if (fn_array[j] == tag_keys[tag_idx_loop].fn && pn_array[j] == tag_keys[tag_idx_loop].pn) {
                            already_in_batch = true;
                            break;
                        }
                    }
                    
                    if (!already_in_batch) {
                        fn_array[batch_size] = tag_keys[tag_idx_loop].fn;
                        pn_array[batch_size] = tag_keys[tag_idx_loop].pn;
                        batch_size++;
                    
                        // 如果是特殊功能码，标记并在添加后立即退出循环
                        if (current_is_special) {
                            has_special_fn = true;
                            plog_debug(plugin, "检测到特殊功能码 FN=%d，将单独发送", tag_keys[tag_idx_loop].fn);
                    // 标记为已处理
                            tag_keys[tag_idx_loop].processed = true; // Mark as processed immediately for special FN
                            break;  // 特殊功能码只能单独发送，所以找到一个后就退出循环
                        }
                    }
                    
                    // 标记为已处理 (非特殊功能码)
                    if (!has_special_fn) { // Only mark if we didn't break due to special FN
                       tag_keys[tag_idx_loop].processed = true;
                    }
                }
            }
            
            if (batch_size == 0) {
                break;  // 没有更多未处理的标签
            }
            
            // 构建请求（统一使用多FN请求函数）
            uint8_t request[1024];  // 请求缓冲区
            uint8_t response[2048]; // 响应缓冲区
            size_t request_len = 0;
            size_t response_len = sizeof(response);
            int build_ret = 0;
            
            // 统一使用多功能码请求构建函数，即使只有一个FN（特殊功能码）
            build_ret = gb_12241_build_multi_request(plugin, request, sizeof(request),
                                                       current_device, plugin->seq++, 
                                                   fn_array, pn_array, batch_size, // batch_size will be 1 for special FNs
                                                       &request_len);
            
            // 添加日志区分单/多FN请求
            if (has_special_fn && batch_size == 1) {
                 plog_debug(plugin, "为特殊功能码 FN=%d 构建单独请求 (使用multi_request)", fn_array[0]);
            } else {
                 plog_debug(plugin, "为普通功能码构建批量请求 (batch_size=%d)", batch_size);
            }

            if (build_ret != 0) {
                plog_error(plugin, "构建请求失败，设备 %d，批次 %d", current_device, total_count);
                // Mark tags in this failed batch as unprocessed? Needs consideration.
                // For now, continue to next batch.
                continue;
            }
            
            // 统计信息更新 - 使用连接状态而非直接更新字段
            total_count++;
            uint64_t send_time = neu_time_ms();
            
            // 发送请求并接收响应
            ret = gb_12241_send_and_receive(plugin, request, request_len, response, &response_len);
            if (ret != 0) {
                plog_error(plugin, "读取组数据失败，设备 %d，批次 %d，错误码 %d", current_device, total_count-1, ret);
                // Mark tags in this failed batch as unprocessed? Needs consideration.
                continue;
            }
            
            // 将回复帧以十六进制格式输出
            char hex_buffer[10240] = {0};
            for (size_t i = 0; i < response_len && (i * 3 < sizeof(hex_buffer) - 3); i++) {
                char temp[4];
                snprintf(temp, sizeof(temp), "%02X ", response[i]);
                strcat(hex_buffer, temp);
            }
            plog_notice(plugin, "回复帧(HEX): %s", hex_buffer);


            // 统计信息更新 - 使用连接状态而非直接更新字段
            success_count++;
            uint64_t recv_time = neu_time_ms();
            rtt += (recv_time - send_time);
            
            // 解析响应
            uint16_t resp_device_addr = 0;
            uint8_t afn = 0;
            uint8_t seq = 0;
            uint8_t control_field = 0; // 新增：用于接收控制域
            uint8_t data[512] = {0};
            size_t data_len = sizeof(data);
            
            size_t frame_size = gb_12241_parse_frame(response, response_len, 
                                                   &resp_device_addr, &afn, &seq, 
                                                   &control_field, // 新增：传入控制域参数
                                                   data, &data_len);

            // 将响应帧以十六进制格式输出
            if (frame_size <= 0 || resp_device_addr != current_device) {
                plog_error(plugin, "解析响应帧失败或设备地址不匹配");
            continue;
        }
        
            // 将响应帧以十六进制格式输出
            char hex_data_buffer[10240] = {0};
            for (size_t i = 0; i < data_len && (i * 3 < sizeof(hex_data_buffer) - 3); i++) {
                char temp[4];
                snprintf(temp, sizeof(temp), "%02X ", data[i]);
                strcat(hex_data_buffer, temp);
            }
            plog_notice(plugin, "用户数据(HEX): %s", hex_data_buffer);

            // 检查AFN和控制域功能码
            S_ControlField ctrl_field;
            ctrl_field.ControlField.BControlField = control_field;
            bool is_valid_response = false;
            
            // 有效响应包括：
            // 1. 请求一类数据的正常响应(AFN_REQUESTONEDATA)
            // 2. 肯定/否认应答(AFN_ACK)且功能码为响应用户数据(RESPONSEUSERDATA)或无数据(NODATA)
            if (afn == AFN_REQUESTONEDATA) {
                plog_debug(plugin, "收到一类数据响应(AFN=0x%02X)", afn);
                is_valid_response = true;
            } else if (afn == AFN_ACK) {
                if (ctrl_field.ControlField.ControlField.FC == RESPONSEUSERDATA) {
                    plog_notice(plugin, "收到确认/否认应答，设备返回用户数据,设备无数据(AFN=0x%02X, FC=0x%02X,resp_device_addr=%d,FN=%d,PN=%d)",
                              afn, ctrl_field.ControlField.ControlField.FC,resp_device_addr,fn_array[0],pn_array[0]);
                    is_valid_response = false;
                } else if (ctrl_field.ControlField.ControlField.FC == NODATA) {
                    plog_notice(plugin, "收到确认/否认应答，但设备无数据(AFN=0x%02X, FC=0x%02X)",
                              afn, ctrl_field.ControlField.ControlField.FC);
                    is_valid_response = false;
                } else {
                    plog_notice(plugin, "收到确认/否认应答，但功能码不正确(AFN=0x%02X, FC=0x%02X)",
                              afn, ctrl_field.ControlField.ControlField.FC);
                    is_valid_response = false;
                }
            } else {
                plog_error(plugin, "收到未知响应类型,不做解析(AFN=0x%02X, FC=0x%02X)",
                          afn, ctrl_field.ControlField.ControlField.FC);
                continue;
            }
            
            if (!is_valid_response) {
                continue;
            }

            // 处理响应数据，更新每个标签的值 - 优化版本
            int tags_updated = 0;
            uint8_t *current_pos = data;
            size_t remaining_len = data_len;
            
            // 跳过AFN(1字节)和SEQ(1字节)，因为gb_12241_parse_frame并没有分离它们
            if (remaining_len >= 2) {
                // 直接使用结构体解析SEQ字节
                S_SEQ seq_struct;
                seq_struct.seq.RSEQ = current_pos[1]; // 将SEQ字节加载到结构体
                
                // 使用结构体访问TpV位
                bool tpv_valid = seq_struct.seq.PSEQ.TpV == 1;
                
                plog_debug(plugin, "跳过AFN(%02X)和SEQ(%02X)字节，TpV=%d", 
                          current_pos[0], current_pos[1], tpv_valid ? 1 : 0);
                current_pos += 2;
                remaining_len -= 2;
                
                // 使用从帧解析获取的控制域
                bool fcb_valid = ctrl_field.ControlField.ControlField.FCB == 1;
                
                plog_debug(plugin, "控制域=%02X, FCB=%d", control_field, fcb_valid ? 1 : 0);
                
                // 根据帧结构知识，检查是否有尾部附加信息
                if (remaining_len > 0) {
                    // 如果有附加信息需要跳过处理
                    size_t tail_bytes = 0;
                    
                    // FCB有效时，有2字节附加信息
                    if (fcb_valid) {
                        tail_bytes += 2;
                        plog_debug(plugin, "帧中FCB有效，尾部有2字节附加信息");
                    }
                    
                    // TpV有效时，有6字节时间标签
                    if (tpv_valid) {
                        tail_bytes += 6;
                        plog_debug(plugin, "帧中TpV有效，尾部有6字节时间标签");
                    }
                    
                    // 确保不溢出
                    if (tail_bytes > 0 && tail_bytes < remaining_len) {
                        // 调整有效数据长度，排除尾部附加信息
                        remaining_len -= tail_bytes;
                        plog_debug(plugin, "调整有效数据长度，排除%zu字节尾部附加信息", tail_bytes);
                    }
                }
            } else {
                plog_error(plugin, "数据长度不足，无法跳过AFN和SEQ");
            continue;
        }
        
            // 创建设备地址->FN->PN->data_index->tag映射，用于快速查找匹配的标签
            typedef struct {
                uint16_t  device_addr;
                uint16_t fn;
                uint16_t  pn;
                uint16_t  data_index;
                neu_datatag_t *tag;
            } tag_map_entry_t;
            
            // 预先解析所有标签的地址信息，避免重复解析
            tag_map_entry_t *tag_map = (tag_map_entry_t *)malloc(utarray_len(group->tags) * sizeof(tag_map_entry_t));
            if (!tag_map) {
                plog_error(plugin, "内存分配失败");
                // 释放之前分配的内存
                free(tag_keys);
                continue;
            }
            
            int map_size = 0;
            utarray_foreach(group->tags, neu_datatag_t *, tag) {
                uint16_t tag_device_addr;
                uint16_t tag_fn;
                uint16_t tag_pn;
                uint16_t data_index;
                
                if (gb_12241_parse_tag_address(plugin, tag->address, 
                                             &tag_device_addr, &tag_fn, &tag_pn, &data_index) == 0) {
                    // 只添加当前设备的标签
                    if (tag_device_addr == current_device) {
                        tag_map[map_size].device_addr = tag_device_addr;
                        tag_map[map_size].fn = tag_fn;
                        tag_map[map_size].pn = tag_pn;
                        tag_map[map_size].data_index = data_index;
                        tag_map[map_size].tag = tag;
                        map_size++;
                    }
                }
            }
            
            plog_debug(plugin, "创建设备%d的标签映射表，共%d个标签", current_device, map_size);
            
            // 循环解析数据单元标识和数据单元
            while (remaining_len >= sizeof(DATA_UNIT_Flag)) {
                DATA_UNIT_Flag data_unitf = {0};
                
                // 1. 获取数据单元标识
                memcpy(&data_unitf, current_pos, sizeof(DATA_UNIT_Flag));
                current_pos += sizeof(DATA_UNIT_Flag);
                remaining_len -= sizeof(DATA_UNIT_Flag);
                
                // 2. 计算实际的pn和fn值 //如果DA1==0x00,DA2==0x00,则PN=0

                uint16_t recv_pn = (data_unitf.DA1 == 0x00 && data_unitf.DA2 == 0x00) ? 0 : (GetDA1(data_unitf.DA1) + (data_unitf.DA2 - 1) * 8);
                uint16_t recv_fn = GetDA1(data_unitf.DT1) + (data_unitf.DT2) * 8;
                
                plog_notice(plugin, "解析数据单元标识: PN=%d, FN=%u", recv_pn, recv_fn);
                
                // 3. 获取数据单元的大小
                int data_unit_size = is_special_fn(recv_fn) ? (int)remaining_len : gb_12241_get_data_unit_size(recv_fn);
                
                // 检查数据单元大小的有效性
                if (data_unit_size == -1) {
                    plog_warn(plugin, "收到未知大小的功能码 FN=%u 的响应，停止解析此帧的剩余数据。", recv_fn);
                    break; // 未知大小，退出循环
                }
                
                if (remaining_len < (size_t)data_unit_size) {
                    plog_error(plugin, "数据单元(FN=%u)所需数据不足: 需要 %d 字节, 剩余 %zu 字节", 
                             recv_fn, data_unit_size, remaining_len);
                    break; // 数据不足，退出循环
                }
                // 特殊功能码的调试信息
                if (is_special_fn(recv_fn)) {
                    plog_debug(plugin, "检测到特殊功能码 FN=%u，数据单元大小设为剩余长度 %d", recv_fn, data_unit_size);
                }
                
                // 4. 直接查找所有匹配的标签并更新它们
                for (int i = 0; i < map_size; i++) {
                    // 只处理匹配当前数据单元的标签
                    if (tag_map[i].fn == recv_fn && tag_map[i].pn == recv_pn) {
                        neu_datatag_t *tag = tag_map[i].tag;
                        uint8_t data_index = tag_map[i].data_index;
                        
                        // 5. 直接从当前位置提取数据值
                        neu_value_u extracted_value = {0};
                        if (gb_12241_extract_data_value(plugin, current_pos, data_unit_size, 
                                                      recv_fn, data_index, &extracted_value) == 0) {
                            // 6. 转换为正确的标签类型
                            neu_value_u tag_value = {0};
                            switch (tag->type) {
                                case NEU_TYPE_BOOL:
                                    if (extracted_value.u8 == 0xEE) {
                                        tag_value.u8 = 0xEE; // 保留无效数据标记
    } else {
                                        tag_value.boolean = extracted_value.boolean;
                                    }
                                    break;
                                case NEU_TYPE_INT8:
                                    if (extracted_value.u8 == 0xEE) {
                                        tag_value.u8 = 0xEE;
                                    } else {
                                        tag_value.i8 = (int8_t)extracted_value.f32;
                                    }
                                    break;
                                case NEU_TYPE_UINT8:
                                    if (extracted_value.u8 == 0xEE) {
                                        tag_value.u8 = 0xEE;
                                    } else {
                                        tag_value.u8 = (uint8_t)extracted_value.f32;
                                    }
                                    break;
                                case NEU_TYPE_INT16:
                                    if (extracted_value.u8 == 0xEE) {
                                        tag_value.u8 = 0xEE;
                                    } else {
                                        tag_value.i16 = (int16_t)extracted_value.f32;
                                    }
                                    break;
                                case NEU_TYPE_UINT16:
                                    if (extracted_value.u8 == 0xEE) {
                                        tag_value.u8 = 0xEE;
                                    } else {
                                        tag_value.u16 = (uint16_t)extracted_value.f32;
                                    }
                                    break;
                                case NEU_TYPE_INT32:
                                    if (extracted_value.u8 == 0xEE) {
                                        tag_value.u8 = 0xEE;
                                    } else {
                                        tag_value.i32 = (int32_t)extracted_value.f32;
                                    }
                                    break;
                                case NEU_TYPE_UINT32:
                                    if (extracted_value.u8 == 0xEE) {
                                        tag_value.u8 = 0xEE;
                                    } else {
                                        tag_value.u32 = (uint32_t)extracted_value.f32;
                                    }
                                    break;
                                case NEU_TYPE_INT64:
                                    if (extracted_value.u8 == 0xEE) {
                                        tag_value.u8 = 0xEE;
                                    } else {
                                        tag_value.i64 = (int64_t)extracted_value.f32;
                                    }
                                    break;
                                case NEU_TYPE_UINT64:
                                    if (extracted_value.u8 == 0xEE) {
                                        tag_value.u8 = 0xEE;
                                    } else {
                                        tag_value.u64 = (uint64_t)extracted_value.f32;
                                    }
                                    break;
                                case NEU_TYPE_FLOAT:
                                    if (extracted_value.u8 == 0xEE) {
                                        tag_value.u8 = 0xEE;
                                    } else {
                                        tag_value.f32 = extracted_value.f32;
                                    }
                                    break;
                                case NEU_TYPE_DOUBLE:
                                    if (extracted_value.u8 == 0xEE) {
                                        tag_value.u8 = 0xEE;
                                    } else {
                                        tag_value.d64 = (double)extracted_value.d64;
                                    }
                                    break;
                                case NEU_TYPE_STRING:
                                    // 字符串类型需要特殊处理
                                    if (extracted_value.u8 == 0xEE) {
                                        snprintf(tag_value.str, sizeof(tag_value.str), "无效");
                                    } else {
                                        snprintf(tag_value.str, sizeof(tag_value.str), "%.2f", extracted_value.f32);
                                    }
                                    break;
                                default:
                                    // 对于其他类型，直接复制
                                    memcpy(&tag_value, &extracted_value, sizeof(neu_value_u));
                                    break;
                            }
                            
                            // 7. 更新标签值
                            neu_plugin_update_tag(plugin, group->group_name, tag, &tag_value);
                            tags_updated++;
                        }
                    }
                }
                
                // 8. 移动到下一个数据单元
                current_pos += data_unit_size;
                remaining_len -= data_unit_size;
            }
            
            free(tag_map);
            plog_notice(plugin, "设备%d响应处理完成，更新了%d个标签值", current_device, tags_updated);

            // 不需要再遍历每个标签进行更新，上面的循环已经完成所有更新
        }
    }
    
    free(tag_keys);
    
    // 更新指标 - 使用metrics API
    if (plugin->common.adapter_callbacks->update_metric) {
        neu_conn_state_t state = neu_conn_state(plugin->conn);
        
        plugin->common.adapter_callbacks->update_metric(
            plugin->common.adapter, NEU_METRIC_SEND_BYTES, state.send_bytes, NULL);
        plugin->common.adapter_callbacks->update_metric(
            plugin->common.adapter, NEU_METRIC_RECV_BYTES, state.recv_bytes, NULL);
        
        // 更新RTT指标
        if (success_count > 0) {
            rtt = rtt / success_count;  // 计算平均RTT
            plugin->common.adapter_callbacks->update_metric(
                plugin->common.adapter, NEU_METRIC_LAST_RTT_MS, rtt, NULL);
        }
        
        // 更新组发送消息指标
        plugin->common.adapter_callbacks->update_metric(
            plugin->common.adapter, NEU_METRIC_GROUP_LAST_SEND_MSGS, tag_count, safe_group_name);
    }
    
    // 如果所有点都读取失败，更新连接状态为断开
    if (success_count == 0 && error_count > 0) {
        plog_warn(plugin, "组 '%s' 中所有标签读取失败，更新连接状态为断开", safe_group_name);
        //plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
    }
    
    // 计算总耗时
    uint64_t total_time_ms = neu_time_ms() - read_start_time;
    
    plog_debug((neu_plugin_t *)plugin, "组 '%s' 成功读取 %d/%d 帧，失败 %d 帧，成功率 %.2f%%，耗时 %llu ms", 
              safe_group_name, success_count, total_count, total_count - success_count, 
              total_count > 0 ? ((float)success_count / total_count * 100.0f) : 0.0f,
              (unsigned long long)total_time_ms);
    
    return (success_count > 0) ? 0 : -1;
}

// 驱动启动函数
static int driver_start(neu_plugin_t *plugin)
{
    if (plugin == NULL) {
        return -1;
    }
    
    plog_info(plugin, "启动GB/T 12241 TCP驱动");
    
    plugin->running = true;
    
    // 初始化连接状态为断开
    plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
    
    // 开始连接
    neu_conn_start(plugin->conn);
    
    // 尝试主动连接服务器
    if (!neu_conn_is_connected(plugin->conn)) {
        plog_info(plugin, "尝试连接服务器...");
        neu_conn_connect(plugin->conn);
        
        if (neu_conn_is_connected(plugin->conn)) {
            plog_info(plugin, "启动时连接服务器成功");
        } else {
            plog_warn(plugin, "启动时连接服务器失败，将在后续自动重试");
        }
    }
    
    return 0;
}

// 驱动停止函数
static int driver_stop(neu_plugin_t *plugin)
{
    if (plugin == NULL) {
        return -1;
    }
    
    plog_info(plugin, "停止GB/T 12241 TCP驱动");
    
    plugin->running = false;
    
    // 断开连接并更新状态
    if (neu_conn_is_connected(plugin->conn)) {
        plog_info(plugin, "停止时断开服务器连接");
        plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
    }
    
    // 停止连接
    neu_conn_stop(plugin->conn);
    
    return 0;
}

// 添加标签函数(处理NEU_REQ_ADD_TAG请求)
static int add_tag(neu_plugin_t *plugin, void *req)
{
    neu_req_add_tag_t *add_req = (neu_req_add_tag_t *)req;
    
    if (plugin == NULL || add_req == NULL) {
        return -1;
    }
    
    plog_info(plugin, "添加标签到组 '%s'", add_req->group);
    
    // 遍历所有要添加的标签
    for (int i = 0; i < add_req->n_tag; i++) {
        neu_datatag_t *tag = &add_req->tags[i];
        
        // 验证标签
        if (driver_validate_tag(plugin, tag) != 0) {
            plog_error(plugin, "标签验证失败: %s", tag->name);
            continue;
        }
        
        // 添加到组
        gb_12241_add_tag_to_group(plugin, add_req->group, tag);
    }
    
    return 0;
}

// GB/T 12241帧解析函数
static size_t gb_12241_parse_frame(const uint8_t *frame, size_t frame_len, 
                      uint16_t *device_addr, uint8_t *afn, uint8_t *seq, 
                      uint8_t *control_field, uint8_t *data, size_t *data_len) {
    if (frame == NULL || frame_len < 14) {  // 最小帧长度：帧头(6) + 数据头(6) + 帧尾(2) = 14
        return 0;
    }

    // 检查帧头
    if (frame[0] != 0x68 || frame[5] != 0x68) {
        return 0;
    }

    // 解析长度字段
    LINK_LEN link_len;
    memcpy(&link_len, &frame[1], sizeof(LINK_LEN));
    size_t user_data_len = ((uint16_t)link_len.LUSERH << 6) | link_len.LUSERL;

    // 计算总长度：用户数据长度 + 8字节固定头部
    size_t total_len = user_data_len + 8;

    // 检查长度一致性
    if (frame_len < total_len) {
        return 0;
    }

    // 检查结束符
    if (frame[total_len - 1] != 0x16) {
        return 0;
    }

    // 计算校验和
    uint8_t checksum = 0;
    for (size_t i = 6; i < total_len - 2; i++) {
        checksum += frame[i];
    }

    // 验证校验和
    if (frame[total_len - 2] != checksum) {
    return 0;
}

    // 提取设备地址
    if (device_addr != NULL) {
        ADDR addr;
        memcpy(&addr, &frame[7], sizeof(ADDR));
        *device_addr = addr.TAL | (addr.TAH << 8);
    }

    // 提取应用功能码和序列号
    if (afn != NULL) {
        *afn = frame[12];  // 从第13字节开始
    }

    if (seq != NULL) {
        *seq = frame[13];  // 从第14字节开始
    }

    // 提取用户数据 - 从应用功能码(AFN)开始提取
    if (data != NULL && data_len != NULL) {
        // 应用层数据从AFN开始
        size_t copy_len = user_data_len - 1- 5; //先减去控制区和地址域才是应用层数据，是以APN和SEQ为起始的
        if (copy_len > *data_len) {
            copy_len = *data_len;
        }
        
        // 复制包括AFN和SEQ在内的所有用户数据
        memcpy(data, &frame[12], copy_len);
        *data_len = copy_len;
    }

    // 添加控制域提取代码，从第6个字节提取
    if (control_field != NULL) {
        // 控制域在帧的第6个字节
        *control_field = frame[6]; // 按照用户指定的位置
    }

    return total_len;
}

// 构建Class1请求帧
static inline int gb_12241_build_class1_request(neu_plugin_t *plugin, uint8_t *frame, size_t frame_size, 
                               uint16_t device_addr, uint8_t seq, 
                               uint16_t fn, uint16_t pn,
                               size_t *request_length)
{
    uint8_t *buf;
    uint16_t user_data_len = 0;
    S_ControlField ctrl;
    S_SEQ frame_seq;
    LINK_LEN link_len = {0};
    DATA_UNIT_Flag dataunitf;
    ADDR addr = {0};  /* 初始化地址结构体 */
    
    /* 检查参数 */
    if (plugin == NULL || frame == NULL || frame_size < 14 || request_length == NULL) {
        return -1;
    }

    /* 添加调试日志 */
    plog_debug(plugin, "构建请求帧: 设备地址=%u, 功能码=%u, 参数号=%u", 
              device_addr, fn, pn);
    
    /* 初始化 */
    buf = frame;
    
    /* 1. 帧起始符 */
    *buf = 0x68;
    buf += 1;
    
    /* 2. 预留长度字段空间 */
    buf += 4;
    
    /* 3. 重复帧起始符 */
    *buf = 0x68;
    buf += 1;
    
    /* 4. 控制域 */
    ctrl.ControlField.ControlField.DIR = 0;         /* 方向位(主站发出=0) */
    ctrl.ControlField.ControlField.PRM = 1;         /* 启动位(主站发出=1) */
    ctrl.ControlField.ControlField.FCB = 1;         /* 帧计数位 */
    ctrl.ControlField.ControlField.FCV = 0;         /* 帧计数有效位 */
    ctrl.ControlField.ControlField.FC = REQUESTTWODATA; /* 功能码 */
    
    *buf = ctrl.ControlField.BControlField;
    buf += 1;
    user_data_len += 1;  /* 控制域长度 */
    
    /* 5. 地址域 - 使用ADDR结构体 */
    addr.TAH = device_addr / 256;    /* 终端地址高字节 */
    addr.TAL = device_addr % 256;    /* 终端地址低字节 */
    addr.GAF = 0;                    /* 终端组地址标志 */
    addr.MSA = 1;                    /* 主站地址 */
    addr.RA1 = 0;                    /* 区域码1 */
    addr.RA2 = 0;                    /* 区域码2 */
    addr.RA3 = 0;                    /* 区域码3 */
    addr.RA4 = 0;                    /* 区域码4 */
    
    memcpy(buf, &addr, 5);
    buf += 5;
    user_data_len += 5;  /* 地址域长度 */
    
    /* 6. 应用功能码 */
    *buf = AFN_REQUESTONEDATA;
    buf += 1;
    user_data_len += 1;  /* 应用功能码长度 */
    
    /* 7. 帧序列域 */
    memset(&frame_seq, 0, sizeof(S_SEQ));
    frame_seq.seq.PSEQ.PSEQ = seq & 0x0F;  /* 序列号 */
    frame_seq.seq.PSEQ.CON = 1;            /* 需要确认 */
    frame_seq.seq.PSEQ.FIN = 1;            /* 末帧标志 */
    frame_seq.seq.PSEQ.FIR = 1;            /* 首帧标志 */
    frame_seq.seq.PSEQ.TpV = 0;            /* 帧时间标签无效 */
    
    memcpy(buf++, &frame_seq.seq.RSEQ, 1); /* 使用与C++代码相同的方式 */
    user_data_len += 1;  /* 帧序列域长度 */
    
    /* 8. 数据单元标识 */
    /* 设置数据单元标识 */
    if (pn == 0) {
        dataunitf.DA1 = 0x00;
        dataunitf.DA2 = 0x00;
    } else {
       dataunitf.DA1 = 0x01 << ((pn - 1) % 8);
        dataunitf.DA2 = (pn - 1) / 8 + 1;
    }
    
    /* 设置功能码 */
    gb_12241_fn_to_dt(&dataunitf, fn);
    
    /* 复制数据单元标识 */
    memcpy(buf, &dataunitf, 4);
    buf += 4;
    user_data_len += 4;
    
    /* 检查用户数据长度是否合法 */
    if (user_data_len > 2047) {  /* 最大支持2047字节(0x7FF) */
        plog_error(plugin, "用户数据长度超出限制: %u", user_data_len);
        return -1;
    }
    
    /* 检查缓冲区溢出 */
    size_t needed_size = (size_t)(buf - frame) + 2;  /* 加上校验和和结束符 */
    if (needed_size > frame_size) {
        plog_error(plugin, "缓冲区溢出: 需要%zu字节, 但只有%zu字节可用", 
                  needed_size, frame_size);
            return -1;
        }
    
    /* 9. 设置长度域 */
    link_len.PFLG = 0x01;                          /* 协议标识 */
    link_len.LUSERL = user_data_len & 0x3F;        /* 用户数据长度低6位 */
    link_len.LUSERH = (user_data_len >> 6) & 0xFF; /* 用户数据长度高8位，限制在8位 */
    
    /* 验证计算的长度是否正确 */
    uint16_t calc_len = ((uint16_t)link_len.LUSERH << 6) | link_len.LUSERL;
    if (calc_len != user_data_len) {
        plog_error(plugin, "长度计算错误: 预期=%u, 实际=%u", user_data_len, calc_len);
        return -1;  /* 长度计算错误 */
    }
    
    /* 复制长度域到预留位置 */
    memcpy(frame + 1, &link_len, 2);
    memcpy(frame + 3, &link_len, 2);
    
    /* 10. 计算校验和 */
    *buf = gb_12241_make_crc(&frame[6], user_data_len);
    buf += 1;
    
    /* 11. 结束符 */
    *buf = 0x16;
    buf += 1;
    
    /* 设置请求长度 */
    *request_length = (size_t)(buf - frame);

    /* 添加调试日志 */
    plog_debug(plugin, "请求帧构建完成: 总长度=%zu, 用户数据长度=%u", 
              *request_length, user_data_len);
    
    return 0;
}

// 发送请求并接收响应
static int gb_12241_send_and_receive(neu_plugin_t *plugin, const uint8_t *request, size_t request_len, 
                                    uint8_t *response, size_t *response_len) {
    if (plugin == NULL || request == NULL || response == NULL || response_len == NULL) {
        return -1;
    }
    
    // 检查连接状态
    // if (plugin->common.link_state != NEU_NODE_LINK_STATE_CONNECTED) {
    //     plog_error(plugin, "设备未连接");
    //     return -1;
    // }
    
    // 发送请求
    ssize_t send_len = neu_conn_send(plugin->conn, (uint8_t *)request, request_len);
    if (send_len < 0 || (size_t)send_len != request_len) {
        plog_error(plugin, "发送请求失败: 期望发送 %zu 字节, 实际发送 %zd 字节", request_len, send_len);
            return -1;
        }
    
    plog_debug(plugin, "成功发送请求: %zu 字节", request_len);
    
    // 将请求帧以十六进制格式输出
    char hex_buffer[10240] = {0};
    for (size_t i = 0; i < request_len && (i * 3 < sizeof(hex_buffer) - 3); i++) {
        char temp[4];
        snprintf(temp, sizeof(temp), "%02X ", request[i]);
        strcat(hex_buffer, temp);
    }
    plog_notice(plugin, "请求帧(HEX): %s", hex_buffer);
    

    
    // 接收数据
    uint8_t temp_buf[10240] = {0};  // 临时缓冲区，用于累积接收的数据
    size_t temp_len = 0;           // 临时缓冲区中当前的数据长度
    int retry_count = 0;
    const int max_retries = plugin->max_retries > 0 ? plugin->max_retries : 3;
    //const int retry_interval = plugin->retry_interval > 0 ? plugin->retry_interval : 100;  // 毫秒
    const uint64_t timeout = plugin->class1_timeout > 0 ? plugin->class1_timeout : 1000;   // 毫秒
    
    uint64_t start_time = neu_time_ms();
    
    while (retry_count < max_retries) {
        // 检查是否超时
        if (neu_time_ms() - start_time > timeout) {
            plog_error(plugin, "接收响应超时");
            return -1;
        }
        
        // 接收数据到临时缓冲区
        ssize_t recv_len = neu_conn_recv(plugin->conn, &temp_buf[temp_len], sizeof(temp_buf) - temp_len);
        if (recv_len <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // 非阻塞模式下没有数据可读，等待后重试
                //usleep(10000); // 添加10毫秒延时
            retry_count++;
            continue;
        }
        
            // 连接错误，断开连接
            plog_error(plugin, "接收数据失败: %s", strerror(errno));
            neu_conn_disconnect(plugin->conn); // 恢复连接断开操作
    return -1;
}

        temp_len += recv_len;
        plog_notice(plugin, "接收到 %zd 字节数据，当前总长度 %zu", recv_len, temp_len);
        
        // 用于存储解析结果的变量
        uint16_t device_addr = 0;
        uint8_t afn = 0;
        uint8_t seq = 0;
        uint8_t control_field = 0; // 新增控制域变量
        uint8_t data[1024] = {0};
        size_t data_len = sizeof(data);
        
        // 尝试从临时缓冲区中解析一个完整的帧
        size_t frame_len = gb_12241_parse_frame(temp_buf, temp_len, &device_addr, &afn, &seq, 
                                               &control_field, // 新增控制域参数
                                               data, &data_len);
        
        if (frame_len > 0) {
            // 找到有效帧，复制到响应缓冲区
            if (frame_len > *response_len) {
                plog_warn(plugin, "响应帧长度(%zu)超过缓冲区大小(%zu)，将被截断", frame_len, *response_len);
                frame_len = *response_len;
            }
            
            // 复制找到的有效帧到响应缓冲区
            memcpy(response, temp_buf, frame_len);
            *response_len = frame_len;  // 更新实际的响应长度
            
            // 处理缓冲区中的剩余数据
            if (temp_len > frame_len) {
                // 将剩余数据移动到缓冲区开头，供下次解析使用
                memmove(temp_buf, temp_buf + frame_len, temp_len - frame_len);
                temp_len -= frame_len;
            } else {
                // 没有剩余数据，清空缓冲区
                temp_len = 0;
            }
            
            plog_debug(plugin, "成功解析响应帧: 设备地址=%u, 功能码=%u, 序列号=%u, 控制域=%02X, 帧长度=%zu", 
                      device_addr, afn, seq, control_field, frame_len);
            
            return 0;  // 成功接收到响应
        }
        
        // 如果缓冲区已满但仍未找到有效帧，则清空部分缓冲区
        if (temp_len >= sizeof(temp_buf) - 64) {
            plog_warn(plugin, "接收缓冲区即将溢出，但未找到有效帧，清空部分数据并继续接收");
            
            // 将最后100字节移到缓冲区开头，保留可能包含帧头的部分
            if (temp_len > 100) {
                memmove(temp_buf, temp_buf + temp_len - 100, 100);
                temp_len = 100;
                
                // 打印剩余数据的十六进制表示
                memset(hex_buffer, 0, sizeof(hex_buffer));
                for (size_t i = 0; i < temp_len && (i * 3 < sizeof(hex_buffer) - 3); i++) {
                    char temp[4];
                    snprintf(temp, sizeof(temp), "%02X ", temp_buf[i]);
                    strcat(hex_buffer, temp);
                }
                plog_debug(plugin, "保留的数据(HEX): %s", hex_buffer);
            }
        }
        
        retry_count++;
    }
    
    plog_error(plugin, "未能在最大重试次数内收到有效响应");
    return -1;
}

// 添加标签到组
static int gb_12241_add_tag_to_group(neu_plugin_t *plugin, const char *group_name, neu_datatag_t *tag)
{
    if (plugin == NULL || group_name == NULL || tag == NULL) {
        return -1;
    }
    
    // 确保组名不为空字符串
    if (group_name[0] == '\0') {
        plog_error(plugin, "组名不能为空");
        return -1;
    }
    
    // 首先验证标签格式是否正确
    if (driver_validate_tag(plugin, tag) != 0) {
        plog_error(plugin, "标签格式无效: %s, 地址: %s", tag->name, tag->address);
        return -1;
    }
    
    // 查找组，如果不存在则创建
    neu_plugin_group_t *group = NULL;
    bool found = false;
    
    unsigned int n_groups = utarray_len(plugin->groups);
    
    for (unsigned int i = 0; i < n_groups; i++) {
        neu_plugin_group_t **pp_group = (neu_plugin_group_t **)utarray_eltptr(plugin->groups, i);
        
        if (pp_group != NULL && *pp_group != NULL && (*pp_group)->group_name != NULL) {
            if (strcmp((*pp_group)->group_name, group_name) == 0) {
                group = *pp_group;
                found = true;
                break;
            }
        }
    }
    
    // 如果组不存在，创建新组
    if (!found) {
        group = calloc(1, sizeof(neu_plugin_group_t));
        
        if (group == NULL) {
            plog_error(plugin, "无法分配内存创建组: %s", group_name);
            return -1;
        }
        
        // 设置组名
        group->group_name = strdup(group_name);
        
        if (group->group_name == NULL) {
            free(group);
            plog_error(plugin, "无法复制组名: %s", group_name);
            return -1;
        }
        
        // 初始化标签数组 - 注意：这里不需要复制标签，标签会由框架管理
        utarray_new(group->tags, neu_tag_get_icd());
        
        // 添加到组数组
        utarray_push_back(plugin->groups, &group);
        
        plog_info(plugin, "创建新组: %s", group_name);
    }
    
    // 添加标签到组 - 直接添加标签，不需要复制
    utarray_push_back(group->tags, tag);
    
    plog_info(plugin, "添加标签 '%s' 到组 '%s'", tag->name, group_name);
    
    return 0;
}

// 驱动组定时器函数
static int driver_group_timer(neu_plugin_t *plugin, neu_plugin_group_t *group)
{
    if (plugin == NULL || group == NULL) {
        return -1;
    }
    
    // 获取安全的组名
    const char *safe_group_name = get_safe_group_name(group);
    
    // 检查插件是否运行
    bool running = plugin->running;
    
    if (!running) {
        plog_debug(plugin, "插件未运行，跳过组定时器 '%s'", safe_group_name);
    return 0;
}

    // 确保TCP连接正常
    if (!neu_conn_is_connected(plugin->conn)) {
        neu_conn_connect(plugin->conn);
        
        // 检查连接结果
        if (!neu_conn_is_connected(plugin->conn)) {
            plog_error(plugin, "连接服务器失败，组: '%s'", safe_group_name);
            return -1;
        }
        plog_info(plugin, "成功连接到服务器");
    }
    
    // 读取组内所有标签
    return gb_12241_read_group(plugin, group);
}

// 驱动写入标签函数
static int driver_write(neu_plugin_t *plugin, void *req, neu_datatag_t *tag,
                   neu_value_u value)
{
    NEU_UNUSED(req);
    
    if (plugin == NULL || tag == NULL) {
        return -1;
    }
    
    if (tag->name == NULL || tag->address == NULL) {
        plog_error(plugin, "标签名称或地址为空");
        return -1;
    }
    
    plog_debug(plugin, "写入标签: %s, 地址: %s", tag->name, tag->address);
    
    // 查找并创建点位
    GB_12241_point_t *point = gb_12241_find_tag(plugin, tag->name);
    
    if (point == NULL) {
        plog_error(plugin, "找不到标签: %s", tag->name);
        return -1;
    }
    
    // 写入标签值
    int ret = gb_12241_write_tag(plugin, point, value);
    
    // 释放点位内存
    if (point != NULL) {
    free(point);
    }
    
    return ret;
}

// 连接回调函数实现
void gb_12241_conn_connected(void *data, int fd)
{
    neu_plugin_t *plugin = (neu_plugin_t *)data;
    (void)fd;
    
    // 记录连接状态变化的日志
    if (plugin->common.link_state != NEU_NODE_LINK_STATE_CONNECTED) {
        plog_notice(plugin, "设备连接状态变化: 已断开 -> 已连接 (fd=%d)", fd);
    }
    
    // 更新连接状态
    plugin->common.link_state = NEU_NODE_LINK_STATE_CONNECTED;
}

void gb_12241_conn_disconnected(void *data, int fd)
{
    neu_plugin_t *plugin = (neu_plugin_t *)data;
    (void)fd;
    
    // 记录连接状态变化的日志
    if (plugin->common.link_state != NEU_NODE_LINK_STATE_DISCONNECTED) {
        plog_notice(plugin, "设备连接状态变化: 已连接 -> 已断开 (fd=%d)", fd);
    }
    
    // 更新连接状态
    plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
}

// 使用Neuron标准插件接口
static const neu_plugin_intf_funs_t plugin_intf_funs = {
    .open    = plugin_open,
    .close   = plugin_close,
    .init    = plugin_init,
    .uninit  = plugin_uninit,
    .start   = plugin_start,
    .stop    = plugin_stop,
    .setting = plugin_config,
    .request = plugin_request,

    .driver.validate_tag  = driver_validate_tag,
    .driver.group_timer   = driver_group_timer,
    .driver.group_sync    = driver_group_timer,
    .driver.write_tag     = driver_write,
    .driver.tag_validator = NULL,
    .driver.write_tags    = NULL,
    .driver.test_read_tag = NULL,
    .driver.add_tags      = NULL,
    .driver.load_tags     = NULL,
    .driver.del_tags      = NULL,
    .driver.directory     = NULL,
    .driver.fup_open      = NULL,
    .driver.fup_data      = NULL,
    .driver.fdown_open    = NULL,
    .driver.fdown_data    = NULL,
};

const neu_plugin_module_t neu_plugin_module = {
    .version     = NEURON_PLUGIN_VER_1_0,
    .schema      = "12241-tcp",
    .module_name = "GB/T 12241 TCP",
    .module_descr =
        "This plugin is used to connect devices using the GB/T 12241 TCP protocol. "
        "It supports standard class 1 and class 2 data acquisition.",
    .module_descr_zh =
        "该插件用于连接使用 GB/T 12241 TCP 协议的设备。"
        "支持标准的一类数据和二类数据采集。",
    .intf_funs = &plugin_intf_funs,
    .kind      = NEU_PLUGIN_KIND_SYSTEM,
    .type      = NEU_NA_TYPE_DRIVER,
    .display   = true,
    .single    = false,
};

// 添加函数实现
static int neu_plugin_send(neu_plugin_t *plugin, neu_reqresp_head_t *head, void *data, size_t len)
{
    (void) len; // 避免未使用参数警告
    
    if (plugin == NULL || head == NULL) {
        return -1;
    }
    
    neu_plugin_common_t *common = neu_plugin_to_plugin_common(plugin);
    if (common == NULL || common->adapter_callbacks == NULL) {
        return -1;
    }
    
    return common->adapter_callbacks->response(common->adapter, head, data);
}

static int neu_plugin_update_tag(neu_plugin_t *plugin, const char *group, neu_datatag_t *tag, neu_value_u *value)
{
    if (plugin == NULL || tag == NULL || value == NULL) {
        return -1;
    }
    
    // 检查组名是否有效
    if (!is_valid_string(group)) {
        group = "(未命名)";
    }
    
    neu_plugin_common_t *common = neu_plugin_to_plugin_common(plugin);
    if (common == NULL || common->adapter_callbacks == NULL) {
        return -1;
    }
    
    neu_dvalue_t dvalue = {0};
    dvalue.type = tag->type;
    dvalue.value = *value;
    
    common->adapter_callbacks->driver.update(common->adapter, group, tag->name, dvalue);
    return 0;
}

static void gb_12241_free_group(neu_plugin_group_t *group)
{
    if (group == NULL) {
        return;
    }
    
    if (group->group_name != NULL) {
        free(group->group_name);
    }
    
    if (group->tags != NULL) {
        // 直接释放数组，不释放各个标签
        utarray_free(group->tags);
    }
    
    free(group);
} 

// 添加一个安全的字符串检查函数
static bool is_valid_string(const char *str)
{
    // 检查字符串是否为NULL
    if (str == NULL) {
        return false;
    }
    
    // 检查字符串是否可访问（简单检查）
    // 这只是一个简单的检查，不能确保完全安全
    // 但可以过滤掉明显无效的字符串
    size_t len = 0;
    for (len = 0; len < NEU_TAG_NAME_LEN; len++) {
        if (str[len] == '\0') {
            return true; // 找到结束符
        }
        
        // 检查非打印字符（可能是损坏的字符串）
        if (str[len] < 32 && str[len] != '\t' && str[len] != '\r' && str[len] != '\n') {
            return false;
        }
    }
    
    // 如果没有找到结束符，可能是无效字符串
    return false;
}

// 安全地获取组名的函数
static const char *get_safe_group_name(neu_plugin_group_t *group)
{
    static const char *unnamed = "(未命名)";
    
    if (group == NULL) {
        return unnamed;
    }
    
    if (!is_valid_string(group->group_name)) {
        return unnamed;
    }
    
    return group->group_name;
}

/* 基础宏定义 - 避免与12241_point.h中重复定义 */
#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef ERROR
#define ERROR 0
#endif
#define ERROR   0

/* 位操作数组 */
static const uint8_t dwBit[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

/**********************************************************************
* 功    能：DT→Fn的计算
* 输    入：ptDataUnitID    指向数据单元标识的指针
*           pwFn            指向Fn输出缓冲区的指针
* 输    出：信息类标识Fn值
*           TRUE        正常
*           FALSE    信息类DT有错误
***********************************************************************/
// static uint8_t gb_12241_dt_to_fn(const DATA_UNIT_Flag *ptDataUnitID, uint16_t *pwFn)
// {
//     uint8_t i;
//     uint8_t bPlaceDT1[8];       /* 信息类元中1所在的位置1~8 */
//     uint16_t wPlaceDT2 = 0;     /* 信息类组中1所在的位置 */
//     uint8_t *pbTemp;
    
//     /* 检查参数有效性 */
//     if ((ptDataUnitID == NULL) || (pwFn == NULL)) {
//         return FALSE;
//     }
    
//     /* 初始化输出数组 */
//     for (i = 0; i < 8; i++) {
//         pwFn[i] = INVALID_PN_FN;
//     }
    
//     if (ptDataUnitID->DT1 == 0) {    /* 信息元不能=0 */
//         return FALSE;
//     }
    
//     /* 计算信息类元中1所在的位置1~8 */
//     pbTemp = bPlaceDT1;
//     for (i = 0; i < 8; i++) {
//         bPlaceDT1[i] = 0;
//         if (TEST_BIT(ptDataUnitID->DT1, dwBit[i])) {
//             *pbTemp++ = i + 1;
//         }
//     }
    
//     if (pbTemp == bPlaceDT1) {    /* 没有找到1 */
//         return ERROR;
//     }
    
//     /* 计算Fn＝DT2×8＋PlaceDT1 */
//     i = 0;
//     wPlaceDT2 = ptDataUnitID->DT2 * 8;
//     while ((bPlaceDT1[i] != 0) && (i < 8)) {
//         pwFn[i] = wPlaceDT2 + bPlaceDT1[i];
//         i++;
//     }
    
//     return TRUE;
// }

/**********************************************************************
* 功    能：Fn→DT的计算
* 输    入：ptDataUnitID    指向数据单元标识的指针
*           wFn             信息类标识Fn值
* 输    出：DT值
*           TRUE        正常
*           FALSE    非法的Fn值
***********************************************************************/
static uint8_t gb_12241_fn_to_dt(DATA_UNIT_Flag *ptDataUnitID, uint16_t wFn)
{
    /* 检查参数有效性 */
    if (ptDataUnitID == NULL) {
        return FALSE;
    }
    
    /* 检查Fn值的合法性 */
    if ((wFn == 0) || (wFn > 2048)) {    /* 非法的Fn值 */
        return FALSE;
    }
    
    /* 公式 DT2＝（Fn－1）／8    DT1＝dwBit[（Fn－1）% 8] */
    ptDataUnitID->DT1 = dwBit[(wFn - 1) % 8];
    ptDataUnitID->DT2 = (wFn - 1) / 8;
    
    return TRUE;
}

/* 函数声明 */
static uint8_t gb_12241_make_crc(const uint8_t *buf, int16_t count);

// 构建包含多个FN+PN的请求帧
static int gb_12241_build_multi_request(neu_plugin_t *plugin, uint8_t *frame, size_t frame_size, 
                               uint16_t device_addr, uint8_t seq, 
                               uint16_t *fn_array, uint16_t *pn_array, int fn_pn_count,
                               size_t *request_length)
{
    uint8_t *buf;
    uint16_t user_data_len = 0;
    S_ControlField ctrl;
    S_SEQ frame_seq;
    LINK_LEN link_len = {0};
    DATA_UNIT_Flag dataunitf;
    ADDR addr = {0};  /* 初始化地址结构体 */
    
    /* 检查参数 */
    if (plugin == NULL || frame == NULL || request_length == NULL || 
        fn_array == NULL || pn_array == NULL || fn_pn_count <= 0 || fn_pn_count > 4) {
        plog_error(plugin, "构建多请求的参数无效: fn_pn_count=%d", fn_pn_count);
        return -1;
    }
    
    /* 初始化 */
    buf = frame;
    
    /* 1. 帧起始符 */
    *buf = 0x68;
    buf += 1;
    
    /* 2. 预留长度字段空间 */
    buf += 4;
    
    /* 3. 重复帧起始符 */
    *buf = 0x68;
    buf += 1;
    
    /* 4. 控制域 */
    ctrl.ControlField.ControlField.DIR = 0;         /* 方向位(主站发出=0) */
    ctrl.ControlField.ControlField.PRM = 1;         /* 启动位(主站发出=1) */
    ctrl.ControlField.ControlField.FCB = 1;         /* 帧计数位 */
    ctrl.ControlField.ControlField.FCV = 0;         /* 帧计数有效位 */
    ctrl.ControlField.ControlField.FC = REQUESTTWODATA; /* 功能码 */
    
    *buf = ctrl.ControlField.BControlField;
    buf += 1;
    user_data_len += 1;  /* 控制域长度 */
    
    /* 5. 地址域 - 使用ADDR结构体 */
    addr.TAH = device_addr / 256;    /* 终端地址高字节 */
    addr.TAL = device_addr % 256;    /* 终端地址低字节 */
    addr.GAF = 0;                    /* 终端组地址标志 */
    addr.MSA = 1;                    /* 主站地址 */
    addr.RA1 = 0;                    /* 区域码1 */
    addr.RA2 = 0;                    /* 区域码2 */
    addr.RA3 = 0;                    /* 区域码3 */
    addr.RA4 = 0;                    /* 区域码4 */
    
    memcpy(buf, &addr, 5);
    buf += 5;
    user_data_len += 5;  /* 地址域长度 */
    
    /* 6. 应用功能码 */
    *buf = AFN_REQUESTONEDATA;
    buf += 1;
    user_data_len += 1;  /* 应用功能码长度 */
    
    /* 7. 帧序列域 */
    memset(&frame_seq, 0, sizeof(S_SEQ));
    frame_seq.seq.PSEQ.PSEQ = seq & 0x0F;  /* 序列号 */
    frame_seq.seq.PSEQ.CON = 1;            /* 需要确认 */
    frame_seq.seq.PSEQ.FIN = 1;            /* 末帧标志 */
    frame_seq.seq.PSEQ.FIR = 1;            /* 首帧标志 */
    frame_seq.seq.PSEQ.TpV = 0;            /* 帧时间标签无效 */
    
    memcpy(buf++, &frame_seq.seq.RSEQ, 1); /* 使用与C++代码相同的方式 */
    user_data_len += 1;  /* 帧序列域长度 */
    
    /* 8. 填充数据单元标识 - 这里处理多个FN+PN */
    for (int i = 0; i < fn_pn_count; i++) {
        /* 重置数据单元标识 */
        memset(&dataunitf, 0, sizeof(DATA_UNIT_Flag));
        
        /* 设置数据单元标识 */
        if (pn_array[i] == 0) {
            dataunitf.DA1 = 0x00;
            dataunitf.DA2 = 0x00;
        } else {
            dataunitf.DA1 = 0x01 << ((pn_array[i] - 1) % 8);
            dataunitf.DA2 = (pn_array[i] - 1) / 8 + 1;
        }
        
        /* 设置功能码 */
        gb_12241_fn_to_dt(&dataunitf, fn_array[i]);
        
        /* 复制数据单元标识 */
        memcpy(buf, &dataunitf, 4);
        buf += 4;
        user_data_len += 4;
    }
    
    /* 检查用户数据长度是否合法 */
    if (user_data_len > 2047) {  /* 最大支持2047字节(0x7FF) */
        plog_error(plugin, "用户数据长度超出限制: %u", user_data_len);
        return -1;
    }
    
    /* 检查缓冲区溢出 */
    size_t needed_size = (size_t)(buf - frame) + 2;  /* 加上校验和和结束符 */
    if (needed_size > frame_size) {
        plog_error(plugin, "缓冲区溢出: 需要%zu字节, 但只有%zu字节可用", 
                  needed_size, frame_size);
        return -1;
    }
    
    /* 9. 设置长度域 */
    link_len.PFLG = 0x01;                          /* 协议标识 */
    link_len.LUSERL = user_data_len & 0x3F;        /* 用户数据长度低6位 */
    link_len.LUSERH = (user_data_len >> 6) & 0xFF; /* 用户数据长度高8位，限制在8位 */
    
    /* 验证计算的长度是否正确 */
    uint16_t calc_len = ((uint16_t)link_len.LUSERH << 6) | link_len.LUSERL;
    if (calc_len != user_data_len) {
        plog_error(plugin, "长度计算错误: 预期=%u, 实际=%u", user_data_len, calc_len);
        return -1;  /* 长度计算错误 */
    }
    
    /* 复制长度域到预留位置 */
    memcpy(frame + 1, &link_len, 2);
    memcpy(frame + 3, &link_len, 2);
    
    /* 10. 计算校验和 */
    *buf = gb_12241_make_crc(frame + 6, user_data_len);
    buf += 1;
    
    /* 11. 结束符 */
    *buf = 0x16;
    buf += 1;
    
    /* 设置请求长度 */
    *request_length = (size_t)(buf - frame);

    /* 添加调试日志 */
    plog_notice(plugin, "多FN请求帧构建完成: 总长度=%zu, FN+PN组合数=%d", 
              *request_length, fn_pn_count);
    
    return 0;
}

// 获取指定功能码对应的数据单元大小
static int gb_12241_get_data_unit_size(uint16_t fn)
{
    // 检查是否为特殊功能码，这些功能码的大小不由内部决定
    if (is_special_fn(fn)) {
        // plog_debug(NULL, "FN=%u 是特殊功能码，数据单元大小未知", fn); // Removed due to missing plugin context
        return -1; // 返回-1表示大小未知或由外部确定
    }
    
    switch (fn) {
        case 12: // F12：430集中器数据
            return sizeof(Data_F12); // 139个DI + 4个AI*4 + 4个CI*4
            
        case 28: // F28：电表运行状态字及其变位标志
            // 按照时间+14个状态字(每个两字节)的大小计算
            return sizeof(Data_ONE_F28) ;
            
        case 25: // F25: 电能量
            return sizeof(Data_ONE_F25);
            
        case 129: // F129: 当前电参量
            return sizeof(Data_ONE_F129);
            
        case 145: // F145: 当月正向有功最大需量及发生时间
            return sizeof(Data_ONE_F145);
            
        case 402: // F402: 水表状态字
            return sizeof(Data_ONE_F402);
        case 502: // F502: 气表状态字
            return sizeof(Data_ONE_F502);
        case 602: // F602: 热力表状态字
            return sizeof(Data_ONE_F602);
            
        case 403: // F403: 水表瞬时流量
            return sizeof(Data_ONE_F403);
        case 503: // F503: 气表瞬时流量
            return sizeof(Data_ONE_F503);
        case 603: // F603: 热力表瞬时流量
            return sizeof(Data_ONE_F603);
            
        case 404: // F404: 水表累积流量
            return sizeof(Data_ONE_F404);
        case 504: // F504: 气表累积流量
            return sizeof(Data_ONE_F504);
    
            
        case 900: // F900: 有功最大需量
            return sizeof(Data_ONE_F900);
            
        case 901: // F901: 电网频率
            return sizeof(Data_ONE_F901);
            
        case 829: // F829: 当前正向有功电能示值
        case 830: // F830: 当前正向无功电能示值
        case 831: // F831: 当前反向有功电能示值
        case 832: // F832: 当前反向无功电能示值
            // 这些数据结构使用统一的Data_ONE_Energy结构体
            return sizeof(Data_ONE_Energy); // 使用完整的结构体大小
            
        default:
            return -1; // 未知功能码
    }
}

// 从数据单元提取特定数据索引的值
static int gb_12241_extract_data_value(neu_plugin_t *plugin, const uint8_t *data, int data_unit_size, 
                                     uint16_t fn, uint8_t data_index, neu_value_u *value)
{
    if (plugin == NULL || data == NULL || value == NULL || data_unit_size <= 0) {
        plog_error(plugin, "参数无效");
        return -1;
    }
    
    switch (fn) {
        case 12: { // F12：430集中器数据
            // 将数据视为Data_F12结构
            Data_F12 *f12 = (Data_F12 *)data;
            
            // 根据data_index范围处理不同类型的数据
            if (data_index <= 138) { // DI数据 (数字量输入)
                // 检查数据有效性 - 0xEE表示无效
                if (f12->di_status[data_index] != 0xEE) {
                    value->boolean = (f12->di_status[data_index] != 0);
                    plog_debug(plugin, "F12 DI[%d] = %d", data_index, value->boolean);
                    return 0; // 返回0表示数据有效
                } else {
                    plog_notice(plugin, "F12 DI数据无效: index=%d", data_index);
                    value->u8 = 0xEE; // 使用无效数据标识
                    return 1; // 返回1表示数据存在但无效
                }
            } else if (data_index >= 139 && data_index <= 142) { // AI数据 (模拟量输入)
                int ai_index = data_index - 139;
                if (ai_index >= 0 && ai_index < 4 && f12->ai_values[ai_index] != 0xEEEEEEEE) {
                    value->f32 = (float)f12->ai_values[ai_index];
                    plog_debug(plugin, "F12 AI[%d] = %.2f", ai_index, value->f32);
                    return 0; // 返回0表示数据有效
                } else {
                    plog_notice(plugin, "F12 AI数据无效: index=%d, ai_index=%d", data_index, ai_index);
                    value->u8 = 0xEE; // 使用无效数据标识
                    return 1; // 返回1表示数据存在但无效
                }
            } else if (data_index >= 143 && data_index <= 146) { // CI数据 (计数输入)
                int ci_index = data_index - 143;
                if (ci_index >= 0 && ci_index < 4 && f12->ci_values[ci_index] != 0xEEEEEEEE) {
                    value->u32 = f12->ci_values[ci_index];
                    plog_debug(plugin, "F12 CI[%d] = %u", ci_index, value->u32);
                    return 0; // 返回0表示数据有效
                } else {
                    plog_notice(plugin, "F12 CI数据无效: index=%d, ci_index=%d", data_index, ci_index);
                    value->u8 = 0xEE; // 使用无效数据标识
                    return 1; // 返回1表示数据存在但无效
                }
            } else {
                plog_error(plugin, "F12数据索引超出范围: %d (有效范围: 0-138, 139-142, 143-146)", data_index);
                return -1; // 返回-1表示数据索引无效
            }
            break;
        }
        
        case 25: { // F25：当前三相及总有功功率、功率因数，三相电压、电流、零序电流、视在功率
            // 传入的data指针就是指向Data_ONE_F25结构的指针
            Data_ONE_F25 *dataF25 = (Data_ONE_F25 *)data;
            
            // 根据data_index获取不同的数据项
            switch (data_index) {
                case 0: // 总有功功率
                    if (data_type_9_getflag(&dataF25->data_P)) {
                        value->f32 = data_type_9_getvalue(&dataF25->data_P);
                    return 0;
                }
                    break;
                    
                case 1: // A相有功功率
                    if (data_type_9_getflag(&dataF25->data_Pa)) {
                        value->f32 = data_type_9_getvalue(&dataF25->data_Pa);
                    return 0;
                }
                    break;
                    
                case 2: // B相有功功率
                    if (data_type_9_getflag(&dataF25->data_Pb)) {
                        value->f32 = data_type_9_getvalue(&dataF25->data_Pb);
                    return 0;
                }
                    break;
                    
                case 3: // C相有功功率
                    if (data_type_9_getflag(&dataF25->data_Pc)) {
                        value->f32 = data_type_9_getvalue(&dataF25->data_Pc);
                        return 0;
            }
            break;
                    
                case 4: // 总无功功率
                    if (data_type_9_getflag(&dataF25->data_Q)) {
                        value->f32 = data_type_9_getvalue(&dataF25->data_Q);
                        return 0;
                    }
                    break;
                    
                case 5: // A相无功功率
                    if (data_type_9_getflag(&dataF25->data_Qa)) {
                        value->f32 = data_type_9_getvalue(&dataF25->data_Qa);
                            return 0;
                        }
                    break;
                    
                case 6: // B相无功功率
                    if (data_type_9_getflag(&dataF25->data_Qb)) {
                        value->f32 = data_type_9_getvalue(&dataF25->data_Qb);
                            return 0;
                        }
                    break;
                    
                case 7: // C相无功功率
                    if (data_type_9_getflag(&dataF25->data_Qc)) {
                        value->f32 = data_type_9_getvalue(&dataF25->data_Qc);
                            return 0;
                        }
                    break;
                    
                case 8: // 总功率因数
                    if (data_type_5_getflag(&dataF25->data_Cs)) {
                        value->f32 = data_type_5_getvalue(&dataF25->data_Cs);
                        return 0;
                    }
                    break;
                    
                case 9: // A相功率因数
                    if (data_type_5_getflag(&dataF25->data_Csa)) {
                        value->f32 = data_type_5_getvalue(&dataF25->data_Csa);
                        return 0;
                    }
                    break;
                    
                case 10: // B相功率因数
                    if (data_type_5_getflag(&dataF25->data_Csb)) {
                        value->f32 = data_type_5_getvalue(&dataF25->data_Csb);
                        return 0;
                    }
                    break;
                    
                case 11: // C相功率因数
                    if (data_type_5_getflag(&dataF25->data_Csc)) {
                        value->f32 = data_type_5_getvalue(&dataF25->data_Csc);
                        return 0;
                    }
                    break;
                    
                case 12: // A相电压
                    if (data_type_7_getflag(&dataF25->data_Ua)) {
                        value->f32 = data_type_7_getvalue(&dataF25->data_Ua);
                        return 0;
                    }
                    break;
                    
                case 13: // B相电压
                    if (data_type_7_getflag(&dataF25->data_Ub)) {
                        value->f32 = data_type_7_getvalue(&dataF25->data_Ub);
                        return 0;
                    }
                    break;
                    
                case 14: // C相电压
                    if (data_type_7_getflag(&dataF25->data_Uc)) {
                        value->f32 = data_type_7_getvalue(&dataF25->data_Uc);
                        return 0;
                    }
                    break;
                    
                case 15: // A相电流
                    if (data_type_25_getflag(&dataF25->data_Ia)) {
                        value->f32 = data_type_25_getvalue(&dataF25->data_Ia);
                        return 0;
                    }
                    break;
                    
                case 16: // B相电流
                    if (data_type_25_getflag(&dataF25->data_Ib)) {
                        value->f32 = data_type_25_getvalue(&dataF25->data_Ib);
                        return 0;
                    }
                    break;
                    
                case 17: // C相电流
                    if (data_type_25_getflag(&dataF25->data_Ic)) {
                        value->f32 = data_type_25_getvalue(&dataF25->data_Ic);
                        return 0;
                    }
                    break;
                    
                case 18: // 零序电流
                    if (data_type_25_getflag(&dataF25->data_I0)) {
                        value->f32 = data_type_25_getvalue(&dataF25->data_I0);
                        return 0;
                    }
                    break;
                    
                case 19: // 总视在功率
                    if (data_type_9_getflag(&dataF25->data_S)) {
                        value->f32 = data_type_9_getvalue(&dataF25->data_S);
                        return 0;
                    }
                    break;
                    
                case 20: // A相视在功率
                    if (data_type_9_getflag(&dataF25->data_Sa)) {
                        value->f32 = data_type_9_getvalue(&dataF25->data_Sa);
                        return 0;
                    }
                    break;
                    
                case 21: // B相视在功率
                    if (data_type_9_getflag(&dataF25->data_Sb)) {
                        value->f32 = data_type_9_getvalue(&dataF25->data_Sb);
                        return 0;
                    }
                    break;
                    
                case 22: // C相视在功率
                    if (data_type_9_getflag(&dataF25->data_Sc)) {
                        value->f32 = data_type_9_getvalue(&dataF25->data_Sc);
                        return 0;
                    }
                    break;
                    
                default:
                    plog_error(plugin, "F25数据索引超出范围: %d", data_index);
                    return -1;
            }
            
            // 数据无效
            plog_debug(plugin, "F25数据无效: index=%d", data_index);
            value->u8 = 0xEE; // 使用无效数据标识
            return 1; // 返回1表示数据存在但无效
                }
                
                case 28: { // F28：电表运行状态字及其变位标志
                    // 根据data_index获取不同状态字内容
                    if (data_index < 28) {
                // 直接将数据视为Data_ONE_F28结构
                Data_ONE_F28 *f28 = (Data_ONE_F28 *)data;
                        uint16_t invalid_word = 0xEEEE; // 无效数据标识
                        
                        // S4 - A相状态字 (data_index: 0-7)
                        if (data_index <= 7) {
                            // 检查是否为无效数据
                    if (memcmp(&f28->S4, &invalid_word, 2) == 0) {
                                plog_debug(plugin, "F28: S4状态字为无效数据");
                                // 对于无效数据，使用整型返回0xEE，表示无效
                                value->u8 = 0xEE;
                        return 1;  // 返回1表示数据存在但无效
                            }
                            
                            // 根据data_index返回对应位
                            switch (data_index) {
                        case 0: value->boolean = f28->S4.bit7; break; // A相断相
                        case 1: value->boolean = f28->S4.bit6; break; // A相反向
                        case 2: value->boolean = f28->S4.bit5; break; // A相过载
                        case 3: value->boolean = f28->S4.bit4; break; // A相过流
                        case 4: value->boolean = f28->S4.bit3; break; // A相失流
                        case 5: value->boolean = f28->S4.bit2; break; // A相过压
                        case 6: value->boolean = f28->S4.bit1; break; // A相欠压
                        case 7: value->boolean = f28->S4.bit0; break; // A相失压
                    }
                    return 0;  // 返回0表示数据有效
                        }
                        
                        // S5 - B相状态字 (data_index: 8-15)
                        else if (data_index >= 8 && data_index <= 15) {
                            // 检查是否为无效数据
                    if (memcmp(&f28->S5, &invalid_word, 2) == 0) {
                                plog_debug(plugin, "F28: S5状态字为无效数据");
                                // 对于无效数据，使用整型返回0xEE，表示无效
                                value->u8 = 0xEE;
                        return 1;  // 返回1表示数据存在但无效
                            }
                            
                            // 根据data_index返回对应位
                            switch (data_index) {
                        case 8:  value->boolean = f28->S5.bit7; break; // B相断相
                        case 9:  value->boolean = f28->S5.bit6; break; // B相反向
                        case 10: value->boolean = f28->S5.bit5; break; // B相过载
                        case 11: value->boolean = f28->S5.bit4; break; // B相过流
                        case 12: value->boolean = f28->S5.bit3; break; // B相失流
                        case 13: value->boolean = f28->S5.bit2; break; // B相过压
                        case 14: value->boolean = f28->S5.bit1; break; // B相欠压
                        case 15: value->boolean = f28->S5.bit0; break; // B相失压
                    }
                    return 0;  // 返回0表示数据有效
                        }
                        
                        // S6 - C相状态字 (data_index: 16-23)
                        else if (data_index >= 16 && data_index <= 23) {
                            // 检查是否为无效数据
                    if (memcmp(&f28->S6, &invalid_word, 2) == 0) {
                                plog_debug(plugin, "F28: S6状态字为无效数据");
                                // 对于无效数据，使用整型返回0xEE，表示无效
                                value->u8 = 0xEE;
                        return 1;  // 返回1表示数据存在但无效
                            }
                            
                            // 根据data_index返回对应位
                            switch (data_index) {
                        case 16: value->boolean = f28->S6.bit7; break; // C相断相
                        case 17: value->boolean = f28->S6.bit6; break; // C相反向
                        case 18: value->boolean = f28->S6.bit5; break; // C相过载
                        case 19: value->boolean = f28->S6.bit4; break; // C相过流
                        case 20: value->boolean = f28->S6.bit3; break; // C相失流
                        case 21: value->boolean = f28->S6.bit2; break; // C相过压
                        case 22: value->boolean = f28->S6.bit1; break; // C相欠压
                        case 23: value->boolean = f28->S6.bit0; break; // C相失压
                    }
                    return 0;  // 返回0表示数据有效
                        }
                        
                        // S7 - 合相状态字 (data_index: 24-27)
                        else if (data_index >= 24 && data_index <= 27) {
                            // 检查是否为无效数据
                    if (memcmp(&f28->S7, &invalid_word, 2) == 0) {
                                plog_debug(plugin, "F28: S7状态字为无效数据");
                                // 对于无效数据，使用整型返回0xEE，表示无效
                                value->u8 = 0xEE;
                        return 1;  // 返回1表示数据存在但无效
                            }
                            
                            // 根据data_index返回对应位
                            switch (data_index) {
                        case 24: value->boolean = f28->S7.bit3; break; // 电流不平衡
                        case 25: value->boolean = f28->S7.bit2; break; // 电压不平衡
                        case 26: value->boolean = f28->S7.bit1; break; // 电流逆相序
                        case 27: value->boolean = f28->S7.bit0; break; // 电压逆相序
                    }
                    return 0;  // 返回0表示数据有效
                }
            }
                    break;
                }
                
        case 900: { // F900：有功最大需量
            // 将数据视为Data_ONE_F900结构
            Data_ONE_F900 *f900 = (Data_ONE_F900 *)data;
            
            // 目前只支持data_index=0 (有功功率)
            if (data_index == 0) {
                if (data_type_9_getflag(&f900->data_PX)) {
                    value->f32 = data_type_9_getvalue(&f900->data_PX);
                            return 0;
                        }
                // 数据无效
                plog_debug(plugin, "F900数据无效");
                value->u8 = 0xEE; // 使用无效数据标识
                return 1; // 返回1表示数据存在但无效
            } else {
                plog_error(plugin, "F900数据索引超出范围: %d", data_index);
                return -1;
            }
                    break;
                }
        
        case 901: { // F901：电网频率
            // 将数据视为Data_ONE_F901结构
            Data_ONE_F901 *f901 = (Data_ONE_F901 *)data;
            
            // 目前只支持data_index=0 (频率)
            if (data_index == 0) {
                if (data_type_6_getflag(&f901->data_F)) {
                    value->f32 = data_type_6_getvalue(&f901->data_F);
                    return 0;
                }
                // 数据无效
                plog_debug(plugin, "F901数据无效");
                value->u8 = 0xEE; // 使用无效数据标识
                return 1; // 返回1表示数据存在但无效
        } else {
                plog_error(plugin, "F901数据索引超出范围: %d", data_index);
                return -1;
            }
                    break;
        }
        
        case 402: { // F402：水表运行状态字及其变位标志
            // 将数据视为Data_ONE_F402结构
            Data_ONE_F402 *f402 = (Data_ONE_F402 *)data;
            
            // 用于检查无效数据的对比值
            Data_Type_BS16 invalid_bs16 = {0};
            memset(&invalid_bs16, 0xEE, sizeof(Data_Type_BS16));
            
            // 处理S1-S4状态字的各个位（data_index范围: 0-31）
            if ( data_index <= 7) {
                // S1 状态字 (data_index: 0-7)
                // 检查是否为无效数据
                if (memcmp(&f402->S1, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                    plog_debug(plugin, "F402: S1状态字为无效数据");
                    value->u8 = 0xEE;
                    return 1; // 返回1表示数据存在但无效
                }
                
                // 根据data_index返回对应位
                switch (data_index) {
                    case 0: value->boolean = f402->S1.bit0; break;
                    case 1: value->boolean = f402->S1.bit1; break;
                    case 2: value->boolean = f402->S1.bit2; break;
                    case 3: value->boolean = f402->S1.bit3; break;
                    case 4: value->boolean = f402->S1.bit4; break;
                    case 5: value->boolean = f402->S1.bit5; break;
                    case 6: value->boolean = f402->S1.bit6; break;
                    case 7: value->boolean = f402->S1.bit7; break;
                }
                return 0; // 返回0表示数据有效
            }
            else if (data_index >= 8 && data_index <= 15) {
                // S2 状态字 (data_index: 8-15)
                // 检查是否为无效数据
                if (memcmp(&f402->S2, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                    plog_debug(plugin, "F402: S2状态字为无效数据");
                    value->u8 = 0xEE;
                    return 1; // 返回1表示数据存在但无效
                }
                
                // 根据data_index返回对应位
                switch (data_index) {
                    case 8:  value->boolean = f402->S2.bit0; break;
                    case 9:  value->boolean = f402->S2.bit1; break;
                    case 10: value->boolean = f402->S2.bit2; break;
                    case 11: value->boolean = f402->S2.bit3; break;
                    case 12: value->boolean = f402->S2.bit4; break;
                    case 13: value->boolean = f402->S2.bit5; break;
                    case 14: value->boolean = f402->S2.bit6; break;
                    case 15: value->boolean = f402->S2.bit7; break;
                }
                return 0; // 返回0表示数据有效
            }
            else if (data_index >= 16 && data_index <= 23) {
                // S3 状态字 (data_index: 16-23)
                // 检查是否为无效数据
                if (memcmp(&f402->S3, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                    plog_debug(plugin, "F402: S3状态字为无效数据");
                    value->u8 = 0xEE;
                    return 1; // 返回1表示数据存在但无效
                }
                
                // 根据data_index返回对应位
                switch (data_index) {
                    case 16: value->boolean = f402->S3.bit0; break;
                    case 17: value->boolean = f402->S3.bit1; break;
                    case 18: value->boolean = f402->S3.bit2; break;
                    case 19: value->boolean = f402->S3.bit3; break;
                    case 20: value->boolean = f402->S3.bit4; break;
                    case 21: value->boolean = f402->S3.bit5; break;
                    case 22: value->boolean = f402->S3.bit6; break;
                    case 23: value->boolean = f402->S3.bit7; break;
                }
                return 0; // 返回0表示数据有效
            }
            else if (data_index >= 24 && data_index <= 64) {
                // 变位标志处理 (BWS1-BWS4) (data_index: 32-63)
                // 变位标志通常不直接读取，可选择返回无效或继续实现
                plog_debug(plugin, "F402: 变位标志不支持直接读取 (data_index=%d)", data_index);
                value->u8 = 0xEE;
                return 1; // 返回1表示数据存在但无效
            }
            else {
                plog_error(plugin, "F402数据索引超出范围: %d (有效范围: 0-63)", data_index);
        return -1;
            }
            break;
        }
        
        case 403: { // F403：水表当前瞬时流量及压力
            // 将数据视为Data_ONE_F403结构
            Data_ONE_F403 *f403 = (Data_ONE_F403 *)data;
            
            // 根据data_index获取不同的数据项
            switch (data_index) {
                case 0: // 当前瞬时流量
                    if (data_type_29_getflag(&f403->data_L)) {
                        value->f32 = data_type_29_getvalue(&f403->data_L);
                        plog_debug(plugin, "F403 瞬时流量 = %.2f", value->f32);
    return 0;
}
                    break;
                    
                case 1: // 压力
                    if (data_type_37_getflag(&f403->data_P)) {
                        value->f32 = data_type_37_getvalue(&f403->data_P);
                        plog_debug(plugin, "F403 压力 = %.2f", value->f32);
                        return 0;
                    }
                    break;
            
        default:
                    plog_error(plugin, "F403数据索引超出范围: %d (有效范围: 0-1)", data_index);
        return -1;
    }
    
            // 数据无效
            plog_debug(plugin, "F403数据无效: index=%d", data_index);
            value->u8 = 0xEE; // 使用无效数据标识
            return 1; // 返回1表示数据存在但无效
        }
        
        case 404: { // F404：水表当前正向总累积流量示值
            // 将数据视为Data_ONE_F404结构
            Data_ONE_F404 *f404 = (Data_ONE_F404 *)data;
            
            // 目前仅支持data_index=0 (当前正向总累积流量)
            if (data_index == 0) {
                if (data_type_38_getflag(&f404->data_ZL)) {
                    value->d64 = data_type_38_getvalue(&f404->data_ZL);
                    plog_debug(plugin, "F404 当前正向总累积流量 = %.2f", value->d64);
                    return 0;
                }
                // 数据无效
                plog_debug(plugin, "F404数据无效");
                value->u8 = 0xEE; // 使用无效数据标识
                return 1; // 返回1表示数据存在但无效
            } else {
                plog_error(plugin, "F404数据索引超出范围: %d (有效范围: 0)", data_index);
                return -1;
            }
        }
        
        case 502: { // F502：气表运行状态字及其变位标志
            // 将数据视为Data_ONE_F502结构
            Data_ONE_F502 *f502 = (Data_ONE_F502 *)data;
            
            // 用于检查无效数据的对比值
            Data_Type_BS16 invalid_bs16 = {0};
            memset(&invalid_bs16, 0xEE, sizeof(Data_Type_BS16));
            
            // 处理S1-S4状态字的各个位（data_index范围: 0-31）
            if (data_index <= 7) {
                // S1 状态字 (data_index: 0-7)
                    // 检查是否为无效数据
                if (memcmp(&f502->S1, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                    plog_debug(plugin, "F502: S1状态字为无效数据");
                        value->u8 = 0xEE;
                    return 1; // 返回1表示数据存在但无效
                    }
                    
                    // 根据data_index返回对应位
                    switch (data_index) {
                    case 0: value->boolean = f502->S1.bit0; break;
                    case 1: value->boolean = f502->S1.bit1; break;
                    case 2: value->boolean = f502->S1.bit2; break;
                    case 3: value->boolean = f502->S1.bit3; break;
                    case 4: value->boolean = f502->S1.bit4; break;
                    case 5: value->boolean = f502->S1.bit5; break;
                    case 6: value->boolean = f502->S1.bit6; break;
                    case 7: value->boolean = f502->S1.bit7; break;
                }
                plog_debug(plugin, "F502 S1状态位[%d] = %d", data_index, value->boolean);
                return 0; // 返回0表示数据有效
            }
                else if (data_index >= 8 && data_index <= 15) {
                // S2 状态字 (data_index: 8-15)
                    // 检查是否为无效数据
                if (memcmp(&f502->S2, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                    plog_debug(plugin, "F502: S2状态字为无效数据");
                        value->u8 = 0xEE;
                    return 1; // 返回1表示数据存在但无效
                    }
                    
                    // 根据data_index返回对应位
                    switch (data_index) {
                    case 8:  value->boolean = f502->S2.bit0; break;
                    case 9:  value->boolean = f502->S2.bit1; break;
                    case 10: value->boolean = f502->S2.bit2; break;
                    case 11: value->boolean = f502->S2.bit3; break;
                    case 12: value->boolean = f502->S2.bit4; break;
                    case 13: value->boolean = f502->S2.bit5; break;
                    case 14: value->boolean = f502->S2.bit6; break;
                    case 15: value->boolean = f502->S2.bit7; break;
                }
                plog_debug(plugin, "F502 S2状态位[%d] = %d", data_index, value->boolean);
                return 0; // 返回0表示数据有效
            }
                else if (data_index >= 16 && data_index <= 23) {
                // S3 状态字 (data_index: 16-23)
                // 检查是否为无效数据
                if (memcmp(&f502->S3, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                    plog_debug(plugin, "F502: S3状态字为无效数据");
                    value->u8 = 0xEE;
                    return 1; // 返回1表示数据存在但无效
                }
                
                // 根据data_index返回对应位
                switch (data_index) {
                    case 16: value->boolean = f502->S3.bit0; break;
                    case 17: value->boolean = f502->S3.bit1; break;
                    case 18: value->boolean = f502->S3.bit2; break;
                    case 19: value->boolean = f502->S3.bit3; break;
                    case 20: value->boolean = f502->S3.bit4; break;
                    case 21: value->boolean = f502->S3.bit5; break;
                    case 22: value->boolean = f502->S3.bit6; break;
                    case 23: value->boolean = f502->S3.bit7; break;
                }
                plog_debug(plugin, "F502 S3状态位[%d] = %d", data_index, value->boolean);
                return 0; // 返回0表示数据有效
            }
            else if (data_index >= 24 && data_index <= 31) {
                // S4 状态字 (data_index: 24-31)
                    // 检查是否为无效数据
                if (memcmp(&f502->S4, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                    plog_debug(plugin, "F502: S4状态字为无效数据");
                        value->u8 = 0xEE;
                    return 1; // 返回1表示数据存在但无效
                    }
                    
                    // 根据data_index返回对应位
                    switch (data_index) {
                    case 24: value->boolean = f502->S4.bit0; break;
                    case 25: value->boolean = f502->S4.bit1; break;
                    case 26: value->boolean = f502->S4.bit2; break;
                    case 27: value->boolean = f502->S4.bit3; break;
                    case 28: value->boolean = f502->S4.bit4; break;
                    case 29: value->boolean = f502->S4.bit5; break;
                    case 30: value->boolean = f502->S4.bit6; break;
                    case 31: value->boolean = f502->S4.bit7; break;
                }
                plog_debug(plugin, "F502 S4状态位[%d] = %d", data_index, value->boolean);
                return 0; // 返回0表示数据有效
            }
            else if (data_index >= 32 && data_index <= 63) {
                // 变位标志处理 (BWS1-BWS4) (data_index: 32-63)
                // 变位标志通常不直接读取，这里简化实现
                plog_debug(plugin, "F502: 变位标志不支持直接读取 (data_index=%d)", data_index);
                value->u8 = 0xEE;
                return 1; // 返回1表示数据存在但无效
            }
            else {
                plog_error(plugin, "F502数据索引超出范围: %d (有效范围: 0-63)", data_index);
        return -1;
            }
            break;
        }
        
        case 503: { // F503：气表当前流速、压力、温度
            // 将数据视为Data_ONE_F503结构
            Data_ONE_F503 *f503 = (Data_ONE_F503 *)data;
            
            // 根据data_index获取不同的数据项
            switch (data_index) {
                case 0: // 当前气体流速(标况)
                    if (data_type_29_getflag(&f503->data_BL)) {
                        value->f32 = data_type_29_getvalue(&f503->data_BL);
                        plog_debug(plugin, "F503 标况气体流速 = %.2f", value->f32);
                    return 0;
                }
                    break;
                    
                case 1: // 当前气体流速(工况)
                    if (data_type_29_getflag(&f503->data_GL)) {
                        value->f32 = data_type_29_getvalue(&f503->data_GL);
                        plog_debug(plugin, "F503 工况气体流速 = %.2f", value->f32);
                    return 0;
                }
                    break;
                    
                case 2: // 压力
                    if (data_type_37_getflag(&f503->data_P)) {
                        value->f32 = data_type_37_getvalue(&f503->data_P);
                        plog_debug(plugin, "F503 压力 = %.2f", value->f32);
                    return 0;
                }
                    break;
                    
                case 3: // 温度
                    if (data_type_37_getflag(&f503->data_T)) {
                        value->f32 = data_type_37_getvalue(&f503->data_T);
                        plog_debug(plugin, "F503 温度 = %.2f", value->f32);
                        return 0;
            }
            break;
                    
                default:
                    plog_error(plugin, "F503数据索引超出范围: %d (有效范围: 0-3)", data_index);
                    return -1;
            }
            
            // 数据无效
            plog_debug(plugin, "F503数据无效: index=%d", data_index);
            value->u8 = 0xEE; // 使用无效数据标识
            return 1; // 返回1表示数据存在但无效
        }
        
        case 504: { // F504：气表当前正向总累积流量示值
            // 将数据视为Data_ONE_F504结构
            Data_ONE_F504 *f504 = (Data_ONE_F504 *)data;
            
            // 处理data_index
            switch (data_index) {
                case 0: // 当前正向总累积流量（标况）
                    if (data_type_38_getflag(&f504->data_BL)) {
                        value->d64 = data_type_38_getvalue(&f504->data_BL);
                        plog_debug(plugin, "F504 当前标况正向总累积流量 = %.2f", value->d64);
                        return 0;
                    }
                    break;
                    
                case 1: // 当前正向总累积流量（工况）
                    if (data_type_38_getflag(&f504->data_GL)) {
                        value->d64 = data_type_38_getvalue(&f504->data_GL);
                        plog_debug(plugin, "F504 当前工况正向总累积流量 = %.2f", value->d64);
                        return 0;
                    }
                    break;
                    
                default:
                    plog_error(plugin, "F504数据索引超出范围: %d (有效范围: 0-1)", data_index);
                    return -1;
            }
            
            // 数据无效
            plog_debug(plugin, "F504数据无效: index=%d", data_index);
            value->u8 = 0xEE; // 使用无效数据标识
            return 1; // 返回1表示数据存在但无效
        }
        
        case 602: { // F602：热量表运行状态字及其变位标志
            // 将数据视为Data_ONE_F602结构
            Data_ONE_F602 *f602 = (Data_ONE_F602 *)data;
            
            // 用于检查无效数据的对比值
            Data_Type_BS16 invalid_bs16 = {0};
            memset(&invalid_bs16, 0xEE, sizeof(Data_Type_BS16));
            
            // 处理S1-S4状态字的各个位（data_index范围: 0-31）
            if (data_index <= 7) {
                // S1 状态字 (data_index: 0-7)
                    // 检查是否为无效数据
                if (memcmp(&f602->S1, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                    plog_debug(plugin, "F602: S1状态字为无效数据");
                        value->u8 = 0xEE;
                    return 1; // 返回1表示数据存在但无效
                    }
                    
                    // 根据data_index返回对应位
                    switch (data_index) {
                    case 0: value->boolean = f602->S1.bit0; break;
                    case 1: value->boolean = f602->S1.bit1; break;
                    case 2: value->boolean = f602->S1.bit2; break;
                    case 3: value->boolean = f602->S1.bit3; break;
                    case 4: value->boolean = f602->S1.bit4; break;
                    case 5: value->boolean = f602->S1.bit5; break;
                    case 6: value->boolean = f602->S1.bit6; break;
                    case 7: value->boolean = f602->S1.bit7; break;
                }
                plog_debug(plugin, "F602 S1状态位[%d] = %d", data_index, value->boolean);
                return 0; // 返回0表示数据有效
            }
                else if (data_index >= 8 && data_index <= 15) {
                // S2 状态字 (data_index: 8-15)
                    // 检查是否为无效数据
                if (memcmp(&f602->S2, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                    plog_debug(plugin, "F602: S2状态字为无效数据");
                        value->u8 = 0xEE;
                    return 1; // 返回1表示数据存在但无效
                    }
                    
                    // 根据data_index返回对应位
                    switch (data_index) {
                    case 8:  value->boolean = f602->S2.bit0; break;
                    case 9:  value->boolean = f602->S2.bit1; break;
                    case 10: value->boolean = f602->S2.bit2; break;
                    case 11: value->boolean = f602->S2.bit3; break;
                    case 12: value->boolean = f602->S2.bit4; break;
                    case 13: value->boolean = f602->S2.bit5; break;
                    case 14: value->boolean = f602->S2.bit6; break;
                    case 15: value->boolean = f602->S2.bit7; break;
                }
                plog_debug(plugin, "F602 S2状态位[%d] = %d", data_index, value->boolean);
                return 0; // 返回0表示数据有效
            }
                else if (data_index >= 16 && data_index <= 23) {
                // S3 状态字 (data_index: 16-23)
                // 检查是否为无效数据
                if (memcmp(&f602->S3, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                    plog_debug(plugin, "F602: S3状态字为无效数据");
                    value->u8 = 0xEE;
                    return 1; // 返回1表示数据存在但无效
                }
                
                // 根据data_index返回对应位
                switch (data_index) {
                    case 16: value->boolean = f602->S3.bit0; break;
                    case 17: value->boolean = f602->S3.bit1; break;
                    case 18: value->boolean = f602->S3.bit2; break;
                    case 19: value->boolean = f602->S3.bit3; break;
                    case 20: value->boolean = f602->S3.bit4; break;
                    case 21: value->boolean = f602->S3.bit5; break;
                    case 22: value->boolean = f602->S3.bit6; break;
                    case 23: value->boolean = f602->S3.bit7; break;
                }
                plog_debug(plugin, "F602 S3状态位[%d] = %d", data_index, value->boolean);
                return 0; // 返回0表示数据有效
            }
            else if (data_index >= 24 && data_index <= 31) {
                // S4 状态字 (data_index: 24-31)
                    // 检查是否为无效数据
                if (memcmp(&f602->S4, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                    plog_debug(plugin, "F602: S4状态字为无效数据");
                        value->u8 = 0xEE;
                    return 1; // 返回1表示数据存在但无效
                    }
                    
                    // 根据data_index返回对应位
                    switch (data_index) {
                    case 24: value->boolean = f602->S4.bit0; break;
                    case 25: value->boolean = f602->S4.bit1; break;
                    case 26: value->boolean = f602->S4.bit2; break;
                    case 27: value->boolean = f602->S4.bit3; break;
                    case 28: value->boolean = f602->S4.bit4; break;
                    case 29: value->boolean = f602->S4.bit5; break;
                    case 30: value->boolean = f602->S4.bit6; break;
                    case 31: value->boolean = f602->S4.bit7; break;
                }
                plog_debug(plugin, "F602 S4状态位[%d] = %d", data_index, value->boolean);
                return 0; // 返回0表示数据有效
            }
            else if (data_index >= 32 && data_index <= 63) {
                // 变位标志处理 (BWS1-BWS4) (data_index: 32-63)
                // 变位标志通常不直接读取，这里简化实现
                plog_debug(plugin, "F602: 变位标志不支持直接读取 (data_index=%d)", data_index);
                value->u8 = 0xEE;
                return 1; // 返回1表示数据存在但无效
            }
            else {
                plog_error(plugin, "F602数据索引超出范围: %d (有效范围: 0-63)", data_index);
                return -1;
            }
            break;
        }
        
        case 603: { // F603：热量表累积流量、热量、冷量，温度、流速、压力
            // 将数据视为Data_ONE_F603结构
            Data_ONE_F603 *f603 = (Data_ONE_F603 *)data;
            
            // 根据data_index获取不同的数据项
            switch (data_index) {
                case 0: // 累积流量
                    if (data_type_38_getflag(&f603->data_SL)) {
                        value->d64 = data_type_38_getvalue(&f603->data_SL);
                        plog_debug(plugin, "F603 累积流量 = %.2f", value->d64);
                    return 0;
                }
                    break;
                    
                case 1: // 累积热量
                    if (data_type_38_getflag(&f603->data_SH)) {
                        value->d64 = data_type_38_getvalue(&f603->data_SH);
                        plog_debug(plugin, "F603 累积热量 = %.2f", value->d64);
                        return 0;
                    }
                    break;
                    
                case 2: // 累积冷量
                    if (data_type_38_getflag(&f603->data_SC)) {
                        value->d64 = data_type_38_getvalue(&f603->data_SC);
                        plog_debug(plugin, "F603 累积冷量 = %.2f", value->d64);
                        return 0;
                    }
                    break;
                    
                case 3: // 当前供水温度
                    if (data_type_36_getflag(&f603->data_GT)) {
                        value->f32 = data_type_36_getvalue(&f603->data_GT);
                        plog_debug(plugin, "F603 当前供水温度 = %.2f", value->f32);
                        return 0;
                    }
                    break;
                    
                case 4: // 当前回水温度
                    if (data_type_36_getflag(&f603->data_HT)) {
                        value->f32 = data_type_36_getvalue(&f603->data_HT);
                        plog_debug(plugin, "F603 当前回水温度 = %.2f", value->f32);
                    return 0;
                }
                    break;
                    
                case 5: // 当前流速
                    if (data_type_29_getflag(&f603->data_L)) {
                        value->f32 = data_type_29_getvalue(&f603->data_L);
                        plog_debug(plugin, "F603 当前流速 = %.2f", value->f32);
                        return 0;
            }
            break;
                    
                case 6: // 压力
                    if (data_type_37_getflag(&f603->data_P)) {
                        value->f32 = data_type_37_getvalue(&f603->data_P);
                        plog_debug(plugin, "F603 压力 = %.2f", value->f32);
                        return 0;
                    }
                    break;
                    
                default:
                    plog_error(plugin, "F603数据索引超出范围: %d (有效范围: 0-6)", data_index);
                    return -1;
            }
            
            // 数据无效
            plog_debug(plugin, "F603数据无效: index=%d", data_index);
            value->u8 = 0xEE; // 使用无效数据标识
            return 1; // 返回1表示数据存在但无效
        }
        
        case 701: { // F701：RTU遥信数据
            // 跳过时间戳
            const uint8_t *yxdata = data + sizeof(GB_12241_MHDMYTIME);
            size_t available_data_len = data_unit_size - sizeof(GB_12241_MHDMYTIME);
            uint16_t invalid_word = 0xEEEE;
            
            // 首先检查数据有效性 - 只有当数据长度至少为4个字节时才检查
            bool is_data_valid = true;
            if (available_data_len >= 4) {
                // 检查前4个字节是否都是无效值
                if ((memcmp(yxdata, &invalid_word, 2) == 0) && 
                    (memcmp(yxdata + 2, &invalid_word, 2) == 0)) {
                    is_data_valid = false;
                    plog_notice(plugin, "F701 遥信数据无效: 前4个字节均为无效值0xEEEE");
                }
            }
            
            if (!is_data_valid) {
                value->u8 = 0xEE;
                return 1; // 数据存在但无效
            }
            
            // 计算位索引
            int byte_index = data_index / 8;
            int bit_index = data_index % 8;
            
            // 检查索引范围
            if ((size_t)byte_index < available_data_len) {
                // 提取对应位的值
                value->boolean = (yxdata[byte_index] >> bit_index) & 0x01;
                plog_debug(plugin, "F701 遥信[%d] = %d (字节%d位%d)", 
                        data_index, value->boolean, byte_index, bit_index);
                return 0; // 数据有效
            } else {
                plog_error(plugin, "F701 遥信索引超出范围: 索引=%d, 最大字节数=%zu", 
                        byte_index, available_data_len);
                value->u8 = 0xEE;
                return -1; // 索引无效
            }
            break;
        }
        
        case 702: { // F702：RTU遥测数据
            // 跳过时间戳
            const uint8_t *ycdata = data + sizeof(GB_12241_MHDMYTIME);
            size_t available_data_len = data_unit_size - sizeof(GB_12241_MHDMYTIME);
            size_t data_type_40_size = sizeof(Data_Type_40);
            int yc_count = available_data_len / data_type_40_size;
            
            // 检查遥测点索引是否在范围内
            if (data_index < yc_count) {
                // 获取对应的Data_Type_40结构
                Data_Type_40 *data40 = (Data_Type_40 *)(ycdata + data_index * data_type_40_size);
                
                // 检查数据有效性
                if (data_type_40_getflag(data40)) {
                    value->d64 = data_type_40_getvalue(data40);
                    plog_debug(plugin, "F702 遥测[%d] = %.2f", data_index, value->d64);
                    return 0; // 数据有效
                } else {
                    plog_notice(plugin, "F702 遥测数据无效: index=%d", data_index);
                    value->u8 = 0xEE;
                    return 1; // 数据存在但无效
                }
            } else {
                plog_error(plugin, "F702 遥测索引超出范围: %d (总点数: %d)", data_index, yc_count);
                return -1; // 索引无效
            }
            break;
        }
        
        case 703: { // F703：RTU电度数据
            // 跳过时间戳
            const uint8_t *kwhdata = data + sizeof(GB_12241_MHDMYTIME);
            size_t available_data_len = data_unit_size - sizeof(GB_12241_MHDMYTIME);
            size_t data_type_40_size = sizeof(Data_Type_40);
            int kwh_count = available_data_len / data_type_40_size;
            
            // 检查电度点索引是否在范围内
            if (data_index < kwh_count) {
                // 获取对应的Data_Type_40结构
                Data_Type_40 *data40 = (Data_Type_40 *)(kwhdata + data_index * data_type_40_size);
                
                // 检查数据有效性
                if (data_type_40_getflag(data40)) {
                    value->d64 = data_type_40_getvalue(data40);
                    plog_debug(plugin, "F703 电度[%d] = %.2f", data_index, value->d64);
                    return 0; // 数据有效
                } else {
                    plog_notice(plugin, "F703 电度数据无效: index=%d", data_index);
                    value->u8 = 0xEE;
                    return 1; // 数据存在但无效
                }
            } else {
                plog_error(plugin, "F703 电度索引超出范围: %d (总点数: %d)", data_index, kwh_count);
                return -1; // 索引无效
            }
            break;
        }
        
        default: {
            // 对于其他功能码，使用数据类型映射获取相应处理函数
            plog_debug(plugin, "未优化处理的功能码: FN=%u", fn);
            return -1; // 无法提取有效值
        }
    }
    
    return -1; // 无法提取有效值
}

// 检查功能码是否需要单独发送（特殊功能码如701、702、703需要单独发送）
static bool is_special_fn(uint16_t fn) {
    // 特殊功能码列表，这些功能码需要单独一帧发送
    static const uint16_t special_fns[] = {701, 702, 703};
    static const size_t special_fns_count = sizeof(special_fns) / sizeof(special_fns[0]);
    
    for (size_t i = 0; i < special_fns_count; i++) {
        if (fn == special_fns[i]) {
            return true;
        }
    }
    
    return false;
}

