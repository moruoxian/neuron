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
#ifndef _NEU_M_PLUGIN_12241_H_
#define _NEU_M_PLUGIN_12241_H_

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <neuron.h>

/* 定义12241协议的功能码 */
typedef enum GB_12241_function {
    GB_12241_READ_DATA        = 0x01,  // 读数据
    GB_12241_WRITE_DATA       = 0x02,  // 写数据
    GB_12241_READ_PARAM       = 0x03,  // 读参数
    GB_12241_WRITE_PARAM      = 0x04,  // 写参数
    GB_12241_EXEC_COMMAND     = 0x05,  // 执行命令
    GB_12241_READ_STATUS      = 0x06,  // 读状态
    GB_12241_READ_ERROR       = 0x81,  // 读错误
    GB_12241_WRITE_ERROR      = 0x82,  // 写错误
    GB_12241_PARAM_READ_ERROR = 0x83,  // 参数读错误
    GB_12241_PARAM_WRITE_ERROR = 0x84, // 参数写错误
    GB_12241_COMMAND_ERROR    = 0x85,  // 命令执行错误
    GB_12241_STATUS_READ_ERROR = 0x86, // 状态读错误
    GB_12241_DEVICE_ERR       = -2
} GB_12241_function_e;

/* 定义12241协议的数据类型 */
typedef enum GB_12241_data_type {
    GB_12241_TYPE_BIT    = 0,  // 位类型
    GB_12241_TYPE_BYTE   = 1,  // 字节类型
    GB_12241_TYPE_WORD   = 2,  // 字类型
    GB_12241_TYPE_DWORD  = 3,  // 双字类型
    GB_12241_TYPE_FLOAT  = 4,  // 浮点数类型
    GB_12241_TYPE_STRING = 5,  // 字符串类型
} GB_12241_data_type_e;

/* 定义12241协议的数据区域 */
typedef enum GB_12241_area {
    GB_12241_AREA_DATA   = 0, // 数据区
    GB_12241_AREA_PARAM  = 1, // 参数区
    GB_12241_AREA_STATUS = 2, // 状态区
} GB_12241_area_e;

/* 定义12241协议的字节序 */
typedef enum GB_12241_endianess {
    GB_12241_ABCD = 1, // 大端序(MSB)
    GB_12241_BADC = 2, // 混合字节序1
    GB_12241_DCBA = 3, // 小端序(LSB)
    GB_12241_CDAB = 4, // 混合字节序2
} GB_12241_endianess;

/* 定义12241协议的地址基准 */
typedef enum GB_12241_address_base {
    base_0 = 0, // 0基准
    base_1 = 1, // 1基准
} GB_12241_address_base;

/* 定义12241协议的AFN功能码 */
typedef enum GB_12241_AFN {
    GB_12241_AFN_CONFIRM    = 0x00,  // 确认/否认
    GB_12241_AFN_RESET      = 0x01,  // 复位命令
    GB_12241_AFN_LINK       = 0x02,  // 链路接口检测
    GB_12241_AFN_RELAY      = 0x03,  // 中继转发
    GB_12241_AFN_SETPARAM   = 0x04,  // 设置参数
    GB_12241_AFN_CTRL       = 0x05,  // 控制命令
    GB_12241_AFN_AUTH       = 0x06,  // 身份认证
    GB_12241_AFN_GETPARAM   = 0x0A,  // 读取参数
    GB_12241_AFN_REALDATA   = 0x0C,  // 读取当前数据（一类数据）
    GB_12241_AFN_HISTDATA   = 0x0D,  // 读取历史数据（二类数据）
    GB_12241_AFN_FILE       = 0x0F,  // 文件传输
} GB_12241_AFN_e;

/* 12241协议头部结构 */
struct GB_12241_header {
    uint8_t  start_flag;   // 起始标志，固定为0x68
    uint16_t data_len;     // 数据区长度
    uint8_t  afn;          // 应用功能码AFN
    uint16_t seq;          // 序列号
    uint8_t  fn;           // 信息点Fn
    uint16_t pn;           // 信息点Pn
} __attribute__((packed));

void GB_12241_header_wrap(neu_protocol_pack_buf_t *buf, uint16_t seq);
int  GB_12241_header_unwrap(neu_protocol_unpack_buf_t *buf,
                           struct GB_12241_header *out_header);

/* 12241地址结构 */
struct GB_12241_address {
    uint16_t device_addr;   // 设备地址
    uint16_t start_address; // 起始地址
    uint16_t data_len;      // 数据长度
} __attribute__((packed));

void GB_12241_address_wrap(neu_protocol_pack_buf_t *buf, uint16_t device_addr,
                          uint16_t start, uint16_t data_len);
int  GB_12241_address_unwrap(neu_protocol_unpack_buf_t *buf,
                            struct GB_12241_address *out_address);

/* 12241数据结构 */
struct GB_12241_data {
    uint16_t data_len;     // 数据长度
    uint8_t  data_type;    // 数据类型
    uint8_t  data[];       // 数据内容
} __attribute__((packed));

void GB_12241_data_wrap(neu_protocol_pack_buf_t *buf, uint16_t data_len,
                       uint8_t *data);
int  GB_12241_data_unwrap(neu_protocol_unpack_buf_t *buf,
                         struct GB_12241_data *out_data);

/* 12241校验结构 */
struct GB_12241_crc {
    uint16_t crc; // CRC校验值
} __attribute__((packed));

void GB_12241_crc_set(neu_protocol_pack_buf_t *buf);
void GB_12241_crc_wrap(neu_protocol_pack_buf_t *buf);
int  GB_12241_crc_unwrap(neu_protocol_unpack_buf_t *buf,
                        struct GB_12241_crc *out_crc);

const char *GB_12241_area_to_str(GB_12241_area_e area);

// 数据格式定义
// 附录A.6 - 频率格式 (2字节)
typedef struct {
    uint16_t value;  // 频率值，单位0.01Hz
} __attribute__((packed)) GB_12241_freq_t;

// 附录A.15 - 时间格式 (5字节)
typedef struct {
    uint8_t minute;  // 分钟
    uint8_t hour;    // 小时
    uint8_t day;     // 日
    uint8_t month;   // 月
    uint8_t year;    // 年
} __attribute__((packed)) GB_12241_time_t;

// 附录A.13 - 电能量格式 (4字节)
typedef struct {
    uint32_t value;  // 电能量值，单位0.01kWh
} __attribute__((packed)) GB_12241_energy_t;

// 附录A.8 - 电压格式 (2字节)
typedef struct {
    uint16_t value;  // 电压值，单位0.1V
} __attribute__((packed)) GB_12241_voltage_t;

// 附录A.9 - 电流格式 (3字节)
typedef struct {
    uint8_t value[3];  // 电流值，单位0.001A
} __attribute__((packed)) GB_12241_current_t;

// 附录A.10 - 功率格式 (3字节)
typedef struct {
    uint8_t value[3];  // 功率值，单位0.0001kW
} __attribute__((packed)) GB_12241_power_t;

// 附录A.11 - 功率因数格式 (2字节)
typedef struct {
    int16_t value;  // 功率因数值，单位0.001
} __attribute__((packed)) GB_12241_power_factor_t;

// F901数据结构
typedef struct {
    GB_12241_time_t time;    // 终端抄表时间
    GB_12241_freq_t freq;    // 电网频率
} __attribute__((packed)) GB_12241_F901_t;

// F701数据结构 (遥信状态)
typedef struct {
    uint16_t phase_a_status;  // A相状态字
    uint16_t phase_b_status;  // B相状态字
    uint16_t phase_c_status;  // C相状态字
    uint16_t system_status;   // 系统状态字
} __attribute__((packed)) GB_12241_F701_t;

// F702数据结构 (遥测数据)
typedef struct {
    GB_12241_power_t total_active_power;         // 总有功功率
    GB_12241_power_t phase_active_power[3];      // 分相有功功率
    GB_12241_power_t total_reactive_power;       // 总无功功率
    GB_12241_power_t phase_reactive_power[3];    // 分相无功功率
    GB_12241_power_factor_t total_power_factor;  // 总功率因数
    GB_12241_power_factor_t phase_power_factor[3]; // 分相功率因数
    GB_12241_voltage_t phase_voltage[3];         // 分相电压
    GB_12241_current_t phase_current[3];         // 分相电流
    GB_12241_current_t zero_sequence_current;    // 零序电流
} __attribute__((packed)) GB_12241_F702_t;

// F703数据结构 (电能量数据)
typedef struct {
    GB_12241_energy_t forward_active_total;     // 正向有功总电能量
    GB_12241_energy_t forward_active_peak;      // 正向有功尖峰电能量
    GB_12241_energy_t forward_active_valley;    // 正向有功谷电能量
    GB_12241_energy_t forward_active_flat;      // 正向有功平电能量
    GB_12241_energy_t reverse_active_total;     // 反向有功总电能量
    GB_12241_energy_t reverse_active_peak;      // 反向有功尖峰电能量
    GB_12241_energy_t reverse_active_valley;    // 反向有功谷电能量
    GB_12241_energy_t reverse_active_flat;      // 反向有功平电能量
} __attribute__((packed)) GB_12241_F703_t;

// 数据转换函数声明
float GB_12241_freq_to_float(GB_12241_freq_t freq);
float GB_12241_voltage_to_float(GB_12241_voltage_t voltage);
float GB_12241_current_to_float(GB_12241_current_t current);
float GB_12241_power_to_float(GB_12241_power_t power);
float GB_12241_power_factor_to_float(GB_12241_power_factor_t pf);
float GB_12241_energy_to_float(GB_12241_energy_t energy);

// 时标结构定义
typedef struct {
    uint8_t second;  // 秒 0-59
    uint8_t minute;  // 分 0-59
    uint8_t hour;    // 时 0-23
    uint8_t day;     // 日 1-31
    uint8_t month;   // 月 1-12
    uint8_t year;    // 年 0-99
} GB_12241_timestamp_t;

// 带时标的数据结构
typedef struct {
    GB_12241_timestamp_t timestamp;  // 数据时标
    uint8_t data_type;              // 数据类型
    uint16_t data_len;              // 数据长度
    uint8_t data[];                 // 数据内容
} GB_12241_timestamped_data_t;

// 时标转换函数声明
void GB_12241_timestamp_to_time(const GB_12241_timestamp_t* ts, time_t* time);
void GB_12241_time_to_timestamp(time_t time, GB_12241_timestamp_t* ts);

#endif /* _NEU_M_PLUGIN_12241_H_ */ 