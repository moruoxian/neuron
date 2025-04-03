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

/* 12241协议头部结构 */
struct GB_12241_header {
    uint8_t  start_flag;   // 起始标志，固定为0x68
    uint16_t data_len;     // 数据区长度
    uint8_t  control_code; // 控制码
    uint16_t seq;          // 序列号
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

#endif /* _NEU_M_PLUGIN_12241_H_ */ 