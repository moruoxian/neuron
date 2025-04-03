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
#ifndef _NEU_M_PLUGIN_12241_POINT_H_
#define _NEU_M_PLUGIN_12241_POINT_H_

#include <neuron.h>

#include "12241.h"

typedef enum GB_12241_point_type {
    GB_12241_POINT_UINT8   = 0, // 8位无符号整数
    GB_12241_POINT_INT8    = 1, // 8位有符号整数
    GB_12241_POINT_UINT16  = 2, // 16位无符号整数
    GB_12241_POINT_INT16   = 3, // 16位有符号整数
    GB_12241_POINT_UINT32  = 4, // 32位无符号整数
    GB_12241_POINT_INT32   = 5, // 32位有符号整数
    GB_12241_POINT_FLOAT32 = 6, // 32位浮点数
    GB_12241_POINT_UINT64  = 7, // 64位无符号整数
    GB_12241_POINT_INT64   = 8, // 64位有符号整数
    GB_12241_POINT_FLOAT64 = 9, // 64位浮点数
    GB_12241_POINT_BIT     = 10, // 位
    GB_12241_POINT_BOOL    = 11, // 布尔值
    GB_12241_POINT_STRING  = 12, // 字符串
} GB_12241_point_type_e;

typedef struct GB_12241_point {
    uint16_t                dev_addr;        // 设备地址
    uint16_t                area;            // 区域
    uint16_t                reg_addr;        // 寄存器地址
    uint8_t                 function;        // 功能码
    uint8_t                 bit_offset;      // 位偏移
    uint16_t                byte_size;       // 字节大小
    GB_12241_endianess      endian;          // 字节序
    GB_12241_point_type_e   type;            // 数据类型
    double                  write_value;     // 写入的值
    bool                    write_value_set; // 是否设置了写入值
} GB_12241_point_t;

// 解析点位地址字符串
int GB_12241_parse_point(const char *str, neu_datatag_addr_t *addr,
                       GB_12241_point_t *point, GB_12241_address_base base,
                       GB_12241_endianess endian);

// 解析读取数据值
int GB_12241_value_read(GB_12241_point_t *point, uint8_t *src, void *value);

// 解析写入数据值
int GB_12241_value_write(GB_12241_point_t *point, double src, uint8_t *dest);

// 获取点位的数据大小
int GB_12241_get_data_size(GB_12241_point_t *point);

#endif /* _NEU_M_PLUGIN_12241_POINT_H_ */ 