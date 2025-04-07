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
#include <stdbool.h>
#include <stdint.h>

#include "12241.h"

// 数据类型定义
typedef enum {
    GB_12241_TYPE_BIT    = 0,  // 位
    GB_12241_TYPE_BYTE   = 1,  // 字节
    GB_12241_TYPE_WORD   = 2,  // 字
    GB_12241_TYPE_DWORD  = 3,  // 双字
    GB_12241_TYPE_FLOAT  = 4,  // 浮点数
} GB_12241_data_type_e;

// 点位结构
typedef struct {
    uint16_t pn;           // 测量点号
    uint8_t  fn;           // 功能码
    uint16_t data_no;      // 数据项编号
    int8_t   bit_offset;   // 位偏移，-1表示不是位操作
    uint8_t  data_type;    // 数据类型
    uint16_t length;       // 数据长度
    uint16_t byte_size;    // 字节大小
} GB_12241_point_t;

/* 点位地址格式：
 * {pn}!F{fn}#{data_no}[.{bit}]
 * 示例：
 * 0!F2#0.0    - P0，F2点位，数据项0，第0位(DI0)
 * 0!F2#0.1    - P0，F2点位，数据项0，第1位(DI1)
 * 0!F2#1      - P0，F2点位，数据项1(电池电压)
 */

// 解析点位地址字符串
int GB_12241_parse_point(const char *addr_str, GB_12241_point_t *point);

// 创建点位地址字符串
int GB_12241_create_point(char *addr_str, size_t size, 
                         const GB_12241_point_t *point);

// 获取数据类型的字节大小
uint16_t GB_12241_get_type_size(uint8_t data_type);

// 计算点位数据的总字节大小
uint16_t GB_12241_calc_byte_size(uint8_t data_type, uint16_t length);

// 读取单个位值
bool GB_12241_read_bit(const uint8_t *data, uint8_t bit_offset);

// 读取多个位值
int GB_12241_read_bits(const uint8_t *data, uint16_t offset, 
                      uint16_t length, bool *values);

// 读取浮点数值
float GB_12241_read_float(const uint8_t *data);

// 读取多个浮点数值
int GB_12241_read_floats(const uint8_t *data, uint16_t offset,
                        uint16_t length, float *values);

// 读取双字整数值
uint32_t GB_12241_read_dword(const uint8_t *data);

// 读取多个双字整数值
int GB_12241_read_dwords(const uint8_t *data, uint16_t offset,
                        uint16_t length, uint32_t *values);

// 获取点位的数据大小
int GB_12241_get_data_size(GB_12241_point_t *point);

/* F25点位创建函数 */
int GB_12241_create_F25_point(char *addr_str, size_t size, uint16_t dev_addr,
                             uint16_t pn);

/* F403点位创建函数 */
int GB_12241_create_F403_point(char *addr_str, size_t size, uint16_t dev_addr,
                              uint16_t pn);

/* F503点位创建函数 */
int GB_12241_create_F503_point(char *addr_str, size_t size, uint16_t dev_addr,
                              uint16_t pn);

#endif /* _NEU_M_PLUGIN_12241_POINT_H_ */ 