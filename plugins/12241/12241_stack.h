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
#ifndef _NEU_M_PLUGIN_12241_STACK_H_
#define _NEU_M_PLUGIN_12241_STACK_H_

#include <neuron.h>

// 最大数据区长度
#define GB_12241_MAX_DATA_SIZE    1024
// 最大寄存器数量
#define GB_12241_MAX_REG_LENGTH   128

// 12241请求结构
typedef struct GB_12241_stack_req {
    uint16_t device_addr;  // 设备地址
    uint8_t  function;     // 功能码
    uint16_t start_addr;   // 起始地址
    uint16_t quantity;     // 数量
    uint16_t byte_size;    // 字节大小
    uint8_t  data[GB_12241_MAX_DATA_SIZE]; // 数据
} GB_12241_stack_req_t;

// 12241响应结构
typedef struct GB_12241_stack_resp {
    uint16_t device_addr;  // 设备地址
    uint8_t  function;     // 功能码
    uint16_t byte_count;   // 字节数
    uint8_t  data[GB_12241_MAX_DATA_SIZE]; // 数据
} GB_12241_stack_resp_t;

// 创建请求
neu_plugin_t *GB_12241_stack_create(void);

// 销毁请求
void GB_12241_stack_destroy(neu_plugin_t *plugin);

// 编码读请求
int GB_12241_encode_read_req(neu_plugin_t *plugin, GB_12241_stack_req_t *req,
                           uint8_t *buf, size_t buf_size, uint16_t seq);

// 编码写请求
int GB_12241_encode_write_req(neu_plugin_t *plugin, GB_12241_stack_req_t *req,
                            uint8_t *buf, size_t buf_size, uint16_t seq);

// 解码读响应
int GB_12241_decode_read_resp(neu_plugin_t *plugin, uint8_t *buf, size_t buf_size,
                            GB_12241_stack_resp_t *resp);

// 解码写响应
int GB_12241_decode_write_resp(neu_plugin_t *plugin, uint8_t *buf, size_t buf_size,
                             GB_12241_stack_resp_t *resp);

#endif /* _NEU_M_PLUGIN_12241_STACK_H_ */ 