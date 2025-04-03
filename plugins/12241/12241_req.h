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
#ifndef _NEU_M_PLUGIN_12241_REQ_H_
#define _NEU_M_PLUGIN_12241_REQ_H_

#include <neuron.h>

#include "12241.h"
#include "12241_point.h"

typedef struct GB_12241_req {
    GB_12241_point_t              *points;      // 点位
    uint16_t                      n_point;      // 点位数量
    uint8_t                       function;     // 功能码
    uint16_t                      dev_addr;     // 设备地址
    uint16_t                      start_addr;   // 起始地址
    uint16_t                      n_register;   // 寄存器数量
    GB_12241_area_e               area;         // 数据区域
    uint16_t                      byte_size;    // 字节大小
    uint16_t                      group;        // 分组
    struct neu_datatag_value_item *value_items; // 值数组
    uint16_t                      n_value;      // 值数量
    UT_hash_handle                hh;           // hash表句柄
} GB_12241_req_t;

// 创建请求
neu_plugin_t *    GB_12241_req_create(void);

// 销毁请求
void              GB_12241_req_destroy(neu_plugin_t *plugin);

// 构建读取请求
int               GB_12241_req_build_read(neu_plugin_t *plugin, neu_reqresp_head_t *head,
                                         uint8_t *buf, size_t buf_size);

// 解析读取响应
int               GB_12241_req_parse_read(neu_plugin_t *plugin, neu_reqresp_head_t *head,
                                         uint8_t *buf, size_t buf_size);

// 生成写请求
int               GB_12241_req_build_write(neu_plugin_t *plugin, neu_reqresp_head_t *head,
                                          uint8_t *buf, size_t buf_size);

// 解析写响应
int               GB_12241_req_parse_write(neu_plugin_t *plugin, neu_reqresp_head_t *head,
                                          uint8_t *buf, size_t buf_size);

// 添加点位
int               GB_12241_req_add_point(neu_plugin_t *plugin, const neu_datatag_t *tag);

// 处理点位
int               GB_12241_req_process_tags(neu_plugin_t *plugin, neu_req_tag_list_t *req);

// 添加写请求
int               GB_12241_req_add_write(neu_plugin_t *plugin, uint16_t dev_addr, uint16_t start,
                                        GB_12241_function_e function, uint8_t *data,
                                        uint16_t size);

// 清除请求
void              GB_12241_req_clean(neu_plugin_t *plugin);

#endif /* _NEU_M_PLUGIN_12241_REQ_H_ */ 