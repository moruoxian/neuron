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
#include <stdlib.h>
#include <string.h>

#include <neuron.h>

#include "12241.h"
#include "12241_stack.h"

typedef struct GB_12241_stack {
    uint8_t buffer[GB_12241_MAX_DATA_SIZE]; // 缓冲区
} GB_12241_stack_t;

neu_plugin_t *GB_12241_stack_create(void)
{
    GB_12241_stack_t *stack = calloc(1, sizeof(GB_12241_stack_t));
    return (neu_plugin_t *) stack;
}

void GB_12241_stack_destroy(neu_plugin_t *plugin)
{
    GB_12241_stack_t *stack = (GB_12241_stack_t *) plugin;
    free(stack);
}

// 编码读请求
int GB_12241_encode_read_req(neu_plugin_t *plugin, GB_12241_stack_req_t *req,
                           uint8_t *buf, size_t buf_size, uint16_t seq)
{
    neu_protocol_pack_buf_t pack_buf = { 0 };
    neu_protocol_pack_buf_init(&pack_buf, buf, buf_size);

    // 封装报文头
    GB_12241_header_wrap(&pack_buf, seq);

    // 编码地址和功能码
    GB_12241_address_wrap(&pack_buf, req->device_addr, req->start_addr, req->quantity);

    // 计算并添加CRC校验
    GB_12241_crc_wrap(&pack_buf);

    // 记录日志
    GB_12241_log_request(req, buf, pack_buf.pos);

    return pack_buf.pos;
}

// 编码写请求
int GB_12241_encode_write_req(neu_plugin_t *plugin, GB_12241_stack_req_t *req,
                            uint8_t *buf, size_t buf_size, uint16_t seq)
{
    neu_protocol_pack_buf_t pack_buf = { 0 };
    neu_protocol_pack_buf_init(&pack_buf, buf, buf_size);

    // 封装报文头
    GB_12241_header_wrap(&pack_buf, seq);

    // 编码地址和功能码
    GB_12241_address_wrap(&pack_buf, req->device_addr, req->start_addr, req->quantity);

    // 封装数据
    GB_12241_data_wrap(&pack_buf, req->byte_size, req->data);

    // 计算并添加CRC校验
    GB_12241_crc_wrap(&pack_buf);

    // 记录日志
    GB_12241_log_request(req, buf, pack_buf.pos);

    return pack_buf.pos;
}

// 解码读响应
int GB_12241_decode_read_resp(neu_plugin_t *plugin, uint8_t *buf, size_t buf_size,
                            GB_12241_stack_resp_t *resp)
{
    neu_protocol_unpack_buf_t unpack_buf = { 0 };
    neu_protocol_unpack_buf_init(&unpack_buf, buf, buf_size);

    struct GB_12241_header header = { 0 };
    struct GB_12241_address addr  = { 0 };
    struct GB_12241_data    data  = { 0 };
    struct GB_12241_crc     crc   = { 0 };

    // 解析报文头
    if (GB_12241_header_unwrap(&unpack_buf, &header) < 0) {
        plog_error("decode header error");
        return -1;
    }

    // 解析地址
    if (GB_12241_address_unwrap(&unpack_buf, &addr) < 0) {
        plog_error("decode address error");
        return -1;
    }

    // 解析数据
    if (GB_12241_data_unwrap(&unpack_buf, &data) < 0) {
        plog_error("decode data error");
        return -1;
    }

    // 解析CRC校验
    if (GB_12241_crc_unwrap(&unpack_buf, &crc) < 0) {
        plog_error("decode crc error");
        return -1;
    }

    // 设置响应结构
    resp->device_addr = addr.device_addr;
    resp->function = header.control_code;
    resp->byte_count = data.data_len;
    if (resp->byte_count > sizeof(resp->data)) {
        plog_error("data length too large: %u", resp->byte_count);
        return -1;
    }
    memcpy(resp->data, data.data, resp->byte_count);

    // 记录日志
    GB_12241_log_response(resp, buf, buf_size);

    return 0;
}

// 解码写响应
int GB_12241_decode_write_resp(neu_plugin_t *plugin, uint8_t *buf, size_t buf_size,
                             GB_12241_stack_resp_t *resp)
{
    neu_protocol_unpack_buf_t unpack_buf = { 0 };
    neu_protocol_unpack_buf_init(&unpack_buf, buf, buf_size);

    struct GB_12241_header header = { 0 };
    struct GB_12241_address addr  = { 0 };
    struct GB_12241_crc     crc   = { 0 };

    // 解析报文头
    if (GB_12241_header_unwrap(&unpack_buf, &header) < 0) {
        plog_error("decode header error");
        return -1;
    }

    // 解析地址
    if (GB_12241_address_unwrap(&unpack_buf, &addr) < 0) {
        plog_error("decode address error");
        return -1;
    }

    // 解析CRC校验
    if (GB_12241_crc_unwrap(&unpack_buf, &crc) < 0) {
        plog_error("decode crc error");
        return -1;
    }

    // 设置响应结构
    resp->device_addr = addr.device_addr;
    resp->function = header.control_code;
    resp->byte_count = 0;

    // 记录日志
    GB_12241_log_response(resp, buf, buf_size);

    return 0;
}

// 添加报文日志记录函数
static void GB_12241_log_request(GB_12241_stack_req_t *req, uint8_t *buf, int len)
{
    if (plog_get_level() <= NEU_PLOG_DEBUG) {
        plog_debug("GB_12241 REQ: dev=%u, func=%u, addr=%u, qty=%u, size=%u",
                 req->device_addr, req->function, req->start_addr, 
                 req->quantity, req->byte_size);
        
        char hex_buffer[1024] = {0};
        char *p = hex_buffer;
        for (int i = 0; i < len && i < 32; i++) {
            p += snprintf(p, sizeof(hex_buffer) - (p - hex_buffer), 
                          "%02X ", buf[i]);
        }
        if (len > 32) {
            p += snprintf(p, sizeof(hex_buffer) - (p - hex_buffer), "...");
        }
        plog_debug("GB_12241 REQ DATA[%d]: %s", len, hex_buffer);
    }
}

static void GB_12241_log_response(GB_12241_stack_resp_t *resp, uint8_t *buf, int len)
{
    if (plog_get_level() <= NEU_PLOG_DEBUG) {
        plog_debug("GB_12241 RESP: dev=%u, func=%u, bytes=%u",
                 resp->device_addr, resp->function, resp->byte_count);
        
        char hex_buffer[1024] = {0};
        char *p = hex_buffer;
        for (int i = 0; i < len && i < 32; i++) {
            p += snprintf(p, sizeof(hex_buffer) - (p - hex_buffer), 
                          "%02X ", buf[i]);
        }
        if (len > 32) {
            p += snprintf(p, sizeof(hex_buffer) - (p - hex_buffer), "...");
        }
        plog_debug("GB_12241 RESP DATA[%d]: %s", len, hex_buffer);
    }
} 