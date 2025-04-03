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
#include <string.h>

#include <neuron.h>

#include "12241.h"

/* CRC16计算函数 */
static uint16_t calc_crc16(uint8_t *buf, int len)
{
    uint16_t crc = 0xFFFF;
    for (int i = 0; i < len; i++) {
        crc ^= (uint16_t)buf[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 0x0001) {
                crc >>= 1;
                crc ^= 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc;
}

void GB_12241_header_wrap(neu_protocol_pack_buf_t *buf, uint16_t seq)
{
    assert(neu_protocol_pack_buf_unused_size(buf) >=
           sizeof(struct GB_12241_header));
    struct GB_12241_header *header =
        (struct GB_12241_header *) neu_protocol_pack_buf(
            buf, sizeof(struct GB_12241_header));

    header->start_flag   = 0x68;        // 固定起始标志
    header->control_code = 0x00;        // 默认控制码
    header->seq          = htons(seq);  // 序列号
    
    // 数据长度在完成打包后设置
    header->data_len     = 0;
}

int GB_12241_header_unwrap(neu_protocol_unpack_buf_t *buf,
                          struct GB_12241_header *out_header)
{
    struct GB_12241_header *header =
        (struct GB_12241_header *) neu_protocol_unpack_buf(
            buf, sizeof(struct GB_12241_header));

    if (header == NULL) {
        return 0;
    }

    if (header->start_flag != 0x68) {
        return -1; // 起始标志错误
    }

    *out_header = *header;
    out_header->data_len = ntohs(out_header->data_len);
    out_header->seq = ntohs(out_header->seq);

    return sizeof(struct GB_12241_header);
}

void GB_12241_address_wrap(neu_protocol_pack_buf_t *buf, uint16_t device_addr,
                          uint16_t start, uint16_t data_len)
{
    assert(neu_protocol_pack_buf_unused_size(buf) >=
           sizeof(struct GB_12241_address));
    struct GB_12241_address *address =
        (struct GB_12241_address *) neu_protocol_pack_buf(
            buf, sizeof(struct GB_12241_address));

    address->device_addr   = htons(device_addr);
    address->start_address = htons(start);
    address->data_len      = htons(data_len);
}

int GB_12241_address_unwrap(neu_protocol_unpack_buf_t *buf,
                           struct GB_12241_address *out_address)
{
    struct GB_12241_address *address =
        (struct GB_12241_address *) neu_protocol_unpack_buf(
            buf, sizeof(struct GB_12241_address));

    if (address == NULL) {
        return 0;
    }

    *out_address = *address;
    out_address->device_addr   = ntohs(out_address->device_addr);
    out_address->start_address = ntohs(out_address->start_address);
    out_address->data_len      = ntohs(out_address->data_len);

    return sizeof(struct GB_12241_address);
}

void GB_12241_data_wrap(neu_protocol_pack_buf_t *buf, uint16_t data_len,
                       uint8_t *data)
{
    assert(neu_protocol_pack_buf_unused_size(buf) >=
           sizeof(struct GB_12241_data) + data_len);
    
    // 先添加数据内容
    uint8_t *data_ptr = neu_protocol_pack_buf(buf, data_len);
    memcpy(data_ptr, data, data_len);
    
    // 再添加数据长度字段
    struct GB_12241_data *t_data =
        (struct GB_12241_data *) neu_protocol_pack_buf(
            buf, sizeof(struct GB_12241_data));
    
    t_data->data_len = htons(data_len);
    
    // 更新头部中的数据区长度
    struct GB_12241_header *header = (struct GB_12241_header *)
        neu_protocol_pack_buf_get_data(buf);
    
    header->data_len = htons(neu_protocol_pack_buf_used_size(buf) -
                           sizeof(struct GB_12241_header));
}

int GB_12241_data_unwrap(neu_protocol_unpack_buf_t *buf,
                        struct GB_12241_data *out_data)
{
    struct GB_12241_data *t_data =
        (struct GB_12241_data *) neu_protocol_unpack_buf(
            buf, sizeof(struct GB_12241_data));

    if (t_data == NULL) {
        return 0;
    }

    out_data->data_len = ntohs(t_data->data_len);
    
    // 检查剩余数据是否足够
    if (out_data->data_len > neu_protocol_unpack_buf_unused_size(buf)) {
        return 0;
    }
    
    // 读取数据内容
    uint8_t *data = neu_protocol_unpack_buf(buf, out_data->data_len);
    if (data == NULL) {
        return 0;
    }
    
    memcpy(out_data->data, data, out_data->data_len);
    
    return sizeof(struct GB_12241_data) + out_data->data_len;
}

void GB_12241_crc_set(neu_protocol_pack_buf_t *buf)
{
    uint8_t *data = neu_protocol_pack_buf_get_data(buf);
    size_t   len  = neu_protocol_pack_buf_used_size(buf);
    
    // 计算CRC
    uint16_t crc = calc_crc16(data, len);
    
    // 添加CRC到包末尾
    assert(neu_protocol_pack_buf_unused_size(buf) >=
           sizeof(struct GB_12241_crc));
    struct GB_12241_crc *t_crc =
        (struct GB_12241_crc *) neu_protocol_pack_buf(
            buf, sizeof(struct GB_12241_crc));
    
    t_crc->crc = htons(crc);
}

void GB_12241_crc_wrap(neu_protocol_pack_buf_t *buf)
{
    GB_12241_crc_set(buf);
}

int GB_12241_crc_unwrap(neu_protocol_unpack_buf_t *buf,
                       struct GB_12241_crc *out_crc)
{
    struct GB_12241_crc *t_crc =
        (struct GB_12241_crc *) neu_protocol_unpack_buf(
            buf, sizeof(struct GB_12241_crc));

    if (t_crc == NULL) {
        return 0;
    }

    *out_crc = *t_crc;
    out_crc->crc = ntohs(out_crc->crc);

    // 验证CRC
    uint8_t *data = neu_protocol_unpack_buf_get_data(buf);
    size_t   data_len = neu_protocol_unpack_buf_used_size(buf) -
                       sizeof(struct GB_12241_crc);
    
    uint16_t calc_crc = calc_crc16(data, data_len);
    
    if (calc_crc != out_crc->crc) {
        return -1; // CRC校验失败
    }

    return sizeof(struct GB_12241_crc);
}

const char *GB_12241_area_to_str(GB_12241_area_e area)
{
    switch (area) {
    case GB_12241_AREA_DATA:
        return "DATA";
    case GB_12241_AREA_PARAM:
        return "PARAM";
    case GB_12241_AREA_STATUS:
        return "STATUS";
    default:
        return "UNKNOWN";
    }
} 