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
#include <ctype.h>
#include <math.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <neuron.h>

#include "12241.h"
#include "12241_point.h"

// 正则表达式解析点位地址
static regex_t GB_12241_data_reg;
static regex_t GB_12241_param_reg;
static regex_t GB_12241_status_reg;
static regex_t GB_12241_bit_reg;
static regex_t GB_12241_string_reg;

static void init_regex_once()
{
    static bool initialized = false;
    if (!initialized) {
        // 数据区点位: 设备地址!D数据地址[#B|#L|#BB|#BL|#LL|#LB]
        regcomp(&GB_12241_data_reg, "^([0-9]+)!D([0-9]+)(#B|#L|#BB|#BL|#LL|#LB)?$", REG_EXTENDED);
        
        // 参数区点位: 设备地址!P参数地址[#B|#L|#BB|#BL|#LL|#LB]
        regcomp(&GB_12241_param_reg, "^([0-9]+)!P([0-9]+)(#B|#L|#BB|#BL|#LL|#LB)?$", REG_EXTENDED);
        
        // 状态区点位: 设备地址!S状态地址[#B|#L|#BB|#BL|#LL|#LB]
        regcomp(&GB_12241_status_reg, "^([0-9]+)!S([0-9]+)(#B|#L|#BB|#BL|#LL|#LB)?$", REG_EXTENDED);
        
        // 位点位: 设备地址!D数据地址.位偏移[B|L]
        regcomp(&GB_12241_bit_reg, "^([0-9]+)!D([0-9]+).([0-7])(B|L)?$", REG_EXTENDED);
        
        // 字符串点位: 设备地址!D数据地址$字符串长度
        regcomp(&GB_12241_string_reg, "^([0-9]+)!D([0-9]+)\\$([0-9]+)$", REG_EXTENDED);
        
        initialized = true;
    }
}

static bool parse_data_area(const char *str, GB_12241_point_t *point,
                             GB_12241_address_base base)
{
    regmatch_t match[5];
    
    if (regexec(&GB_12241_data_reg, str, 5, match, 0) == 0) {
        // 设备地址
        char dev_addr[32] = { 0 };
        strncpy(dev_addr, str + match[1].rm_so, match[1].rm_eo - match[1].rm_so);
        point->dev_addr = (uint16_t) atoi(dev_addr);
        
        // 寄存器地址
        char reg_addr[32] = { 0 };
        strncpy(reg_addr, str + match[2].rm_so, match[2].rm_eo - match[2].rm_so);
        point->reg_addr = (uint16_t) atoi(reg_addr);
        
        // 调整地址基准
        point->reg_addr = base == base_1 ? point->reg_addr - 1 : point->reg_addr;
        
        // 区域类型
        point->area = GB_12241_AREA_DATA;
        point->function = GB_12241_READ_DATA;
        
        // 默认为32位类型
        point->type = GB_12241_POINT_FLOAT32;
        point->byte_size = 4;
        
        // 处理字节序
        if (match[3].rm_so != -1) {
            char endian[8] = { 0 };
            strncpy(endian, str + match[3].rm_so, match[3].rm_eo - match[3].rm_so);
            
            if (strcmp(endian, "#B") == 0) {
                point->endian = GB_12241_ABCD; // 大端
            } else if (strcmp(endian, "#L") == 0) {
                point->endian = GB_12241_DCBA; // 小端
            } else if (strcmp(endian, "#BB") == 0) {
                point->endian = GB_12241_ABCD; // 大端-大端
            } else if (strcmp(endian, "#BL") == 0) {
                point->endian = GB_12241_BADC; // 大端-小端
            } else if (strcmp(endian, "#LB") == 0) {
                point->endian = GB_12241_CDAB; // 小端-大端
            } else if (strcmp(endian, "#LL") == 0) {
                point->endian = GB_12241_DCBA; // 小端-小端
            }
        }
        
        return true;
    }
    
    return false;
}

static bool parse_param_area(const char *str, GB_12241_point_t *point,
                               GB_12241_address_base base)
{
    regmatch_t match[5];
    
    if (regexec(&GB_12241_param_reg, str, 5, match, 0) == 0) {
        // 设备地址
        char dev_addr[32] = { 0 };
        strncpy(dev_addr, str + match[1].rm_so, match[1].rm_eo - match[1].rm_so);
        point->dev_addr = (uint16_t) atoi(dev_addr);
        
        // 寄存器地址
        char reg_addr[32] = { 0 };
        strncpy(reg_addr, str + match[2].rm_so, match[2].rm_eo - match[2].rm_so);
        point->reg_addr = (uint16_t) atoi(reg_addr);
        
        // 调整地址基准
        point->reg_addr = base == base_1 ? point->reg_addr - 1 : point->reg_addr;
        
        // 区域类型
        point->area = GB_12241_AREA_PARAM;
        point->function = GB_12241_READ_PARAM;
        
        // 默认为32位类型
        point->type = GB_12241_POINT_FLOAT32;
        point->byte_size = 4;
        
        // 处理字节序
        if (match[3].rm_so != -1) {
            char endian[8] = { 0 };
            strncpy(endian, str + match[3].rm_so, match[3].rm_eo - match[3].rm_so);
            
            if (strcmp(endian, "#B") == 0) {
                point->endian = GB_12241_ABCD; // 大端
            } else if (strcmp(endian, "#L") == 0) {
                point->endian = GB_12241_DCBA; // 小端
            } else if (strcmp(endian, "#BB") == 0) {
                point->endian = GB_12241_ABCD; // 大端-大端
            } else if (strcmp(endian, "#BL") == 0) {
                point->endian = GB_12241_BADC; // 大端-小端
            } else if (strcmp(endian, "#LB") == 0) {
                point->endian = GB_12241_CDAB; // 小端-大端
            } else if (strcmp(endian, "#LL") == 0) {
                point->endian = GB_12241_DCBA; // 小端-小端
            }
        }
        
        return true;
    }
    
    return false;
}

static bool parse_status_area(const char *str, GB_12241_point_t *point,
                                GB_12241_address_base base)
{
    regmatch_t match[5];
    
    if (regexec(&GB_12241_status_reg, str, 5, match, 0) == 0) {
        // 设备地址
        char dev_addr[32] = { 0 };
        strncpy(dev_addr, str + match[1].rm_so, match[1].rm_eo - match[1].rm_so);
        point->dev_addr = (uint16_t) atoi(dev_addr);
        
        // 寄存器地址
        char reg_addr[32] = { 0 };
        strncpy(reg_addr, str + match[2].rm_so, match[2].rm_eo - match[2].rm_so);
        point->reg_addr = (uint16_t) atoi(reg_addr);
        
        // 调整地址基准
        point->reg_addr = base == base_1 ? point->reg_addr - 1 : point->reg_addr;
        
        // 区域类型
        point->area = GB_12241_AREA_STATUS;
        point->function = GB_12241_READ_STATUS;
        
        // 默认为16位类型
        point->type = GB_12241_POINT_UINT16;
        point->byte_size = 2;
        
        // 处理字节序
        if (match[3].rm_so != -1) {
            char endian[8] = { 0 };
            strncpy(endian, str + match[3].rm_so, match[3].rm_eo - match[3].rm_so);
            
            if (strcmp(endian, "#B") == 0) {
                point->endian = GB_12241_ABCD; // 大端
            } else if (strcmp(endian, "#L") == 0) {
                point->endian = GB_12241_DCBA; // 小端
            } else if (strcmp(endian, "#BB") == 0) {
                point->endian = GB_12241_ABCD; // 大端-大端
            } else if (strcmp(endian, "#BL") == 0) {
                point->endian = GB_12241_BADC; // 大端-小端
            } else if (strcmp(endian, "#LB") == 0) {
                point->endian = GB_12241_CDAB; // 小端-大端
            } else if (strcmp(endian, "#LL") == 0) {
                point->endian = GB_12241_DCBA; // 小端-小端
            }
        }
        
        return true;
    }
    
    return false;
}

static bool parse_bit(const char *str, GB_12241_point_t *point,
                        GB_12241_address_base base)
{
    regmatch_t match[5];
    
    if (regexec(&GB_12241_bit_reg, str, 5, match, 0) == 0) {
        // 设备地址
        char dev_addr[32] = { 0 };
        strncpy(dev_addr, str + match[1].rm_so, match[1].rm_eo - match[1].rm_so);
        point->dev_addr = (uint16_t) atoi(dev_addr);
        
        // 寄存器地址
        char reg_addr[32] = { 0 };
        strncpy(reg_addr, str + match[2].rm_so, match[2].rm_eo - match[2].rm_so);
        point->reg_addr = (uint16_t) atoi(reg_addr);
        
        // 调整地址基准
        point->reg_addr = base == base_1 ? point->reg_addr - 1 : point->reg_addr;
        
        // 位偏移
        char bit_offset[8] = { 0 };
        strncpy(bit_offset, str + match[3].rm_so, match[3].rm_eo - match[3].rm_so);
        point->bit_offset = (uint8_t) atoi(bit_offset);
        
        // 区域类型
        point->area = GB_12241_AREA_DATA;
        point->function = GB_12241_READ_DATA;
        
        // 位类型
        point->type = GB_12241_POINT_BIT;
        point->byte_size = 1;
        
        return true;
    }
    
    return false;
}

static bool parse_string(const char *str, GB_12241_point_t *point,
                           GB_12241_address_base base)
{
    regmatch_t match[5];
    
    if (regexec(&GB_12241_string_reg, str, 5, match, 0) == 0) {
        // 设备地址
        char dev_addr[32] = { 0 };
        strncpy(dev_addr, str + match[1].rm_so, match[1].rm_eo - match[1].rm_so);
        point->dev_addr = (uint16_t) atoi(dev_addr);
        
        // 寄存器地址
        char reg_addr[32] = { 0 };
        strncpy(reg_addr, str + match[2].rm_so, match[2].rm_eo - match[2].rm_so);
        point->reg_addr = (uint16_t) atoi(reg_addr);
        
        // 调整地址基准
        point->reg_addr = base == base_1 ? point->reg_addr - 1 : point->reg_addr;
        
        // 字符串长度
        char str_len[32] = { 0 };
        strncpy(str_len, str + match[3].rm_so, match[3].rm_eo - match[3].rm_so);
        point->byte_size = (uint16_t) atoi(str_len);
        
        // 区域类型
        point->area = GB_12241_AREA_DATA;
        point->function = GB_12241_READ_DATA;
        
        // 字符串类型
        point->type = GB_12241_POINT_STRING;
        
        return true;
    }
    
    return false;
}

int GB_12241_parse_point(const char *str, neu_datatag_addr_t *addr,
                        GB_12241_point_t *point, GB_12241_address_base base,
                        GB_12241_endianess endian)
{
    init_regex_once();
    
    point->endian = endian;
    
    // 尝试各种地址格式解析
    if (parse_data_area(str, point, base) ||
        parse_param_area(str, point, base) ||
        parse_status_area(str, point, base) ||
        parse_bit(str, point, base) ||
        parse_string(str, point, base)) {
        
        memcpy(addr->value.opaques.bytes, point, sizeof(GB_12241_point_t));
        addr->value.type = NEU_DATATAG_VALUE_TYPE_OPAQUE;
        addr->value.opaques.length = sizeof(GB_12241_point_t);
        return 0;
    }
    
    return -1;
}

static int GB_12241_value_convert(GB_12241_point_t *point, uint8_t *src,
                                 void *value)
{
    union {
        uint8_t  u8;
        int8_t   i8;
        uint16_t u16;
        int16_t  i16;
        uint32_t u32;
        int32_t  i32;
        uint64_t u64;
        int64_t  i64;
        float    f32;
        double   d64;
        uint8_t  bytes[8];
    } bytes, conv;
    
    // 读取数据
    for (int i = 0; i < point->byte_size; i++) {
        bytes.bytes[i] = src[i];
    }
    
    // 根据类型和字节序转换
    switch (point->type) {
    case GB_12241_POINT_UINT8:
        *(uint8_t *)value = bytes.u8;
        break;
        
    case GB_12241_POINT_INT8:
        *(int8_t *)value = bytes.i8;
        break;
        
    case GB_12241_POINT_UINT16:
        // 字节序转换
        if (point->endian == GB_12241_ABCD) {
            // 大端字节序 (ABCD)
            conv.bytes[0] = bytes.bytes[0];
            conv.bytes[1] = bytes.bytes[1];
        } else {
            // 小端字节序 (DCBA)
            conv.bytes[0] = bytes.bytes[1];
            conv.bytes[1] = bytes.bytes[0];
        }
        *(uint16_t *)value = conv.u16;
        break;
        
    case GB_12241_POINT_INT16:
        // 字节序转换
        if (point->endian == GB_12241_ABCD) {
            // 大端字节序 (ABCD)
            conv.bytes[0] = bytes.bytes[0];
            conv.bytes[1] = bytes.bytes[1];
        } else {
            // 小端字节序 (DCBA)
            conv.bytes[0] = bytes.bytes[1];
            conv.bytes[1] = bytes.bytes[0];
        }
        *(int16_t *)value = conv.i16;
        break;
        
    case GB_12241_POINT_UINT32:
        // 字节序转换
        switch (point->endian) {
        case GB_12241_ABCD: // 大端 (ABCD)
            conv.bytes[0] = bytes.bytes[0];
            conv.bytes[1] = bytes.bytes[1];
            conv.bytes[2] = bytes.bytes[2];
            conv.bytes[3] = bytes.bytes[3];
            break;
        case GB_12241_BADC: // 大端-小端 (BADC)
            conv.bytes[0] = bytes.bytes[1];
            conv.bytes[1] = bytes.bytes[0];
            conv.bytes[2] = bytes.bytes[3];
            conv.bytes[3] = bytes.bytes[2];
            break;
        case GB_12241_CDAB: // 小端-大端 (CDAB)
            conv.bytes[0] = bytes.bytes[2];
            conv.bytes[1] = bytes.bytes[3];
            conv.bytes[2] = bytes.bytes[0];
            conv.bytes[3] = bytes.bytes[1];
            break;
        case GB_12241_DCBA: // 小端 (DCBA)
            conv.bytes[0] = bytes.bytes[3];
            conv.bytes[1] = bytes.bytes[2];
            conv.bytes[2] = bytes.bytes[1];
            conv.bytes[3] = bytes.bytes[0];
            break;
        }
        *(uint32_t *)value = conv.u32;
        break;
        
    case GB_12241_POINT_INT32:
        // 字节序转换
        switch (point->endian) {
        case GB_12241_ABCD: // 大端 (ABCD)
            conv.bytes[0] = bytes.bytes[0];
            conv.bytes[1] = bytes.bytes[1];
            conv.bytes[2] = bytes.bytes[2];
            conv.bytes[3] = bytes.bytes[3];
            break;
        case GB_12241_BADC: // 大端-小端 (BADC)
            conv.bytes[0] = bytes.bytes[1];
            conv.bytes[1] = bytes.bytes[0];
            conv.bytes[2] = bytes.bytes[3];
            conv.bytes[3] = bytes.bytes[2];
            break;
        case GB_12241_CDAB: // 小端-大端 (CDAB)
            conv.bytes[0] = bytes.bytes[2];
            conv.bytes[1] = bytes.bytes[3];
            conv.bytes[2] = bytes.bytes[0];
            conv.bytes[3] = bytes.bytes[1];
            break;
        case GB_12241_DCBA: // 小端 (DCBA)
            conv.bytes[0] = bytes.bytes[3];
            conv.bytes[1] = bytes.bytes[2];
            conv.bytes[2] = bytes.bytes[1];
            conv.bytes[3] = bytes.bytes[0];
            break;
        }
        *(int32_t *)value = conv.i32;
        break;
        
    case GB_12241_POINT_FLOAT32:
        // 字节序转换
        switch (point->endian) {
        case GB_12241_ABCD: // 大端 (ABCD)
            conv.bytes[0] = bytes.bytes[0];
            conv.bytes[1] = bytes.bytes[1];
            conv.bytes[2] = bytes.bytes[2];
            conv.bytes[3] = bytes.bytes[3];
            break;
        case GB_12241_BADC: // 大端-小端 (BADC)
            conv.bytes[0] = bytes.bytes[1];
            conv.bytes[1] = bytes.bytes[0];
            conv.bytes[2] = bytes.bytes[3];
            conv.bytes[3] = bytes.bytes[2];
            break;
        case GB_12241_CDAB: // 小端-大端 (CDAB)
            conv.bytes[0] = bytes.bytes[2];
            conv.bytes[1] = bytes.bytes[3];
            conv.bytes[2] = bytes.bytes[0];
            conv.bytes[3] = bytes.bytes[1];
            break;
        case GB_12241_DCBA: // 小端 (DCBA)
            conv.bytes[0] = bytes.bytes[3];
            conv.bytes[1] = bytes.bytes[2];
            conv.bytes[2] = bytes.bytes[1];
            conv.bytes[3] = bytes.bytes[0];
            break;
        }
        *(float *)value = conv.f32;
        break;
        
    case GB_12241_POINT_BIT:
        // 提取位值
        *(bool *)value = (bytes.u8 >> point->bit_offset) & 0x01;
        break;
        
    default:
        return -1;
    }
    
    return 0;
}

int GB_12241_value_read(GB_12241_point_t *point, uint8_t *src, void *value)
{
    return GB_12241_value_convert(point, src, value);
}

int GB_12241_value_write(GB_12241_point_t *point, double src, uint8_t *dest)
{
    union {
        uint8_t  u8;
        int8_t   i8;
        uint16_t u16;
        int16_t  i16;
        uint32_t u32;
        int32_t  i32;
        uint64_t u64;
        int64_t  i64;
        float    f32;
        double   d64;
        uint8_t  bytes[8];
    } bytes, conv;
    
    // 将源值转换为目标类型
    switch (point->type) {
    case GB_12241_POINT_UINT8:
        bytes.u8 = (uint8_t)src;
        break;
        
    case GB_12241_POINT_INT8:
        bytes.i8 = (int8_t)src;
        break;
        
    case GB_12241_POINT_UINT16:
        bytes.u16 = (uint16_t)src;
        // 字节序转换
        if (point->endian == GB_12241_ABCD) {
            // 大端 (ABCD)
            conv.bytes[0] = bytes.bytes[0];
            conv.bytes[1] = bytes.bytes[1];
        } else {
            // 小端 (DCBA)
            conv.bytes[0] = bytes.bytes[1];
            conv.bytes[1] = bytes.bytes[0];
        }
        dest[0] = conv.bytes[0];
        dest[1] = conv.bytes[1];
        return 2;
        
    case GB_12241_POINT_INT16:
        bytes.i16 = (int16_t)src;
        // 字节序转换
        if (point->endian == GB_12241_ABCD) {
            // 大端 (ABCD)
            conv.bytes[0] = bytes.bytes[0];
            conv.bytes[1] = bytes.bytes[1];
        } else {
            // 小端 (DCBA)
            conv.bytes[0] = bytes.bytes[1];
            conv.bytes[1] = bytes.bytes[0];
        }
        dest[0] = conv.bytes[0];
        dest[1] = conv.bytes[1];
        return 2;
        
    case GB_12241_POINT_UINT32:
        bytes.u32 = (uint32_t)src;
        // 字节序转换
        switch (point->endian) {
        case GB_12241_ABCD: // 大端 (ABCD)
            dest[0] = bytes.bytes[0];
            dest[1] = bytes.bytes[1];
            dest[2] = bytes.bytes[2];
            dest[3] = bytes.bytes[3];
            break;
        case GB_12241_BADC: // 大端-小端 (BADC)
            dest[0] = bytes.bytes[1];
            dest[1] = bytes.bytes[0];
            dest[2] = bytes.bytes[3];
            dest[3] = bytes.bytes[2];
            break;
        case GB_12241_CDAB: // 小端-大端 (CDAB)
            dest[0] = bytes.bytes[2];
            dest[1] = bytes.bytes[3];
            dest[2] = bytes.bytes[0];
            dest[3] = bytes.bytes[1];
            break;
        case GB_12241_DCBA: // 小端 (DCBA)
            dest[0] = bytes.bytes[3];
            dest[1] = bytes.bytes[2];
            dest[2] = bytes.bytes[1];
            dest[3] = bytes.bytes[0];
            break;
        }
        return 4;
        
    case GB_12241_POINT_INT32:
        bytes.i32 = (int32_t)src;
        // 字节序转换
        switch (point->endian) {
        case GB_12241_ABCD: // 大端 (ABCD)
            dest[0] = bytes.bytes[0];
            dest[1] = bytes.bytes[1];
            dest[2] = bytes.bytes[2];
            dest[3] = bytes.bytes[3];
            break;
        case GB_12241_BADC: // 大端-小端 (BADC)
            dest[0] = bytes.bytes[1];
            dest[1] = bytes.bytes[0];
            dest[2] = bytes.bytes[3];
            dest[3] = bytes.bytes[2];
            break;
        case GB_12241_CDAB: // 小端-大端 (CDAB)
            dest[0] = bytes.bytes[2];
            dest[1] = bytes.bytes[3];
            dest[2] = bytes.bytes[0];
            dest[3] = bytes.bytes[1];
            break;
        case GB_12241_DCBA: // 小端 (DCBA)
            dest[0] = bytes.bytes[3];
            dest[1] = bytes.bytes[2];
            dest[2] = bytes.bytes[1];
            dest[3] = bytes.bytes[0];
            break;
        }
        return 4;
        
    case GB_12241_POINT_FLOAT32:
        bytes.f32 = (float)src;
        // 字节序转换
        switch (point->endian) {
        case GB_12241_ABCD: // 大端 (ABCD)
            dest[0] = bytes.bytes[0];
            dest[1] = bytes.bytes[1];
            dest[2] = bytes.bytes[2];
            dest[3] = bytes.bytes[3];
            break;
        case GB_12241_BADC: // 大端-小端 (BADC)
            dest[0] = bytes.bytes[1];
            dest[1] = bytes.bytes[0];
            dest[2] = bytes.bytes[3];
            dest[3] = bytes.bytes[2];
            break;
        case GB_12241_CDAB: // 小端-大端 (CDAB)
            dest[0] = bytes.bytes[2];
            dest[1] = bytes.bytes[3];
            dest[2] = bytes.bytes[0];
            dest[3] = bytes.bytes[1];
            break;
        case GB_12241_DCBA: // 小端 (DCBA)
            dest[0] = bytes.bytes[3];
            dest[1] = bytes.bytes[2];
            dest[2] = bytes.bytes[1];
            dest[3] = bytes.bytes[0];
            break;
        }
        return 4;
        
    case GB_12241_POINT_BIT:
        // 设置特定位
        if (src != 0) {
            dest[0] = 1 << point->bit_offset;
        } else {
            dest[0] = 0;
        }
        return 1;
        
    default:
        return -1;
    }
    
    // 处理单字节类型
    dest[0] = bytes.u8;
    return 1;
}

int GB_12241_get_data_size(GB_12241_point_t *point)
{
    if (!point) {
        return -1;
    }
    
    return point->byte_size;
}

// 获取数据类型的字节大小
uint16_t GB_12241_get_type_size(uint8_t data_type)
{
    switch (data_type) {
        case GB_12241_TYPE_BIT:
            return 1;  // 1位
        case GB_12241_TYPE_BYTE:
            return 1;  // 1字节
        case GB_12241_TYPE_WORD:
            return 2;  // 2字节
        case GB_12241_TYPE_DWORD:
        case GB_12241_TYPE_FLOAT:
            return 4;  // 4字节
        default:
            return 0;
    }
}

// 计算点位数据的总字节大小
uint16_t GB_12241_calc_byte_size(uint8_t data_type, uint16_t length)
{
    if (data_type == GB_12241_TYPE_BIT) {
        return (length + 7) / 8;  // 向上取整到字节
    }
    return GB_12241_get_type_size(data_type) * length;
}

// 解析点位地址字符串
int GB_12241_parse_point(const char *addr_str, GB_12241_point_t *point)
{
    if (!addr_str || !point) {
        return -1;
    }

    // 格式：{pn}!F{fn}#{data_no}[.{bit}]
    unsigned int pn, fn, data_no;
    int bit = -1;

    // 尝试解析带位的格式
    int matched = sscanf(addr_str, "%u!F%u#%u.%d", &pn, &fn, &data_no, &bit);
    if (matched < 3) {
        return -1;
    }

    point->pn = pn;
    point->fn = fn;
    point->data_no = data_no;
    point->bit_offset = (matched == 4) ? bit : -1;
    
    // 根据是否有位操作设置数据类型
    if (point->bit_offset >= 0) {
        point->data_type = GB_12241_TYPE_BIT;
        point->length = 1;
    } else {
        // 根据数据项编号设置类型
        if (data_no == 0) {
            // DI状态字
            point->data_type = GB_12241_TYPE_WORD;
            point->length = 1;
        } else if (data_no >= 1 && data_no <= 4) {
            // 模拟量(电池电压等)
            point->data_type = GB_12241_TYPE_FLOAT;
            point->length = 1;
        } else if (data_no >= 5 && data_no <= 8) {
            // 计数器
            point->data_type = GB_12241_TYPE_DWORD;
            point->length = 1;
        } else {
            // 未知类型
            point->data_type = GB_12241_TYPE_BYTE;
            point->length = 1;
        }
    }

    point->byte_size = GB_12241_calc_byte_size(point->data_type, point->length);

    return 0;
}

// 创建点位地址字符串
int GB_12241_create_point(char *addr_str, size_t size, 
                         const GB_12241_point_t *point)
{
    if (!addr_str || !point || size == 0) {
        return -1;
    }

    if (point->bit_offset >= 0) {
        return snprintf(addr_str, size, "%u!F%u#%u.%d",
                       point->pn, point->fn, point->data_no, point->bit_offset);
    } else {
        return snprintf(addr_str, size, "%u!F%u#%u",
                       point->pn, point->fn, point->data_no);
    }
}

// 读取单个位值
bool GB_12241_read_bit(const uint8_t *data, uint8_t bit_offset)
{
    if (!data) {
        return false;
    }

    uint8_t byte = data[bit_offset / 8];
    return (byte >> (bit_offset % 8)) & 0x01;
}

// 读取多个位值
int GB_12241_read_bits(const uint8_t *data, uint16_t offset, 
                      uint16_t length, bool *values)
{
    if (!data || !values || length == 0) {
        return -1;
    }

    for (uint16_t i = 0; i < length; i++) {
        values[i] = GB_12241_read_bit(data, offset + i);
    }

    return 0;
}

// 读取浮点数值
float GB_12241_read_float(const uint8_t *data)
{
    if (!data) {
        return 0.0f;
    }

    float value;
    memcpy(&value, data, sizeof(float));
    return value;
}

// 读取多个浮点数值
int GB_12241_read_floats(const uint8_t *data, uint16_t offset,
                        uint16_t length, float *values)
{
    if (!data || !values || length == 0) {
        return -1;
    }

    for (uint16_t i = 0; i < length; i++) {
        values[i] = GB_12241_read_float(data + offset + i * sizeof(float));
    }

    return 0;
}

// 读取双字整数值
uint32_t GB_12241_read_dword(const uint8_t *data)
{
    if (!data) {
        return 0;
    }

    uint32_t value;
    memcpy(&value, data, sizeof(uint32_t));
    return value;
}

// 读取多个双字整数值
int GB_12241_read_dwords(const uint8_t *data, uint16_t offset,
                        uint16_t length, uint32_t *values)
{
    if (!data || !values || length == 0) {
        return -1;
    }

    for (uint16_t i = 0; i < length; i++) {
        values[i] = GB_12241_read_dword(data + offset + i * sizeof(uint32_t));
    }

    return 0;
} 