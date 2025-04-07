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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "12241.h"
#include "12241_standard_points.h"

/**
 * 从点位ID和区域生成标准点位地址字符串
 *
 * @param dev_addr 设备地址
 * @param point_id 标准点位ID
 * @param area 点位所在区域 (GB_12241_AREA_DATA, GB_12241_AREA_PARAM, GB_12241_AREA_STATUS)
 * @param endian 字节序 (GB_12241_ABCD, GB_12241_BADC, GB_12241_CDAB, GB_12241_DCBA)
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @return 0:成功, 其他:失败
 */
int GB_12241_format_standard_point(uint16_t dev_addr, uint16_t point_id,
                                  uint8_t area, uint8_t endian,
                                  char *addr_str, size_t size)
{
    if (addr_str == NULL || size == 0) {
        return -1;
    }

    // 确定区域前缀
    char area_prefix = 'D'; // 默认为数据区
    switch (area) {
    case GB_12241_AREA_DATA:
        area_prefix = 'D';
        break;
    case GB_12241_AREA_PARAM:
        area_prefix = 'P';
        break;
    case GB_12241_AREA_STATUS:
        area_prefix = 'S';
        break;
    default:
        return -2; // 无效区域
    }

    // 确定字节序后缀
    char *endian_suffix = "";
    switch (endian) {
    case GB_12241_ABCD:
        endian_suffix = "#BB"; // 大端-大端
        break;
    case GB_12241_BADC:
        endian_suffix = "#BL"; // 大端-小端
        break;
    case GB_12241_CDAB:
        endian_suffix = "#LB"; // 小端-大端
        break;
    case GB_12241_DCBA:
        endian_suffix = "#LL"; // 小端-小端
        break;
    default:
        endian_suffix = "#BB"; // 默认为大端
        break;
    }

    // 生成地址字符串
    int ret = snprintf(addr_str, size, "%u!%c%u%s", dev_addr, area_prefix, point_id, endian_suffix);
    if (ret < 0 || (size_t) ret >= size) {
        return -3; // 缓冲区太小
    }

    return 0;
}

/**
 * 为电气设备创建标准电压点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param phase 相位 (0:A相, 1:B相, 2:C相, 3:三相平均)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_voltage_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                 int phase, uint8_t endian)
{
    uint16_t point_id;
    
    switch (phase) {
    case 0: // A相
        point_id = GB_12241_VOLTAGE_A;
        break;
    case 1: // B相
        point_id = GB_12241_VOLTAGE_B;
        break;
    case 2: // C相
        point_id = GB_12241_VOLTAGE_C;
        break;
    case 3: // 平均
        point_id = GB_12241_VOLTAGE_AVG;
        break;
    default:
        return -1; // 无效相位
    }
    
    return GB_12241_format_standard_point(dev_addr, point_id, GB_12241_AREA_DATA, endian, addr_str, size);
}

/**
 * 为电气设备创建标准电流点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param phase 相位 (0:A相, 1:B相, 2:C相, 3:N相, 4:三相平均)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_current_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                 int phase, uint8_t endian)
{
    uint16_t point_id;
    
    switch (phase) {
    case 0: // A相
        point_id = GB_12241_CURRENT_A;
        break;
    case 1: // B相
        point_id = GB_12241_CURRENT_B;
        break;
    case 2: // C相
        point_id = GB_12241_CURRENT_C;
        break;
    case 3: // N相
        point_id = GB_12241_CURRENT_N;
        break;
    case 4: // 平均
        point_id = GB_12241_CURRENT_AVG;
        break;
    default:
        return -1; // 无效相位
    }
    
    return GB_12241_format_standard_point(dev_addr, point_id, GB_12241_AREA_DATA, endian, addr_str, size);
}

/**
 * 为电气设备创建标准有功功率点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param phase 相位 (0:A相, 1:B相, 2:C相, 3:总功率)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_active_power_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                      int phase, uint8_t endian)
{
    uint16_t point_id;
    
    switch (phase) {
    case 0: // A相
        point_id = GB_12241_ACTIVE_POWER_A;
        break;
    case 1: // B相
        point_id = GB_12241_ACTIVE_POWER_B;
        break;
    case 2: // C相
        point_id = GB_12241_ACTIVE_POWER_C;
        break;
    case 3: // 总功率
        point_id = GB_12241_ACTIVE_POWER_TOTAL;
        break;
    default:
        return -1; // 无效相位
    }
    
    return GB_12241_format_standard_point(dev_addr, point_id, GB_12241_AREA_DATA, endian, addr_str, size);
}

/**
 * 为电气设备创建标准功率因数点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param phase 相位 (0:A相, 1:B相, 2:C相, 3:总功率因数)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_power_factor_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                      int phase, uint8_t endian)
{
    uint16_t point_id;
    
    switch (phase) {
    case 0: // A相
        point_id = GB_12241_POWER_FACTOR_A;
        break;
    case 1: // B相
        point_id = GB_12241_POWER_FACTOR_B;
        break;
    case 2: // C相
        point_id = GB_12241_POWER_FACTOR_C;
        break;
    case 3: // 总功率因数
        point_id = GB_12241_POWER_FACTOR_TOTAL;
        break;
    default:
        return -1; // 无效相位
    }
    
    return GB_12241_format_standard_point(dev_addr, point_id, GB_12241_AREA_DATA, endian, addr_str, size);
}

/**
 * 为电气设备创建标准频率点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_frequency_point(char *addr_str, size_t size, uint16_t dev_addr, uint8_t endian)
{
    return GB_12241_format_standard_point(dev_addr, GB_12241_FREQUENCY, GB_12241_AREA_DATA, endian, addr_str, size);
}

/**
 * 为电气设备创建标准电能点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param type 类型 (0:正向有功, 1:反向有功, 2:正向无功, 3:反向无功)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_energy_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                int type, uint8_t endian)
{
    uint16_t point_id;
    
    switch (type) {
    case 0: // 正向有功
        point_id = GB_12241_ACTIVE_ENERGY_IMPORT;
        break;
    case 1: // 反向有功
        point_id = GB_12241_ACTIVE_ENERGY_EXPORT;
        break;
    case 2: // 正向无功
        point_id = GB_12241_REACTIVE_ENERGY_IMPORT;
        break;
    case 3: // 反向无功
        point_id = GB_12241_REACTIVE_ENERGY_EXPORT;
        break;
    default:
        return -1; // 无效类型
    }
    
    return GB_12241_format_standard_point(dev_addr, point_id, GB_12241_AREA_DATA, endian, addr_str, size);
}

/**
 * 为水设备创建标准流量点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param type 类型 (0:实时流量, 1:最大流量, 2:最小流量, 3:平均流量)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_water_flow_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                    int type, uint8_t endian)
{
    uint16_t point_id;
    
    switch (type) {
    case 0: // 实时流量
        point_id = GB_12241_WATER_FLOW_RATE;
        break;
    case 1: // 最大流量
        point_id = GB_12241_WATER_FLOW_RATE_MAX;
        break;
    case 2: // 最小流量
        point_id = GB_12241_WATER_FLOW_RATE_MIN;
        break;
    case 3: // 平均流量
        point_id = GB_12241_WATER_FLOW_RATE_AVG;
        break;
    default:
        return -1; // 无效类型
    }
    
    return GB_12241_format_standard_point(dev_addr, point_id, GB_12241_AREA_DATA, endian, addr_str, size);
}

/**
 * 为水设备创建标准总量点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param type 类型 (0:总量, 1:日累积, 2:月累积, 3:年累积)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_water_total_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                     int type, uint8_t endian)
{
    uint16_t point_id;
    
    switch (type) {
    case 0: // 总量
        point_id = GB_12241_WATER_TOTAL;
        break;
    case 1: // 日累积
        point_id = GB_12241_WATER_TOTAL_DAILY;
        break;
    case 2: // 月累积
        point_id = GB_12241_WATER_TOTAL_MONTHLY;
        break;
    case 3: // 年累积
        point_id = GB_12241_WATER_TOTAL_YEARLY;
        break;
    default:
        return -1; // 无效类型
    }
    
    return GB_12241_format_standard_point(dev_addr, point_id, GB_12241_AREA_DATA, endian, addr_str, size);
}

/**
 * 为水设备创建标准压力点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param type 类型 (0:实时压力, 1:最大压力, 2:最小压力, 3:平均压力)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_water_pressure_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                        int type, uint8_t endian)
{
    uint16_t point_id;
    
    switch (type) {
    case 0: // 实时压力
        point_id = GB_12241_WATER_PRESSURE;
        break;
    case 1: // 最大压力
        point_id = GB_12241_WATER_PRESSURE_MAX;
        break;
    case 2: // 最小压力
        point_id = GB_12241_WATER_PRESSURE_MIN;
        break;
    case 3: // 平均压力
        point_id = GB_12241_WATER_PRESSURE_AVG;
        break;
    default:
        return -1; // 无效类型
    }
    
    return GB_12241_format_standard_point(dev_addr, point_id, GB_12241_AREA_DATA, endian, addr_str, size);
}

/**
 * 为水设备创建标准温度点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param type 类型 (0:水温度, 1:进水温度, 2:出水温度)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_water_temperature_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                           int type, uint8_t endian)
{
    uint16_t point_id;
    
    switch (type) {
    case 0: // 水温度
        point_id = GB_12241_WATER_TEMPERATURE;
        break;
    case 1: // 进水温度
        point_id = GB_12241_WATER_TEMPERATURE_INLET;
        break;
    case 2: // 出水温度
        point_id = GB_12241_WATER_TEMPERATURE_OUTLET;
        break;
    default:
        return -1; // 无效类型
    }
    
    return GB_12241_format_standard_point(dev_addr, point_id, GB_12241_AREA_DATA, endian, addr_str, size);
}

/**
 * 为气体设备创建标准流量点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param type 类型 (0:实时流量, 1:最大流量, 2:最小流量, 3:平均流量, 4:标况流量)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_gas_flow_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                  int type, uint8_t endian)
{
    uint16_t point_id;
    
    switch (type) {
    case 0: // 实时流量
        point_id = GB_12241_GAS_FLOW_RATE;
        break;
    case 1: // 最大流量
        point_id = GB_12241_GAS_FLOW_RATE_MAX;
        break;
    case 2: // 最小流量
        point_id = GB_12241_GAS_FLOW_RATE_MIN;
        break;
    case 3: // 平均流量
        point_id = GB_12241_GAS_FLOW_RATE_AVG;
        break;
    case 4: // 标况流量
        point_id = GB_12241_GAS_FLOW_RATE_STD;
        break;
    default:
        return -1; // 无效类型
    }
    
    return GB_12241_format_standard_point(dev_addr, point_id, GB_12241_AREA_DATA, endian, addr_str, size);
}

/**
 * 为气体设备创建标准总量点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param type 类型 (0:总量, 1:日累积, 2:月累积, 3:年累积, 4:标况总量)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_gas_total_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                   int type, uint8_t endian)
{
    uint16_t point_id;
    
    switch (type) {
    case 0: // 总量
        point_id = GB_12241_GAS_TOTAL;
        break;
    case 1: // 日累积
        point_id = GB_12241_GAS_TOTAL_DAILY;
        break;
    case 2: // 月累积
        point_id = GB_12241_GAS_TOTAL_MONTHLY;
        break;
    case 3: // 年累积
        point_id = GB_12241_GAS_TOTAL_YEARLY;
        break;
    case 4: // 标况总量
        point_id = GB_12241_GAS_TOTAL_STD;
        break;
    default:
        return -1; // 无效类型
    }
    
    return GB_12241_format_standard_point(dev_addr, point_id, GB_12241_AREA_DATA, endian, addr_str, size);
}

/**
 * 为气体设备创建标准压力点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param type 类型 (0:实时压力, 1:最大压力, 2:最小压力, 3:平均压力)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_gas_pressure_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                      int type, uint8_t endian)
{
    uint16_t point_id;
    
    switch (type) {
    case 0: // 实时压力
        point_id = GB_12241_GAS_PRESSURE;
        break;
    case 1: // 最大压力
        point_id = GB_12241_GAS_PRESSURE_MAX;
        break;
    case 2: // 最小压力
        point_id = GB_12241_GAS_PRESSURE_MIN;
        break;
    case 3: // 平均压力
        point_id = GB_12241_GAS_PRESSURE_AVG;
        break;
    default:
        return -1; // 无效类型
    }
    
    return GB_12241_format_standard_point(dev_addr, point_id, GB_12241_AREA_DATA, endian, addr_str, size);
}

/**
 * 为气体设备创建标准温度点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param type 类型 (0:气体温度, 1:最大温度, 2:最小温度, 3:平均温度)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_gas_temperature_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                         int type, uint8_t endian)
{
    uint16_t point_id;
    
    switch (type) {
    case 0: // 气体温度
        point_id = GB_12241_GAS_TEMPERATURE;
        break;
    case 1: // 最大温度
        point_id = GB_12241_GAS_TEMPERATURE_MAX;
        break;
    case 2: // 最小温度
        point_id = GB_12241_GAS_TEMPERATURE_MIN;
        break;
    case 3: // 平均温度
        point_id = GB_12241_GAS_TEMPERATURE_AVG;
        break;
    default:
        return -1; // 无效类型
    }
    
    return GB_12241_format_standard_point(dev_addr, point_id, GB_12241_AREA_DATA, endian, addr_str, size);
}

/**
 * 为热量设备创建标准热量点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param type 类型 (0:总量, 1:日累积, 2:月累积, 3:年累积)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_heat_energy_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                     int type, uint8_t endian)
{
    uint16_t point_id;
    
    switch (type) {
    case 0: // 总量
        point_id = GB_12241_HEAT_ENERGY;
        break;
    case 1: // 日累积
        point_id = GB_12241_HEAT_ENERGY_DAILY;
        break;
    case 2: // 月累积
        point_id = GB_12241_HEAT_ENERGY_MONTHLY;
        break;
    case 3: // 年累积
        point_id = GB_12241_HEAT_ENERGY_YEARLY;
        break;
    default:
        return -1; // 无效类型
    }
    
    return GB_12241_format_standard_point(dev_addr, point_id, GB_12241_AREA_DATA, endian, addr_str, size);
}

/**
 * 为热量设备创建标准温度点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param type 类型 (0:供热温度, 1:回热温度, 2:供回温差)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_heat_temperature_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                          int type, uint8_t endian)
{
    uint16_t point_id;
    
    switch (type) {
    case 0: // 供热温度
        point_id = GB_12241_HEAT_TEMPERATURE_SUPPLY;
        break;
    case 1: // 回热温度
        point_id = GB_12241_HEAT_TEMPERATURE_RETURN;
        break;
    case 2: // 供回温差
        point_id = GB_12241_HEAT_TEMPERATURE_DIFF;
        break;
    default:
        return -1; // 无效类型
    }
    
    return GB_12241_format_standard_point(dev_addr, point_id, GB_12241_AREA_DATA, endian, addr_str, size);
}

/**
 * 为热量设备创建标准压力点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param type 类型 (0:供热压力, 1:回热压力, 2:供回压差)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_heat_pressure_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                       int type, uint8_t endian)
{
    uint16_t point_id;
    
    switch (type) {
    case 0: // 供热压力
        point_id = GB_12241_HEAT_PRESSURE_SUPPLY;
        break;
    case 1: // 回热压力
        point_id = GB_12241_HEAT_PRESSURE_RETURN;
        break;
    case 2: // 供回压差
        point_id = GB_12241_HEAT_PRESSURE_DIFF;
        break;
    default:
        return -1; // 无效类型
    }
    
    return GB_12241_format_standard_point(dev_addr, point_id, GB_12241_AREA_DATA, endian, addr_str, size);
}

/**
 * 为设备创建自身属性点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param attr_id 属性ID
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_device_attribute_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                          uint16_t attr_id, uint8_t endian)
{
    // 自身属性点位通常放在参数区(P)
    return GB_12241_format_standard_point(dev_addr, attr_id, GB_12241_AREA_PARAM, endian, addr_str, size);
}

/**
 * 为设备创建基本信息点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param type 类型 (0:设备类型, 1:制造商ID, 2:产品型号, 3:序列号, 4:硬件版本, 5:软件版本, 6:固件版本, 7:协议版本)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_device_info_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                     int type, uint8_t endian)
{
    uint16_t point_id;
    
    switch (type) {
    case 0: // 设备类型
        point_id = GB_12241_DEVICE_TYPE;
        break;
    case 1: // 制造商ID
        point_id = GB_12241_MANUFACTURER_ID;
        break;
    case 2: // 产品型号
        point_id = GB_12241_PRODUCT_MODEL;
        break;
    case 3: // 序列号
        point_id = GB_12241_SERIAL_NUMBER;
        break;
    case 4: // 硬件版本
        point_id = GB_12241_HARDWARE_VERSION;
        break;
    case 5: // 软件版本
        point_id = GB_12241_SOFTWARE_VERSION;
        break;
    case 6: // 固件版本
        point_id = GB_12241_FIRMWARE_VERSION;
        break;
    case 7: // 协议版本
        point_id = GB_12241_PROTOCOL_VERSION;
        break;
    default:
        return -1; // 无效类型
    }
    
    return GB_12241_create_device_attribute_point(addr_str, size, dev_addr, point_id, endian);
}

/**
 * 为设备创建状态信息点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param type 类型 (0:运行状态, 1:主错误代码, 2:子错误代码, 3:故障描述, 4:自诊断信息, 5:维护状态, 6:告警计数)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_device_status_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                       int type, uint8_t endian)
{
    uint16_t point_id;
    
    switch (type) {
    case 0: // 运行状态
        point_id = GB_12241_RUNNING_STATUS;
        break;
    case 1: // 主错误代码
        point_id = GB_12241_ERROR_CODE_MAIN;
        break;
    case 2: // 子错误代码
        point_id = GB_12241_ERROR_CODE_SUB;
        break;
    case 3: // 故障描述
        point_id = GB_12241_FAULT_DESCRIPTION;
        break;
    case 4: // 自诊断信息
        point_id = GB_12241_DIAGNOSTIC_INFO;
        break;
    case 5: // 维护状态
        point_id = GB_12241_MAINTENANCE_STATUS;
        break;
    case 6: // 告警计数
        point_id = GB_12241_ALARM_COUNT;
        break;
    default:
        return -1; // 无效类型
    }
    
    return GB_12241_create_device_attribute_point(addr_str, size, dev_addr, point_id, endian);
}

/**
 * 为设备创建通信参数点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param type 类型 (0:通信地址, 1:波特率, 2:校验位, 3:停止位, 4:通信模式, 5:通信协议, 6:IP地址, 7:子网掩码, 8:网关, 9:DNS服务器)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_comm_param_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                    int type, uint8_t endian)
{
    uint16_t point_id;
    
    switch (type) {
    case 0: // 通信地址
        point_id = GB_12241_COMM_ADDRESS;
        break;
    case 1: // 波特率
        point_id = GB_12241_BAUD_RATE;
        break;
    case 2: // 校验位
        point_id = GB_12241_PARITY;
        break;
    case 3: // 停止位
        point_id = GB_12241_STOP_BITS;
        break;
    case 4: // 通信模式
        point_id = GB_12241_COMM_MODE;
        break;
    case 5: // 通信协议
        point_id = GB_12241_COMM_PROTOCOL;
        break;
    case 6: // IP地址
        point_id = GB_12241_IP_ADDRESS;
        break;
    case 7: // 子网掩码
        point_id = GB_12241_SUBNET_MASK;
        break;
    case 8: // 网关
        point_id = GB_12241_GATEWAY;
        break;
    case 9: // DNS服务器
        point_id = GB_12241_DNS_SERVER;
        break;
    default:
        return -1; // 无效类型
    }
    
    return GB_12241_create_device_attribute_point(addr_str, size, dev_addr, point_id, endian);
}

/**
 * 为设备创建时间信息点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param type 类型 (0:设备日期时间, 1:总运行时间, 2:启动时间, 3:上次维护时间, 4:下次维护时间)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_time_info_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                   int type, uint8_t endian)
{
    uint16_t point_id;
    
    switch (type) {
    case 0: // 设备日期时间
        point_id = GB_12241_DEVICE_DATETIME;
        break;
    case 1: // 总运行时间
        point_id = GB_12241_RUNTIME_TOTAL;
        break;
    case 2: // 启动时间
        point_id = GB_12241_STARTUP_TIME;
        break;
    case 3: // 上次维护时间
        point_id = GB_12241_LAST_MAINTENANCE_TIME;
        break;
    case 4: // 下次维护时间
        point_id = GB_12241_NEXT_MAINTENANCE_TIME;
        break;
    default:
        return -1; // 无效类型
    }
    
    return GB_12241_create_device_attribute_point(addr_str, size, dev_addr, point_id, endian);
}

/**
 * 为设备创建系统参数点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param type 类型 (0:采样间隔, 1:数据上传间隔, 2:工作模式, 3:节能模式, 4:预留参数1, 5:预留参数2)
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_system_param_point(char *addr_str, size_t size, uint16_t dev_addr, 
                                      int type, uint8_t endian)
{
    uint16_t point_id;
    
    switch (type) {
    case 0: // 采样间隔
        point_id = GB_12241_SAMPLING_INTERVAL;
        break;
    case 1: // 数据上传间隔
        point_id = GB_12241_DATA_UPLOAD_INTERVAL;
        break;
    case 2: // 工作模式
        point_id = GB_12241_WORKING_MODE;
        break;
    case 3: // 节能模式
        point_id = GB_12241_POWER_SAVING_MODE;
        break;
    case 4: // 预留参数1
        point_id = GB_12241_RESERVED_PARAM1;
        break;
    case 5: // 预留参数2
        point_id = GB_12241_RESERVED_PARAM2;
        break;
    default:
        return -1; // 无效类型
    }
    
    return GB_12241_create_device_attribute_point(addr_str, size, dev_addr, point_id, endian);
} 