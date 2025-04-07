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

#ifndef PLUGINS_GB_12241_STANDARD_POINTS_H
#define PLUGINS_GB_12241_STANDARD_POINTS_H

#include <stdint.h>

/**
 * GB/T 12241协议标准点位定义
 * 
 * 按照GB/T 12241协议规范，定义了一些标准的电气参数点位
 * 这些点位可以在数据区(D)、参数区(P)或状态区(S)中访问
 * 电气参数通常使用FLOAT32类型
 */

/* 电压相关点位 */
// 三相电压点位定义 (V)
#define GB_12241_VOLTAGE_A         1000    // A相电压
#define GB_12241_VOLTAGE_B         1001    // B相电压
#define GB_12241_VOLTAGE_C         1002    // C相电压
#define GB_12241_VOLTAGE_LINE_AB   1003    // AB线电压
#define GB_12241_VOLTAGE_LINE_BC   1004    // BC线电压
#define GB_12241_VOLTAGE_LINE_CA   1005    // CA线电压
#define GB_12241_VOLTAGE_AVG       1006    // 三相平均电压

/* 电流相关点位 */
// 三相电流点位定义 (A)
#define GB_12241_CURRENT_A         1020    // A相电流
#define GB_12241_CURRENT_B         1021    // B相电流
#define GB_12241_CURRENT_C         1022    // C相电流
#define GB_12241_CURRENT_N         1023    // N相电流
#define GB_12241_CURRENT_AVG       1024    // 三相平均电流

/* 功率相关点位 */
// 有功功率点位定义 (kW)
#define GB_12241_ACTIVE_POWER_A    1040    // A相有功功率
#define GB_12241_ACTIVE_POWER_B    1041    // B相有功功率
#define GB_12241_ACTIVE_POWER_C    1042    // C相有功功率
#define GB_12241_ACTIVE_POWER_TOTAL 1043   // 总有功功率

// 无功功率点位定义 (kVar)
#define GB_12241_REACTIVE_POWER_A  1050    // A相无功功率
#define GB_12241_REACTIVE_POWER_B  1051    // B相无功功率
#define GB_12241_REACTIVE_POWER_C  1052    // C相无功功率
#define GB_12241_REACTIVE_POWER_TOTAL 1053 // 总无功功率

// 视在功率点位定义 (kVA)
#define GB_12241_APPARENT_POWER_A  1060    // A相视在功率
#define GB_12241_APPARENT_POWER_B  1061    // B相视在功率
#define GB_12241_APPARENT_POWER_C  1062    // C相视在功率
#define GB_12241_APPARENT_POWER_TOTAL 1063 // 总视在功率

/* 功率因数相关点位 */
#define GB_12241_POWER_FACTOR_A    1070    // A相功率因数
#define GB_12241_POWER_FACTOR_B    1071    // B相功率因数
#define GB_12241_POWER_FACTOR_C    1072    // C相功率因数
#define GB_12241_POWER_FACTOR_TOTAL 1073   // 总功率因数

/* 频率相关点位 */
#define GB_12241_FREQUENCY         1080    // 电网频率 (Hz)

/* 电能相关点位 */
// 有功电能点位定义 (kWh)
#define GB_12241_ACTIVE_ENERGY_IMPORT      1100    // 正向有功电能
#define GB_12241_ACTIVE_ENERGY_EXPORT      1101    // 反向有功电能

// 无功电能点位定义 (kVarh)
#define GB_12241_REACTIVE_ENERGY_IMPORT    1110    // 正向无功电能
#define GB_12241_REACTIVE_ENERGY_EXPORT    1111    // 反向无功电能

/* 温度相关点位 */
#define GB_12241_TEMPERATURE               1200    // 设备温度 (°C)

/* 负载相关点位 */
#define GB_12241_LOAD_PERCENTAGE           1300    // 负载百分比 (%)

/* 运行状态点位 */
#define GB_12241_DEVICE_STATUS             2000    // 设备状态
#define GB_12241_ALARM_STATUS              2001    // 报警状态
#define GB_12241_ERROR_CODE                2002    // 错误代码

/* 控制点位 */
#define GB_12241_CONTROL_COMMAND           3000    // 控制命令
#define GB_12241_RESET_COMMAND             3001    // 复位命令

/******************************************************************************/
/* 水相关点位 (4000-4999) */
/******************************************************************************/

/* 水流量相关点位 (m³/h) */
#define GB_12241_WATER_FLOW_RATE           4000    // 水流量
#define GB_12241_WATER_FLOW_RATE_MAX       4001    // 最大水流量
#define GB_12241_WATER_FLOW_RATE_MIN       4002    // 最小水流量
#define GB_12241_WATER_FLOW_RATE_AVG       4003    // 平均水流量

/* 水总量相关点位 (m³) */
#define GB_12241_WATER_TOTAL               4010    // 水总量
#define GB_12241_WATER_TOTAL_DAILY         4011    // 日累积水量
#define GB_12241_WATER_TOTAL_MONTHLY       4012    // 月累积水量
#define GB_12241_WATER_TOTAL_YEARLY        4013    // 年累积水量

/* 水压力相关点位 (MPa) */
#define GB_12241_WATER_PRESSURE            4020    // 水压力
#define GB_12241_WATER_PRESSURE_MAX        4021    // 最大水压力
#define GB_12241_WATER_PRESSURE_MIN        4022    // 最小水压力
#define GB_12241_WATER_PRESSURE_AVG        4023    // 平均水压力

/* 水温度相关点位 (°C) */
#define GB_12241_WATER_TEMPERATURE         4030    // 水温度
#define GB_12241_WATER_TEMPERATURE_INLET   4031    // 进水温度
#define GB_12241_WATER_TEMPERATURE_OUTLET  4032    // 出水温度

/* 水质相关点位 */
#define GB_12241_WATER_PH                  4040    // 水pH值
#define GB_12241_WATER_CONDUCTIVITY        4041    // 水电导率 (μS/cm)
#define GB_12241_WATER_TURBIDITY           4042    // 水浊度 (NTU)
#define GB_12241_WATER_DISSOLVED_OXYGEN    4043    // 溶解氧 (mg/L)
#define GB_12241_WATER_RESIDUAL_CHLORINE   4044    // 残余氯 (mg/L)

/******************************************************************************/
/* 气体相关点位 (5000-5999) */
/******************************************************************************/

/* 气体流量相关点位 (m³/h) */
#define GB_12241_GAS_FLOW_RATE             5000    // 气体流量
#define GB_12241_GAS_FLOW_RATE_MAX         5001    // 最大气体流量
#define GB_12241_GAS_FLOW_RATE_MIN         5002    // 最小气体流量
#define GB_12241_GAS_FLOW_RATE_AVG         5003    // 平均气体流量
#define GB_12241_GAS_FLOW_RATE_STD         5004    // 标况气体流量

/* 气体总量相关点位 (m³) */
#define GB_12241_GAS_TOTAL                 5010    // 气体总量
#define GB_12241_GAS_TOTAL_DAILY           5011    // 日累积气体量
#define GB_12241_GAS_TOTAL_MONTHLY         5012    // 月累积气体量
#define GB_12241_GAS_TOTAL_YEARLY          5013    // 年累积气体量
#define GB_12241_GAS_TOTAL_STD             5014    // 标况气体总量

/* 气体压力相关点位 (kPa) */
#define GB_12241_GAS_PRESSURE              5020    // 气体压力
#define GB_12241_GAS_PRESSURE_MAX          5021    // 最大气体压力
#define GB_12241_GAS_PRESSURE_MIN          5022    // 最小气体压力
#define GB_12241_GAS_PRESSURE_AVG          5023    // 平均气体压力

/* 气体温度相关点位 (°C) */
#define GB_12241_GAS_TEMPERATURE           5030    // 气体温度
#define GB_12241_GAS_TEMPERATURE_MAX       5031    // 最大气体温度
#define GB_12241_GAS_TEMPERATURE_MIN       5032    // 最小气体温度
#define GB_12241_GAS_TEMPERATURE_AVG       5033    // 平均气体温度

/* 气体成分相关点位 (%) */
#define GB_12241_GAS_METHANE               5040    // 甲烷含量
#define GB_12241_GAS_OXYGEN                5041    // 氧气含量
#define GB_12241_GAS_NITROGEN              5042    // 氮气含量
#define GB_12241_GAS_CARBON_DIOXIDE        5043    // 二氧化碳含量
#define GB_12241_GAS_HYDROGEN_SULFIDE      5044    // 硫化氢含量 (ppm)

/* 气体热值相关点位 (MJ/m³) */
#define GB_12241_GAS_CALORIFIC_VALUE       5050    // 气体热值
#define GB_12241_GAS_CALORIFIC_VALUE_HIGH  5051    // 高位热值
#define GB_12241_GAS_CALORIFIC_VALUE_LOW   5052    // 低位热值

/******************************************************************************/
/* 热量相关点位 (6000-6999) */
/******************************************************************************/

/* 热量流量相关点位 (m³/h) */
#define GB_12241_HEAT_FLOW_RATE            6000    // 热媒流量
#define GB_12241_HEAT_FLOW_RATE_MAX        6001    // 最大热媒流量
#define GB_12241_HEAT_FLOW_RATE_MIN        6002    // 最小热媒流量
#define GB_12241_HEAT_FLOW_RATE_AVG        6003    // 平均热媒流量

/* 热量功率相关点位 (kW) */
#define GB_12241_HEAT_POWER                6010    // 热功率
#define GB_12241_HEAT_POWER_MAX            6011    // 最大热功率
#define GB_12241_HEAT_POWER_MIN            6012    // 最小热功率
#define GB_12241_HEAT_POWER_AVG            6013    // 平均热功率

/* 热量总量相关点位 (GJ) */
#define GB_12241_HEAT_ENERGY               6020    // 热量总量
#define GB_12241_HEAT_ENERGY_DAILY         6021    // 日累积热量
#define GB_12241_HEAT_ENERGY_MONTHLY       6022    // 月累积热量
#define GB_12241_HEAT_ENERGY_YEARLY        6023    // 年累积热量

/* 热量温度相关点位 (°C) */
#define GB_12241_HEAT_TEMPERATURE_SUPPLY   6030    // 供热温度
#define GB_12241_HEAT_TEMPERATURE_RETURN   6031    // 回热温度
#define GB_12241_HEAT_TEMPERATURE_DIFF     6032    // 供回温差

/* 热量压力相关点位 (MPa) */
#define GB_12241_HEAT_PRESSURE_SUPPLY      6040    // 供热压力
#define GB_12241_HEAT_PRESSURE_RETURN      6041    // 回热压力
#define GB_12241_HEAT_PRESSURE_DIFF        6042    // 供回压差

/******************************************************************************/
/* 设备自身属性点位 (0-999) */
/******************************************************************************/

/* 设备基本信息 */
#define GB_12241_DEVICE_TYPE             0     // 设备类型
#define GB_12241_MANUFACTURER_ID         1     // 制造商ID
#define GB_12241_PRODUCT_MODEL           2     // 产品型号
#define GB_12241_SERIAL_NUMBER           3     // 序列号
#define GB_12241_HARDWARE_VERSION        4     // 硬件版本
#define GB_12241_SOFTWARE_VERSION        5     // 软件版本
#define GB_12241_FIRMWARE_VERSION        6     // 固件版本
#define GB_12241_PROTOCOL_VERSION        7     // 协议版本

/* 设备状态信息 */
#define GB_12241_RUNNING_STATUS          20    // 运行状态(0:停止,1:运行,2:故障,3:维护)
#define GB_12241_ERROR_CODE_MAIN         21    // 主错误代码
#define GB_12241_ERROR_CODE_SUB          22    // 子错误代码
#define GB_12241_FAULT_DESCRIPTION       23    // 故障描述
#define GB_12241_DIAGNOSTIC_INFO         24    // 自诊断信息
#define GB_12241_MAINTENANCE_STATUS      25    // 维护状态
#define GB_12241_ALARM_COUNT             26    // 告警计数

/* 通信参数 */
#define GB_12241_COMM_ADDRESS            40    // 通信地址
#define GB_12241_BAUD_RATE               41    // 波特率
#define GB_12241_PARITY                  42    // 校验位
#define GB_12241_STOP_BITS               43    // 停止位
#define GB_12241_COMM_MODE               44    // 通信模式
#define GB_12241_COMM_PROTOCOL           45    // 通信协议
#define GB_12241_IP_ADDRESS              46    // IP地址
#define GB_12241_SUBNET_MASK             47    // 子网掩码
#define GB_12241_GATEWAY                 48    // 网关
#define GB_12241_DNS_SERVER              49    // DNS服务器

/* 时间信息 */
#define GB_12241_DEVICE_DATETIME         60    // 设备日期时间
#define GB_12241_RUNTIME_TOTAL           61    // 总运行时间(小时)
#define GB_12241_STARTUP_TIME            62    // 启动时间
#define GB_12241_LAST_MAINTENANCE_TIME   63    // 上次维护时间
#define GB_12241_NEXT_MAINTENANCE_TIME   64    // 下次维护时间

/* 系统参数 */
#define GB_12241_SAMPLING_INTERVAL       80    // 采样间隔(ms)
#define GB_12241_DATA_UPLOAD_INTERVAL    81    // 数据上传间隔(s)
#define GB_12241_WORKING_MODE            82    // 工作模式
#define GB_12241_POWER_SAVING_MODE       83    // 节能模式
#define GB_12241_RESERVED_PARAM1         84    // 预留参数1
#define GB_12241_RESERVED_PARAM2         85    // 预留参数2

/* GB/T 12241协议标准点位定义 */

/* 一类数据信息点定义 (AFN=0CH) */
#define GB_12241_F2_CALENDAR          2    // 终端日历时钟
#define GB_12241_F7_EVENT_COUNTER     7    // 终端事件计数器当前值
#define GB_12241_F8_EVENT_FLAG        8    // 终端事件标志状态
#define GB_12241_F10_TRAFFIC          10   // 终端与主站日月通信流量
#define GB_12241_F25_POWER_PARAM      25   // 当前三相及总有/无功功率、功率因数，三相电压、电流
#define GB_12241_F28_METER_STATUS     28   // 电能表状态字及变位标识
#define GB_12241_F129_ACTIVE_ENERGY_FORWARD    129  // 当前正向有功电能示值
#define GB_12241_F130_REACTIVE_ENERGY_FORWARD  130  // 当前正向无功电能示值
#define GB_12241_F131_ACTIVE_ENERGY_REVERSE    131  // 当前反向有功电能示值
#define GB_12241_F132_REACTIVE_ENERGY_REVERSE  132  // 当前反向无功电能示值
#define GB_12241_F145_MAX_DEMAND              145  // 当月正向有最大需量及发生时间

/* 水表相关信息点 */
#define GB_12241_F402_WATER_STATUS    402  // 水表状态字及变位标识
#define GB_12241_F403_WATER_FLOW      403  // 水表当前流量及压力
#define GB_12241_F404_WATER_TOTAL     404  // 水表正向累计流量

/* 气表相关信息点 */
#define GB_12241_F502_GAS_STATUS      502  // 气表状态字及变位标识
#define GB_12241_F503_GAS_FLOW        503  // 气表当前流量、压力、温度
#define GB_12241_F504_GAS_TOTAL       504  // 气表正向累计流量

/* 热表相关信息点 */
#define GB_12241_F602_HEAT_STATUS     602  // 热表状态字及变位标识
#define GB_12241_F603_HEAT_TOTAL      603  // 热表累计热量示值

/* RTU设备相关信息点 */
#define GB_12241_F701_RTU_DI          701  // RTU设备遥信值
#define GB_12241_F702_RTU_AI          702  // RTU设备遥测值
#define GB_12241_F703_RTU_ENERGY      703  // RTU设备电度值
#define GB_12241_F704_RTU_FLOAT       704  // RTU设备浮点数值

/* 12位数据长度电能示值 */
#define GB_12241_F829_ACTIVE_ENERGY_FORWARD_12    829  // 当前正向有功电能示值(12位)
#define GB_12241_F830_REACTIVE_ENERGY_FORWARD_12  830  // 当前正向无功电能示值(12位)
#define GB_12241_F831_ACTIVE_ENERGY_REVERSE_12    831  // 当前反向有功电能示值(12位)
#define GB_12241_F832_REACTIVE_ENERGY_REVERSE_12  832  // 当前反向无功电能示值(12位)

/* 其他信息点 */
#define GB_12241_F900_MAX_DEMAND      900  // 当前有功最大需量
#define GB_12241_F901_FREQUENCY       901  // 电网频率

/* F25数据结构体定义 */
typedef struct {
    float voltage_a;        // A相电压
    float voltage_b;        // B相电压
    float voltage_c;        // C相电压
    float current_a;        // A相电流
    float current_b;        // B相电流
    float current_c;        // C相电流
    float current_zero;     // 零序电流
    float active_power;     // 总有功功率
    float reactive_power;   // 总无功功率
    float power_factor;     // 总功率因数
} GB_12241_F25_data_t;

/* F403数据结构体定义 */
typedef struct {
    float flow_rate;        // 当前流量
    float pressure;         // 当前压力
} GB_12241_F403_data_t;

/* F503数据结构体定义 */
typedef struct {
    float flow_rate;        // 当前流量
    float pressure;         // 当前压力
    float temperature;      // 当前温度
} GB_12241_F503_data_t;

/**
 * 点位访问函数
 */

/**
 * 从字符串创建标准点位地址
 *
 * @param dev_addr 设备地址
 * @param point_id 标准点位ID
 * @param area 点位所在区域 (GB_12241_AREA_DATA, GB_12241_AREA_PARAM, GB_12241_AREA_STATUS)
 * @param endian 字节序
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @return 0:成功, 其他:失败
 */
int GB_12241_format_standard_point(uint16_t dev_addr, uint16_t point_id, 
                                   uint8_t area, uint8_t endian,
                                   char *addr_str, size_t size);

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
                                 int phase, uint8_t endian);

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
                                 int phase, uint8_t endian);

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
                                      int phase, uint8_t endian);

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
                                      int phase, uint8_t endian);

/**
 * 为电气设备创建标准频率点位
 *
 * @param addr_str 输出的地址字符串缓冲区
 * @param size 缓冲区大小
 * @param dev_addr 设备地址
 * @param endian 字节序
 * @return 0:成功, 其他:失败
 */
int GB_12241_create_frequency_point(char *addr_str, size_t size, uint16_t dev_addr, uint8_t endian);

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
                                int type, uint8_t endian);

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
                                    int type, uint8_t endian);

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
                                     int type, uint8_t endian);

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
                                        int type, uint8_t endian);

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
                                           int type, uint8_t endian);

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
                                  int type, uint8_t endian);

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
                                   int type, uint8_t endian);

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
                                      int type, uint8_t endian);

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
                                         int type, uint8_t endian);

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
                                     int type, uint8_t endian);

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
                                          int type, uint8_t endian);

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
                                       int type, uint8_t endian);

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
                                          uint16_t attr_id, uint8_t endian);

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
                                     int type, uint8_t endian);

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
                                       int type, uint8_t endian);

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
                                    int type, uint8_t endian);

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
                                   int type, uint8_t endian);

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
                                      int type, uint8_t endian);

#endif // PLUGINS_GB_12241_STANDARD_POINTS_H 