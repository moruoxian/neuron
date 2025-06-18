/**
 * NEURON IIoT System for Industry 4.0
 * Copyright (C) 2020-2022 EMQ Technologies Co., Ltd All rights reserved.
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

/* 包含标准库 */
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h> // 添加ctype.h头文件支持isdigit函数
#include <errno.h>
#include <jansson.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Neuron核心头文件 */
#include <adapter.h>
#include <neuron.h>
#include <plugin.h>
#include <tag.h>
#include <utils/log.h>
#include <utils/utarray.h>
#include <utils/utextend.h>
#include <utils/uthash.h>
#include <utils/utlist.h>

/* 包含12241_point.h */
#include "12241_point.h"

/* 结构体前向声明 */
struct neu_plugin_group;
typedef struct neu_plugin_group neu_plugin_group_t;
struct DATA_UNIT_Flag;

/* 定义NEU_UNUSED宏 */
#define NEU_UNUSED(x) (void) (x)

/* 点位状态相关结构体定义 */
typedef struct {
    char           group_name[NEU_GROUP_NAME_LEN];
    char           tag_name[NEU_TAG_NAME_LEN];
    time_t         last_update_time;            // 最新数据更新时间
    time_t         last_polled_historical_time; // 历史召测断点时间
    bool           dirty; // 新增：是否需要写入数据库
    UT_hash_handle hh;    // uthash句柄
} tag_state_t;
// 召测点配置结构体
typedef struct {
    char   group[NEU_GROUP_NAME_LEN];
    char **tags;
    int    tag_count;
} polling_group_t;

// 历史召测任务结构体定义
typedef struct {
    char   group_name[NEU_GROUP_NAME_LEN];
    char   tag_name[NEU_TAG_NAME_LEN];
    char   tag_address[NEU_TAG_ADDRESS_LEN]; // 标签地址信息
    time_t start_time;
    time_t end_time;
    int    retry_count;
} polling_task_t;

// 组级时间戳控制结构体定义
typedef struct {
    char           group_name[NEU_GROUP_NAME_LEN];
    time_t         last_polling_time;
    UT_hash_handle hh;
} group_polling_time_t;

/* 点位状态相关函数声明 */
static int  init_tag_state_db(neu_plugin_t *plugin);
static void close_tag_state_db(neu_plugin_t *plugin);
static int  update_tag_state(neu_plugin_t *plugin, const char *group_name,
                             const char *tag_name, time_t update_time);
static int  get_tag_state(neu_plugin_t *plugin, const char *group_name,
                          const char *tag_name, tag_state_t **state);
static polling_group_t *parse_polling_tags(const char *json_str,
                                           int *       group_count);
static void             generate_polling_tasks_for_group(neu_plugin_t *      plugin,
                                                         neu_plugin_group_t *group);
static void             execute_polling_tasks(neu_plugin_t *plugin);
static int gb_12241_build_his_request(neu_plugin_t *plugin, uint8_t *frame,
                                      size_t frame_size, uint16_t device_addr,
                                      uint8_t seq, uint16_t fn, uint16_t pn,
                                      time_t start_time, time_t end_time,
                                      size_t *request_length);
static int parse_and_store_historical_data(
    neu_plugin_t *plugin, const uint8_t *response, size_t response_len,
    const char *group_name, const char *tag_name, uint16_t fn, uint16_t pn,
    uint16_t data_index, time_t start_time, time_t end_time);
static int get_interval_seconds_from_density(uint8_t density);

// 新的基于tag_name+实时FN的映射函数声明
static uint16_t    get_historical_fn_from_tag_and_fn(neu_plugin_t *plugin,
                                                     const char *  tag_name,
                                                     uint16_t      realtime_fn);
static const char *get_fn_mapping_description(neu_plugin_t *plugin,
                                              const char *  tag_name,
                                              uint16_t      realtime_fn);
static int         init_fn_mapping_hash(neu_plugin_t *plugin);
static void        cleanup_fn_mapping_hash(neu_plugin_t *plugin);

// 组级时间戳管理函数声明
static bool should_generate_polling_tasks(neu_plugin_t *plugin,
                                          const char *  group_name);
static void cleanup_group_polling_times(neu_plugin_t *plugin);
// 添加连接回调函数定义
void               gb_12241_conn_connected(void *data, int fd);
void               gb_12241_conn_disconnected(void *data, int fd);
static bool        is_valid_string(const char *str);
static const char *get_safe_group_name(neu_plugin_group_t *group);
static uint8_t     gb_12241_make_crc(const uint8_t *buf, int16_t count);
// 特殊fn判断
static bool is_special_fn(uint16_t fn);

// ===== 历史数据FN映射表 =====

// 基于标签名称的历史FN映射结构
typedef struct {
    const char *tag_name_pattern; // 标签名称模式（支持通配符）
    uint16_t    historical_fn;    // 对应的历史数据功能码
    const char *description;      // 描述信息
} tag_name_mapping_t;

// 基于标签名称的历史FN映射表

// ===== 高效的历史FN映射机制（基于tag_name + 实时FN联合键） =====

// 映射键结构体（用于uthash）
typedef struct {
    char     tag_name[NEU_TAG_NAME_LEN]; // 标签名称
    uint16_t realtime_fn;                // 实时功能码
} fn_mapping_key_t;

// 映射条目结构体
typedef struct {
    fn_mapping_key_t key;           // 联合键（tag_name + realtime_fn）
    uint16_t         historical_fn; // 对应的历史功能码
    const char *     description;   // 描述信息
    UT_hash_handle   hh;            // uthash句柄
} fn_mapping_entry_t;

// 静态映射数据（基于tag_name + 实时FN -> 历史FN）
typedef struct {
    const char *tag_name;
    uint16_t    realtime_fn;
    uint16_t    historical_fn;
    const char *description;
} static_fn_mapping_t;

// RTU标签映射缓存条目
typedef struct {
    char           tag_name[NEU_TAG_NAME_LEN];     // 标签名称
    char           group_name[NEU_GROUP_NAME_LEN]; // 组名
    int            rtu_order;     // RTU在组内的顺序（0-11）
    uint16_t       historical_fn; // 对应的历史FN（710-721）
    time_t         cache_time;    // 缓存时间戳
    UT_hash_handle hh;            // uthash句柄
} rtu_mapping_cache_t;

// RTU标签模式定义
typedef struct {
    const char *pattern;     // 模式字符串
    const char *description; // 描述
} rtu_tag_pattern_t;

// RTU标签模式数组（静态常量，多实例共享安全）
static const rtu_tag_pattern_t rtu_patterns[] = { { "rtudi", "RTU数字量输入" },
                                                  { "rtuai", "RTU模拟量输入" },
                                                  { "rtuci",
                                                    "RTU计数器输入" } };
static const size_t            rtu_patterns_count =
    sizeof(rtu_patterns) / sizeof(rtu_tag_pattern_t);

static const static_fn_mapping_t static_fn_mappings[] = {
    // ===== 电表类数据映射 =====
    // F25当前电参量 -> 对应的历史曲线
    { "ActivePower_Total", 25, 81, "总有功功率(F25) -> 有功功率曲线(F81)" },
    { "ActivePower_A", 25, 82, "A相有功功率(F25) -> A相有功功率曲线(F82)" },
    { "ActivePower_B", 25, 83, "B相有功功率(F25) -> B相有功功率曲线(F83)" },
    { "ActivePower_C", 25, 84, "C相有功功率(F25) -> C相有功功率曲线(F84)" },
    { "ReactivePower_Total", 25, 85, "总无功功率(F25) -> 无功功率曲线(F85)" },
    { "ReactivePower_A", 25, 86, "A相无功功率(F25) -> A相无功功率曲线(F86)" },
    { "ReactivePower_B", 25, 87, "B相无功功率(F25) -> B相无功功率曲线(F87)" },
    { "ReactivePower_C", 25, 88, "C相无功功率(F25) -> C相无功功率曲线(F88)" },
    { "Voltage_A", 25, 89, "A相电压(F25) -> A相电压曲线(F89)" },
    { "Voltage_B", 25, 90, "B相电压(F25) -> B相电压曲线(F90)" },
    { "Voltage_C", 25, 91, "C相电压(F25) -> C相电压曲线(F91)" },
    { "Current_A", 25, 92, "A相电流(F25) -> A相电流曲线(F92)" },
    { "Current_B", 25, 93, "B相电流(F25) -> B相电流曲线(F93)" },
    { "Current_C", 25, 94, "C相电流(F25) -> C相电流曲线(F94)" },
    { "Current_Zero", 25, 95, "零序电流(F25) -> 零序电流曲线(F95)" },
    { "PowerFactor_Total", 25, 105, "总功率因数(F25) -> 总功率因数曲线(F105)" },
    { "PowerFactor_A", 25, 106, "A相功率因数(F25) -> A相功率因数曲线(F106)" },
    { "PowerFactor_B", 25, 107, "B相功率因数(F25) -> B相功率因数曲线(F107)" },
    { "PowerFactor_C", 25, 108, "C相功率因数(F25) -> C相功率因数曲线(F108)" },
    { "ApparentPower_Total", 25, 0, "总视在功率(F25) -> 无对应历史功能码" },
    { "ApparentPower_A", 25, 0, "A相视在功率(F25) -> 无对应历史功能码" },
    { "ApparentPower_B", 25, 0, "B相视在功率(F25) -> 无对应历史功能码" },
    { "ApparentPower_C", 25, 0, "C相视在功率(F25) -> 无对应历史功能码" },

    // F829当前正向有功电能 -> 电能示值曲线（标准版）
    { "ForwardActiveEnergy_Total", 829, 801,
      "正向有功总电能(F829) -> 正向有功电能示值（总）曲线(F801)" },
    { "ForwardActiveEnergy_Sharp", 829, 809,
      "正向有功尖时电能(F829) -> 正向有功电能示值（尖）曲线(F809)" },
    { "ForwardActiveEnergy_Peak", 829, 810,
      "正向有功峰时电能(F829) -> 正向有功电能示值（峰）曲线(F810)" },
    { "ForwardActiveEnergy_Ground", 829, 811,
      "正向有功平时电能(F829) -> 正向有功电能示值（平）曲线(F811)" },
    { "ForwardActiveEnergy_Valley", 829, 812,
      "正向有功谷时电能(F829) -> 正向有功电能示值（谷）曲线(F812)" },

    // F145当月正向有功最大需量 -> 不支持
    { "MonthActiveMaxDemand", 145, 0,
      "当月正向有功最大需量(F145) -> 无对应历史功能码" },

    // F900有功最大需量 -> F900当前有功需量曲线
    { "ActiveDemand", 900, 900,
      "有功最大需量(F900) -> 当前有功需量曲线(F900)" },

    // F901电网频率 -> F901电网频率曲线
    { "Frequency", 901, 901, "电网频率(F901) -> 电网频率曲线(F901)" },

    // F28电表运行状态字 -> 无对应历史功能码（状态字数据）
    { "PhaseA_Open", 28, 0, "A相断相(F28) -> 无对应历史功能码" },
    { "PhaseA_Reverse", 28, 0, "A相反向(F28) -> 无对应历史功能码" },
    { "PhaseA_Overload", 28, 0, "A相过载(F28) -> 无对应历史功能码" },
    { "PhaseA_OverCurrent", 28, 0, "A相过流(F28) -> 无对应历史功能码" },
    { "PhaseA_LossCurrent", 28, 0, "A相失流(F28) -> 无对应历史功能码" },
    { "PhaseA_OverVoltage", 28, 0, "A相过压(F28) -> 无对应历史功能码" },
    { "PhaseA_UnderVoltage", 28, 0, "A相欠压(F28) -> 无对应历史功能码" },
    { "PhaseA_LossVoltage", 28, 0, "A相失压(F28) -> 无对应历史功能码" },
    { "PhaseB_Open", 28, 0, "B相断相(F28) -> 无对应历史功能码" },
    { "PhaseB_Reverse", 28, 0, "B相反向(F28) -> 无对应历史功能码" },
    { "PhaseB_Overload", 28, 0, "B相过载(F28) -> 无对应历史功能码" },
    { "PhaseB_OverCurrent", 28, 0, "B相过流(F28) -> 无对应历史功能码" },
    { "PhaseB_LossCurrent", 28, 0, "B相失流(F28) -> 无对应历史功能码" },
    { "PhaseB_OverVoltage", 28, 0, "B相过压(F28) -> 无对应历史功能码" },
    { "PhaseB_UnderVoltage", 28, 0, "B相欠压(F28) -> 无对应历史功能码" },
    { "PhaseB_LossVoltage", 28, 0, "B相失压(F28) -> 无对应历史功能码" },
    { "PhaseC_Open", 28, 0, "C相断相(F28) -> 无对应历史功能码" },
    { "PhaseC_Reverse", 28, 0, "C相反向(F28) -> 无对应历史功能码" },
    { "PhaseC_Overload", 28, 0, "C相过载(F28) -> 无对应历史功能码" },
    { "PhaseC_OverCurrent", 28, 0, "C相过流(F28) -> 无对应历史功能码" },
    { "PhaseC_LossCurrent", 28, 0, "C相失流(F28) -> 无对应历史功能码" },
    { "PhaseC_OverVoltage", 28, 0, "C相过压(F28) -> 无对应历史功能码" },
    { "PhaseC_UnderVoltage", 28, 0, "C相欠压(F28) -> 无对应历史功能码" },
    { "PhaseC_LossVoltage", 28, 0, "C相失压(F28) -> 无对应历史功能码" },
    { "Current_Unbalance", 28, 0, "电流不平衡(F28) -> 无对应历史功能码" },
    { "Voltage_Unbalance", 28, 0, "电压不平衡(F28) -> 无对应历史功能码" },
    { "Current_ReversePhase", 28, 0, "电流逆相序(F28) -> 无对应历史功能码" },
    { "Voltage_ReversePhase", 28, 0, "电压逆相序(F28) -> 无对应历史功能码" },

    // ===== 水表类数据映射 =====
    // F403水表瞬时流量 -> 对应历史曲线
    { "FlowRate", 403, 0, "瞬时流量(F403) -> 无对应历史功能码)" },
    { "Pressure", 403, 402, "压力(F403) -> 水表压力曲线(F402)" },

    // F404水表累积流量 -> F401水表正向总累积流量曲线
    { "TotalFlow", 404, 401,
      "总累积流量(F404) -> 水表正向总累积流量曲线(F401)" },

    // F402水表状态字 -> 无对应历史功能码（状态字数据）
    { "PressureSensor_Status_Bit0", 402, 0,
      "压力传感器状态位0(F402) -> 无对应历史功能码" },
    { "PressureSensor_Status_Bit1", 402, 0,
      "压力传感器状态位1(F402) -> 无对应历史功能码" },
    { "FlowSensor_Status_Bit0", 402, 0,
      "流量传感器状态位0(F402) -> 无对应历史功能码" },
    { "FlowSensor_Status_Bit1", 402, 0,
      "流量传感器状态位1(F402) -> 无对应历史功能码" },
    { "DirectRead_Abnormal", 402, 0, "直读异常(F402) -> 无对应历史功能码" },
    { "PulseCount_Abnormal", 402, 0, "脉冲计数异常(F402) -> 无对应历史功能码" },
    { "ClockBattery_Low", 402, 0, "时钟电池(F402) -> 无对应历史功能码" },
    { "Battery1_Low", 402, 0, "电池1欠压(F402) -> 无对应历史功能码" },
    { "Battery2_Low", 402, 0, "电池2欠压(F402) -> 无对应历史功能码" },
    { "Battery3_Low", 402, 0, "电池3欠压(F402) -> 无对应历史功能码" },
    { "Battery4_Low", 402, 0, "电池4欠压(F402) -> 无对应历史功能码" },
    { "Battery5_Low", 402, 0, "电池5欠压(F402) -> 无对应历史功能码" },
    { "Storage_Abnormal", 402, 0, "存储器状态(F402) -> 无对应历史功能码" },
    { "DataVerify_Abnormal", 402, 0, "数据校验(F402) -> 无对应历史功能码" },
    { "Wireless_Abnormal", 402, 0, "无线模块(F402) -> 无对应历史功能码" },
    { "MagneticDetection_Abnormal", 402, 0,
      "强磁监测(F402) -> 无对应历史功能码" },

    // ===== 气表类数据映射 =====
    // F503气表瞬时流量 -> 对应历史曲线
    { "StandardFlowRate", 503, 504,
      "标况瞬时流量(F503) -> 气表标况瞬时流量曲线(F504)" },
    { "WorkingFlowRate", 503, 505,
      "工况瞬时流量(F503) -> 气表工况瞬时流量曲线(F505)" },
    { "Pressure", 503, 502, "压力(F503) -> 气表压力曲线(F502)" },
    { "Temperature", 503, 503, "温度(F503) -> 气表温度曲线(F503)" },

    // F504气表累积流量 -> 对应历史曲线
    { "StandardTotalFlow", 504, 506,
      "标况累积流量(F504) -> 气表标况累积流量曲线(F506)" },
    { "WorkingTotalFlow", 504, 507,
      "工况累积流量(F504) -> 气表工况累积流量曲线(F507)" },

    // F502气表状态字 -> 无对应历史功能码（状态字数据）
    { "TempSensor_Status_Bit0", 502, 0,
      "温度传感器状态位0(F502) -> 无对应历史功能码" },
    { "TempSensor_Status_Bit1", 502, 0,
      "温度传感器状态位1(F502) -> 无对应历史功能码" },

    // ===== 热表类数据映射 =====
    // F603热表瞬时流量和温度 -> 对应历史曲线
    { "SupplyWaterTemp", 603, 607, "供水温度(F603) -> 热表进水温度曲线(F607)" },
    { "ReturnWaterTemp", 603, 608, "回水温度(F603) -> 热表回水温度曲线(F608)" },
    { "FlowRate", 603, 610, "瞬时流量(F603) -> 热表瞬时流量曲线(F610)" },
    { "Pressure", 603, 0, "压力(F603) -> 无对应历史功能码" },
    { "AccumFlow", 603, 612,
      "累积流量(F603) -> 热量表正向总累积流量曲线(F612)" },
    { "AccumHeat", 603, 611,
      "累积热量(F603) -> 热量表正向总累积热量曲线(F611)" },
    { "AccumCold", 603, 0, "累积冷量(F603) -> 无对应历史功能码" },

    // F602热表状态字 -> 无对应历史功能码（状态字数据）
    { "TempControl_Status", 602, 0, "温控校状态(F602) -> 无对应历史功能码" },

    // ===== RTU自定义数据映射 =====

    // ===== 通用状态数据（无历史召测需求） =====
    // F12 RTU状态数据 -> 无对应历史功能码
    { "DI0", 12, 0, "数字量输入DI0(F12) -> 无对应历史功能码" },
    { "DI1", 12, 0, "数字量输入DI1(F12) -> 无对应历史功能码" },
    { "DI2", 12, 0, "数字量输入DI2(F12) -> 无对应历史功能码" },
    { "DI3", 12, 0, "数字量输入DI3(F12) -> 无对应历史功能码" },
    { "DI4", 12, 0, "数字量输入DI4(F12) -> 无对应历史功能码" },
    { "BatteryVoltage", 12, 0, "电池电压(F12) -> 无对应历史功能码" },
    { "AI1", 12, 0, "模拟量输入AI1(F12) -> 无对应历史功能码" },
    { "AI2", 12, 0, "模拟量输入AI2(F12) -> 无对应历史功能码" },
    { "AI3", 12, 0, "模拟量输入AI3(F12) -> 无对应历史功能码" },
    { "PulseCounter0", 12, 0, "脉冲计数器CI0(F12) -> 无对应历史功能码" },
    { "PulseCounter1", 12, 0, "脉冲计数器CI1(F12) -> 无对应历史功能码" },
    { "PulseCounter2", 12, 0, "脉冲计数器CI2(F12) -> 无对应历史功能码" },
    { "PulseCounter3", 12, 0, "脉冲计数器CI3(F12) -> 无对应历史功能码" },
};

/* 定义neu_plugin_t结构 */
typedef struct neu_plugin {
    neu_plugin_common_t common;

    // 连接管理
    neu_conn_t *conn;

    // 设备参数 - 直接存储在plugin中
    bool               connected;
    bool               waiting;
    uint8_t            seq;
    neu_reqresp_head_t waiting_req;
    UT_array *         cmd_queue;
    int                class1_timeout;
    int                class2_timeout;
    int                check_header;
    int                degrade_enabled;
    int                degrade_cycle;
    int                degrade_time;
    int                max_retries;
    int                retry_interval;
    int                endianess;
    // +++++ 召测配置 +++++
    bool  polling_enabled;
    int   max_poll_age_sec;
    int   current_before_time_sec;
    char *polling_tags_str; // 存储原始的逗号分隔字符串
    // 新增：结构化召测点配置
    polling_group_t *polling_groups;
    int              polling_group_count;
    // +++++++++++++++++++++++++++++++
    int address_base;
    int group_interval;

    // 状态标志
    bool running;
    // +++++ 对时功能（简化版） +++++
    time_t last_time_sync; // 上次对时时间戳
    // +++++ 点位状态管理 +++++
    sqlite3 *       tag_state_db;    // 点位状态数据库连接
    tag_state_t *   tag_states;      // 内存中的点位状态哈希表
    pthread_mutex_t tag_state_mutex; // 点位状态互斥锁
    // +++++ 历史召测任务管理 +++++
    UT_array *      polling_tasks;      // 历史召测任务队列
    pthread_mutex_t polling_task_mutex; // 历史召测任务互斥锁
    UT_icd          polling_task_icd;   // 实例级 UT_array 配置（新增）
    // +++++ 组级时间戳控制 +++++
    group_polling_time_t *group_polling_times; // 组级召测时间戳哈希表
    pthread_mutex_t       group_polling_time_mutex; // 组级时间戳互斥锁

    // +++++ 实例级FN映射系统（新增） +++++
    fn_mapping_entry_t *fn_mapping_hash;        // 实例级映射哈希表
    pthread_mutex_t     fn_mapping_mutex;       // 实例级互斥锁
    bool                fn_mapping_initialized; // 实例级初始化标志

    // +++++ RTU映射缓存（新增，为后续RTU功能预留） +++++
    rtu_mapping_cache_t *rtu_mapping_cache;     // 实例级RTU映射缓存
    pthread_mutex_t      rtu_cache_mutex;       // 实例级缓存互斥锁
    bool                 rtu_cache_initialized; // 实例级初始化标志
    // +++++++++++++++++++++++++++++++
    // +++++++++++++++++++++++++++++++
} neu_plugin_t;

// 获取DA1或DT1低4位的值
static int16_t GetDA1(uint8_t value)
{
    switch (value) {
    case 0x01:
        return 1;
    case 0x02:
        return 2;
    case 0x04:
        return 3;
    case 0x08:
        return 4;
    case 0x10:
        return 5;
    case 0x20:
        return 6;
    case 0x40:
        return 7;
    case 0x80:
        return 8;
    default:
        return 0;
    }
}

/* 函数前向声明 */
static neu_plugin_t *plugin_open(void);
static int           plugin_close(neu_plugin_t *plugin);
static int driver_write(neu_plugin_t *plugin, void *req, neu_datatag_t *tag,
                        neu_value_u value);
static int driver_group_timer(neu_plugin_t *plugin, neu_plugin_group_t *group);
static int neu_plugin_update_tag(neu_plugin_t *plugin, const char *group,
                                 neu_datatag_t *tag, neu_value_u *value);
// 新增函数前向声明
static int gb_12241_get_data_unit_size(uint16_t fn);
static int gb_12241_extract_data_value(neu_plugin_t * plugin,
                                       const uint8_t *data, int data_unit_size,
                                       uint16_t fn, uint8_t data_index,
                                       neu_value_u *value);
static int gb_12241_parse_tag_address(neu_plugin_t *plugin,
                                      const char *  addr_str,
                                      uint16_t *device_addr, uint16_t *fn,
                                      uint16_t *pn, uint16_t *data_index);
static int gb_12241_read_group(neu_plugin_t *plugin, neu_plugin_group_t *group);
static size_t gb_12241_parse_frame(const uint8_t *frame, size_t frame_len,
                                   uint16_t *device_addr, uint8_t *afn,
                                   uint8_t *seq, uint8_t *control_field,
                                   uint8_t *data, size_t *data_len);
static int    gb_12241_send_and_receive(neu_plugin_t * plugin,
                                        const uint8_t *request, size_t request_len,
                                        uint8_t *response, size_t *response_len);

// GB 12241 帧结构定义
#define GB_12241_FRAME_HEADER_SIZE 17 // 从起始符到数据单元标识结束
#define GB_12241_MIN_FRAME_SIZE 12    // 帧头 + CRC16
#define GB_12241_MAX_FRAME_SIZE 1024
#define GB_12241_START_CODE 0x68
#define GB_12241_END_CODE 0x16

// GB 12241 命令码定义
typedef enum {
    GB_12241_CMD_CLASS1_DATA = 0x01, // 一类数据
    GB_12241_CMD_CLASS2_DATA = 0x02, // 二类数据
    GB_12241_CMD_READ_TIME   = 0x03, // 读时间
    GB_12241_CMD_WRITE_TIME  = 0x04, // 写时间
    GB_12241_CMD_READ_ADDR   = 0x05, // 读通信地址
    GB_12241_CMD_WRITE_ADDR  = 0x06  // 写通信地址
} GB_12241_cmd_e;

// 链路层帧长度定义
typedef struct {
    uint8_t PFLG : 2;   // 协议标识
    uint8_t LUSERL : 6; // 用户数据长度低6位
    uint8_t LUSERH;     // 用户数据长度高8位
} LINK_LEN;

// 控制域
typedef struct {
    uint8_t FC : 4;  // 功能码
    uint8_t FCV : 1; // 计数有效位
    uint8_t FCB : 1; // 计数位
    uint8_t PRM : 1; // 启动报文位
    uint8_t DIR : 1; // 方向位
} Sou_ControlField;

typedef struct {
    union {
        Sou_ControlField ControlField;
        uint8_t          BControlField;
    } ControlField;
} S_ControlField;

// 地址域
typedef struct {
    uint8_t RA4 : 4; // 区号段4
    uint8_t RA3 : 4; // 区号段3
    uint8_t RA2 : 4; // 区号段2
    uint8_t RA1 : 4; // 区号段1
    uint8_t TAL;     // 终端地址低
    uint8_t TAH;     // 终端地址高
    uint8_t GAF : 1; // 终端组地址标志
    uint8_t MSA : 7; // 主站地址
} ADDR;

// 数据单元标识
typedef struct {
    uint8_t DA1; // 信息点 pn
    uint8_t DA2;
    uint8_t DT1; // 信息类 Fn
    uint8_t DT2;
} DATA_UNIT_Flag;

static uint8_t gb_12241_fn_to_dt(DATA_UNIT_Flag *ptDataUnitID, uint16_t wFn);
// 帧序列
typedef struct {
    uint8_t PSEQ : 4; // 启动帧序号
    uint8_t CON : 1;  // 请求确认标志位
    uint8_t FIN : 1;  // 末帧标志
    uint8_t FIR : 1;  // 首帧标志
    uint8_t TpV : 1;  // 帧时间标签有效标志
} SEQ;

typedef struct {
    union {
        SEQ     PSEQ;
        uint8_t RSEQ;
    } seq;
} S_SEQ;

// GB 12241 数据类型定义
typedef enum {
    GB_12241_TYPE_UNKNOWN,
    GB_12241_TYPE_INT8,
    GB_12241_TYPE_UINT8,
    GB_12241_TYPE_INT16,
    GB_12241_TYPE_UINT16,
    GB_12241_TYPE_INT32,
    GB_12241_TYPE_UINT32,
    GB_12241_TYPE_FLOAT,
    GB_12241_TYPE_DOUBLE,
    GB_12241_TYPE_STRING,
    GB_12241_TYPE_BOOL,
    GB_12241_TYPE_BIT
} GB_12241_data_type_e;

// GB 12241 字节序
typedef enum {
    GB_12241_BIG_ENDIAN    = 0,
    GB_12241_LITTLE_ENDIAN = 1
} GB_12241_endianess;

// GB 12241 地址基准
typedef enum {
    GB_12241_ADDR_BASE_0 = 0,
    GB_12241_ADDR_BASE_1 = 1
} GB_12241_address_base;

// 自定义常量定义
#define GB_12241_FN_DEVICE_STATUS 0x01 // 设备状态功能码

// 帧头结构
#pragma pack(push, 1)
typedef struct {
    uint8_t start_code[2]; // 起始码 0x68 0x68
    uint8_t addr_code[4];  // 地址域
    uint8_t afn;           // 应用功能码
    uint8_t seq;           // 序列号
} GB_12241_header;

// 地址信息
typedef struct {
    uint16_t device_addr; // 设备地址
    uint16_t reg_addr;    // 寄存器地址
    uint8_t  reg_count;   // 寄存器数量，针对连续读取
} GB_12241_address;

// 点位数据
typedef struct {
    GB_12241_data_type_e type; // 数据类型
    union {
        int8_t   i8;
        uint8_t  u8;
        int16_t  i16;
        uint16_t u16;
        int32_t  i32;
        uint32_t u32;
        float    f32;
        double   d64;
        bool     boolean;
        struct {
            uint8_t *bytes;
            uint16_t length;
        } str;
        struct {
            uint8_t *bytes;
            uint16_t length;
        } bytes;
    } value;
} GB_12241_data;

// 点位结构
typedef struct {
    char                 name[NEU_TAG_NAME_LEN];
    char                 address[NEU_TAG_ADDRESS_LEN];
    GB_12241_address     addr;
    GB_12241_data_type_e type;
    uint16_t             size;
    uint8_t              bit_offset;
    uint8_t data_index; // 新增：数据索引，表示读取的第几个数据
} GB_12241_point_t;

// 函数前向声明
static GB_12241_point_t *gb_12241_find_tag(neu_plugin_t *plugin,
                                           const char *  tag_name);
static int gb_12241_write_tag(neu_plugin_t *plugin, GB_12241_point_t *point,
                              neu_value_u value);
static int gb_12241_read_group(neu_plugin_t *plugin, neu_plugin_group_t *group);
static int gb_12241_send_and_receive(neu_plugin_t * plugin,
                                     const uint8_t *request, size_t request_len,
                                     uint8_t *response, size_t *response_len);
static size_t gb_12241_parse_frame(const uint8_t *frame, size_t frame_len,
                                   uint16_t *device_addr, uint8_t *afn,
                                   uint8_t *seq, uint8_t *control_field,
                                   uint8_t *data, size_t *data_len);
static int    gb_12241_build_multi_request(neu_plugin_t *plugin, uint8_t *frame,
                                           size_t frame_size, uint16_t device_addr,
                                           uint8_t seq, uint16_t *fn_array,
                                           uint16_t *pn_array, int fn_pn_count,
                                           size_t *request_length);
//对时
static int gb_12241_build_time_sync_request(neu_plugin_t *plugin,
                                            uint8_t *frame, size_t frame_size,
                                            uint16_t device_addr, uint8_t seq,
                                            size_t *request_length);
//执行对时
static int gb_12241_execute_time_sync(neu_plugin_t *plugin);

static GB_12241_data_type_e gb_12241_neuron_type_to_type(neu_type_e type);
static int                  driver_start(neu_plugin_t *plugin);
static int                  driver_stop(neu_plugin_t *plugin);
static int driver_validate_tag(neu_plugin_t *plugin, neu_datatag_t *tag);
static int driver_group_timer(neu_plugin_t *plugin, neu_plugin_group_t *group);
static int plugin_stop(neu_plugin_t *plugin);

/**
 * @brief 检查标签名称是否为RTU类型
 * @param tag_name 标签名称
 * @return true 如果是RTU类型，false 否则
 */
static bool is_rtu_tag(const char *tag_name)
{
    if (!tag_name)
        return false;

    // 检查是否匹配RTU标签模式：rtudi、rtuai、rtuci
    for (size_t i = 0; i < rtu_patterns_count; i++) {
        if (strncmp(tag_name, rtu_patterns[i].pattern,
                    strlen(rtu_patterns[i].pattern)) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * @brief 从预构建的映射表中获取RTU标签顺序
 * @param plugin 插件实例
 * @param group_name 组名
 * @param tag_name 标签名称
 * @return RTU标签的顺序位置（0-11），如果未找到则返回-1
 */
static int get_rtu_tag_order_in_group(neu_plugin_t *plugin,
                                      const char *  group_name,
                                      const char *  tag_name)
{
    if (!plugin || !group_name || !tag_name || !is_rtu_tag(tag_name)) {
        return -1;
    }

    pthread_mutex_lock(&plugin->rtu_cache_mutex);

    // 在映射表中查找
    rtu_mapping_cache_t *mapping, *tmp;
    HASH_ITER(hh, plugin->rtu_mapping_cache, mapping, tmp)
    {
        if (strcmp(mapping->group_name, group_name) == 0 &&
            strcmp(mapping->tag_name, tag_name) == 0) {
            int order = mapping->rtu_order;
            pthread_mutex_unlock(&plugin->rtu_cache_mutex);
            return order;
        }
    }

    pthread_mutex_unlock(&plugin->rtu_cache_mutex);

    plog_warn(plugin, "RTU标签 '%s' 在组'%s'中未找到映射", tag_name,
              group_name);
    return -1;
}
/**
 * @brief 专用于RTU标签的历史FN获取函数
 * @param plugin 插件实例
 * @param group_name 组名
 * @param tag_name 标签名称
 * @param realtime_fn 实时功能码（RTU类型中不使用，但保持接口一致）
 * @return 历史功能码（710-721），失败返回0
 */
static uint16_t get_rtu_historical_fn(neu_plugin_t *plugin,
                                      const char *  group_name,
                                      const char *  tag_name,
                                      uint16_t      realtime_fn)
{
    NEU_UNUSED(realtime_fn); // RTU映射不依赖实时FN

    if (!plugin || !group_name || !tag_name || !is_rtu_tag(tag_name)) {
        return 0;
    }

    // 获取RTU标签在组内的顺序
    int rtu_order = get_rtu_tag_order_in_group(plugin, group_name, tag_name);

    if (rtu_order >= 0 && rtu_order < 12) {
        // RTU标签按顺序映射到FN 710-721
        uint16_t historical_fn = 710 + rtu_order;

        plog_debug(plugin, "RTU标签映射: %s 在组'%s'中顺序=%d, 映射到历史FN=%u",
                   tag_name, group_name, rtu_order, historical_fn);

        return historical_fn;
    } else {
        plog_warn(plugin, "RTU标签 '%s' 在组'%s'中顺序无效: %d", tag_name,
                  group_name, rtu_order);
        return 0;
    }
}

/**
 * @brief 初始化RTU映射缓存系统
 * @param plugin 插件实例
 * @return 0成功，-1失败
 */
static int init_rtu_mapping_cache(neu_plugin_t *plugin)
{
    if (!plugin) {
        return -1;
    }

    // 初始化互斥锁
    if (pthread_mutex_init(&plugin->rtu_cache_mutex, NULL) != 0) {
        plog_error(plugin, "RTU缓存互斥锁初始化失败");
        return -1;
    }

    // 初始化哈希表
    plugin->rtu_mapping_cache     = NULL;
    plugin->rtu_cache_initialized = true;

    plog_info(plugin, "RTU映射缓存系统初始化完成");
    return 0;
}
/**
 * @brief 根据polling_groups配置构建RTU映射表（内存安全版本）
 * @param plugin 插件实例
 * @return 0成功，-1失败
 */
static int build_rtu_mapping_table(neu_plugin_t *plugin)
{
    if (!plugin)
        return -1;

    pthread_mutex_lock(&plugin->rtu_cache_mutex);

    // 1. 清理现有映射表
    rtu_mapping_cache_t *entry, *tmp;
    HASH_ITER(hh, plugin->rtu_mapping_cache, entry, tmp)
    {
        HASH_DEL(plugin->rtu_mapping_cache, entry);
        free(entry);
    }
    plugin->rtu_mapping_cache = NULL;

    // 2. 先构建到临时哈希表，成功后再赋值（原子操作）
    rtu_mapping_cache_t *temp_mapping_table = NULL;
    bool                 build_success      = true;

    // 遍历所有组，构建RTU映射
    for (int i = 0; i < plugin->polling_group_count && build_success; i++) {
        const char *group_name = plugin->polling_groups[i].group;
        int         rtu_order  = 0;

        for (int j = 0;
             j < plugin->polling_groups[i].tag_count && build_success; j++) {
            const char *tag_name = plugin->polling_groups[i].tags[j];

            if (is_rtu_tag(tag_name)) {
                if (rtu_order < 12) {
                    // 创建映射条目
                    rtu_mapping_cache_t *mapping =
                        calloc(1, sizeof(rtu_mapping_cache_t));
                    if (!mapping) {
                        plog_error(plugin, "分配RTU映射条目内存失败");
                        build_success = false;
                        break;
                    }

                    strncpy(mapping->group_name, group_name,
                            NEU_GROUP_NAME_LEN - 1);
                    strncpy(mapping->tag_name, tag_name, NEU_TAG_NAME_LEN - 1);
                    mapping->rtu_order     = rtu_order;
                    mapping->historical_fn = 710 + rtu_order;

                    // 添加到临时哈希表
                    HASH_ADD_STR(temp_mapping_table, tag_name, mapping);

                    plog_debug(plugin, "构建RTU映射: %s.%s -> 顺序%d, FN=%u",
                               group_name, tag_name, rtu_order,
                               mapping->historical_fn);

                    rtu_order++;
                } else {
                    plog_warn(
                        plugin,
                        "RTU标签 '%s' 在组'%s'中顺序超出限制: %d (最大11)",
                        tag_name, group_name, rtu_order);
                }
            }
        }
    }

    if (build_success) {
        // 3. 构建成功，原子替换
        plugin->rtu_mapping_cache = temp_mapping_table;
        plog_info(plugin, "RTU映射表构建完成");
    } else {
        // 4. 构建失败，清理临时表
        HASH_ITER(hh, temp_mapping_table, entry, tmp)
        {
            HASH_DEL(temp_mapping_table, entry);
            free(entry);
        }
        plog_error(plugin, "RTU映射表构建失败，保持原有映射");
    }

    pthread_mutex_unlock(&plugin->rtu_cache_mutex);

    return build_success ? 0 : -1;
}
/**
 * @brief 清理RTU映射缓存系统（简化版）
 * @param plugin 插件实例
 */
static void cleanup_rtu_mapping_cache(neu_plugin_t *plugin)
{
    if (!plugin || !plugin->rtu_cache_initialized) {
        return;
    }

    pthread_mutex_lock(&plugin->rtu_cache_mutex);

    // 清理RTU映射缓存（现在就是映射表）
    rtu_mapping_cache_t *cache_entry, *cache_tmp;
    HASH_ITER(hh, plugin->rtu_mapping_cache, cache_entry, cache_tmp)
    {
        HASH_DEL(plugin->rtu_mapping_cache, cache_entry);
        free(cache_entry);
    }

    pthread_mutex_unlock(&plugin->rtu_cache_mutex);
    pthread_mutex_destroy(&plugin->rtu_cache_mutex);

    plugin->rtu_cache_initialized = false;
    plog_info(plugin, "RTU映射缓存系统已清理");
}

// ==== 实用函数 ====

// CRC校验计算
static uint8_t gb_12241_make_crc(const uint8_t *buf, int16_t count)
{
    uint8_t crc = 0;
    int16_t i;

    if (buf == NULL || count <= 0) {
        return 0;
    }

    for (i = 0; i < count; i++) {
        crc += buf[i];
    }

    return crc;
}

// 从Neuron类型映射到GB12241类型
static GB_12241_data_type_e gb_12241_neuron_type_to_type(neu_type_e type)
{
    switch (type) {
    case NEU_TYPE_BOOL:
        return GB_12241_TYPE_BOOL;
    case NEU_TYPE_INT8:
        return GB_12241_TYPE_INT8;
    case NEU_TYPE_UINT8:
        return GB_12241_TYPE_UINT8;
    case NEU_TYPE_INT16:
        return GB_12241_TYPE_INT16;
    case NEU_TYPE_UINT16:
        return GB_12241_TYPE_UINT16;
    case NEU_TYPE_INT32:
        return GB_12241_TYPE_INT32;
    case NEU_TYPE_UINT32:
        return GB_12241_TYPE_UINT32;
    case NEU_TYPE_FLOAT:
        return GB_12241_TYPE_FLOAT;
    case NEU_TYPE_DOUBLE:
        return GB_12241_TYPE_DOUBLE;
    case NEU_TYPE_STRING:
        return GB_12241_TYPE_STRING;
    case NEU_TYPE_BIT:
        return GB_12241_TYPE_BIT;
    default:
        return GB_12241_TYPE_UNKNOWN;
    }
}

// ==== 插件接口实现 ====

static neu_plugin_t *plugin_open(void)
{
    neu_plugin_t *plugin = calloc(1, sizeof(neu_plugin_t));
    if (plugin == NULL) {
        return NULL;
    }

    // 初始化通用部分
    neu_plugin_common_init(&plugin->common);

    // 初始化内部状态
    plugin->running   = false;
    plugin->connected = false;
    plugin->waiting   = false;
    plugin->seq       = 0;

    // 初始化默认参数值
    plugin->class1_timeout  = 10000;
    plugin->class2_timeout  = 60000;
    plugin->check_header    = 0;
    plugin->degrade_enabled = 0;
    plugin->degrade_cycle   = 2;
    plugin->degrade_time    = 600;
    plugin->max_retries     = 0;
    plugin->retry_interval  = 0;
    plugin->endianess       = 1;
    plugin->address_base    = 0;
    plugin->group_interval  = 1000;

    // 初始化组级时间戳哈希表
    plugin->group_polling_times = NULL;

    return plugin;
}

static int plugin_close(neu_plugin_t *plugin)
{
    if (plugin == NULL) {
        return -1;
    }

    // 关闭TCP连接
    if (plugin->conn != NULL) {
        neu_conn_stop(plugin->conn);
        neu_conn_destory(plugin->conn);
    }

    // 释放召测标签字符串
    if (plugin->polling_tags_str != NULL) {
        free(plugin->polling_tags_str);
        plugin->polling_tags_str = NULL;
    }

    // 释放结构化召测点配置
    if (plugin->polling_groups) {
        for (int i = 0; i < plugin->polling_group_count; i++) {
            if (plugin->polling_groups[i].tags) {
                for (int j = 0; j < plugin->polling_groups[i].tag_count; j++) {
                    free(plugin->polling_groups[i].tags[j]);
                }
                free(plugin->polling_groups[i].tags);
            }
        }
        free(plugin->polling_groups);
        plugin->polling_groups      = NULL;
        plugin->polling_group_count = 0;
    }

    free(plugin);

    return 0;
}

static int plugin_init(neu_plugin_t *plugin, bool load)
{
    if (plugin == NULL) {
        return -1;
    }

    NEU_UNUSED(load);

    // 初始化连接为NULL
    plugin->conn = NULL;

    // 初始化命令队列
    plugin->cmd_queue = NULL;
    utarray_new(plugin->cmd_queue, &ut_ptr_icd);

    // 初始化组级时间戳哈希表和互斥锁
    plugin->group_polling_times = NULL;
    if (pthread_mutex_init(&plugin->group_polling_time_mutex, NULL) != 0) {
        plog_error(plugin, "group_polling_time_mutex init failed");
        return -1;
    }

    // +++++ 新增：初始化实例级FN映射系统 +++++
    plugin->fn_mapping_hash        = NULL;
    plugin->fn_mapping_initialized = false;
    if (pthread_mutex_init(&plugin->fn_mapping_mutex, NULL) != 0) {
        plog_error(plugin, "fn_mapping_mutex init failed");
        pthread_mutex_destroy(&plugin->group_polling_time_mutex);
        return -1;
    }

    // 初始化RTU映射缓存系统
    if (init_rtu_mapping_cache(plugin) != 0) {
        plog_error(plugin, "RTU映射缓存系统初始化失败");
        // 继续执行，不是致命错误
    }
    // +++++++++++++++++++++++++++++++

    return 0;
}

static int plugin_uninit(neu_plugin_t *plugin)
{
    if (plugin == NULL) {
        return -1;
    }

    // 先调用 stop 确保驱动正确停止
    plugin_stop(plugin);

    plugin->running = false;

    // +++++ 新增：清理实例级FN映射系统 +++++
    cleanup_fn_mapping_hash(plugin);
    pthread_mutex_destroy(&plugin->fn_mapping_mutex);
    // +++++++++++++++++++++++++++++++

    // +++++ 新增：清理RTU映射缓存系统 +++++
    cleanup_rtu_mapping_cache(plugin);
    // +++++++++++++++++++++++++++++++

    // 释放连接资源
    if (plugin->conn != NULL) {
        neu_conn_destory(plugin->conn);
        plugin->conn = NULL;
    }

    // 释放命令队列
    if (plugin->cmd_queue) {
        utarray_free(plugin->cmd_queue);
        plugin->cmd_queue = NULL;
    }

    plog_notice(plugin, "插件已卸载");

    return 0;
}

static int plugin_start(neu_plugin_t *plugin)
{
    if (plugin == NULL) {
        return -1;
    }

    return driver_start(plugin);
}

static int plugin_stop(neu_plugin_t *plugin)
{
    if (plugin == NULL) {
        return -1;
    }

    plugin->running = false;

    return driver_stop(plugin);
}

static int plugin_config(neu_plugin_t *plugin, const char *config)
{
    if (plugin == NULL || config == NULL) {
        return -1;
    }

    int              ret             = 0;
    char *           err_param       = NULL;
    neu_json_elem_t  port            = { .name = "port", .t = NEU_JSON_INT };
    neu_json_elem_t  timeout         = { .name = "timeout", .t = NEU_JSON_INT };
    neu_json_elem_t  host            = { .name      = "host",
                             .t         = NEU_JSON_STR,
                             .v.val_str = NULL };
    neu_conn_param_t param           = { 0 };
    neu_json_elem_t  class1_timeout  = { .name = "class1_timeout",
                                       .t    = NEU_JSON_INT };
    neu_json_elem_t  class2_timeout  = { .name = "class2_timeout",
                                       .t    = NEU_JSON_INT };
    neu_json_elem_t  connection_mode = { .name = "connection_mode",
                                        .t    = NEU_JSON_INT };
    neu_json_elem_t  check_header    = { .name = "check_header",
                                     .t    = NEU_JSON_INT };
    neu_json_elem_t  device_degrade  = { .name = "device_degrade",
                                       .t    = NEU_JSON_INT };
    neu_json_elem_t  degrade_cycle   = { .name = "degrade_cycle",
                                      .t    = NEU_JSON_INT };
    neu_json_elem_t  degrade_time    = { .name = "degrade_time",
                                     .t    = NEU_JSON_INT };
    neu_json_elem_t  max_retries = { .name = "max_retries", .t = NEU_JSON_INT };
    neu_json_elem_t  retry_interval = { .name = "retry_interval",
                                       .t    = NEU_JSON_INT };
    neu_json_elem_t  endianess    = { .name = "endianess", .t = NEU_JSON_INT };
    neu_json_elem_t  address_base = { .name = "address_base",
                                     .t    = NEU_JSON_INT };

    // +++++ u5b9au4e49u53ecu6d4bu914du7f6eu5143u7d20 +++++
    neu_json_elem_t polling_enabled_elem     = { .name = "polling_enabled",
                                             .t    = NEU_JSON_INT };
    neu_json_elem_t max_poll_age_elem        = { .name = "max_poll_age",
                                          .t    = NEU_JSON_INT };
    neu_json_elem_t current_before_time_elem = { .name = "current_before_time",
                                                 .t    = NEU_JSON_INT };
    neu_json_elem_t polling_tags_elem        = { .name = "polling_tags",
                                          .t    = NEU_JSON_STR };
    // ++++++++++++++++++++++++++++++++

    // 解析基本参数：host、port、timeout
    ret =
        neu_parse_param((char *) config, &err_param, 3, &host, &port, &timeout);
    if (ret != 0) {
        plog_error(plugin, "config: %s, decode error: %s", config, err_param);
        free(err_param);
        if (host.v.val_str != NULL) {
            free(host.v.val_str);
        }
        return -1;
    }

    // 验证必需参数
    if (host.v.val_str == NULL || port.v.val_int <= 0 ||
        port.v.val_int > 65535) {
        plog_error(plugin, "缺少必需参数或参数无效: host或port");
        if (host.v.val_str != NULL) {
            free(host.v.val_str);
        }
        return -1;
    }

    // 解析可选参数
    ret = neu_parse_param((char *) config, &err_param, 1, &connection_mode);
    if (ret != 0) {
        free(err_param);
        connection_mode.v.val_int = 0; // 默认客户端模式
    }

    ret = neu_parse_param((char *) config, &err_param, 2, &class1_timeout,
                          &class2_timeout);
    if (ret != 0) {
        free(err_param);
        class1_timeout.v.val_int = 10000; // 默认10秒
        class2_timeout.v.val_int = 60000; // 默认60秒
    }

    ret = neu_parse_param((char *) config, &err_param, 1, &check_header);
    if (ret != 0) {
        free(err_param);
        check_header.v.val_int = 0;
    }

    ret = neu_parse_param((char *) config, &err_param, 3, &device_degrade,
                          &degrade_cycle, &degrade_time);
    if (ret != 0) {
        free(err_param);
        device_degrade.v.val_int = 0;
        degrade_cycle.v.val_int  = 2;
        degrade_time.v.val_int   = 600;
    }

    ret = neu_parse_param((char *) config, &err_param, 2, &max_retries,
                          &retry_interval);
    if (ret != 0) {
        free(err_param);
        max_retries.v.val_int    = 0;
        retry_interval.v.val_int = 0;
    }

    ret = neu_parse_param((char *) config, &err_param, 1, &endianess);
    if (ret != 0) {
        free(err_param);
        endianess.v.val_int = 1; // 默认ABCD
    }

    ret = neu_parse_param((char *) config, &err_param, 1, &address_base);
    if (ret != 0) {
        free(err_param);
        address_base.v.val_int = 0; // 默认从0开始
    }

    // 打印配置信息
    plog_notice(plugin,
                "配置参数 - host: %s, port: %" PRId64 ", timeout: %" PRId64
                " ms",
                host.v.val_str, port.v.val_int, timeout.v.val_int);
    plog_notice(plugin,
                "配置参数 - connection_mode: %" PRId64
                ", class1_timeout: %" PRId64 " ms, class2_timeout: %" PRId64
                " ms",
                connection_mode.v.val_int, class1_timeout.v.val_int,
                class2_timeout.v.val_int);
    plog_notice(plugin,
                "配置参数 - check_header: %" PRId64 ", device_degrade: %" PRId64
                "",
                check_header.v.val_int, device_degrade.v.val_int);
    plog_notice(plugin,
                "配置参数 - degrade_cycle: %" PRId64 ", degrade_time: %" PRId64
                "",
                degrade_cycle.v.val_int, degrade_time.v.val_int);
    plog_notice(plugin,
                "配置参数 - max_retries: %" PRId64 ", retry_interval: %" PRId64
                "",
                max_retries.v.val_int, retry_interval.v.val_int);
    plog_notice(plugin,
                "配置参数 - endianess: %" PRId64 ", address_base: %" PRId64 "",
                endianess.v.val_int, address_base.v.val_int);
    plog_notice(plugin, "配置参数 - group_interval: 1000 ms");

    // 根据连接模式配置连接参数
    param.log = plugin->common.log;

    if (connection_mode.v.val_int == 0) {
        // 客户端模式
        param.type                      = NEU_CONN_TCP_CLIENT;
        param.params.tcp_client.ip      = strdup(host.v.val_str);
        param.params.tcp_client.port    = port.v.val_int;
        param.params.tcp_client.timeout = timeout.v.val_int;

        // 配置或创建连接
        if (plugin->conn != NULL) {
            plugin->conn = neu_conn_reconfig(plugin->conn, &param);
        } else {
            plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
            plugin->conn =
                neu_conn_new(&param, (void *) plugin, gb_12241_conn_connected,
                             gb_12241_conn_disconnected);
        }

        free(param.params.tcp_client.ip);
    } else {
        // 服务器模式
        param.type                           = NEU_CONN_TCP_SERVER;
        param.params.tcp_server.ip           = strdup(host.v.val_str);
        param.params.tcp_server.port         = port.v.val_int;
        param.params.tcp_server.timeout      = timeout.v.val_int;
        param.params.tcp_server.max_link     = 5;    // 最大连接数
        param.params.tcp_server.start_listen = NULL; // 暂不支持回调
        param.params.tcp_server.stop_listen  = NULL;

        // 配置或创建连接
        if (plugin->conn != NULL) {
            plugin->conn = neu_conn_reconfig(plugin->conn, &param);
        } else {
            plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
            plugin->conn =
                neu_conn_new(&param, (void *) plugin, gb_12241_conn_connected,
                             gb_12241_conn_disconnected);
        }

        free(param.params.tcp_server.ip);
    }

    // 将所有参数存储到plugin结构
    plugin->class1_timeout  = class1_timeout.v.val_int;
    plugin->class2_timeout  = class2_timeout.v.val_int;
    plugin->check_header    = check_header.v.val_int;
    plugin->degrade_enabled = device_degrade.v.val_int;
    plugin->degrade_cycle   = degrade_cycle.v.val_int;
    plugin->degrade_time    = degrade_time.v.val_int;
    plugin->max_retries     = max_retries.v.val_int;
    plugin->retry_interval  = retry_interval.v.val_int;
    plugin->endianess       = endianess.v.val_int;
    plugin->address_base    = address_base.v.val_int;
    plugin->group_interval  = 1000; // 默认值

    // ++++ 设置召测配置 ++++
    // 从配置文件中读取召测相关参数
    ret = neu_parse_param((char *) config, &err_param, 4, &polling_enabled_elem,
                          &max_poll_age_elem, &current_before_time_elem,
                          &polling_tags_elem);

    if (ret != 0) {
        free(err_param);
        // 设置默认值
        plugin->polling_enabled         = false;
        plugin->max_poll_age_sec        = 86400; // 默认一天
        plugin->current_before_time_sec = 300;   // 默认5分钟
        plugin->polling_tags_str        = NULL;
        plog_notice(plugin, "召测配置 - 未找到或不完整，使用默认值：禁用");
    } else {
        // 设置配置值
        plugin->polling_enabled         = (polling_enabled_elem.v.val_int == 1);
        plugin->max_poll_age_sec        = max_poll_age_elem.v.val_int;
        plugin->current_before_time_sec = current_before_time_elem.v.val_int;

        // 处理召测标签字符串
        if (polling_tags_elem.v.val_str != NULL) {
            plugin->polling_tags_str = strdup(polling_tags_elem.v.val_str);
            free(polling_tags_elem.v.val_str);
        } else {
            plugin->polling_tags_str = NULL;
        }

        plog_notice(
            plugin,
            "召测配置 - 启用: %s, 最大时间范围: %d秒, 当前时间偏移: %d秒",
            plugin->polling_enabled ? "是" : "否", plugin->max_poll_age_sec,
            plugin->current_before_time_sec);

        if (plugin->polling_tags_str != NULL) {
            plog_notice(plugin, "召测配置 - 标签列表: %s",
                        plugin->polling_tags_str);
        } else {
            plog_notice(plugin, "召测配置 - 标签列表: 未指定");
        }
    }
    // +++++++++++++++++++++++

    // 释放资源
    if (host.v.val_str != NULL) {
        free(host.v.val_str);
        host.v.val_str = NULL;
    }

    // ====== 召测功能数据库初始化逻辑 ======
    // 只有启用polling_enabled时才初始化点位状态数据库
    if (plugin->polling_enabled) {
        if (plugin->tag_state_db) {
            // 已经初始化过，先关闭，防止重复分配
            close_tag_state_db(plugin);
        }
        if (init_tag_state_db(plugin) != 0) {
            plog_error(plugin, "点位状态数据库初始化失败，召测功能将被禁用");
            plugin->polling_enabled = false;
        } else {
            plog_notice(plugin, "点位状态数据库初始化成功，召测功能已启用");
        }
    } else {
        // 未启用召测功能，确保数据库未被初始化
        if (plugin->tag_state_db) {
            close_tag_state_db(plugin);
        }
    }
    plugin->polling_groups      = NULL;
    plugin->polling_group_count = 0;
    if (plugin->polling_tags_str && strlen(plugin->polling_tags_str) > 0) {
        plugin->polling_groups = parse_polling_tags(
            plugin->polling_tags_str, &plugin->polling_group_count);
        if (!plugin->polling_groups) {
            plog_error(plugin,
                       "解析polling_tags JSON字符串失败，格式应为: "
                       "[{\"group\":\"group1\",\"tags\":[\"Ua\",\"Ub\"]}]");
        } else {
            plog_notice(plugin, "成功解析polling_tags: %d组",
                        plugin->polling_group_count);
        }
    }
    // ===== 新增：构建RTU映射表 =====
    if (plugin->polling_groups && plugin->rtu_cache_initialized) {
        if (build_rtu_mapping_table(plugin) != 0) {
            plog_error(plugin, "构建RTU映射表失败");
        }
    }
    // ======================================

    return 0;
}

// 解析标签地址
static int gb_12241_parse_tag_address(neu_plugin_t *plugin,
                                      const char *  addr_str,
                                      uint16_t *device_addr, uint16_t *fn,
                                      uint16_t *pn, uint16_t *data_index)
{
    NEU_UNUSED(plugin);

    if (addr_str == NULL) {
        plog_error(plugin, "标签地址为空");
        return -1;
    }

    // 地址格式1：device,fn[,pn[,dtype]] - 逗号分隔的旧格式
    // 地址格式2：device!fn[.pn] - 兼容Modbus风格的格式
    // 地址格式3：device!FfnPpn[.x] - 新格式，明确功能码和参数号
    unsigned int dev       = 0;
    unsigned int fun       = 0;
    unsigned int param     = 0;
    unsigned int idx       = 0;
    char         func_type = 0;
    int          ret       = 0;

    // 首先尝试解析新的FfnPpn[.x]格式
    ret = sscanf(addr_str, "%u!F%uP%u.%u", &dev, &fun, &param, &idx);
    if (ret == 4) {
        *device_addr = (uint16_t) dev;
        *fn          = (uint16_t) fun;
        *pn          = (uint16_t) param;
        if (data_index) {
            *data_index = (uint8_t) idx;
        }
        plog_debug(plugin,
                   "解析地址成功(新格式4): %s -> 设备号=%u, 功能码=%u, "
                   "参数号=%u, 数据索引=%u",
                   addr_str, dev, fun, param, data_index ? *data_index : 0);
        return 0;
    }

    // 尝试解析没有数据索引的新格式
    ret = sscanf(addr_str, "%u!F%uP%u", &dev, &fun, &param);
    if (ret == 3) {
        *device_addr = (uint16_t) dev;
        *fn          = (uint16_t) fun;
        *pn          = (uint8_t) param;
        if (data_index) {
            *data_index = 0;
        }
        plog_notice(plugin,
                    "解析地址成功(新格式3): %s -> 设备号=%u, 功能码=%u, "
                    "参数号=%u, 数据索引=%u",
                    addr_str, dev, fun, param, data_index ? *data_index : 0);
        return 0;
    }

    // 尝试解析逗号分隔的原始格式
    unsigned int dtype = 0; // 仍然需要这个变量来正确解析格式，但不再使用其值
    ret = sscanf(addr_str, "%u,%u,%u,%u", &dev, &fun, &param, &dtype);

    if (ret >= 2) {
        // 逗号格式解析成功
        *device_addr = (uint16_t) dev;
        *fn          = (uint16_t) fun;
        if (data_index) {
            *data_index = 0;
        }

        // 设置可选参数
        if (ret >= 3) {
            *pn = (uint16_t) param;
        } else {
            *pn = 0;
        }

        plog_notice(plugin,
                    "解析地址成功(逗号格式): %s -> 设备号=%u, 功能码=%u, "
                    "参数号=%u, 数据索引=%u",
                    addr_str, dev, fun, *pn, data_index ? *data_index : 0);
        return 0;
    }

    // 尝试解析带字母功能码且带参数的格式 (例如 "1!F25.1")
    ret = sscanf(addr_str, "%u!%c%u.%u", &dev, &func_type, &fun, &param);
    if (ret == 4) {
        *device_addr = (uint16_t) dev;
        *fn          = (uint16_t) fun;
        *pn          = (uint16_t) param;
        if (data_index) {
            *data_index = 0;
        }
        plog_notice(plugin,
                    "解析地址成功(字母格式带参数): %s -> 设备号=%u, 功能码=%u, "
                    "参数号=%u, 数据索引=%u",
                    addr_str, dev, fun, param, data_index ? *data_index : 0);
        return 0;
    }

    // 尝试解析带字母功能码的格式 (例如 "1!F25")
    ret = sscanf(addr_str, "%u!%c%u", &dev, &func_type, &fun);
    if (ret == 3) {
        *device_addr = (uint16_t) dev;
        *fn          = (uint16_t) fun;
        *pn          = 0;
        if (data_index) {
            *data_index = 0;
        }
        plog_notice(plugin,
                    "解析地址成功(字母格式): %s -> 设备号=%u, 功能码=%u, "
                    "参数号=%u, 数据索引=%u",
                    addr_str, dev, fun, *pn, data_index ? *data_index : 0);
        return 0;
    }

    // 尝试解析纯数字功能码带参数格式 (例如 "1!25.1")
    ret = sscanf(addr_str, "%u!%u.%u", &dev, &fun, &param);
    if (ret == 3) {
        *device_addr = (uint16_t) dev;
        *fn          = (uint16_t) fun;
        *pn          = (uint16_t) param;
        if (data_index) {
            *data_index = 0;
        }
        plog_notice(plugin,
                    "解析地址成功(纯数字带参数): %s -> 设备号=%u, 功能码=%u, "
                    "参数号=%u, 数据索引=%u",
                    addr_str, dev, fun, param, data_index ? *data_index : 0);
        return 0;
    }

    // 尝试解析纯数字功能码格式 (例如 "1!25")
    ret = sscanf(addr_str, "%u!%u", &dev, &fun);
    if (ret == 2) {
        *device_addr = (uint16_t) dev;
        *fn          = (uint16_t) fun;
        *pn          = 0;
        if (data_index) {
            *data_index = 0;
        }
        plog_notice(plugin,
                    "解析地址成功(纯数字): %s -> 设备号=%u, 功能码=%u, "
                    "参数号=%u, 数据索引=%u",
                    addr_str, dev, fun, *pn, data_index ? *data_index : 0);
        return 0;
    }

    plog_error(plugin,
               "无效的标签地址格式: %s, 支持格式: 设备号,功能码[,参数[,类型]] "
               "或 设备号!功能码[.参数] 或 设备号!F功能码P参数[.索引]",
               addr_str);
    return -1;
}

// 查找标签 - 由于框架管理标签，这个函数不再需要
static GB_12241_point_t *gb_12241_find_tag(neu_plugin_t *plugin,
                                           const char *  tag_name)
{
    if (plugin == NULL || tag_name == NULL) {
        return NULL;
    }

    // 框架会直接调用driver_write，不需要在这里查找标签
    plog_debug(plugin, "gb_12241_find_tag已废弃，标签由框架管理: %s", tag_name);
    return NULL;
}

// 驱动实现函数
static int driver_validate_tag(neu_plugin_t *plugin, neu_datatag_t *tag)
{
    if (plugin == NULL || tag == NULL) {
        return -1;
    }

    plog_debug(plugin, "验证标签: %s, 地址: %s", tag->name, tag->address);

    // 解析地址
    uint16_t device_addr = 0;
    uint16_t fn          = 0;
    uint16_t pn          = 0;

    if (gb_12241_parse_tag_address(plugin, tag->address, &device_addr, &fn, &pn,
                                   NULL) != 0) {
        return -1;
    }

    // 验证数据类型
    GB_12241_data_type_e gb_type = gb_12241_neuron_type_to_type(tag->type);
    if (gb_type == GB_12241_TYPE_UNKNOWN) {
        plog_error(plugin, "不支持的数据类型: %d", tag->type);
        return -1;
    }

    // 验证设备地址范围 - 允许0(采集器自身)
    if ((unsigned int) device_addr > 128U) {
        plog_error(plugin, "设备地址超出允许范围(0-128): %d", device_addr);
        return -1;
    }

    // 验证功能码范围
    if (fn == 0) {
        plog_error(plugin, "无效的功能码: %d", fn);
        return -1;
    }

    return 0;
}

// 读取标签值
static int gb_12241_write_tag(neu_plugin_t *plugin, GB_12241_point_t *point,
                              neu_value_u value)
{
    NEU_UNUSED(value);
    if (plugin == NULL || point == NULL) {
        return -1;
    }

    plog_debug(plugin, "写入标签: %s, 地址: %s", point->name, point->address);

    // GB/T 12241协议通常是只读的，如果需要支持写入操作，需要实现此功能
    plog_warn(plugin, "写入操作暂不支持: %s", point->name);
    return -1;
}

// 读取组内所有标签
static int gb_12241_read_group(neu_plugin_t *plugin, neu_plugin_group_t *group)
{
    if (plugin == NULL || group == NULL) {
        return -1;
    }

    int          ret             = 0;
    int          success_count   = 0;
    int          error_count     = 0;
    int64_t      rtt             = 0; // 响应时间
    int          total_count     = 0; // 总请求数量
    uint64_t     read_start_time = neu_time_ms();
    unsigned int tag_count       = utarray_len(group->tags);
    const char * safe_group_name = get_safe_group_name(group);

    plog_debug((neu_plugin_t *) plugin, "读取组 '%s' 中的 %d 个标签",
               safe_group_name, tag_count);

    // 如果组中没有标签，直接返回
    if (tag_count == 0) {
        plog_debug(plugin, "组 '%s' 中没有标签", safe_group_name);
        return 0;
    }

    // 确保TCP连接正常
    if (!neu_conn_is_connected(plugin->conn)) {
        plog_info(plugin, "尝试连接服务器...");
        neu_conn_connect(plugin->conn);

        if (!neu_conn_is_connected(plugin->conn)) {
            plog_error(plugin, "连接服务器失败，无法读取组: '%s'",
                       safe_group_name);
            return -1;
        }
    }

    // 1. 遍历标签，按设备地址和FN+PN进行分组，最多4个FN+PN一组
    typedef struct {
        uint16_t device_addr;
        uint16_t fn;
        uint16_t pn;
        uint16_t data_index;
        bool     processed;
    } tag_key_t;

    tag_key_t *tag_keys = (tag_key_t *) malloc(tag_count * sizeof(tag_key_t));
    if (tag_keys == NULL) {
        plog_error(plugin, "内存分配失败");
        // 释放之前分配的内存
        free(tag_keys);
        return -1;
    }

    memset(tag_keys, 0, tag_count * sizeof(tag_key_t));

    // 创建设备地址集合
    uint16_t unique_devices[tag_count];
    int      unique_device_count = 0;

    // 提取所有标签的设备地址、FN和PN，同时收集唯一设备地址
    int tag_idx = 0;
    utarray_foreach(group->tags, neu_datatag_t *, tag)
    {
        // 解析标签地址
        uint16_t device_addr = 0;
        uint16_t fn          = 0;
        uint16_t pn          = 0;
        uint16_t data_index  = 0;

        if (gb_12241_parse_tag_address(plugin, tag->address, &device_addr, &fn,
                                       &pn, &data_index) != 0) {
            plog_error(plugin, "无法解析标签地址: %s", tag->address);
            continue;
        }

        // 保存解析结果
        tag_keys[tag_idx].device_addr = device_addr;
        tag_keys[tag_idx].fn          = fn;
        tag_keys[tag_idx].pn          = pn;
        tag_keys[tag_idx].data_index  = data_index;
        tag_keys[tag_idx].processed   = false;
        tag_idx++;

        // 检查是否是新的设备地址，如果是则添加到唯一设备列表
        bool device_exists = false;
        for (int j = 0; j < unique_device_count; j++) {
            if (unique_devices[j] == device_addr) {
                device_exists = true;
                break;
            }
        }

        if (!device_exists) {
            unique_devices[unique_device_count++] = device_addr;
        }
    }

    plog_debug(plugin, "解析成功 %d 个标签，检测到 %d 个唯一设备地址", tag_idx,
               unique_device_count);

    // 2. 按设备地址分组，每组最多4个FN+PN
    const int max_fn_per_request = 4; // 每个请求最多包含4个FN+PN

    // 只处理实际存在的设备
    for (int i = 0; i < unique_device_count; i++) {
        uint16_t current_device = unique_devices[i];

        // 处理当前设备的标签，每批最多max_fn_per_request个FN+PN
        while (true) {
            uint16_t fn_array[max_fn_per_request];
            uint16_t pn_array[max_fn_per_request];
            int      batch_size     = 0;
            bool     has_special_fn = false;

            // 收集一批未处理的FN+PN
            for (unsigned int tag_idx_loop = 0;
                 tag_idx_loop < tag_count && batch_size < max_fn_per_request;
                 tag_idx_loop++) {
                if (tag_keys[tag_idx_loop].device_addr == current_device &&
                    !tag_keys[tag_idx_loop].processed) {
                    // 检查是否是特殊功能码
                    bool current_is_special =
                        is_special_fn(tag_keys[tag_idx_loop].fn);

                    // 如果当前批次已有特殊功能码或当前是特殊功能码但批次已有其他功能码，则跳过
                    if ((has_special_fn || current_is_special) &&
                        batch_size > 0) {
                        continue;
                    }

                    // 检查此FN+PN是否已在批次中
                    bool already_in_batch = false;
                    for (int j = 0; j < batch_size; j++) {
                        if (fn_array[j] == tag_keys[tag_idx_loop].fn &&
                            pn_array[j] == tag_keys[tag_idx_loop].pn) {
                            already_in_batch = true;
                            break;
                        }
                    }

                    if (!already_in_batch) {
                        fn_array[batch_size] = tag_keys[tag_idx_loop].fn;
                        pn_array[batch_size] = tag_keys[tag_idx_loop].pn;
                        batch_size++;

                        // 如果是特殊功能码，标记并在添加后立即退出循环
                        if (current_is_special) {
                            has_special_fn = true;
                            plog_debug(plugin,
                                       "检测到特殊功能码 FN=%d，将单独发送",
                                       tag_keys[tag_idx_loop].fn);
                            // 标记为已处理
                            tag_keys[tag_idx_loop].processed =
                                true; // Mark as processed immediately for
                                      // special FN
                            break; // 特殊功能码只能单独发送，所以找到一个后就退出循环
                        }
                    }

                    // 标记为已处理 (非特殊功能码)
                    if (!has_special_fn) { // Only mark if we didn't break due
                                           // to special FN
                        tag_keys[tag_idx_loop].processed = true;
                    }
                }
            }

            if (batch_size == 0) {
                break; // 没有更多未处理的标签
            }

            // 构建请求（统一使用多FN请求函数）
            uint8_t request[1024];  // 请求缓冲区
            uint8_t response[2048]; // 响应缓冲区
            size_t  request_len  = 0;
            size_t  response_len = sizeof(response);
            int     build_ret    = 0;

            // 统一使用多功能码请求构建函数，即使只有一个FN（特殊功能码）
            build_ret = gb_12241_build_multi_request(
                plugin, request, sizeof(request), current_device, plugin->seq++,
                fn_array, pn_array,
                batch_size, // batch_size will be 1 for special FNs
                &request_len);

            // 添加日志区分单/多FN请求
            if (has_special_fn && batch_size == 1) {
                plog_debug(
                    plugin,
                    "为特殊功能码 FN=%d 构建单独请求 (使用multi_request)",
                    fn_array[0]);
            } else {
                plog_debug(plugin, "为普通功能码构建批量请求 (batch_size=%d)",
                           batch_size);
            }

            if (build_ret != 0) {
                plog_error(plugin, "构建请求失败，设备 %d，批次 %d",
                           current_device, total_count);
                // Mark tags in this failed batch as unprocessed? Needs
                // consideration. For now, continue to next batch.
                continue;
            }

            // 统计信息更新 - 使用连接状态而非直接更新字段
            total_count++;
            uint64_t send_time = neu_time_ms();

            // 发送请求并接收响应
            ret = gb_12241_send_and_receive(plugin, request, request_len,
                                            response, &response_len);
            if (ret != 0) {
                plog_error(plugin,
                           "读取组数据失败，设备 %d，批次 %d，错误码 %d",
                           current_device, total_count - 1, ret);
                // Mark tags in this failed batch as unprocessed? Needs
                // consideration.
                continue;
            }

            // 将回复帧以十六进制格式输出
            char hex_buffer[10240] = { 0 };
            for (size_t i = 0;
                 i < response_len && (i * 3 < sizeof(hex_buffer) - 3); i++) {
                char temp[4];
                snprintf(temp, sizeof(temp), "%02X ", response[i]);
                strcat(hex_buffer, temp);
            }
            plog_notice(plugin, "回复帧(HEX): %s", hex_buffer);

            // 统计信息更新 - 使用连接状态而非直接更新字段
            success_count++;
            uint64_t recv_time = neu_time_ms();
            rtt += (recv_time - send_time);

            // 解析响应
            uint16_t resp_device_addr = 0;
            uint8_t  afn              = 0;
            uint8_t  seq              = 0;
            uint8_t  control_field    = 0; // 新增：用于接收控制域
            uint8_t  data[512]        = { 0 };
            size_t   data_len         = sizeof(data);

            size_t frame_size = gb_12241_parse_frame(
                response, response_len, &resp_device_addr, &afn, &seq,
                &control_field, // 新增：传入控制域参数
                data, &data_len);

            // 将响应帧以十六进制格式输出
            if (frame_size <= 0 || resp_device_addr != current_device) {
                plog_error(plugin, "解析响应帧失败或设备地址不匹配");
                continue;
            }

            // 将响应帧以十六进制格式输出
            char hex_data_buffer[10240] = { 0 };
            for (size_t i = 0;
                 i < data_len && (i * 3 < sizeof(hex_data_buffer) - 3); i++) {
                char temp[4];
                snprintf(temp, sizeof(temp), "%02X ", data[i]);
                strcat(hex_data_buffer, temp);
            }
            plog_notice(plugin, "用户数据(HEX): %s", hex_data_buffer);

            // 检查AFN和控制域功能码
            S_ControlField ctrl_field;
            ctrl_field.ControlField.BControlField = control_field;
            bool is_valid_response                = false;

            // 有效响应包括：
            // 1. 请求一类数据的正常响应(AFN_REQUESTONEDATA)
            // 2.
            // 肯定/否认应答(AFN_ACK)且功能码为响应用户数据(RESPONSEUSERDATA)或无数据(NODATA)
            if (afn == AFN_REQUESTONEDATA) {
                plog_debug(plugin, "收到一类数据响应(AFN=0x%02X)", afn);
                is_valid_response = true;
            } else if (afn == AFN_ACK) {
                if (ctrl_field.ControlField.ControlField.FC ==
                    RESPONSEUSERDATA) {
                    plog_notice(
                        plugin,
                        "收到确认/"
                        "否认应答，设备返回用户数据,设备无数据(AFN=0x%02X, "
                        "FC=0x%02X,resp_device_addr=%d,FN=%d,PN=%d)",
                        afn, ctrl_field.ControlField.ControlField.FC,
                        resp_device_addr, fn_array[0], pn_array[0]);
                    is_valid_response = false;
                } else if (ctrl_field.ControlField.ControlField.FC == NODATA) {
                    plog_notice(plugin,
                                "收到确认/否认应答，但设备无数据(AFN=0x%02X, "
                                "FC=0x%02X)",
                                afn, ctrl_field.ControlField.ControlField.FC);
                    is_valid_response = false;
                } else {
                    plog_notice(plugin,
                                "收到确认/否认应答，但功能码不正确(AFN=0x%02X, "
                                "FC=0x%02X)",
                                afn, ctrl_field.ControlField.ControlField.FC);
                    is_valid_response = false;
                }
            } else {
                plog_error(plugin,
                           "收到未知响应类型,不做解析(AFN=0x%02X, FC=0x%02X)",
                           afn, ctrl_field.ControlField.ControlField.FC);
                continue;
            }

            if (!is_valid_response) {
                continue;
            }

            // 处理响应数据，更新每个标签的值 - 优化版本
            int      tags_updated  = 0;
            uint8_t *current_pos   = data;
            size_t   remaining_len = data_len;

            // 跳过AFN(1字节)和SEQ(1字节)，因为gb_12241_parse_frame并没有分离它们
            if (remaining_len >= 2) {
                // 直接使用结构体解析SEQ字节
                S_SEQ seq_struct;
                seq_struct.seq.RSEQ = current_pos[1]; // 将SEQ字节加载到结构体

                // 使用结构体访问TpV位
                bool tpv_valid = seq_struct.seq.PSEQ.TpV == 1;

                plog_debug(plugin, "跳过AFN(%02X)和SEQ(%02X)字节，TpV=%d",
                           current_pos[0], current_pos[1], tpv_valid ? 1 : 0);
                current_pos += 2;
                remaining_len -= 2;

                // 使用从帧解析获取的控制域
                bool fcb_valid = ctrl_field.ControlField.ControlField.FCB == 1;

                plog_debug(plugin, "控制域=%02X, FCB=%d", control_field,
                           fcb_valid ? 1 : 0);

                // 根据帧结构知识，检查是否有尾部附加信息
                if (remaining_len > 0) {
                    // 如果有附加信息需要跳过处理
                    size_t tail_bytes = 0;

                    // FCB有效时，有2字节附加信息
                    if (fcb_valid) {
                        tail_bytes += 2;
                        plog_debug(plugin, "帧中FCB有效，尾部有2字节附加信息");
                    }

                    // TpV有效时，有6字节时间标签
                    if (tpv_valid) {
                        tail_bytes += 6;
                        plog_debug(plugin, "帧中TpV有效，尾部有6字节时间标签");
                    }

                    // 确保不溢出
                    if (tail_bytes > 0 && tail_bytes < remaining_len) {
                        // 调整有效数据长度，排除尾部附加信息
                        remaining_len -= tail_bytes;
                        plog_debug(plugin,
                                   "调整有效数据长度，排除%zu字节尾部附加信息",
                                   tail_bytes);
                    }
                }
            } else {
                plog_error(plugin, "数据长度不足，无法跳过AFN和SEQ");
                continue;
            }

            // 创建设备地址->FN->PN->data_index->tag映射，用于快速查找匹配的标签
            typedef struct {
                uint16_t       device_addr;
                uint16_t       fn;
                uint16_t       pn;
                uint16_t       data_index;
                neu_datatag_t *tag;
            } tag_map_entry_t;

            // 预先解析所有标签的地址信息，避免重复解析
            tag_map_entry_t *tag_map = (tag_map_entry_t *) malloc(
                utarray_len(group->tags) * sizeof(tag_map_entry_t));
            if (!tag_map) {
                plog_error(plugin, "内存分配失败");
                // 释放之前分配的内存
                free(tag_keys);
                continue;
            }

            int map_size = 0;
            utarray_foreach(group->tags, neu_datatag_t *, tag)
            {
                uint16_t tag_device_addr;
                uint16_t tag_fn;
                uint16_t tag_pn;
                uint16_t data_index;

                if (gb_12241_parse_tag_address(plugin, tag->address,
                                               &tag_device_addr, &tag_fn,
                                               &tag_pn, &data_index) == 0) {
                    // 只添加当前设备的标签
                    if (tag_device_addr == current_device) {
                        tag_map[map_size].device_addr = tag_device_addr;
                        tag_map[map_size].fn          = tag_fn;
                        tag_map[map_size].pn          = tag_pn;
                        tag_map[map_size].data_index  = data_index;
                        tag_map[map_size].tag         = tag;
                        map_size++;
                    }
                }
            }

            plog_debug(plugin, "创建设备%d的标签映射表，共%d个标签",
                       current_device, map_size);

            // 循环解析数据单元标识和数据单元
            while (remaining_len >= sizeof(DATA_UNIT_Flag)) {
                DATA_UNIT_Flag data_unitf = { 0 };

                // 1. 获取数据单元标识
                memcpy(&data_unitf, current_pos, sizeof(DATA_UNIT_Flag));
                current_pos += sizeof(DATA_UNIT_Flag);
                remaining_len -= sizeof(DATA_UNIT_Flag);

                // 2. 计算实际的pn和fn值 //如果DA1==0x00,DA2==0x00,则PN=0

                uint16_t recv_pn =
                    (data_unitf.DA1 == 0x00 && data_unitf.DA2 == 0x00)
                    ? 0
                    : (GetDA1(data_unitf.DA1) + (data_unitf.DA2 - 1) * 8);
                uint16_t recv_fn =
                    GetDA1(data_unitf.DT1) + (data_unitf.DT2) * 8;

                plog_notice(plugin, "解析数据单元标识: PN=%d, FN=%u", recv_pn,
                            recv_fn);

                // 3. 获取数据单元的大小
                int data_unit_size = is_special_fn(recv_fn)
                    ? (int) remaining_len
                    : gb_12241_get_data_unit_size(recv_fn);

                // 检查数据单元大小的有效性
                if (data_unit_size == -1) {
                    plog_warn(plugin,
                              "收到未知大小的功能码 FN=%u "
                              "的响应，停止解析此帧的剩余数据。",
                              recv_fn);
                    break; // 未知大小，退出循环
                }

                if (remaining_len < (size_t) data_unit_size) {
                    plog_error(plugin,
                               "数据单元(FN=%u)所需数据不足: 需要 %d 字节, "
                               "剩余 %zu 字节",
                               recv_fn, data_unit_size, remaining_len);
                    break; // 数据不足，退出循环
                }
                // 特殊功能码的调试信息
                if (is_special_fn(recv_fn)) {
                    plog_debug(
                        plugin,
                        "检测到特殊功能码 FN=%u，数据单元大小设为剩余长度 %d",
                        recv_fn, data_unit_size);
                }
                // 记录本批采集的统一时间戳，保证同一批采集点位更新时间一致，提升性能
                time_t now = time(NULL);
                // 4. 直接查找所有匹配的标签并更新它们
                for (int i = 0; i < map_size; i++) {
                    // 只处理匹配当前数据单元的标签
                    if (tag_map[i].fn == recv_fn && tag_map[i].pn == recv_pn) {
                        neu_datatag_t *tag        = tag_map[i].tag;
                        uint8_t        data_index = tag_map[i].data_index;

                        // 5. 直接从当前位置提取数据值
                        neu_value_u extracted_value = { 0 };
                        if (gb_12241_extract_data_value(
                                plugin, current_pos, data_unit_size, recv_fn,
                                data_index, &extracted_value) == 0) {
                            // 6. 转换为正确的标签类型
                            neu_value_u tag_value = { 0 };
                            switch (tag->type) {
                            case NEU_TYPE_BOOL:
                                if (extracted_value.u8 == 0xEE) {
                                    tag_value.u8 = 0xEE; // 保留无效数据标记
                                } else {
                                    tag_value.boolean = extracted_value.boolean;
                                }
                                break;
                            case NEU_TYPE_INT8:
                                if (extracted_value.u8 == 0xEE) {
                                    tag_value.u8 = 0xEE;
                                } else {
                                    tag_value.i8 = (int8_t) extracted_value.f32;
                                }
                                break;
                            case NEU_TYPE_UINT8:
                                if (extracted_value.u8 == 0xEE) {
                                    tag_value.u8 = 0xEE;
                                } else {
                                    tag_value.u8 =
                                        (uint8_t) extracted_value.f32;
                                }
                                break;
                            case NEU_TYPE_INT16:
                                if (extracted_value.u8 == 0xEE) {
                                    tag_value.u8 = 0xEE;
                                } else {
                                    tag_value.i16 =
                                        (int16_t) extracted_value.f32;
                                }
                                break;
                            case NEU_TYPE_UINT16:
                                if (extracted_value.u8 == 0xEE) {
                                    tag_value.u8 = 0xEE;
                                } else {
                                    tag_value.u16 =
                                        (uint16_t) extracted_value.f32;
                                }
                                break;
                            case NEU_TYPE_INT32:
                                if (extracted_value.u8 == 0xEE) {
                                    tag_value.u8 = 0xEE;
                                } else {
                                    tag_value.i32 =
                                        (int32_t) extracted_value.f32;
                                }
                                break;
                            case NEU_TYPE_UINT32:
                                if (extracted_value.u8 == 0xEE) {
                                    tag_value.u8 = 0xEE;
                                } else {
                                    tag_value.u32 =
                                        (uint32_t) extracted_value.f32;
                                }
                                break;
                            case NEU_TYPE_INT64:
                                if (extracted_value.u8 == 0xEE) {
                                    tag_value.u8 = 0xEE;
                                } else {
                                    tag_value.i64 =
                                        (int64_t) extracted_value.f32;
                                }
                                break;
                            case NEU_TYPE_UINT64:
                                if (extracted_value.u8 == 0xEE) {
                                    tag_value.u8 = 0xEE;
                                } else {
                                    tag_value.u64 =
                                        (uint64_t) extracted_value.f32;
                                }
                                break;
                            case NEU_TYPE_FLOAT:
                                if (extracted_value.u8 == 0xEE) {
                                    tag_value.u8 = 0xEE;
                                } else {
                                    tag_value.f32 = extracted_value.f32;
                                }
                                break;
                            case NEU_TYPE_DOUBLE:
                                if (extracted_value.u8 == 0xEE) {
                                    tag_value.u8 = 0xEE;
                                } else {
                                    tag_value.d64 =
                                        (double) extracted_value.d64;
                                }
                                break;
                            case NEU_TYPE_STRING:
                                // 字符串类型需要特殊处理
                                if (extracted_value.u8 == 0xEE) {
                                    snprintf(tag_value.str,
                                             sizeof(tag_value.str), "无效");
                                } else {
                                    snprintf(tag_value.str,
                                             sizeof(tag_value.str), "%.2f",
                                             extracted_value.f32);
                                }
                                break;
                            default:
                                // 对于其他类型，直接复制
                                memcpy(&tag_value, &extracted_value,
                                       sizeof(neu_value_u));
                                break;
                            }

                            // 7. 更新标签值
                            neu_plugin_update_tag(plugin, group->group_name,
                                                  tag, &tag_value);
                            // 采集到有效数据后，更新点位状态表的last_update_time，便于断点续传和状态持久化
                            update_tag_state(plugin, group->group_name,
                                             tag->name, now);
                            tags_updated++;
                        }
                    }
                }

                // 8. 移动到下一个数据单元
                current_pos += data_unit_size;
                remaining_len -= data_unit_size;
            }

            free(tag_map);
            plog_notice(plugin, "设备%d响应处理完成，更新了%d个标签值",
                        current_device, tags_updated);

            // 不需要再遍历每个标签进行更新，上面的循环已经完成所有更新
        }
    }

    free(tag_keys);

    // 更新指标 - 使用metrics API
    if (plugin->common.adapter_callbacks->update_metric) {
        neu_conn_state_t state = neu_conn_state(plugin->conn);

        plugin->common.adapter_callbacks->update_metric(plugin->common.adapter,
                                                        NEU_METRIC_SEND_BYTES,
                                                        state.send_bytes, NULL);
        plugin->common.adapter_callbacks->update_metric(plugin->common.adapter,
                                                        NEU_METRIC_RECV_BYTES,
                                                        state.recv_bytes, NULL);

        // 更新RTT指标
        if (success_count > 0) {
            rtt = rtt / success_count; // 计算平均RTT
            plugin->common.adapter_callbacks->update_metric(
                plugin->common.adapter, NEU_METRIC_LAST_RTT_MS, rtt, NULL);
        }

        // 更新组发送消息指标
        plugin->common.adapter_callbacks->update_metric(
            plugin->common.adapter, NEU_METRIC_GROUP_LAST_SEND_MSGS, tag_count,
            safe_group_name);
    }

    // 如果所有点都读取失败，更新连接状态为断开
    if (success_count == 0 && error_count > 0) {
        plog_warn(plugin, "组 '%s' 中所有标签读取失败，更新连接状态为断开",
                  safe_group_name);
        // plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
    }

    // 计算总耗时
    uint64_t total_time_ms = neu_time_ms() - read_start_time;

    plog_debug(
        (neu_plugin_t *) plugin,
        "组 '%s' 成功读取 %d/%d 帧，失败 %d 帧，成功率 %.2f%%，耗时 %llu ms",
        safe_group_name, success_count, total_count,
        total_count - success_count,
        total_count > 0 ? ((float) success_count / total_count * 100.0f) : 0.0f,
        (unsigned long long) total_time_ms);

    return (success_count > 0) ? 0 : -1;
}

// 驱动启动函数
static int driver_start(neu_plugin_t *plugin)
{
    if (plugin == NULL) {
        return -1;
    }
    plog_info(plugin, "启动GB/T 12241 TCP驱动");
    plugin->running           = true;
    plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
    neu_conn_start(plugin->conn);
    if (!neu_conn_is_connected(plugin->conn)) {
        plog_info(plugin, "尝试连接服务器...");
        neu_conn_connect(plugin->conn);
        if (neu_conn_is_connected(plugin->conn)) {
            plog_info(plugin, "启动时连接服务器成功");
        } else {
            plog_warn(plugin, "启动时连接服务器失败，将在后续自动重试");
        }
    }
    // 不再启动flush线程
    return 0;
}
// 驱动停止函数
static int driver_stop(neu_plugin_t *plugin)
{
    if (plugin == NULL) {
        return -1;
    }
    plog_info(plugin, "停止GB/T 12241 TCP驱动");
    plugin->running = false;

    // 批量持久化所有dirty点位
    if (plugin->tag_state_db) {
        pthread_mutex_lock(&plugin->tag_state_mutex);
        char *errmsg = NULL;
        int rc = sqlite3_exec(plugin->tag_state_db, "BEGIN TRANSACTION;", NULL,
                              NULL, &errmsg);
        if (rc != SQLITE_OK) {
            plog_error(plugin, "开启事务失败: %s",
                       errmsg ? errmsg : sqlite3_errmsg(plugin->tag_state_db));
            if (errmsg)
                sqlite3_free(errmsg);
            pthread_mutex_unlock(&plugin->tag_state_mutex);
            return -1;
        }

        int          count = 0;
        tag_state_t *state, *tmp;
        HASH_ITER(hh, plugin->tag_states, state, tmp)
        {
            if (state->dirty) {
                const char *sql =
                    "INSERT OR REPLACE INTO tag_state (group_name, tag_name, "
                    "last_update_time, last_polled_historical_time, dirty) "
                    "VALUES (?, ?, ?, ?, ?);";
                sqlite3_stmt *stmt;
                rc = sqlite3_prepare_v2(plugin->tag_state_db, sql, -1, &stmt,
                                        NULL);
                if (rc == SQLITE_OK) {
                    sqlite3_bind_text(stmt, 1, state->group_name, -1,
                                      SQLITE_STATIC);
                    sqlite3_bind_text(stmt, 2, state->tag_name, -1,
                                      SQLITE_STATIC);
                    sqlite3_bind_int64(stmt, 3, state->last_update_time);
                    sqlite3_bind_int64(stmt, 4,
                                       state->last_polled_historical_time);
                    sqlite3_bind_int(stmt, 5, 0);
                    rc = sqlite3_step(stmt);
                    if (rc != SQLITE_DONE) {
                        plog_error(plugin, "写入点位状态失败 [%s.%s]: %s",
                                   state->group_name, state->tag_name,
                                   sqlite3_errmsg(plugin->tag_state_db));
                    } else {
                        state->dirty = false;
                        count++;
                    }
                    sqlite3_finalize(stmt);
                } else {
                    plog_error(plugin, "准备SQL语句失败 [%s.%s]: %s",
                               state->group_name, state->tag_name,
                               sqlite3_errmsg(plugin->tag_state_db));
                }
            }
        }

        // 提交事务
        errmsg = NULL;
        rc = sqlite3_exec(plugin->tag_state_db, "COMMIT;", NULL, NULL, &errmsg);
        if (rc != SQLITE_OK) {
            plog_error(plugin, "提交事务失败: %s",
                       errmsg ? errmsg : sqlite3_errmsg(plugin->tag_state_db));
            if (errmsg)
                sqlite3_free(errmsg);
            // 回滚事务
            sqlite3_exec(plugin->tag_state_db, "ROLLBACK;", NULL, NULL, NULL);
            pthread_mutex_unlock(&plugin->tag_state_mutex);
            return -1;
        }
        if (errmsg)
            sqlite3_free(errmsg);

        pthread_mutex_unlock(&plugin->tag_state_mutex);
        plog_info(plugin, "批量持久化点位状态 %d 条", count);
    }

    // 断开连接并更新状态
    if (neu_conn_is_connected(plugin->conn)) {
        plog_info(plugin, "停止时断开服务器连接");
        plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
    }
    neu_conn_stop(plugin->conn);

    // 销毁互斥锁
    pthread_mutex_destroy(&plugin->tag_state_mutex);

    // ===== 新增：批量持久化polling_tasks =====
    if (plugin->tag_state_db && plugin->polling_tasks) {
        pthread_mutex_lock(&plugin->polling_task_mutex);

        char *errmsg = NULL;
        int rc = sqlite3_exec(plugin->tag_state_db, "BEGIN TRANSACTION;", NULL,
                              NULL, &errmsg);
        if (rc != SQLITE_OK) {
            plog_error(plugin, "开启polling_task事务失败: %s",
                       errmsg ? errmsg : sqlite3_errmsg(plugin->tag_state_db));
            if (errmsg)
                sqlite3_free(errmsg);
            pthread_mutex_unlock(&plugin->polling_task_mutex);
            // 继续执行，不中断停止流程
        } else {
            // 先清空现有任务
            rc = sqlite3_exec(plugin->tag_state_db, "DELETE FROM polling_task;",
                              NULL, NULL, &errmsg);
            if (rc != SQLITE_OK) {
                plog_error(plugin, "清空polling_task表失败: %s",
                           errmsg ? errmsg
                                  : sqlite3_errmsg(plugin->tag_state_db));
                if (errmsg)
                    sqlite3_free(errmsg);
                sqlite3_exec(plugin->tag_state_db, "ROLLBACK;", NULL, NULL,
                             NULL);
                pthread_mutex_unlock(&plugin->polling_task_mutex);
                // 继续执行，不中断停止流程
            } else {
                // 批量插入当前任务
                int          task_count  = 0;
                unsigned int total_tasks = utarray_len(plugin->polling_tasks);

                for (unsigned int i = 0; i < total_tasks; i++) {
                    polling_task_t *task = (polling_task_t *) utarray_eltptr(
                        plugin->polling_tasks, i);
                    if (task) {
                        const char *sql =
                            "INSERT INTO polling_task (group_name, tag_name, "
                            "tag_address, start_time, end_time, retry_count) "
                            "VALUES (?, ?, ?, ?, ?, ?);";
                        sqlite3_stmt *stmt;
                        rc = sqlite3_prepare_v2(plugin->tag_state_db, sql, -1,
                                                &stmt, NULL);
                        if (rc == SQLITE_OK) {
                            sqlite3_bind_text(stmt, 1, task->group_name, -1,
                                              SQLITE_STATIC);
                            sqlite3_bind_text(stmt, 2, task->tag_name, -1,
                                              SQLITE_STATIC);
                            sqlite3_bind_text(stmt, 3, task->tag_address, -1,
                                              SQLITE_STATIC);
                            sqlite3_bind_int64(stmt, 3, task->start_time);
                            sqlite3_bind_int64(stmt, 4, task->end_time);
                            sqlite3_bind_int(stmt, 5, task->retry_count);

                            rc = sqlite3_step(stmt);
                            if (rc == SQLITE_DONE) {
                                task_count++;
                            } else {
                                plog_error(
                                    plugin, "插入polling_task失败 [%s.%s]: %s",
                                    task->group_name, task->tag_name,
                                    sqlite3_errmsg(plugin->tag_state_db));
                            }
                            sqlite3_finalize(stmt);
                        } else {
                            plog_error(plugin,
                                       "准备polling_task SQL语句失败: %s",
                                       sqlite3_errmsg(plugin->tag_state_db));
                        }
                    }
                }

                // 提交事务
                errmsg = NULL;
                rc = sqlite3_exec(plugin->tag_state_db, "COMMIT;", NULL, NULL,
                                  &errmsg);
                if (rc != SQLITE_OK) {
                    plog_error(plugin, "提交polling_task事务失败: %s",
                               errmsg ? errmsg
                                      : sqlite3_errmsg(plugin->tag_state_db));
                    if (errmsg)
                        sqlite3_free(errmsg);
                    sqlite3_exec(plugin->tag_state_db, "ROLLBACK;", NULL, NULL,
                                 NULL);
                } else {
                    plog_notice(plugin,
                                "批量持久化polling_task任务 %d 条 (总共 %d 条)",
                                task_count, total_tasks);
                }
                if (errmsg)
                    sqlite3_free(errmsg);
            }
        }

        pthread_mutex_unlock(&plugin->polling_task_mutex);
    }

    // 清理历史召测任务队列和互斥锁
    if (plugin->polling_tasks) {
        utarray_free(plugin->polling_tasks);
        plugin->polling_tasks = NULL;
    }
    pthread_mutex_destroy(&plugin->polling_task_mutex);

    // 清理组级时间戳哈希表
    cleanup_group_polling_times(plugin);
    pthread_mutex_destroy(&plugin->group_polling_time_mutex);

    // 清理组级时间戳哈希表
    cleanup_group_polling_times(plugin);
    pthread_mutex_destroy(&plugin->group_polling_time_mutex);

    return 0;
}

// GB/T 12241帧解析函数
static size_t gb_12241_parse_frame(const uint8_t *frame, size_t frame_len,
                                   uint16_t *device_addr, uint8_t *afn,
                                   uint8_t *seq, uint8_t *control_field,
                                   uint8_t *data, size_t *data_len)
{
    if (frame == NULL ||
        frame_len < 14) { // 最小帧长度：帧头(6) + 数据头(6) + 帧尾(2) = 14
        return 0;
    }

    // 检查帧头
    if (frame[0] != 0x68 || frame[5] != 0x68) {
        return 0;
    }

    // 解析长度字段
    LINK_LEN link_len;
    memcpy(&link_len, &frame[1], sizeof(LINK_LEN));
    size_t user_data_len = ((uint16_t) link_len.LUSERH << 6) | link_len.LUSERL;

    // 计算总长度：用户数据长度 + 8字节固定头部
    size_t total_len = user_data_len + 8;

    // 检查长度一致性
    if (frame_len < total_len) {
        return 0;
    }

    // 检查结束符
    if (frame[total_len - 1] != 0x16) {
        return 0;
    }

    // 计算校验和
    uint8_t checksum = 0;
    for (size_t i = 6; i < total_len - 2; i++) {
        checksum += frame[i];
    }

    // 验证校验和
    if (frame[total_len - 2] != checksum) {
        return 0;
    }

    // 提取设备地址
    if (device_addr != NULL) {
        ADDR addr;
        memcpy(&addr, &frame[7], sizeof(ADDR));
        *device_addr = addr.TAL | (addr.TAH << 8);
    }

    // 提取应用功能码和序列号
    if (afn != NULL) {
        *afn = frame[12]; // 从第13字节开始
    }

    if (seq != NULL) {
        *seq = frame[13]; // 从第14字节开始
    }

    // 提取用户数据 - 从应用功能码(AFN)开始提取
    if (data != NULL && data_len != NULL) {
        // 应用层数据从AFN开始
        size_t copy_len = user_data_len - 1 -
            5; //先减去控制区和地址域才是应用层数据，是以APN和SEQ为起始的
        if (copy_len > *data_len) {
            copy_len = *data_len;
        }

        // 复制包括AFN和SEQ在内的所有用户数据
        memcpy(data, &frame[12], copy_len);
        *data_len = copy_len;
    }

    // 添加控制域提取代码，从第6个字节提取
    if (control_field != NULL) {
        // 控制域在帧的第6个字节
        *control_field = frame[6]; // 按照用户指定的位置
    }

    return total_len;
}

// 发送请求并接收响应
static int gb_12241_send_and_receive(neu_plugin_t * plugin,
                                     const uint8_t *request, size_t request_len,
                                     uint8_t *response, size_t *response_len)
{
    if (plugin == NULL || request == NULL || response == NULL ||
        response_len == NULL) {
        return -1;
    }

    // 检查连接状态
    // if (plugin->common.link_state != NEU_NODE_LINK_STATE_CONNECTED) {
    //     plog_error(plugin, "设备未连接");
    //     return -1;
    // }

    // 发送请求
    ssize_t send_len =
        neu_conn_send(plugin->conn, (uint8_t *) request, request_len);
    if (send_len < 0 || (size_t) send_len != request_len) {
        plog_error(plugin, "发送请求失败: 期望发送 %zu 字节, 实际发送 %zd 字节",
                   request_len, send_len);
        return -1;
    }

    plog_debug(plugin, "成功发送请求: %zu 字节", request_len);

    // 将请求帧以十六进制格式输出
    char hex_buffer[10240] = { 0 };
    for (size_t i = 0; i < request_len && (i * 3 < sizeof(hex_buffer) - 3);
         i++) {
        char temp[4];
        snprintf(temp, sizeof(temp), "%02X ", request[i]);
        strcat(hex_buffer, temp);
    }
    plog_notice(plugin, "请求帧(HEX): %s", hex_buffer);

    // 接收数据
    uint8_t temp_buf[10240] = { 0 }; // 临时缓冲区，用于累积接收的数据
    size_t    temp_len      = 0; // 临时缓冲区中当前的数据长度
    int       retry_count = 0;
    const int max_retries = plugin->max_retries > 0 ? plugin->max_retries : 3;
    // const int retry_interval = plugin->retry_interval > 0 ?
    // plugin->retry_interval : 100;  // 毫秒
    const uint64_t timeout =
        plugin->class1_timeout > 0 ? plugin->class1_timeout : 1000; // 毫秒

    uint64_t start_time = neu_time_ms();

    while (retry_count < max_retries) {
        // 检查是否超时
        if (neu_time_ms() - start_time > timeout) {
            plog_error(plugin, "接收响应超时");
            return -1;
        }

        // 接收数据到临时缓冲区
        ssize_t recv_len = neu_conn_recv(plugin->conn, &temp_buf[temp_len],
                                         sizeof(temp_buf) - temp_len);
        if (recv_len <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // 非阻塞模式下没有数据可读，等待后重试
                // usleep(10000); // 添加10毫秒延时
                retry_count++;
                continue;
            }

            // 连接错误，断开连接
            plog_error(plugin, "接收数据失败: %s", strerror(errno));
            neu_conn_disconnect(plugin->conn); // 恢复连接断开操作
            return -1;
        }

        temp_len += recv_len;
        plog_notice(plugin, "接收到 %zd 字节数据，当前总长度 %zu", recv_len,
                    temp_len);

        // 用于存储解析结果的变量
        uint16_t device_addr   = 0;
        uint8_t  afn           = 0;
        uint8_t  seq           = 0;
        uint8_t  control_field = 0; // 新增控制域变量
        uint8_t  data[1024]    = { 0 };
        size_t   data_len      = sizeof(data);

        // 尝试从临时缓冲区中解析一个完整的帧
        size_t frame_len =
            gb_12241_parse_frame(temp_buf, temp_len, &device_addr, &afn, &seq,
                                 &control_field, // 新增控制域参数
                                 data, &data_len);

        if (frame_len > 0) {
            // 找到有效帧，复制到响应缓冲区
            if (frame_len > *response_len) {
                plog_warn(plugin,
                          "响应帧长度(%zu)超过缓冲区大小(%zu)，将被截断",
                          frame_len, *response_len);
                frame_len = *response_len;
            }

            // 复制找到的有效帧到响应缓冲区
            memcpy(response, temp_buf, frame_len);
            *response_len = frame_len; // 更新实际的响应长度

            // 处理缓冲区中的剩余数据
            if (temp_len > frame_len) {
                // 将剩余数据移动到缓冲区开头，供下次解析使用
                memmove(temp_buf, temp_buf + frame_len, temp_len - frame_len);
                temp_len -= frame_len;
            } else {
                // 没有剩余数据，清空缓冲区
                temp_len = 0;
            }

            plog_debug(plugin,
                       "成功解析响应帧: 设备地址=%u, 功能码=%u, 序列号=%u, "
                       "控制域=%02X, 帧长度=%zu",
                       device_addr, afn, seq, control_field, frame_len);

            return 0; // 成功接收到响应
        }

        // 如果缓冲区已满但仍未找到有效帧，则清空部分缓冲区
        if (temp_len >= sizeof(temp_buf) - 64) {
            plog_warn(
                plugin,
                "接收缓冲区即将溢出，但未找到有效帧，清空部分数据并继续接收");

            // 将最后100字节移到缓冲区开头，保留可能包含帧头的部分
            if (temp_len > 100) {
                memmove(temp_buf, temp_buf + temp_len - 100, 100);
                temp_len = 100;

                // 打印剩余数据的十六进制表示
                memset(hex_buffer, 0, sizeof(hex_buffer));
                for (size_t i = 0;
                     i < temp_len && (i * 3 < sizeof(hex_buffer) - 3); i++) {
                    char temp[4];
                    snprintf(temp, sizeof(temp), "%02X ", temp_buf[i]);
                    strcat(hex_buffer, temp);
                }
                plog_debug(plugin, "保留的数据(HEX): %s", hex_buffer);
            }
        }

        retry_count++;
    }

    plog_error(plugin, "未能在最大重试次数内收到有效响应");
    return -1;
}

// 驱动组定时器函数
static int driver_group_timer(neu_plugin_t *plugin, neu_plugin_group_t *group)
{
    if (plugin == NULL || group == NULL) {
        return -1;
    }

    // 获取安全的组名
    const char *safe_group_name = get_safe_group_name(group);

    // 检查插件是否运行
    bool running = plugin->running;

    if (!running) {
        plog_debug(plugin, "插件未运行，跳过组定时器 '%s'", safe_group_name);
        return 0;
    }

    // 确保TCP连接正常
    if (!neu_conn_is_connected(plugin->conn)) {
        neu_conn_connect(plugin->conn);

        // 检查连接结果
        if (!neu_conn_is_connected(plugin->conn)) {
            plog_error(plugin, "连接服务器失败，组: '%s'", safe_group_name);
            return -1;
        }
        plog_info(plugin, "成功连接到服务器");
    }

    //先定时对时（1小时对一次）
    gb_12241_execute_time_sync(plugin);

    // 生成历史召测任务（传入group信息以获取标签地址）
    // 使用组级时间戳控制，每个组每60秒检查生成一次任务
    if (plugin->polling_enabled &&
        should_generate_polling_tasks(plugin, safe_group_name)) {
        generate_polling_tasks_for_group(plugin, group);
    }

    // 读取组内所有标签
    int ret = gb_12241_read_group(plugin, group);

    // 实时采集完成后，执行历史召测（如果有任务且连接正常）
    if (plugin->polling_enabled && neu_conn_is_connected(plugin->conn)) {
        execute_polling_tasks(plugin);
    }

    return ret;
}

// 驱动写入标签函数
static int driver_write(neu_plugin_t *plugin, void *req, neu_datatag_t *tag,
                        neu_value_u value)
{
    NEU_UNUSED(req);

    if (plugin == NULL || tag == NULL) {
        return -1;
    }

    if (tag->name == NULL || tag->address == NULL) {
        plog_error(plugin, "标签名称或地址为空");
        return -1;
    }

    plog_debug(plugin, "写入标签: %s, 地址: %s", tag->name, tag->address);

    // 查找并创建点位
    GB_12241_point_t *point = gb_12241_find_tag(plugin, tag->name);

    if (point == NULL) {
        plog_error(plugin, "找不到标签: %s", tag->name);
        return -1;
    }

    // 写入标签值
    int ret = gb_12241_write_tag(plugin, point, value);

    // 释放点位内存
    if (point != NULL) {
        free(point);
    }

    return ret;
}

// 连接回调函数实现
void gb_12241_conn_connected(void *data, int fd)
{
    neu_plugin_t *plugin = (neu_plugin_t *) data;
    (void) fd;

    // 记录连接状态变化的日志
    if (plugin->common.link_state != NEU_NODE_LINK_STATE_CONNECTED) {
        plog_notice(plugin, "设备连接状态变化: 已断开 -> 已连接 (fd=%d)", fd);
    }

    // 更新连接状态
    plugin->common.link_state = NEU_NODE_LINK_STATE_CONNECTED;
}

void gb_12241_conn_disconnected(void *data, int fd)
{
    neu_plugin_t *plugin = (neu_plugin_t *) data;
    (void) fd;

    // 记录连接状态变化的日志
    if (plugin->common.link_state != NEU_NODE_LINK_STATE_DISCONNECTED) {
        plog_notice(plugin, "设备连接状态变化: 已连接 -> 已断开 (fd=%d)", fd);
    }

    // 更新连接状态
    plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
}

// 使用Neuron标准插件接口
static const neu_plugin_intf_funs_t plugin_intf_funs = {
    .open    = plugin_open,
    .close   = plugin_close,
    .init    = plugin_init,
    .uninit  = plugin_uninit,
    .start   = plugin_start,
    .stop    = plugin_stop,
    .setting = plugin_config,
    .request = NULL,

    .driver.validate_tag  = driver_validate_tag,
    .driver.group_timer   = driver_group_timer,
    .driver.group_sync    = driver_group_timer,
    .driver.write_tag     = driver_write,
    .driver.tag_validator = NULL,
    .driver.write_tags    = NULL,
    .driver.test_read_tag = NULL,
    .driver.add_tags      = NULL,
    .driver.load_tags     = NULL,
    .driver.del_tags      = NULL,
    .driver.directory     = NULL,
    .driver.fup_open      = NULL,
    .driver.fup_data      = NULL,
    .driver.fdown_open    = NULL,
    .driver.fdown_data    = NULL,
};

const neu_plugin_module_t neu_plugin_module = {
    .version     = NEURON_PLUGIN_VER_1_0,
    .schema      = "12241-tcp",
    .module_name = "GB/T 12241 TCP",
    .module_descr =
        "This plugin is used to connect devices using the GB/T 12241 TCP "
        "protocol. "
        "It supports standard class 1 and class 2 data acquisition.",
    .module_descr_zh = "该插件用于连接使用 GB/T 12241 TCP 协议的设备。"
                       "支持标准的一类数据和二类数据采集。",
    .intf_funs = &plugin_intf_funs,
    .kind      = NEU_PLUGIN_KIND_SYSTEM,
    .type      = NEU_NA_TYPE_DRIVER,
    .display   = true,
    .single    = false,
};

static int neu_plugin_update_tag(neu_plugin_t *plugin, const char *group,
                                 neu_datatag_t *tag, neu_value_u *value)
{
    if (plugin == NULL || tag == NULL || value == NULL) {
        return -1;
    }

    // 检查组名是否有效
    if (!is_valid_string(group)) {
        group = "(未命名)";
    }

    neu_plugin_common_t *common = neu_plugin_to_plugin_common(plugin);
    if (common == NULL || common->adapter_callbacks == NULL) {
        return -1;
    }

    neu_dvalue_t dvalue = { 0 };
    dvalue.type         = tag->type;
    dvalue.value        = *value;

    common->adapter_callbacks->driver.update(common->adapter, group, tag->name,
                                             dvalue);
    return 0;
}

// 添加一个安全的字符串检查函数
static bool is_valid_string(const char *str)
{
    // 检查字符串是否为NULL
    if (str == NULL) {
        return false;
    }

    // 检查字符串是否可访问（简单检查）
    // 这只是一个简单的检查，不能确保完全安全
    // 但可以过滤掉明显无效的字符串
    size_t len = 0;
    for (len = 0; len < NEU_TAG_NAME_LEN; len++) {
        if (str[len] == '\0') {
            return true; // 找到结束符
        }

        // 检查非打印字符（可能是损坏的字符串）
        if (str[len] < 32 && str[len] != '\t' && str[len] != '\r' &&
            str[len] != '\n') {
            return false;
        }
    }

    // 如果没有找到结束符，可能是无效字符串
    return false;
}

// 安全地获取组名的函数
static const char *get_safe_group_name(neu_plugin_group_t *group)
{
    static const char *unnamed = "(未命名)";

    if (group == NULL) {
        return unnamed;
    }

    if (!is_valid_string(group->group_name)) {
        return unnamed;
    }

    return group->group_name;
}

/* 基础宏定义 - 避免与12241_point.h中重复定义 */
#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef ERROR
#define ERROR 0
#endif
#define ERROR 0

/* 位操作数组 */
static const uint8_t dwBit[8] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
};

/**********************************************************************
 * 功    能：Fn→DT的计算
 * 输    入：ptDataUnitID    指向数据单元标识的指针
 *           wFn             信息类标识Fn值
 * 输    出：DT值
 *           TRUE        正常
 *           FALSE    非法的Fn值
 ***********************************************************************/
static uint8_t gb_12241_fn_to_dt(DATA_UNIT_Flag *ptDataUnitID, uint16_t wFn)
{
    /* 检查参数有效性 */
    if (ptDataUnitID == NULL) {
        return FALSE;
    }

    /* 检查Fn值的合法性 */
    if ((wFn == 0) || (wFn > 2048)) { /* 非法的Fn值 */
        return FALSE;
    }

    /* 公式 DT2＝（Fn－1）／8    DT1＝dwBit[（Fn－1）% 8] */
    ptDataUnitID->DT1 = dwBit[(wFn - 1) % 8];
    ptDataUnitID->DT2 = (wFn - 1) / 8;

    return TRUE;
}

/* 函数声明 */
static uint8_t gb_12241_make_crc(const uint8_t *buf, int16_t count);

// 构建包含多个FN+PN的请求帧
static int gb_12241_build_multi_request(neu_plugin_t *plugin, uint8_t *frame,
                                        size_t frame_size, uint16_t device_addr,
                                        uint8_t seq, uint16_t *fn_array,
                                        uint16_t *pn_array, int fn_pn_count,
                                        size_t *request_length)
{
    uint8_t *      buf;
    uint16_t       user_data_len = 0;
    S_ControlField ctrl;
    S_SEQ          frame_seq;
    LINK_LEN       link_len = { 0 };
    DATA_UNIT_Flag dataunitf;
    ADDR           addr = { 0 }; /* 初始化地址结构体 */

    /* 检查参数 */
    if (plugin == NULL || frame == NULL || request_length == NULL ||
        fn_array == NULL || pn_array == NULL || fn_pn_count <= 0 ||
        fn_pn_count > 4) {
        plog_error(plugin, "构建多请求的参数无效: fn_pn_count=%d", fn_pn_count);
        return -1;
    }

    /* 初始化 */
    buf = frame;

    /* 1. 帧起始符 */
    *buf = 0x68;
    buf += 1;

    /* 2. 预留长度字段空间 */
    buf += 4;

    /* 3. 重复帧起始符 */
    *buf = 0x68;
    buf += 1;

    /* 4. 控制域 */
    ctrl.ControlField.ControlField.DIR = 0; /* 方向位(主站发出=0) */
    ctrl.ControlField.ControlField.PRM = 1; /* 启动位(主站发出=1) */
    ctrl.ControlField.ControlField.FCB = 1; /* 帧计数位 */
    ctrl.ControlField.ControlField.FCV = 0; /* 帧计数有效位 */
    ctrl.ControlField.ControlField.FC  = REQUESTTWODATA; /* 功能码 */

    *buf = ctrl.ControlField.BControlField;
    buf += 1;
    user_data_len += 1; /* 控制域长度 */

    /* 5. 地址域 - 使用ADDR结构体 */
    addr.TAH = device_addr / 256; /* 终端地址高字节 */
    addr.TAL = device_addr % 256; /* 终端地址低字节 */
    addr.GAF = 0;                 /* 终端组地址标志 */
    addr.MSA = 1;                 /* 主站地址 */
    addr.RA1 = 0;                 /* 区域码1 */
    addr.RA2 = 0;                 /* 区域码2 */
    addr.RA3 = 0;                 /* 区域码3 */
    addr.RA4 = 0;                 /* 区域码4 */

    memcpy(buf, &addr, 5);
    buf += 5;
    user_data_len += 5; /* 地址域长度 */

    /* 6. 应用功能码 */
    *buf = AFN_REQUESTONEDATA;
    buf += 1;
    user_data_len += 1; /* 应用功能码长度 */

    /* 7. 帧序列域 */
    memset(&frame_seq, 0, sizeof(S_SEQ));
    frame_seq.seq.PSEQ.PSEQ = seq & 0x0F; /* 序列号 */
    frame_seq.seq.PSEQ.CON  = 1;          /* 需要确认 */
    frame_seq.seq.PSEQ.FIN  = 1;          /* 末帧标志 */
    frame_seq.seq.PSEQ.FIR  = 1;          /* 首帧标志 */
    frame_seq.seq.PSEQ.TpV  = 0;          /* 帧时间标签无效 */

    memcpy(buf++, &frame_seq.seq.RSEQ, 1); /* 使用与C++代码相同的方式 */
    user_data_len += 1;                    /* 帧序列域长度 */

    /* 8. 填充数据单元标识 - 这里处理多个FN+PN */
    for (int i = 0; i < fn_pn_count; i++) {
        /* 重置数据单元标识 */
        memset(&dataunitf, 0, sizeof(DATA_UNIT_Flag));

        /* 设置数据单元标识 */
        if (pn_array[i] == 0) {
            dataunitf.DA1 = 0x00;
            dataunitf.DA2 = 0x00;
        } else {
            dataunitf.DA1 = 0x01 << ((pn_array[i] - 1) % 8);
            dataunitf.DA2 = (pn_array[i] - 1) / 8 + 1;
        }

        /* 设置功能码 */
        gb_12241_fn_to_dt(&dataunitf, fn_array[i]);

        /* 复制数据单元标识 */
        memcpy(buf, &dataunitf, 4);
        buf += 4;
        user_data_len += 4;
    }

    /* 检查用户数据长度是否合法 */
    if (user_data_len > 2047) { /* 最大支持2047字节(0x7FF) */
        plog_error(plugin, "用户数据长度超出限制: %u", user_data_len);
        return -1;
    }

    /* 检查缓冲区溢出 */
    size_t needed_size = (size_t)(buf - frame) + 2; /* 加上校验和和结束符 */
    if (needed_size > frame_size) {
        plog_error(plugin, "缓冲区溢出: 需要%zu字节, 但只有%zu字节可用",
                   needed_size, frame_size);
        return -1;
    }

    /* 9. 设置长度域 */
    link_len.PFLG   = 0x01;                 /* 协议标识 */
    link_len.LUSERL = user_data_len & 0x3F; /* 用户数据长度低6位 */
    link_len.LUSERH =
        (user_data_len >> 6) & 0xFF; /* 用户数据长度高8位，限制在8位 */

    /* 验证计算的长度是否正确 */
    uint16_t calc_len = ((uint16_t) link_len.LUSERH << 6) | link_len.LUSERL;
    if (calc_len != user_data_len) {
        plog_error(plugin, "长度计算错误: 预期=%u, 实际=%u", user_data_len,
                   calc_len);
        return -1; /* 长度计算错误 */
    }

    /* 复制长度域到预留位置 */
    memcpy(frame + 1, &link_len, 2);
    memcpy(frame + 3, &link_len, 2);

    /* 10. 计算校验和 */
    *buf = gb_12241_make_crc(frame + 6, user_data_len);
    buf += 1;

    /* 11. 结束符 */
    *buf = 0x16;
    buf += 1;

    /* 设置请求长度 */
    *request_length = (size_t)(buf - frame);

    /* 添加调试日志 */
    plog_notice(plugin, "多FN请求帧构建完成: 总长度=%zu, FN+PN组合数=%d",
                *request_length, fn_pn_count);

    return 0;
}

// 执行对时操作
static int gb_12241_execute_time_sync(neu_plugin_t *plugin)
{

    if (plugin == NULL) {
        plog_error(plugin, "插件为空");
        return -1;
    }
    time_t current_time = time(NULL);

    // 检查是否需要对时 - 每1小时执行一次
    if (plugin->last_time_sync != 0 &&
        (current_time - plugin->last_time_sync) < 60) {
        return 0; // 无需对时
    }

    // 构建对时请求
    uint8_t  time_sync_frame[256];
    size_t   frame_len;
    uint16_t device_addr = 1; // 默认设备地址

    int ret = gb_12241_build_time_sync_request(
        plugin, time_sync_frame, sizeof(time_sync_frame), device_addr,
        plugin->seq++, &frame_len);
    if (ret != 0) {
        plog_error(plugin, "构建对时请求失败");
        return -1;
    }

    // 发送对时请求
    uint8_t response[256];
    size_t  response_len = sizeof(response);
    ret = gb_12241_send_and_receive(plugin, time_sync_frame, frame_len,
                                    response, &response_len);

    if (ret == 0) {
        plugin->last_time_sync = current_time;
        // plog_notice 回复的帧
        char hex_buffer[10240] = { 0 };
        for (size_t i = 0; i < response_len && (i * 3 < sizeof(hex_buffer) - 3);
             i++) {
            char temp[4];
            snprintf(temp, sizeof(temp), "%02X ", response[i]);
            strcat(hex_buffer, temp);
        }
        plog_notice(plugin, "回复帧(HEX): %s", hex_buffer);

        plog_notice(plugin, "对时成功执行，下次对时时间: %s",
                    ctime(&(time_t) { current_time + 86400 }));
        return 0;
    } else {
        plog_error(plugin, "对时失败，将在下个周期重试");
        return -1;
    }
}

//对时
static int gb_12241_build_time_sync_request(neu_plugin_t *plugin,
                                            uint8_t *frame, size_t frame_size,
                                            uint16_t device_addr, uint8_t seq,
                                            size_t *request_length)
{
    uint8_t *      buf;
    uint16_t       user_data_len = 0;
    S_ControlField ctrl;
    S_SEQ          frame_seq;
    LINK_LEN       link_len = { 0 };
    DATA_UNIT_Flag dataunitf;
    ADDR           addr = { 0 };
    GB_12241_TIME  sync_time;
    uint8_t        auth_code[16];

    /* 检查参数 */
    if (plugin == NULL || frame == NULL || request_length == NULL) {
        plog_error(plugin, "构建对时请求的参数无效");
        return -1;
    }

    /* 初始化 */
    buf = frame;

    /* 1. 帧起始符 */
    *buf = 0x68;
    buf += 1;

    /* 2. 预留长度字段空间 */
    buf += 4;

    /* 3. 重复帧起始符 */
    *buf = 0x68;
    buf += 1;

    /* 4. 控制域 - 按照C++代码的设置 */
    ctrl.ControlField.ControlField.DIR = 0; /* 方向位(主站发出=0) */
    ctrl.ControlField.ControlField.PRM = 1; /* 启动位(主站发出=1) */
    ctrl.ControlField.ControlField.FCB = 0; /* 帧计数位=0(对时命令特殊设置) */
    ctrl.ControlField.ControlField.FCV = 0; /* 帧计数有效位=0 */
    ctrl.ControlField.ControlField.FC  = REQUESTONEDATA; /* 功能码=0x0a */

    *buf = ctrl.ControlField.BControlField;
    buf += 1;
    user_data_len += 1; /* 控制域长度 */

    /* 5. 地址域 - 使用ADDR结构体 */
    addr.TAH = device_addr / 256; /* 终端地址高字节 */
    addr.TAL = device_addr % 256; /* 终端地址低字节 */
    addr.GAF = 0;                 /* 终端组地址标志 */
    addr.MSA = 1;                 /* 主站地址 */
    addr.RA1 = 0;                 /* 区域码1 */
    addr.RA2 = 0;                 /* 区域码2 */
    addr.RA3 = 0;                 /* 区域码3 */
    addr.RA4 = 0;                 /* 区域码4 */

    memcpy(buf, &addr, 5);
    buf += 5;
    user_data_len += 5; /* 地址域长度 */

    /* 6. 应用功能码 AFN_CMD=0x05 */
    *buf = AFN_CMD;
    buf += 1;
    user_data_len += 1; /* 应用功能码长度 */

    /* 7. 帧序列域 - 按照C++代码设置 */
    memset(&frame_seq, 0, sizeof(S_SEQ));
    frame_seq.seq.PSEQ.PSEQ = seq & 0x0F; /* 序列号 */
    frame_seq.seq.PSEQ.CON  = 1;          /* 需要确认 */
    frame_seq.seq.PSEQ.FIN  = 1;          /* 末帧标志 */
    frame_seq.seq.PSEQ.FIR  = 1;          /* 首帧标志 */
    frame_seq.seq.PSEQ.TpV  = 0;          /* 帧时间标签无效 */

    memcpy(buf++, &frame_seq.seq.RSEQ, 1);
    user_data_len += 1; /* 帧序列域长度 */

    /* 8. 数据单元标识 - F31对时命令 */
    memset(&dataunitf, 0, sizeof(DATA_UNIT_Flag));
    dataunitf.DA1 = 0x00; /* DA1=0x00 */
    dataunitf.DA2 = 0x00; /* DA2=0x00 */
    dataunitf.DT1 = 0x40; /* DT1=0x40 (F31对时命令) */
    dataunitf.DT2 = 0x03; /* DT2=0x03 */

    memcpy(buf, &dataunitf, 4);
    buf += 4;
    user_data_len += 4;

    /* 9. 时间数据 - 6字节 */
    time_t now_time = time(NULL);
    gb_12241_time_setvalue(&sync_time, now_time);

    memcpy(buf, &sync_time, 6);
    buf += 6;
    user_data_len += 6;

    /* 10. 消息认证码 - 16字节全零 */
    memset(auth_code, 0, 16);
    memcpy(buf, auth_code, 16);
    buf += 16;
    user_data_len += 16;

    /* 检查用户数据长度是否合法 */
    if (user_data_len > 2047) { /* 最大支持2047字节(0x7FF) */
        plog_error(plugin, "对时请求用户数据长度超出限制: %u", user_data_len);
        return -1;
    }

    /* 检查缓冲区溢出 */
    size_t needed_size = (size_t)(buf - frame) + 2; /* 加上校验和和结束符 */
    if (needed_size > frame_size) {
        plog_error(plugin, "对时请求缓冲区溢出: 需要%zu字节, 但只有%zu字节可用",
                   needed_size, frame_size);
        return -1;
    }

    /* 11. 设置长度域 */
    link_len.PFLG   = 0x01;                 /* 协议标识 */
    link_len.LUSERL = user_data_len & 0x3F; /* 用户数据长度低6位 */
    link_len.LUSERH = (user_data_len >> 6) & 0xFF; /* 用户数据长度高8位 */

    /* 验证计算的长度是否正确 */
    uint16_t calc_len = ((uint16_t) link_len.LUSERH << 6) | link_len.LUSERL;
    if (calc_len != user_data_len) {
        plog_error(plugin, "对时请求长度计算错误: 预期=%u, 实际=%u",
                   user_data_len, calc_len);
        return -1;
    }

    /* 复制长度域到预留位置 */
    memcpy(frame + 1, &link_len, 2);
    memcpy(frame + 3, &link_len, 2);

    /* 12. 计算校验和 */
    *buf = gb_12241_make_crc(frame + 6, user_data_len);
    buf += 1;

    /* 13. 结束符 */
    *buf = 0x16;
    buf += 1;

    /* 设置请求长度 */
    *request_length = (size_t)(buf - frame);

    /* 添加调试日志 */
    struct tm *tm_info = localtime(&now_time);
    plog_notice(plugin,
                "对时请求帧构建完成: 总长度=%zu, 设备地址=%u, "
                "时间=%04d-%02d-%02d %02d:%02d:%02d",
                *request_length, device_addr, tm_info->tm_year + 1900,
                tm_info->tm_mon + 1, tm_info->tm_mday, tm_info->tm_hour,
                tm_info->tm_min, tm_info->tm_sec);

    return 0;
}

// 获取指定功能码对应的数据单元大小
static int gb_12241_get_data_unit_size(uint16_t fn)
{
    // 检查是否为特殊功能码，这些功能码的大小不由内部决定
    if (is_special_fn(fn)) {
        // plog_debug(NULL, "FN=%u 是特殊功能码，数据单元大小未知", fn); //
        // Removed due to missing plugin context
        return -1; // 返回-1表示大小未知或由外部确定
    }

    switch (fn) {
    case 12:                     // F12：430集中器数据
        return sizeof(Data_F12); // 139个DI + 4个AI*4 + 4个CI*4

    case 28: // F28：电表运行状态字及其变位标志
        // 按照时间+14个状态字(每个两字节)的大小计算
        return sizeof(Data_ONE_F28);

    case 25: // F25: 电能量
        return sizeof(Data_ONE_F25);

    case 129: // F129: 当前电参量
        return sizeof(Data_ONE_F129);

    case 145: // F145: 当月正向有功最大需量及发生时间
        return sizeof(Data_ONE_F145);

    case 402: // F402: 水表状态字
        return sizeof(Data_ONE_F402);
    case 502: // F502: 气表状态字
        return sizeof(Data_ONE_F502);
    case 602: // F602: 热力表状态字
        return sizeof(Data_ONE_F602);

    case 403: // F403: 水表瞬时流量
        return sizeof(Data_ONE_F403);
    case 503: // F503: 气表瞬时流量
        return sizeof(Data_ONE_F503);
    case 603: // F603: 热力表瞬时流量
        return sizeof(Data_ONE_F603);

    case 404: // F404: 水表累积流量
        return sizeof(Data_ONE_F404);
    case 504: // F504: 气表累积流量
        return sizeof(Data_ONE_F504);

    case 900: // F900: 有功最大需量
        return sizeof(Data_ONE_F900);

    case 901: // F901: 电网频率
        return sizeof(Data_ONE_F901);

    default:
        return -1; // 未知功能码
    }
}

// 从数据单元提取特定数据索引的值
static int gb_12241_extract_data_value(neu_plugin_t * plugin,
                                       const uint8_t *data, int data_unit_size,
                                       uint16_t fn, uint8_t data_index,
                                       neu_value_u *value)
{
    if (plugin == NULL || data == NULL || value == NULL ||
        data_unit_size <= 0) {
        plog_error(plugin, "参数无效");
        return -1;
    }

    switch (fn) {
    case 12: { // F12：430集中器数据
        // 将数据视为Data_F12结构
        Data_F12 *f12 = (Data_F12 *) data;

        // 根据data_index范围处理不同类型的数据
        if (data_index <= 138) { // DI数据 (数字量输入)
            // 检查数据有效性 - 0xEE表示无效
            if (f12->di_status[data_index] != 0xEE) {
                value->boolean = (f12->di_status[data_index] != 0);
                plog_debug(plugin, "F12 DI[%d] = %d", data_index,
                           value->boolean);
                return 0; // 返回0表示数据有效
            } else {
                plog_notice(plugin, "F12 DI数据无效: index=%d", data_index);
                value->u8 = 0xEE; // 使用无效数据标识
                return 1;         // 返回1表示数据存在但无效
            }
        } else if (data_index >= 139 &&
                   data_index <= 142) { // AI数据 (模拟量输入)
            int ai_index = data_index - 139;
            if (ai_index >= 0 && ai_index < 4 &&
                f12->ai_values[ai_index] != 0xEEEEEEEE) {
                value->f32 = (float) f12->ai_values[ai_index];
                plog_debug(plugin, "F12 AI[%d] = %.2f", ai_index, value->f32);
                return 0; // 返回0表示数据有效
            } else {
                plog_notice(plugin, "F12 AI数据无效: index=%d, ai_index=%d",
                            data_index, ai_index);
                value->u8 = 0xEE; // 使用无效数据标识
                return 1;         // 返回1表示数据存在但无效
            }
        } else if (data_index >= 143 &&
                   data_index <= 146) { // CI数据 (计数输入)
            int ci_index = data_index - 143;
            if (ci_index >= 0 && ci_index < 4 &&
                f12->ci_values[ci_index] != 0xEEEEEEEE) {
                value->u32 = f12->ci_values[ci_index];
                plog_debug(plugin, "F12 CI[%d] = %u", ci_index, value->u32);
                return 0; // 返回0表示数据有效
            } else {
                plog_notice(plugin, "F12 CI数据无效: index=%d, ci_index=%d",
                            data_index, ci_index);
                value->u8 = 0xEE; // 使用无效数据标识
                return 1;         // 返回1表示数据存在但无效
            }
        } else {
            plog_error(
                plugin,
                "F12数据索引超出范围: %d (有效范围: 0-138, 139-142, 143-146)",
                data_index);
            return -1; // 返回-1表示数据索引无效
        }
        break;
    }

    case 25: { // F25：当前三相及总有功功率、功率因数，三相电压、电流、零序电流、视在功率
        // 传入的data指针就是指向Data_ONE_F25结构的指针
        Data_ONE_F25 *dataF25 = (Data_ONE_F25 *) data;

        // 根据data_index获取不同的数据项
        switch (data_index) {
        case 0: // 总有功功率
            if (data_type_9_getflag(&dataF25->data_P)) {
                value->f32 = data_type_9_getvalue(&dataF25->data_P);
                return 0;
            }
            break;

        case 1: // A相有功功率
            if (data_type_9_getflag(&dataF25->data_Pa)) {
                value->f32 = data_type_9_getvalue(&dataF25->data_Pa);
                return 0;
            }
            break;

        case 2: // B相有功功率
            if (data_type_9_getflag(&dataF25->data_Pb)) {
                value->f32 = data_type_9_getvalue(&dataF25->data_Pb);
                return 0;
            }
            break;

        case 3: // C相有功功率
            if (data_type_9_getflag(&dataF25->data_Pc)) {
                value->f32 = data_type_9_getvalue(&dataF25->data_Pc);
                return 0;
            }
            break;

        case 4: // 总无功功率
            if (data_type_9_getflag(&dataF25->data_Q)) {
                value->f32 = data_type_9_getvalue(&dataF25->data_Q);
                return 0;
            }
            break;

        case 5: // A相无功功率
            if (data_type_9_getflag(&dataF25->data_Qa)) {
                value->f32 = data_type_9_getvalue(&dataF25->data_Qa);
                return 0;
            }
            break;

        case 6: // B相无功功率
            if (data_type_9_getflag(&dataF25->data_Qb)) {
                value->f32 = data_type_9_getvalue(&dataF25->data_Qb);
                return 0;
            }
            break;

        case 7: // C相无功功率
            if (data_type_9_getflag(&dataF25->data_Qc)) {
                value->f32 = data_type_9_getvalue(&dataF25->data_Qc);
                return 0;
            }
            break;

        case 8: // 总功率因数
            if (data_type_5_getflag(&dataF25->data_Cs)) {
                value->f32 = data_type_5_getvalue(&dataF25->data_Cs);
                return 0;
            }
            break;

        case 9: // A相功率因数
            if (data_type_5_getflag(&dataF25->data_Csa)) {
                value->f32 = data_type_5_getvalue(&dataF25->data_Csa);
                return 0;
            }
            break;

        case 10: // B相功率因数
            if (data_type_5_getflag(&dataF25->data_Csb)) {
                value->f32 = data_type_5_getvalue(&dataF25->data_Csb);
                return 0;
            }
            break;

        case 11: // C相功率因数
            if (data_type_5_getflag(&dataF25->data_Csc)) {
                value->f32 = data_type_5_getvalue(&dataF25->data_Csc);
                return 0;
            }
            break;

        case 12: // A相电压
            if (data_type_7_getflag(&dataF25->data_Ua)) {
                value->f32 = data_type_7_getvalue(&dataF25->data_Ua);
                return 0;
            }
            break;

        case 13: // B相电压
            if (data_type_7_getflag(&dataF25->data_Ub)) {
                value->f32 = data_type_7_getvalue(&dataF25->data_Ub);
                return 0;
            }
            break;

        case 14: // C相电压
            if (data_type_7_getflag(&dataF25->data_Uc)) {
                value->f32 = data_type_7_getvalue(&dataF25->data_Uc);
                return 0;
            }
            break;

        case 15: // A相电流
            if (data_type_25_getflag(&dataF25->data_Ia)) {
                value->f32 = data_type_25_getvalue(&dataF25->data_Ia);
                return 0;
            }
            break;

        case 16: // B相电流
            if (data_type_25_getflag(&dataF25->data_Ib)) {
                value->f32 = data_type_25_getvalue(&dataF25->data_Ib);
                return 0;
            }
            break;

        case 17: // C相电流
            if (data_type_25_getflag(&dataF25->data_Ic)) {
                value->f32 = data_type_25_getvalue(&dataF25->data_Ic);
                return 0;
            }
            break;

        case 18: // 零序电流
            if (data_type_25_getflag(&dataF25->data_I0)) {
                value->f32 = data_type_25_getvalue(&dataF25->data_I0);
                return 0;
            }
            break;

        case 19: // 总视在功率
            if (data_type_9_getflag(&dataF25->data_S)) {
                value->f32 = data_type_9_getvalue(&dataF25->data_S);
                return 0;
            }
            break;

        case 20: // A相视在功率
            if (data_type_9_getflag(&dataF25->data_Sa)) {
                value->f32 = data_type_9_getvalue(&dataF25->data_Sa);
                return 0;
            }
            break;

        case 21: // B相视在功率
            if (data_type_9_getflag(&dataF25->data_Sb)) {
                value->f32 = data_type_9_getvalue(&dataF25->data_Sb);
                return 0;
            }
            break;

        case 22: // C相视在功率
            if (data_type_9_getflag(&dataF25->data_Sc)) {
                value->f32 = data_type_9_getvalue(&dataF25->data_Sc);
                return 0;
            }
            break;

        default:
            plog_error(plugin, "F25数据索引超出范围: %d", data_index);
            return -1;
        }

        // 数据无效
        plog_debug(plugin, "F25数据无效: index=%d", data_index);
        value->u8 = 0xEE; // 使用无效数据标识
        return 1;         // 返回1表示数据存在但无效
    }

    case 28: { // F28：电表运行状态字及其变位标志
        // 根据data_index获取不同状态字内容
        if (data_index < 28) {
            // 直接将数据视为Data_ONE_F28结构
            Data_ONE_F28 *f28          = (Data_ONE_F28 *) data;
            uint16_t      invalid_word = 0xEEEE; // 无效数据标识

            // S4 - A相状态字 (data_index: 0-7)
            if (data_index <= 7) {
                // 检查是否为无效数据
                if (memcmp(&f28->S4, &invalid_word, 2) == 0) {
                    plog_debug(plugin, "F28: S4状态字为无效数据");
                    // 对于无效数据，使用整型返回0xEE，表示无效
                    value->u8 = 0xEE;
                    return 1; // 返回1表示数据存在但无效
                }

                // 根据data_index返回对应位
                switch (data_index) {
                case 0:
                    value->boolean = f28->S4.bit7;
                    break; // A相断相
                case 1:
                    value->boolean = f28->S4.bit6;
                    break; // A相反向
                case 2:
                    value->boolean = f28->S4.bit5;
                    break; // A相过载
                case 3:
                    value->boolean = f28->S4.bit4;
                    break; // A相过流
                case 4:
                    value->boolean = f28->S4.bit3;
                    break; // A相失流
                case 5:
                    value->boolean = f28->S4.bit2;
                    break; // A相过压
                case 6:
                    value->boolean = f28->S4.bit1;
                    break; // A相欠压
                case 7:
                    value->boolean = f28->S4.bit0;
                    break; // A相失压
                }
                return 0; // 返回0表示数据有效
            }

            // S5 - B相状态字 (data_index: 8-15)
            else if (data_index >= 8 && data_index <= 15) {
                // 检查是否为无效数据
                if (memcmp(&f28->S5, &invalid_word, 2) == 0) {
                    plog_debug(plugin, "F28: S5状态字为无效数据");
                    // 对于无效数据，使用整型返回0xEE，表示无效
                    value->u8 = 0xEE;
                    return 1; // 返回1表示数据存在但无效
                }

                // 根据data_index返回对应位
                switch (data_index) {
                case 8:
                    value->boolean = f28->S5.bit7;
                    break; // B相断相
                case 9:
                    value->boolean = f28->S5.bit6;
                    break; // B相反向
                case 10:
                    value->boolean = f28->S5.bit5;
                    break; // B相过载
                case 11:
                    value->boolean = f28->S5.bit4;
                    break; // B相过流
                case 12:
                    value->boolean = f28->S5.bit3;
                    break; // B相失流
                case 13:
                    value->boolean = f28->S5.bit2;
                    break; // B相过压
                case 14:
                    value->boolean = f28->S5.bit1;
                    break; // B相欠压
                case 15:
                    value->boolean = f28->S5.bit0;
                    break; // B相失压
                }
                return 0; // 返回0表示数据有效
            }

            // S6 - C相状态字 (data_index: 16-23)
            else if (data_index >= 16 && data_index <= 23) {
                // 检查是否为无效数据
                if (memcmp(&f28->S6, &invalid_word, 2) == 0) {
                    plog_debug(plugin, "F28: S6状态字为无效数据");
                    // 对于无效数据，使用整型返回0xEE，表示无效
                    value->u8 = 0xEE;
                    return 1; // 返回1表示数据存在但无效
                }

                // 根据data_index返回对应位
                switch (data_index) {
                case 16:
                    value->boolean = f28->S6.bit7;
                    break; // C相断相
                case 17:
                    value->boolean = f28->S6.bit6;
                    break; // C相反向
                case 18:
                    value->boolean = f28->S6.bit5;
                    break; // C相过载
                case 19:
                    value->boolean = f28->S6.bit4;
                    break; // C相过流
                case 20:
                    value->boolean = f28->S6.bit3;
                    break; // C相失流
                case 21:
                    value->boolean = f28->S6.bit2;
                    break; // C相过压
                case 22:
                    value->boolean = f28->S6.bit1;
                    break; // C相欠压
                case 23:
                    value->boolean = f28->S6.bit0;
                    break; // C相失压
                }
                return 0; // 返回0表示数据有效
            }

            // S7 - 合相状态字 (data_index: 24-27)
            else if (data_index >= 24 && data_index <= 27) {
                // 检查是否为无效数据
                if (memcmp(&f28->S7, &invalid_word, 2) == 0) {
                    plog_debug(plugin, "F28: S7状态字为无效数据");
                    // 对于无效数据，使用整型返回0xEE，表示无效
                    value->u8 = 0xEE;
                    return 1; // 返回1表示数据存在但无效
                }

                // 根据data_index返回对应位
                switch (data_index) {
                case 24:
                    value->boolean = f28->S7.bit3;
                    break; // 电流不平衡
                case 25:
                    value->boolean = f28->S7.bit2;
                    break; // 电压不平衡
                case 26:
                    value->boolean = f28->S7.bit1;
                    break; // 电流逆相序
                case 27:
                    value->boolean = f28->S7.bit0;
                    break; // 电压逆相序
                }
                return 0; // 返回0表示数据有效
            }
        }
        break;
    }
    case 145: { // F145：当月正向有功最大需量及发生时间
        if (data_unit_size < 6) { // 至少需要5字节时标 + 1字节费率
            plog_error(plugin, "F145 数据长度不足: 期望至少6字节, 实际%d字节",
                       data_unit_size);
            return -1;
        }

        // 目前只支持data_index=0 (总最大需量)
        if (data_index == 0) {
            // 检查数据长度是否足够包含总需量值
            size_t min_required_size = 6 + sizeof(Data_Type_23);
            if (data_unit_size < (int) min_required_size) {
                plog_error(plugin,
                           "F145 数据长度不足: 期望至少%zu字节, "
                           "实际%d字节",
                           min_required_size, data_unit_size);
                return -1;
            }

            // 跳过5字节时标 + 1字节费率数量，直接读取总需量值
            Data_Type_23 *demand_total = (Data_Type_23 *) (data + 6);

            // 检查需量值数据有效性
            if (data_type_23_getflag(demand_total)) {
                double demand_value = data_type_23_getvalue(demand_total);
                value->d64          = demand_value;
                plog_debug(plugin, "F145 总最大需量: %.4f kW", demand_value);
                return 0;
            }

            // 数据无效
            plog_debug(plugin, "F145 总最大需量数据无效");
            value->u8 = 0xEE; // 使用无效数据标识
            return 1;         // 返回1表示数据存在但无效
        } else {
            plog_error(plugin, "F145 数据索引超出范围: %d (仅支持data_index=0)",
                       data_index);
            return -1;
        }
        break;
    }
    case 900: { // F900：有功最大需量
        // 将数据视为Data_ONE_F900结构
        Data_ONE_F900 *f900 = (Data_ONE_F900 *) data;

        // 目前只支持data_index=0 (有功功率)
        if (data_index == 0) {
            if (data_type_9_getflag(&f900->data_PX)) {
                value->f32 = data_type_9_getvalue(&f900->data_PX);
                return 0;
            }
            // 数据无效
            plog_debug(plugin, "F900数据无效");
            value->u8 = 0xEE; // 使用无效数据标识
            return 1;         // 返回1表示数据存在但无效
        } else {
            plog_error(plugin, "F900数据索引超出范围: %d", data_index);
            return -1;
        }
        break;
    }

    case 901: { // F901：电网频率
        // 将数据视为Data_ONE_F901结构
        Data_ONE_F901 *f901 = (Data_ONE_F901 *) data;

        // 目前只支持data_index=0 (频率)
        if (data_index == 0) {
            if (data_type_6_getflag(&f901->data_F)) {
                value->f32 = data_type_6_getvalue(&f901->data_F);
                return 0;
            }
            // 数据无效
            plog_debug(plugin, "F901数据无效");
            value->u8 = 0xEE; // 使用无效数据标识
            return 1;         // 返回1表示数据存在但无效
        } else {
            plog_error(plugin, "F901数据索引超出范围: %d", data_index);
            return -1;
        }
        break;
    }
    case 829: // F829: 当前正向有功电能示值（总、费率1-M）
    case 830: // F830: 当前正向无功电能示值（总、费率1-M）
    case 831: // F831: 当前反向有功电能示值（总、费率1-M）
    case 832: // F832: 当前反向无功电能示值（总、费率1-M）
    {
        if (data_unit_size < 6) { // 至少需要5字节时标 + 1字节费率
            plog_error(plugin, "FN %u 数据长度不足: 期望至少6字节, 实际%d字节",
                       fn, data_unit_size);
            return -1;
        }

        // 解析1字节费率数量（跳过5字节时标）
        uint8_t tarrif = data[5];

        plog_debug(plugin, "FN %u: 费率数量=%u, data_index=%u", fn, tarrif,
                   data_index);

        // 检查数据长度是否足够包含所有 Data_Type_39
        size_t expected_data_size = 6 + (tarrif + 1) * sizeof(Data_Type_39);
        if (data_unit_size < (int) expected_data_size) {
            plog_error(plugin, "FN %u 数据长度不足: 期望%zu字节, 实际%d字节",
                       fn, expected_data_size, data_unit_size);
            return -1;
        }

        // 检查数据索引是否在有效范围内
        if (data_index > tarrif) {
            plog_error(plugin, "FN %u 数据索引超出范围: data_index=%u, 最大=%u",
                       fn, data_index, tarrif);
            return -1;
        }

        // 解析 Data_Type_39 数组
        const uint8_t *data39_ptr    = data + 6;
        Data_Type_39 * data39_array  = (Data_Type_39 *) data39_ptr;
        Data_Type_39 * target_data39 = &data39_array[data_index];

        // 检查数据有效性
        if (data_type_39_getflag(target_data39)) {
            // 提取数据值
            double energy_value = data_type_39_getvalue(target_data39);
            value->d64          = energy_value;
            plog_debug(plugin, "FN %u data_index=%u: 电能值=%.4f", fn,
                       data_index, energy_value);
            return 0;
        }

        // 数据无效
        plog_debug(plugin, "FN %u data_index=%u: 数据无效", fn, data_index);
        value->u8 = 0xEE; // 使用无效数据标识
        return 1;         // 返回1表示数据存在但无效
        break;
    }

    case 402: { // F402：水表运行状态字及其变位标志
        // 将数据视为Data_ONE_F402结构
        Data_ONE_F402 *f402 = (Data_ONE_F402 *) data;

        // 用于检查无效数据的对比值
        Data_Type_BS16 invalid_bs16 = { 0 };
        memset(&invalid_bs16, 0xEE, sizeof(Data_Type_BS16));

        // 处理S1-S4状态字的各个位（data_index范围: 0-31）
        if (data_index <= 7) {
            // S1 状态字 (data_index: 0-7)
            // 检查是否为无效数据
            if (memcmp(&f402->S1, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                plog_debug(plugin, "F402: S1状态字为无效数据");
                value->u8 = 0xEE;
                return 1; // 返回1表示数据存在但无效
            }

            // 根据data_index返回对应位
            switch (data_index) {
            case 0:
                value->boolean = f402->S1.bit0;
                break;
            case 1:
                value->boolean = f402->S1.bit1;
                break;
            case 2:
                value->boolean = f402->S1.bit2;
                break;
            case 3:
                value->boolean = f402->S1.bit3;
                break;
            case 4:
                value->boolean = f402->S1.bit4;
                break;
            case 5:
                value->boolean = f402->S1.bit5;
                break;
            case 6:
                value->boolean = f402->S1.bit6;
                break;
            case 7:
                value->boolean = f402->S1.bit7;
                break;
            }
            return 0; // 返回0表示数据有效
        } else if (data_index >= 8 && data_index <= 15) {
            // S2 状态字 (data_index: 8-15)
            // 检查是否为无效数据
            if (memcmp(&f402->S2, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                plog_debug(plugin, "F402: S2状态字为无效数据");
                value->u8 = 0xEE;
                return 1; // 返回1表示数据存在但无效
            }

            // 根据data_index返回对应位
            switch (data_index) {
            case 8:
                value->boolean = f402->S2.bit0;
                break;
            case 9:
                value->boolean = f402->S2.bit1;
                break;
            case 10:
                value->boolean = f402->S2.bit2;
                break;
            case 11:
                value->boolean = f402->S2.bit3;
                break;
            case 12:
                value->boolean = f402->S2.bit4;
                break;
            case 13:
                value->boolean = f402->S2.bit5;
                break;
            case 14:
                value->boolean = f402->S2.bit6;
                break;
            case 15:
                value->boolean = f402->S2.bit7;
                break;
            }
            return 0; // 返回0表示数据有效
        } else if (data_index >= 16 && data_index <= 23) {
            // S3 状态字 (data_index: 16-23)
            // 检查是否为无效数据
            if (memcmp(&f402->S3, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                plog_debug(plugin, "F402: S3状态字为无效数据");
                value->u8 = 0xEE;
                return 1; // 返回1表示数据存在但无效
            }

            // 根据data_index返回对应位
            switch (data_index) {
            case 16:
                value->boolean = f402->S3.bit0;
                break;
            case 17:
                value->boolean = f402->S3.bit1;
                break;
            case 18:
                value->boolean = f402->S3.bit2;
                break;
            case 19:
                value->boolean = f402->S3.bit3;
                break;
            case 20:
                value->boolean = f402->S3.bit4;
                break;
            case 21:
                value->boolean = f402->S3.bit5;
                break;
            case 22:
                value->boolean = f402->S3.bit6;
                break;
            case 23:
                value->boolean = f402->S3.bit7;
                break;
            }
            return 0; // 返回0表示数据有效
        } else if (data_index >= 24 && data_index <= 64) {
            // 变位标志处理 (BWS1-BWS4) (data_index: 32-63)
            // 变位标志通常不直接读取，可选择返回无效或继续实现
            plog_debug(plugin, "F402: 变位标志不支持直接读取 (data_index=%d)",
                       data_index);
            value->u8 = 0xEE;
            return 1; // 返回1表示数据存在但无效
        } else {
            plog_error(plugin, "F402数据索引超出范围: %d (有效范围: 0-63)",
                       data_index);
            return -1;
        }
        break;
    }

    case 403: { // F403：水表当前瞬时流量及压力
        // 将数据视为Data_ONE_F403结构
        Data_ONE_F403 *f403 = (Data_ONE_F403 *) data;

        // 根据data_index获取不同的数据项
        switch (data_index) {
        case 0: // 当前瞬时流量
            if (data_type_29_getflag(&f403->data_L)) {
                value->f32 = data_type_29_getvalue(&f403->data_L);
                plog_debug(plugin, "F403 瞬时流量 = %.2f", value->f32);
                return 0;
            }
            break;

        case 1: // 压力
            if (data_type_37_getflag(&f403->data_P)) {
                value->f32 = data_type_37_getvalue(&f403->data_P);
                plog_debug(plugin, "F403 压力 = %.2f", value->f32);
                return 0;
            }
            break;

        default:
            plog_error(plugin, "F403数据索引超出范围: %d (有效范围: 0-1)",
                       data_index);
            return -1;
        }

        // 数据无效
        plog_debug(plugin, "F403数据无效: index=%d", data_index);
        value->u8 = 0xEE; // 使用无效数据标识
        return 1;         // 返回1表示数据存在但无效
    }

    case 404: { // F404：水表当前正向总累积流量示值
        // 将数据视为Data_ONE_F404结构
        Data_ONE_F404 *f404 = (Data_ONE_F404 *) data;

        // 目前仅支持data_index=0 (当前正向总累积流量)
        if (data_index == 0) {
            if (data_type_38_getflag(&f404->data_ZL)) {
                value->d64 = data_type_38_getvalue(&f404->data_ZL);
                plog_debug(plugin, "F404 当前正向总累积流量 = %.2f",
                           value->d64);
                return 0;
            }
            // 数据无效
            plog_debug(plugin, "F404数据无效");
            value->u8 = 0xEE; // 使用无效数据标识
            return 1;         // 返回1表示数据存在但无效
        } else {
            plog_error(plugin, "F404数据索引超出范围: %d (有效范围: 0)",
                       data_index);
            return -1;
        }
    }

    case 502: { // F502：气表运行状态字及其变位标志
        // 将数据视为Data_ONE_F502结构
        Data_ONE_F502 *f502 = (Data_ONE_F502 *) data;

        // 用于检查无效数据的对比值
        Data_Type_BS16 invalid_bs16 = { 0 };
        memset(&invalid_bs16, 0xEE, sizeof(Data_Type_BS16));

        // 处理S1-S4状态字的各个位（data_index范围: 0-31）
        if (data_index <= 7) {
            // S1 状态字 (data_index: 0-7)
            // 检查是否为无效数据
            if (memcmp(&f502->S1, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                plog_debug(plugin, "F502: S1状态字为无效数据");
                value->u8 = 0xEE;
                return 1; // 返回1表示数据存在但无效
            }

            // 根据data_index返回对应位
            switch (data_index) {
            case 0:
                value->boolean = f502->S1.bit0;
                break;
            case 1:
                value->boolean = f502->S1.bit1;
                break;
            case 2:
                value->boolean = f502->S1.bit2;
                break;
            case 3:
                value->boolean = f502->S1.bit3;
                break;
            case 4:
                value->boolean = f502->S1.bit4;
                break;
            case 5:
                value->boolean = f502->S1.bit5;
                break;
            case 6:
                value->boolean = f502->S1.bit6;
                break;
            case 7:
                value->boolean = f502->S1.bit7;
                break;
            }
            plog_debug(plugin, "F502 S1状态位[%d] = %d", data_index,
                       value->boolean);
            return 0; // 返回0表示数据有效
        } else if (data_index >= 8 && data_index <= 15) {
            // S2 状态字 (data_index: 8-15)
            // 检查是否为无效数据
            if (memcmp(&f502->S2, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                plog_debug(plugin, "F502: S2状态字为无效数据");
                value->u8 = 0xEE;
                return 1; // 返回1表示数据存在但无效
            }

            // 根据data_index返回对应位
            switch (data_index) {
            case 8:
                value->boolean = f502->S2.bit0;
                break;
            case 9:
                value->boolean = f502->S2.bit1;
                break;
            case 10:
                value->boolean = f502->S2.bit2;
                break;
            case 11:
                value->boolean = f502->S2.bit3;
                break;
            case 12:
                value->boolean = f502->S2.bit4;
                break;
            case 13:
                value->boolean = f502->S2.bit5;
                break;
            case 14:
                value->boolean = f502->S2.bit6;
                break;
            case 15:
                value->boolean = f502->S2.bit7;
                break;
            }
            plog_debug(plugin, "F502 S2状态位[%d] = %d", data_index,
                       value->boolean);
            return 0; // 返回0表示数据有效
        } else if (data_index >= 16 && data_index <= 23) {
            // S3 状态字 (data_index: 16-23)
            // 检查是否为无效数据
            if (memcmp(&f502->S3, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                plog_debug(plugin, "F502: S3状态字为无效数据");
                value->u8 = 0xEE;
                return 1; // 返回1表示数据存在但无效
            }

            // 根据data_index返回对应位
            switch (data_index) {
            case 16:
                value->boolean = f502->S3.bit0;
                break;
            case 17:
                value->boolean = f502->S3.bit1;
                break;
            case 18:
                value->boolean = f502->S3.bit2;
                break;
            case 19:
                value->boolean = f502->S3.bit3;
                break;
            case 20:
                value->boolean = f502->S3.bit4;
                break;
            case 21:
                value->boolean = f502->S3.bit5;
                break;
            case 22:
                value->boolean = f502->S3.bit6;
                break;
            case 23:
                value->boolean = f502->S3.bit7;
                break;
            }
            plog_debug(plugin, "F502 S3状态位[%d] = %d", data_index,
                       value->boolean);
            return 0; // 返回0表示数据有效
        } else if (data_index >= 24 && data_index <= 31) {
            // S4 状态字 (data_index: 24-31)
            // 检查是否为无效数据
            if (memcmp(&f502->S4, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                plog_debug(plugin, "F502: S4状态字为无效数据");
                value->u8 = 0xEE;
                return 1; // 返回1表示数据存在但无效
            }

            // 根据data_index返回对应位
            switch (data_index) {
            case 24:
                value->boolean = f502->S4.bit0;
                break;
            case 25:
                value->boolean = f502->S4.bit1;
                break;
            case 26:
                value->boolean = f502->S4.bit2;
                break;
            case 27:
                value->boolean = f502->S4.bit3;
                break;
            case 28:
                value->boolean = f502->S4.bit4;
                break;
            case 29:
                value->boolean = f502->S4.bit5;
                break;
            case 30:
                value->boolean = f502->S4.bit6;
                break;
            case 31:
                value->boolean = f502->S4.bit7;
                break;
            }
            plog_debug(plugin, "F502 S4状态位[%d] = %d", data_index,
                       value->boolean);
            return 0; // 返回0表示数据有效
        } else if (data_index >= 32 && data_index <= 63) {
            // 变位标志处理 (BWS1-BWS4) (data_index: 32-63)
            // 变位标志通常不直接读取，这里简化实现
            plog_debug(plugin, "F502: 变位标志不支持直接读取 (data_index=%d)",
                       data_index);
            value->u8 = 0xEE;
            return 1; // 返回1表示数据存在但无效
        } else {
            plog_error(plugin, "F502数据索引超出范围: %d (有效范围: 0-63)",
                       data_index);
            return -1;
        }
        break;
    }

    case 503: { // F503：气表当前流速、压力、温度
        // 将数据视为Data_ONE_F503结构
        Data_ONE_F503 *f503 = (Data_ONE_F503 *) data;

        // 根据data_index获取不同的数据项
        switch (data_index) {
        case 0: // 当前气体流速(标况)
            if (data_type_29_getflag(&f503->data_BL)) {
                value->f32 = data_type_29_getvalue(&f503->data_BL);
                plog_debug(plugin, "F503 标况气体流速 = %.2f", value->f32);
                return 0;
            }
            break;

        case 1: // 当前气体流速(工况)
            if (data_type_29_getflag(&f503->data_GL)) {
                value->f32 = data_type_29_getvalue(&f503->data_GL);
                plog_debug(plugin, "F503 工况气体流速 = %.2f", value->f32);
                return 0;
            }
            break;

        case 2: // 压力
            if (data_type_37_getflag(&f503->data_P)) {
                value->f32 = data_type_37_getvalue(&f503->data_P);
                plog_debug(plugin, "F503 压力 = %.2f", value->f32);
                return 0;
            }
            break;

        case 3: // 温度
            if (data_type_37_getflag(&f503->data_T)) {
                value->f32 = data_type_37_getvalue(&f503->data_T);
                plog_debug(plugin, "F503 温度 = %.2f", value->f32);
                return 0;
            }
            break;

        default:
            plog_error(plugin, "F503数据索引超出范围: %d (有效范围: 0-3)",
                       data_index);
            return -1;
        }

        // 数据无效
        plog_debug(plugin, "F503数据无效: index=%d", data_index);
        value->u8 = 0xEE; // 使用无效数据标识
        return 1;         // 返回1表示数据存在但无效
    }

    case 504: { // F504：气表当前正向总累积流量示值
        // 将数据视为Data_ONE_F504结构
        Data_ONE_F504 *f504 = (Data_ONE_F504 *) data;

        // 处理data_index
        switch (data_index) {
        case 0: // 当前正向总累积流量（标况）
            if (data_type_38_getflag(&f504->data_BL)) {
                value->d64 = data_type_38_getvalue(&f504->data_BL);
                plog_debug(plugin, "F504 当前标况正向总累积流量 = %.2f",
                           value->d64);
                return 0;
            }
            break;

        case 1: // 当前正向总累积流量（工况）
            if (data_type_38_getflag(&f504->data_GL)) {
                value->d64 = data_type_38_getvalue(&f504->data_GL);
                plog_debug(plugin, "F504 当前工况正向总累积流量 = %.2f",
                           value->d64);
                return 0;
            }
            break;

        default:
            plog_error(plugin, "F504数据索引超出范围: %d (有效范围: 0-1)",
                       data_index);
            return -1;
        }

        // 数据无效
        plog_debug(plugin, "F504数据无效: index=%d", data_index);
        value->u8 = 0xEE; // 使用无效数据标识
        return 1;         // 返回1表示数据存在但无效
    }

    case 602: { // F602：热量表运行状态字及其变位标志
        // 将数据视为Data_ONE_F602结构
        Data_ONE_F602 *f602 = (Data_ONE_F602 *) data;

        // 用于检查无效数据的对比值
        Data_Type_BS16 invalid_bs16 = { 0 };
        memset(&invalid_bs16, 0xEE, sizeof(Data_Type_BS16));

        // 处理S1-S4状态字的各个位（data_index范围: 0-31）
        if (data_index <= 7) {
            // S1 状态字 (data_index: 0-7)
            // 检查是否为无效数据
            if (memcmp(&f602->S1, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                plog_debug(plugin, "F602: S1状态字为无效数据");
                value->u8 = 0xEE;
                return 1; // 返回1表示数据存在但无效
            }

            // 根据data_index返回对应位
            switch (data_index) {
            case 0:
                value->boolean = f602->S1.bit0;
                break;
            case 1:
                value->boolean = f602->S1.bit1;
                break;
            case 2:
                value->boolean = f602->S1.bit2;
                break;
            case 3:
                value->boolean = f602->S1.bit3;
                break;
            case 4:
                value->boolean = f602->S1.bit4;
                break;
            case 5:
                value->boolean = f602->S1.bit5;
                break;
            case 6:
                value->boolean = f602->S1.bit6;
                break;
            case 7:
                value->boolean = f602->S1.bit7;
                break;
            }
            plog_debug(plugin, "F602 S1状态位[%d] = %d", data_index,
                       value->boolean);
            return 0; // 返回0表示数据有效
        } else if (data_index >= 8 && data_index <= 15) {
            // S2 状态字 (data_index: 8-15)
            // 检查是否为无效数据
            if (memcmp(&f602->S2, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                plog_debug(plugin, "F602: S2状态字为无效数据");
                value->u8 = 0xEE;
                return 1; // 返回1表示数据存在但无效
            }

            // 根据data_index返回对应位
            switch (data_index) {
            case 8:
                value->boolean = f602->S2.bit0;
                break;
            case 9:
                value->boolean = f602->S2.bit1;
                break;
            case 10:
                value->boolean = f602->S2.bit2;
                break;
            case 11:
                value->boolean = f602->S2.bit3;
                break;
            case 12:
                value->boolean = f602->S2.bit4;
                break;
            case 13:
                value->boolean = f602->S2.bit5;
                break;
            case 14:
                value->boolean = f602->S2.bit6;
                break;
            case 15:
                value->boolean = f602->S2.bit7;
                break;
            }
            plog_debug(plugin, "F602 S2状态位[%d] = %d", data_index,
                       value->boolean);
            return 0; // 返回0表示数据有效
        } else if (data_index >= 16 && data_index <= 23) {
            // S3 状态字 (data_index: 16-23)
            // 检查是否为无效数据
            if (memcmp(&f602->S3, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                plog_debug(plugin, "F602: S3状态字为无效数据");
                value->u8 = 0xEE;
                return 1; // 返回1表示数据存在但无效
            }

            // 根据data_index返回对应位
            switch (data_index) {
            case 16:
                value->boolean = f602->S3.bit0;
                break;
            case 17:
                value->boolean = f602->S3.bit1;
                break;
            case 18:
                value->boolean = f602->S3.bit2;
                break;
            case 19:
                value->boolean = f602->S3.bit3;
                break;
            case 20:
                value->boolean = f602->S3.bit4;
                break;
            case 21:
                value->boolean = f602->S3.bit5;
                break;
            case 22:
                value->boolean = f602->S3.bit6;
                break;
            case 23:
                value->boolean = f602->S3.bit7;
                break;
            }
            plog_debug(plugin, "F602 S3状态位[%d] = %d", data_index,
                       value->boolean);
            return 0; // 返回0表示数据有效
        } else if (data_index >= 24 && data_index <= 31) {
            // S4 状态字 (data_index: 24-31)
            // 检查是否为无效数据
            if (memcmp(&f602->S4, &invalid_bs16, sizeof(Data_Type_BS16)) == 0) {
                plog_debug(plugin, "F602: S4状态字为无效数据");
                value->u8 = 0xEE;
                return 1; // 返回1表示数据存在但无效
            }

            // 根据data_index返回对应位
            switch (data_index) {
            case 24:
                value->boolean = f602->S4.bit0;
                break;
            case 25:
                value->boolean = f602->S4.bit1;
                break;
            case 26:
                value->boolean = f602->S4.bit2;
                break;
            case 27:
                value->boolean = f602->S4.bit3;
                break;
            case 28:
                value->boolean = f602->S4.bit4;
                break;
            case 29:
                value->boolean = f602->S4.bit5;
                break;
            case 30:
                value->boolean = f602->S4.bit6;
                break;
            case 31:
                value->boolean = f602->S4.bit7;
                break;
            }
            plog_debug(plugin, "F602 S4状态位[%d] = %d", data_index,
                       value->boolean);
            return 0; // 返回0表示数据有效
        } else if (data_index >= 32 && data_index <= 63) {
            // 变位标志处理 (BWS1-BWS4) (data_index: 32-63)
            // 变位标志通常不直接读取，这里简化实现
            plog_debug(plugin, "F602: 变位标志不支持直接读取 (data_index=%d)",
                       data_index);
            value->u8 = 0xEE;
            return 1; // 返回1表示数据存在但无效
        } else {
            plog_error(plugin, "F602数据索引超出范围: %d (有效范围: 0-63)",
                       data_index);
            return -1;
        }
        break;
    }

    case 603: { // F603：热量表累积流量、热量、冷量，温度、流速、压力
        // 将数据视为Data_ONE_F603结构
        Data_ONE_F603 *f603 = (Data_ONE_F603 *) data;

        // 根据data_index获取不同的数据项
        switch (data_index) {
        case 0: // 累积流量
            if (data_type_38_getflag(&f603->data_SL)) {
                value->d64 = data_type_38_getvalue(&f603->data_SL);
                plog_debug(plugin, "F603 累积流量 = %.2f", value->d64);
                return 0;
            }
            break;

        case 1: // 累积热量
            if (data_type_38_getflag(&f603->data_SH)) {
                value->d64 = data_type_38_getvalue(&f603->data_SH);
                plog_debug(plugin, "F603 累积热量 = %.2f", value->d64);
                return 0;
            }
            break;

        case 2: // 累积冷量
            if (data_type_38_getflag(&f603->data_SC)) {
                value->d64 = data_type_38_getvalue(&f603->data_SC);
                plog_debug(plugin, "F603 累积冷量 = %.2f", value->d64);
                return 0;
            }
            break;

        case 3: // 当前供水温度
            if (data_type_36_getflag(&f603->data_GT)) {
                value->f32 = data_type_36_getvalue(&f603->data_GT);
                plog_debug(plugin, "F603 当前供水温度 = %.2f", value->f32);
                return 0;
            }
            break;

        case 4: // 当前回水温度
            if (data_type_36_getflag(&f603->data_HT)) {
                value->f32 = data_type_36_getvalue(&f603->data_HT);
                plog_debug(plugin, "F603 当前回水温度 = %.2f", value->f32);
                return 0;
            }
            break;

        case 5: // 当前流速
            if (data_type_29_getflag(&f603->data_L)) {
                value->f32 = data_type_29_getvalue(&f603->data_L);
                plog_debug(plugin, "F603 当前流速 = %.2f", value->f32);
                return 0;
            }
            break;

        case 6: // 压力
            if (data_type_37_getflag(&f603->data_P)) {
                value->f32 = data_type_37_getvalue(&f603->data_P);
                plog_debug(plugin, "F603 压力 = %.2f", value->f32);
                return 0;
            }
            break;

        default:
            plog_error(plugin, "F603数据索引超出范围: %d (有效范围: 0-6)",
                       data_index);
            return -1;
        }

        // 数据无效
        plog_debug(plugin, "F603数据无效: index=%d", data_index);
        value->u8 = 0xEE; // 使用无效数据标识
        return 1;         // 返回1表示数据存在但无效
    }

    case 701: { // F701：RTU遥信数据
        // 跳过时间戳
        const uint8_t *yxdata     = data + sizeof(GB_12241_MHDMYTIME);
        size_t available_data_len = data_unit_size - sizeof(GB_12241_MHDMYTIME);
        uint16_t invalid_word     = 0xEEEE;

        // 首先检查数据有效性 - 只有当数据长度至少为4个字节时才检查
        bool is_data_valid = true;
        if (available_data_len >= 4) {
            // 检查前4个字节是否都是无效值
            if ((memcmp(yxdata, &invalid_word, 2) == 0) &&
                (memcmp(yxdata + 2, &invalid_word, 2) == 0)) {
                is_data_valid = false;
                plog_notice(plugin,
                            "F701 遥信数据无效: 前4个字节均为无效值0xEEEE");
            }
        }

        if (!is_data_valid) {
            value->u8 = 0xEE;
            return 1; // 数据存在但无效
        }

        // 计算位索引
        int byte_index = data_index / 8;
        int bit_index  = data_index % 8;

        // 检查索引范围
        if ((size_t) byte_index < available_data_len) {
            // 提取对应位的值
            value->boolean = (yxdata[byte_index] >> bit_index) & 0x01;
            plog_debug(plugin, "F701 遥信[%d] = %d (字节%d位%d)", data_index,
                       value->boolean, byte_index, bit_index);
            return 0; // 数据有效
        } else {
            plog_error(plugin, "F701 遥信索引超出范围: 索引=%d, 最大字节数=%zu",
                       byte_index, available_data_len);
            value->u8 = 0xEE;
            return -1; // 索引无效
        }
        break;
    }

    case 702: { // F702：RTU遥测数据
        // 跳过时间戳
        const uint8_t *ycdata     = data + sizeof(GB_12241_MHDMYTIME);
        size_t available_data_len = data_unit_size - sizeof(GB_12241_MHDMYTIME);
        size_t data_type_40_size  = sizeof(Data_Type_40);
        int    yc_count           = available_data_len / data_type_40_size;

        // 检查遥测点索引是否在范围内
        if (data_index < yc_count) {
            // 获取对应的Data_Type_40结构
            Data_Type_40 *data40 =
                (Data_Type_40 *) (ycdata + data_index * data_type_40_size);

            // 检查数据有效性
            if (data_type_40_getflag(data40)) {
                value->d64 = data_type_40_getvalue(data40);
                plog_debug(plugin, "F702 遥测[%d] = %.2f", data_index,
                           value->d64);
                return 0; // 数据有效
            } else {
                plog_notice(plugin, "F702 遥测数据无效: index=%d", data_index);
                value->u8 = 0xEE;
                return 1; // 数据存在但无效
            }
        } else {
            plog_error(plugin, "F702 遥测索引超出范围: %d (总点数: %d)",
                       data_index, yc_count);
            return -1; // 索引无效
        }
        break;
    }

    case 703: { // F703：RTU电度数据
        // 跳过时间戳
        const uint8_t *kwhdata    = data + sizeof(GB_12241_MHDMYTIME);
        size_t available_data_len = data_unit_size - sizeof(GB_12241_MHDMYTIME);
        size_t data_type_40_size  = sizeof(Data_Type_40);
        int    kwh_count          = available_data_len / data_type_40_size;

        // 检查电度点索引是否在范围内
        if (data_index < kwh_count) {
            // 获取对应的Data_Type_40结构
            Data_Type_40 *data40 =
                (Data_Type_40 *) (kwhdata + data_index * data_type_40_size);

            // 检查数据有效性
            if (data_type_40_getflag(data40)) {
                value->d64 = data_type_40_getvalue(data40);
                plog_debug(plugin, "F703 电度[%d] = %.2f", data_index,
                           value->d64);
                return 0; // 数据有效
            } else {
                plog_notice(plugin, "F703 电度数据无效: index=%d", data_index);
                value->u8 = 0xEE;
                return 1; // 数据存在但无效
            }
        } else {
            plog_error(plugin, "F703 电度索引超出范围: %d (总点数: %d)",
                       data_index, kwh_count);
            return -1; // 索引无效
        }
        break;
    }

    default: {
        // 对于其他功能码，使用数据类型映射获取相应处理函数
        plog_debug(plugin, "未优化处理的功能码: FN=%u", fn);
        return -1; // 无法提取有效值
    }
    }

    return -1; // 无法提取有效值
}

// 检查功能码是否需要单独发送（特殊功能码如701、702、703需要单独发送）
static bool is_special_fn(uint16_t fn)
{
    // 特殊功能码列表，这些功能码需要单独一帧发送
    static const uint16_t special_fns[] = { 701, 702, 703, 829, 830, 831, 832 };
    static const size_t   special_fns_count =
        sizeof(special_fns) / sizeof(special_fns[0]);

    for (size_t i = 0; i < special_fns_count; i++) {
        if (fn == special_fns[i]) {
            return true;
        }
    }

    return false;
}

/* 初始化点位状态数据库 */
static int init_tag_state_db(neu_plugin_t *plugin)
{
    char  db_path[256];
    char *err_msg = NULL;
    int   rc;

    // 构建数据库文件路径
    snprintf(db_path, sizeof(db_path), "persistence/12241_%s.db",
             plugin->common.name);

    // 打开数据库连接
    rc = sqlite3_open(db_path, &plugin->tag_state_db);
    if (rc != SQLITE_OK) {
        plog_error(plugin, "Cannot open database: %s",
                   sqlite3_errmsg(plugin->tag_state_db));
        sqlite3_close(plugin->tag_state_db);
        return -1;
    }

    // 创建点位状态表
    const char *sql = "CREATE TABLE IF NOT EXISTS tag_state ("
                      "group_name TEXT NOT NULL,"
                      "tag_name TEXT NOT NULL,"
                      "last_update_time INTEGER DEFAULT 0,"
                      "last_polled_historical_time INTEGER DEFAULT 0,"
                      "dirty INTEGER DEFAULT 0,"
                      "PRIMARY KEY (group_name, tag_name));";

    rc = sqlite3_exec(plugin->tag_state_db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        plog_error(plugin, "SQL error: %s", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(plugin->tag_state_db);
        return -1;
    }

    // 创建历史召测任务表和索引
    const char *sql_create_polling_task =
        "CREATE TABLE IF NOT EXISTS polling_task ("
        "group_name TEXT NOT NULL,"
        "tag_name TEXT NOT NULL,"
        "tag_address TEXT NOT NULL,"
        "start_time INTEGER NOT NULL,"
        "end_time INTEGER NOT NULL,"
        "retry_count INTEGER DEFAULT 0,"
        "PRIMARY KEY (group_name, tag_name, start_time, end_time)"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_polling_task_group_tag ON "
        "polling_task(group_name, tag_name);";
    rc = sqlite3_exec(plugin->tag_state_db, sql_create_polling_task, 0, 0,
                      &err_msg);
    if (rc != SQLITE_OK) {
        plog_error(plugin, "SQL error (create polling_task): %s", err_msg);
        sqlite3_free(err_msg);
        // 不return，继续后续tag_state逻辑
    }

    // 初始化互斥锁
    if (pthread_mutex_init(&plugin->tag_state_mutex, NULL) != 0) {
        plog_error(plugin, "tag_state_mutex init failed");
        sqlite3_close(plugin->tag_state_db);
        return -1;
    }
    plugin->polling_task_icd =
        (UT_icd) { sizeof(polling_task_t), NULL, NULL, NULL };

    // 初始化历史召测任务UT_array和互斥锁
    if (!plugin->polling_tasks) {
        utarray_new(plugin->polling_tasks, &plugin->polling_task_icd);
    }
    if (pthread_mutex_init(&plugin->polling_task_mutex, NULL) != 0) {
        plog_error(plugin, "polling_task_mutex init failed");
        sqlite3_close(plugin->tag_state_db);
        return -1;
    }

    // 从数据库加载所有点位状态到内存
    sql = "SELECT group_name, tag_name, last_update_time, "
          "last_polled_historical_time, dirty FROM tag_state;";
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(plugin->tag_state_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        plog_error(plugin, "Failed to prepare statement: %s",
                   sqlite3_errmsg(plugin->tag_state_db));
        return -1;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        tag_state_t *state = calloc(1, sizeof(tag_state_t));
        if (!state) {
            plog_error(plugin, "Failed to allocate memory for tag state");
            continue;
        }

        strncpy(state->group_name, (const char *) sqlite3_column_text(stmt, 0),
                NEU_GROUP_NAME_LEN - 1);
        strncpy(state->tag_name, (const char *) sqlite3_column_text(stmt, 1),
                NEU_TAG_NAME_LEN - 1);
        state->last_update_time            = sqlite3_column_int64(stmt, 2);
        state->last_polled_historical_time = sqlite3_column_int64(stmt, 3);
        state->dirty                       = sqlite3_column_int(stmt, 4);

        // 使用联合主键(group_name+tag_name)作为哈希key
        HASH_ADD(hh, plugin->tag_states, group_name,
                 NEU_GROUP_NAME_LEN + NEU_TAG_NAME_LEN, state);
    }

    sqlite3_finalize(stmt);

    // 加载历史召测任务到UT_array
    const char *sql_select =
        "SELECT group_name, tag_name, tag_address, start_time, end_time, "
        "retry_count FROM polling_task;";
    rc = sqlite3_prepare_v2(plugin->tag_state_db, sql_select, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        pthread_mutex_lock(&plugin->polling_task_mutex);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            polling_task_t task = { 0 };
            strncpy(task.group_name,
                    (const char *) sqlite3_column_text(stmt, 0),
                    NEU_GROUP_NAME_LEN - 1);
            strncpy(task.tag_name, (const char *) sqlite3_column_text(stmt, 1),
                    NEU_TAG_NAME_LEN - 1);
            strncpy(task.tag_address,
                    (const char *) sqlite3_column_text(stmt, 2),
                    NEU_TAG_ADDRESS_LEN - 1); //
            task.start_time  = sqlite3_column_int64(stmt, 3);
            task.end_time    = sqlite3_column_int64(stmt, 4);
            task.retry_count = sqlite3_column_int(stmt, 5);
            utarray_push_back(plugin->polling_tasks, &task);
        }
        pthread_mutex_unlock(&plugin->polling_task_mutex);
        sqlite3_finalize(stmt);
        plog_notice(plugin, "历史召测任务加载完成，共%u条",
                    (unsigned) utarray_len(plugin->polling_tasks));
    } else {
        plog_error(plugin, "prepare polling_task select failed: %s",
                   sqlite3_errmsg(plugin->tag_state_db));
    }

    return 0;
}

/* 关闭点位状态数据库 */
static void close_tag_state_db(neu_plugin_t *plugin)
{
    if (!plugin->tag_state_db) {
        return;
    }

    // 清理内存中的点位状态
    tag_state_t *current, *tmp;
    HASH_ITER(hh, plugin->tag_states, current, tmp)
    {
        HASH_DEL(plugin->tag_states, current);
        free(current);
    }

    // 关闭数据库连接
    sqlite3_close(plugin->tag_state_db);
    plugin->tag_state_db = NULL;

    // 销毁互斥锁
    pthread_mutex_destroy(&plugin->tag_state_mutex);

    // 清理历史召测任务队列和互斥锁
    if (plugin->polling_tasks) {
        utarray_free(plugin->polling_tasks);
        plugin->polling_tasks = NULL;
    }
    pthread_mutex_destroy(&plugin->polling_task_mutex);
}

/* 更新点位状态 */
static int update_tag_state(neu_plugin_t *plugin, const char *group_name,
                            const char *tag_name, time_t update_time)
{
    if (!plugin->tag_state_db || !group_name || !tag_name) {
        return -1;
    }

    pthread_mutex_lock(&plugin->tag_state_mutex);

    // 使用(group_name, tag_name)联合主键查找，保证每个组下每个tag唯一
    tag_state_t key = { 0 };
    strncpy(key.group_name, group_name, NEU_GROUP_NAME_LEN - 1);
    strncpy(key.tag_name, tag_name, NEU_TAG_NAME_LEN - 1);
    tag_state_t *state = NULL;
    HASH_FIND(hh, plugin->tag_states, &key,
              NEU_GROUP_NAME_LEN + NEU_TAG_NAME_LEN, state);

    if (!state) {
        state = calloc(1, sizeof(tag_state_t));
        if (!state) {
            pthread_mutex_unlock(&plugin->tag_state_mutex);
            return -1;
        }
        strncpy(state->group_name, group_name, NEU_GROUP_NAME_LEN - 1);
        strncpy(state->tag_name, tag_name, NEU_TAG_NAME_LEN - 1);
        // 添加到哈希表时用联合主键，使用state->group_name作为key
        HASH_ADD(hh, plugin->tag_states, group_name,
                 NEU_GROUP_NAME_LEN + NEU_TAG_NAME_LEN, state);
    }
    // 如果更新时间大于当前时间，则更新时间戳
    if (update_time > state->last_update_time) {
        state->last_update_time = update_time;
        state->dirty            = true;
    }

    pthread_mutex_unlock(&plugin->tag_state_mutex);
    return 0;
}

static polling_group_t *parse_polling_tags(const char *json_str,
                                           int *       group_count)
{
    if (!json_str || strlen(json_str) == 0)
        return NULL;
    json_t *root = (json_t *) neu_json_decode_new(json_str);
    if (!root)
        return NULL;
    if (!json_is_array(root)) {
        neu_json_decode_free(root);
        return NULL;
    }
    int n = json_array_size(root);
    if (n <= 0) {
        neu_json_decode_free(root);
        return NULL;
    }
    polling_group_t *groups = calloc(n, sizeof(polling_group_t));
    if (!groups) {
        neu_json_decode_free(root);
        return NULL;
    }
    for (int i = 0; i < n; i++) {
        json_t *obj = json_array_get(root, i);
        if (!obj || !json_is_object(obj))
            continue;
        neu_json_elem_t fields[2] = { { .name = "group", .t = NEU_JSON_STR },
                                      { .name = "tags",
                                        .t    = NEU_JSON_ARRAY_STR } };
        if (neu_json_decode_by_json(obj, 2, fields) != 0) {
            neu_json_elem_free(&fields[0]);
            neu_json_elem_free(&fields[1]);
            continue;
        }
        if (!fields[0].v.val_str || fields[1].t != NEU_JSON_ARRAY_STR ||
            fields[1].v.val_array_str.length <= 0) {
            neu_json_elem_free(&fields[0]);
            neu_json_elem_free(&fields[1]);
            continue;
        }
        strncpy(groups[i].group, fields[0].v.val_str, NEU_GROUP_NAME_LEN - 1);
        int tag_n           = fields[1].v.val_array_str.length;
        groups[i].tags      = calloc(tag_n, sizeof(char *));
        groups[i].tag_count = tag_n;
        for (int j = 0; j < tag_n; j++) {
            if (fields[1].v.val_array_str.p_strs[j])
                groups[i].tags[j] = strdup(fields[1].v.val_array_str.p_strs[j]);
            else
                groups[i].tags[j] = NULL;
        }
        neu_json_elem_free(&fields[0]);
        neu_json_elem_free(&fields[1]);
    }
    if (group_count)
        *group_count = n;
    neu_json_decode_free(root);
    return groups;
}

#define POLL_INTERVAL_SEC 300 // 5分钟
// 修复 get_tag_state，确保以 group_name+tag_name 联合主键查找
static int get_tag_state(neu_plugin_t *plugin, const char *group_name,
                         const char *tag_name, tag_state_t **state)
{
    if (!plugin->tag_state_db || !group_name || !tag_name || !state) {
        return -1;
    }
    pthread_mutex_lock(&plugin->tag_state_mutex);
    tag_state_t key = { 0 };
    strncpy(key.group_name, group_name, NEU_GROUP_NAME_LEN - 1);
    strncpy(key.tag_name, tag_name, NEU_TAG_NAME_LEN - 1);
    *state = NULL;
    HASH_FIND(hh, plugin->tag_states, &key,
              NEU_GROUP_NAME_LEN + NEU_TAG_NAME_LEN, *state);
    pthread_mutex_unlock(&plugin->tag_state_mutex);
    return (*state != NULL) ? 0 : -1;
}

/**
 * @brief 执行历史召测任务
 *
 * 执行逻辑：
 * 1. 从队列中取出待执行的召测任务（每次最多10个）
 * 2. 通过遍历所有组的标签找到对应的标签地址
 * 3. 构建带时间参数的历史召测请求
 * 4. 发送请求并接收响应
 * 5. 解析历史数据并存储（不更新实时标签）
 * 6. 根据执行结果删除任务或重试
 * 7. 控制执行频率，避免影响实时采集
 */
static void execute_polling_tasks(neu_plugin_t *plugin)
{
    if (!plugin->polling_enabled || !plugin->polling_tasks) {
        return;
    }

    // 检查连接状态，召测需要稳定连接
    if (!neu_conn_is_connected(plugin->conn)) {
        plog_debug(plugin, "连接断开，跳过历史召测执行");
        return;
    }

    pthread_mutex_lock(&plugin->polling_task_mutex);

    // 检查是否有待执行任务
    unsigned int task_count = utarray_len(plugin->polling_tasks);
    if (task_count == 0) {
        pthread_mutex_unlock(&plugin->polling_task_mutex);
        return;
    }

    // 每次最多执行10个任务，避免影响实时采集性能
    const unsigned int max_tasks_per_batch = 10;
    unsigned int       tasks_to_process =
        (task_count < max_tasks_per_batch) ? task_count : max_tasks_per_batch;

    // 复制任务信息到临时数组，避免长时间持锁
    polling_task_t current_tasks[max_tasks_per_batch];
    for (unsigned int i = 0; i < tasks_to_process; i++) {
        polling_task_t *task =
            (polling_task_t *) utarray_eltptr(plugin->polling_tasks, i);
        if (task) {
            current_tasks[i] = *task;
        }
    }

    // 从队列中移除这些任务（无论成功失败都移除，避免重复执行）
    utarray_erase(plugin->polling_tasks, 0, tasks_to_process);

    pthread_mutex_unlock(&plugin->polling_task_mutex);

    plog_notice(plugin, "开始批量执行历史召测: %d个任务", tasks_to_process);

    // 逐个处理任务
    for (unsigned int task_idx = 0; task_idx < tasks_to_process; task_idx++) {
        polling_task_t *current_task = &current_tasks[task_idx];

        // 格式化时间用于日志
        char      timebuf_start[32], timebuf_end[32];
        struct tm tm_start, tm_end;
        localtime_r(&current_task->start_time, &tm_start);
        localtime_r(&current_task->end_time, &tm_end);
        strftime(timebuf_start, sizeof(timebuf_start), "%Y-%m-%d %H:%M:%S",
                 &tm_start);
        strftime(timebuf_end, sizeof(timebuf_end), "%Y-%m-%d %H:%M:%S",
                 &tm_end);

        plog_notice(plugin, "执行历史召测 [%d/%d]: %s.%s [%s~%s] (重试%d次)",
                    task_idx + 1, tasks_to_process, current_task->group_name,
                    current_task->tag_name, timebuf_start, timebuf_end,
                    current_task->retry_count);

        // 通过适配器获取标签地址信息
        char *tag_address = NULL;

        // 临时解决方案：使用现有的tag_address字段
        if (strlen(current_task->tag_address) > 0) {
            tag_address = current_task->tag_address;
        } else {
            plog_warn(plugin, "历史召测失败: 标签地址为空 %s.%s",
                      current_task->group_name, current_task->tag_name);
            continue;
        }

        // 解析标签地址获取FN和PN
        uint16_t device_addr = 0;
        uint16_t fn          = 0;
        uint16_t pn          = 0;
        uint16_t data_index  = 0;

        if (gb_12241_parse_tag_address(plugin, tag_address, &device_addr, &fn,
                                       &pn, &data_index) != 0) {
            plog_error(plugin, "历史召测失败: 无法解析标签地址 %s",
                       tag_address);
            continue;
        }

        // ===== 关键修改：使用基于标签名称的历史FN映射 =====
        uint16_t realtime_fn = fn; // 保存原始实时FN
        // 获取历史FN - 特殊处理RTU标签
        uint16_t historical_fn;
        if (is_rtu_tag(current_task->tag_name)) {
            historical_fn =
                get_rtu_historical_fn(plugin, current_task->group_name,
                                      current_task->tag_name, realtime_fn);
            if (historical_fn > 0) {
                plog_debug(plugin, "RTU标签 '%s' 在组 '%s' 中映射到历史FN=%u",
                           current_task->tag_name, current_task->group_name,
                           historical_fn);
            }
        } else {
            historical_fn = get_historical_fn_from_tag_and_fn(
                plugin, current_task->tag_name, realtime_fn);
        }
        if (historical_fn == 0) {
            plog_warn(plugin,
                      "历史召测跳过: 标签名称'%s'无对应历史功能码，标签=%s.%s",
                      current_task->tag_name, current_task->group_name,
                      current_task->tag_name);
            continue;
        }

        // 使用历史FN替换实时FN
        fn = historical_fn;

        const char *mapping_desc = get_fn_mapping_description(
            plugin, current_task->tag_name, realtime_fn);
        plog_notice(plugin, "历史召测FN映射: %s.%s 实时FN=%u -> 历史FN=%u (%s)",
                    current_task->group_name, current_task->tag_name,
                    realtime_fn, historical_fn,
                    mapping_desc ? mapping_desc : "未知映射");

        // 构建历史召测请求
        uint8_t request[1024];
        size_t  request_len = 0;

        int ret = gb_12241_build_his_request(
            plugin, request, sizeof(request), device_addr, plugin->seq++, fn,
            pn, current_task->start_time, current_task->end_time, &request_len);

        if (ret != 0) {
            plog_error(plugin,
                       "历史召测失败: 构建请求帧失败，设备=%d, FN=%d, PN=%d",
                       device_addr, fn, pn);
            continue;
        }

        // 发送请求并接收响应
        uint8_t response[2048];
        size_t  response_len = sizeof(response);

        ret = gb_12241_send_and_receive(plugin, request, request_len, response,
                                        &response_len);
        if (ret != 0) {
            plog_error(plugin,
                       "历史召测失败: 发送接收失败，设备=%d, FN=%d, PN=%d",
                       device_addr, fn, pn);
            continue;
        }

        plog_notice(plugin, "历史召测响应: %s.%s [%s~%s], 收到 %zu 字节",
                    current_task->group_name, current_task->tag_name,
                    timebuf_start, timebuf_end, response_len);

        // 解析历史数据响应并存储
        ret = parse_and_store_historical_data(
            plugin, response, response_len, current_task->group_name,
            current_task->tag_name, fn, pn, data_index,
            current_task->start_time, current_task->end_time);

        if (ret == 0) {
            plog_notice(plugin, "历史数据解析存储成功: %s.%s [%s~%s]",
                        current_task->group_name, current_task->tag_name,
                        timebuf_start, timebuf_end);
        } else {
            plog_error(plugin, "历史数据解析存储失败: %s.%s [%s~%s], 错误码=%d",
                       current_task->group_name, current_task->tag_name,
                       timebuf_start, timebuf_end, ret);
        }
    }

    plog_notice(plugin, "批量历史召测执行完成: %d个任务", tasks_to_process);
}

/**
 * @brief 构建历史召测请求帧
 *
 * 历史召测请求特点：
 * 1. 使用AFN_REQUESTTWODATA (0x0C) 应用功能码
 * 2. 设置TpV位表示包含时间标签
 * 3. 数据单元包含：数据单元标识 + Td_c结构体 + Tp结构体
 * 4. 每次请求单个FN+PN组合
 */
static int gb_12241_build_his_request(neu_plugin_t *plugin, uint8_t *frame,
                                      size_t frame_size, uint16_t device_addr,
                                      uint8_t seq, uint16_t fn, uint16_t pn,
                                      time_t start_time, time_t end_time,
                                      size_t *request_length)
{
    uint8_t *      buf;
    uint16_t       user_data_len = 0;
    S_ControlField ctrl;
    S_SEQ          frame_seq;
    LINK_LEN       link_len = { 0 };
    DATA_UNIT_Flag dataunitf;
    ADDR           addr = { 0 };

    /* 使用end_time避免未使用参数警告 */
    (void) end_time;

    /* 检查参数 */
    if (plugin == NULL || frame == NULL || frame_size < 30 ||
        request_length == NULL) {
        plog_error(plugin, "历史召测请求参数无效");
        return -1;
    }

    /* 添加调试日志 */
    plog_debug(plugin, "构建历史召测请求: 设备地址=%u, 功能码=%u, 参数号=%u",
               device_addr, fn, pn);

    /* 初始化 */
    buf = frame;

    /* 1. 帧起始符 */
    *buf = 0x68;
    buf += 1;

    /* 2. 预留长度字段空间 */
    buf += 4;

    /* 3. 重复帧起始符 */
    *buf = 0x68;
    buf += 1;

    /* 4. 控制域 - 历史召测使用REQUESTTWODATA */
    ctrl.ControlField.ControlField.DIR = 0; /* 方向位(主站发出=0) */
    ctrl.ControlField.ControlField.PRM = 1; /* 启动位(主站发出=1) */
    ctrl.ControlField.ControlField.FCB = 1; /* 帧计数位 */
    ctrl.ControlField.ControlField.FCV = 0; /* 帧计数有效位 */
    ctrl.ControlField.ControlField.FC = REQUESTTWODATA; /* 功能码：二类数据 */

    *buf = ctrl.ControlField.BControlField;
    buf += 1;
    user_data_len += 1;

    /* 5. 地址域 */
    addr.TAH = device_addr / 256;
    addr.TAL = device_addr % 256;
    addr.GAF = 0;
    addr.MSA = 1;
    addr.RA1 = 0;
    addr.RA2 = 0;
    addr.RA3 = 0;
    addr.RA4 = 0;

    memcpy(buf, &addr, 5);
    buf += 5;
    user_data_len += 5;

    /* 6. 应用功能码 - 历史召测使用AFN_REQUESTTWODATA */
    *buf = AFN_REQUESTTWODATA; // 0x0d - 二类数据
    buf += 1;
    user_data_len += 1;

    /* 7. 帧序列域 - 设置TpV位表示包含时间标签 */
    memset(&frame_seq, 0, sizeof(S_SEQ));
    frame_seq.seq.PSEQ.PSEQ = seq & 0x0F;
    frame_seq.seq.PSEQ.CON  = 1; /* 需要确认 */
    frame_seq.seq.PSEQ.FIN  = 1; /* 末帧标志 */
    frame_seq.seq.PSEQ.FIR  = 1; /* 首帧标志 */
    frame_seq.seq.PSEQ.TpV = 1; /* 帧时间标签有效 - 历史召测关键！ */

    memcpy(buf++, &frame_seq.seq.RSEQ, 1);
    user_data_len += 1;

    /* 8. 数据单元标识 */
    memset(&dataunitf, 0, sizeof(DATA_UNIT_Flag));

    /* 设置参数号 */
    if (pn == 0) {
        dataunitf.DA1 = 0x00;
        dataunitf.DA2 = 0x00;
    } else {
        dataunitf.DA1 = 0x01 << ((pn - 1) % 8);
        dataunitf.DA2 = (pn - 1) / 8 + 1;
    }

    /* 设置功能码 */
    gb_12241_fn_to_dt(&dataunitf, fn);

    /* 复制数据单元标识 */
    memcpy(buf, &dataunitf, 4);
    buf += 4;
    user_data_len += 4;

    /* 9. Td_c结构体 - 历史召测时标 */
    Td_c tmp_td_c;
    memset(&tmp_td_c, 0, sizeof(Td_c));

    /* 设置时间为起始时间 - 使用正确的函数 */
    gb_12241_mhdmytime_setvalue(&tmp_td_c.time, start_time);

    /* 设置密度（间隔）- 这里设置为5分钟间隔作为默认值 */
    tmp_td_c.density = 254; // 5分钟间隔
    tmp_td_c.Nums    = 1;

    /* 复制Td_c结构体 */
    memcpy(buf, &tmp_td_c, sizeof(Td_c));
    buf += sizeof(Td_c); // 7字节
    user_data_len += sizeof(Td_c);

    /* 10. Tp结构体 - 时间标签 */
    Tp tp;
    memset(&tp, 0, sizeof(Tp));

    /* 设置PFC - 帧计数位 */
    tp.PFC = (plugin->seq & 0x0F); // 使用当前序列号

    /* 复制Tp结构体 */
    memcpy(buf, &tp, sizeof(Tp));
    buf += sizeof(Tp); // 6字节
    user_data_len += sizeof(Tp);

    /* 检查用户数据长度 */
    if (user_data_len > 2047) {
        plog_error(plugin, "历史召测用户数据长度超出限制: %u", user_data_len);
        return -1;
    }

    /* 检查缓冲区溢出 */
    size_t needed_size = (size_t)(buf - frame) + 2;
    if (needed_size > frame_size) {
        plog_error(plugin, "历史召测缓冲区溢出: 需要%zu字节, 但只有%zu字节可用",
                   needed_size, frame_size);
        return -1;
    }

    /* 11. 设置长度域 */
    link_len.PFLG   = 0x01;
    link_len.LUSERL = user_data_len & 0x3F;
    link_len.LUSERH = (user_data_len >> 6) & 0xFF;

    /* 复制长度域到预留位置 */
    memcpy(frame + 1, &link_len, 2);
    memcpy(frame + 3, &link_len, 2);

    /* 12. 计算校验和 */
    *buf = gb_12241_make_crc(frame + 6, user_data_len);
    buf += 1;

    /* 13. 结束符 */
    *buf = 0x16;
    buf += 1;

    /* 设置请求长度 */
    *request_length = (size_t)(buf - frame);

    /* 添加调试日志 */
    struct tm *tm_start = localtime(&start_time);
    struct tm *tm_end   = localtime(&end_time);
    plog_notice(plugin,
                "历史召测请求帧构建完成: 总长度=%zu, 用户数据长度=%u, "
                "时间范围=[%04d-%02d-%02d %02d:%02d:%02d ~ %04d-%02d-%02d "
                "%02d:%02d:%02d]",
                *request_length, user_data_len, tm_start->tm_year + 1900,
                tm_start->tm_mon + 1, tm_start->tm_mday, tm_start->tm_hour,
                tm_start->tm_min, tm_start->tm_sec, tm_end->tm_year + 1900,
                tm_end->tm_mon + 1, tm_end->tm_mday, tm_end->tm_hour,
                tm_end->tm_min, tm_end->tm_sec);

    return 0;
}

/**
 * @brief 解析历史数据响应并存储
 *
 * @param plugin 插件实例
 * @param response 响应数据
 * @param response_len 响应数据长度
 * @param group_name 组名
 * @param tag_name 标签名
 * @param fn 功能码
 * @param pn 参数号
 * @param data_index 数据索引
 * @param start_time 起始时间
 * @param end_time 结束时间
 * @return 0成功，-1失败
 */
static int parse_and_store_historical_data(
    neu_plugin_t *plugin, const uint8_t *response, size_t response_len,
    const char *group_name, const char *tag_name, uint16_t fn, uint16_t pn,
    uint16_t data_index, time_t start_time, time_t end_time)
{
    if (!plugin || !response || response_len == 0 || !group_name || !tag_name) {
        plog_error(plugin, "历史数据解析参数无效");
        return -1;
    }

    NEU_UNUSED(end_time);
    NEU_UNUSED(data_index);
    NEU_UNUSED(start_time);
    // 解析响应帧
    uint16_t resp_device_addr = 0;
    uint8_t  afn              = 0;
    uint8_t  seq              = 0;
    uint8_t  control_field    = 0;
    uint8_t  data[1024]       = { 0 };
    size_t   data_len         = sizeof(data);

    size_t frame_size =
        gb_12241_parse_frame(response, response_len, &resp_device_addr, &afn,
                             &seq, &control_field, data, &data_len);
    if (frame_size == 0) {
        plog_error(plugin, "历史数据响应帧解析失败");
        return -1;
    }

    plog_debug(plugin, "历史数据响应: 设备地址=%u, AFN=%u, 数据长度=%zu",
               resp_device_addr, afn, data_len);

    // 检查是否为历史数据响应
    if (afn != AFN_REQUESTTWODATA && afn != AFN_ACK) {
        plog_error(plugin, "收到非历史数据响应: AFN=%u", afn);
        return -1;
    }

    // 解析控制域
    S_ControlField ctrl_field;
    ctrl_field.ControlField.BControlField = control_field;

    // 对于AFN_ACK，检查功能码
    if (afn == AFN_REQUESTTWODATA) {
        plog_debug(plugin, "收到二类数据响应(AFN=0x%02X)", afn);
    }
    if (afn == AFN_ACK) {
        if (ctrl_field.ControlField.ControlField.FC == NODATA ||
            ctrl_field.ControlField.ControlField.FC == RESPONSEUSERDATA) {
            plog_notice(plugin, "设备无历史数据(AFN=0x%02X, FC=0x%02X)", afn,
                        ctrl_field.ControlField.ControlField.FC);
            return 0; // 无数据不算错误
        } else if (ctrl_field.ControlField.ControlField.FC !=
                   RESPONSEUSERDATA) {
            plog_warn(plugin,
                      "收到确认应答，但功能码不正确(AFN=0x%02X, FC=0x%02X)",
                      afn, ctrl_field.ControlField.ControlField.FC);
            return -1;
        }
    }

    // 解析序列号和时间标签
    uint8_t *current_pos   = data;
    size_t   remaining_len = data_len;

    // 跳过AFN(1字节)和SEQ(1字节)，参考read_group的解析逻辑
    if (remaining_len >= 2) {
        // 直接使用结构体解析SEQ字节
        S_SEQ seq_struct;
        seq_struct.seq.RSEQ = current_pos[1]; // 将SEQ字节加载到结构体

        // 使用结构体访问TpV位
        bool tpv_valid = seq_struct.seq.PSEQ.TpV == 1;

        plog_debug(plugin, "历史数据帧: AFN=%02X, SEQ=%02X, TpV=%d",
                   current_pos[0], current_pos[1], tpv_valid ? 1 : 0);

        current_pos += 2;
        remaining_len -= 2;

        // 使用从帧解析获取的控制域
        bool fcb_valid = ctrl_field.ControlField.ControlField.FCB == 1;

        plog_debug(plugin, "控制域=%02X, FCB=%d", control_field,
                   fcb_valid ? 1 : 0);

        // 根据帧结构知识，检查是否有尾部附加信息
        if (remaining_len > 0) {
            // 如果有附加信息需要跳过处理
            size_t tail_bytes = 0;

            // FCB有效时，有2字节附加信息
            if (fcb_valid) {
                tail_bytes += 2;
                plog_debug(plugin, "历史数据帧中FCB有效，尾部有2字节附加信息");
            }

            // TpV有效时，有6字节时间标签
            if (tpv_valid) {
                tail_bytes += 6;
                plog_debug(plugin, "历史数据帧中TpV有效，尾部有6字节时间标签");
            }

            // 确保不溢出
            if (tail_bytes > 0 && tail_bytes < remaining_len) {
                // 调整有效数据长度，排除尾部附加信息
                remaining_len -= tail_bytes;
                plog_debug(plugin,
                           "调整历史数据有效长度，排除%zu字节尾部附加信息",
                           tail_bytes);
            }
        }
    } else {
        plog_error(plugin, "历史数据长度不足，无法跳过AFN和SEQ");
        return -1;
    }

    // 解析数据单元
    while (remaining_len >= sizeof(DATA_UNIT_Flag)) {
        DATA_UNIT_Flag data_unitf = { 0 };

        // 获取数据单元标识
        memcpy(&data_unitf, current_pos, sizeof(DATA_UNIT_Flag));
        current_pos += sizeof(DATA_UNIT_Flag);
        remaining_len -= sizeof(DATA_UNIT_Flag);

        // 计算实际的pn和fn值
        uint16_t recv_pn = (data_unitf.DA1 == 0x00 && data_unitf.DA2 == 0x00)
            ? 0
            : (GetDA1(data_unitf.DA1) + (data_unitf.DA2 - 1) * 8);
        uint16_t recv_fn = GetDA1(data_unitf.DT1) + (data_unitf.DT2) * 8;

        plog_notice(plugin, "历史数据单元: PN=%d, FN=%u", recv_pn, recv_fn);

        // 检查是否匹配请求的FN和PN
        if (recv_fn != fn || recv_pn != pn) {
            plog_error(plugin,
                       "历史数据单元不匹配: 期望FN=%u,PN=%u, 实际FN=%u,PN=%u",
                       fn, pn, recv_fn, recv_pn);
            // 跳过这个数据单元
            break;
        }

        // 检查是否为曲线类历史数据 (FN 81-88)
        if ((recv_fn >= 81 && recv_fn <= 88) ||   // 功率曲线
            (recv_fn >= 89 && recv_fn <= 91)      // 电压曲线
            || (recv_fn >= 92 && recv_fn <= 95)   // 电流曲线
            || (recv_fn >= 105 && recv_fn <= 108) // 功率因数
            || (recv_fn >= 801 && recv_fn <= 812) // 扩展版电能数据
            || recv_fn == 900 || recv_fn == 901   // 需量和频率曲线
            || recv_fn == 401 || recv_fn == 402 // 水表正向总累计流量、压力曲线
            || (recv_fn >= 502 && recv_fn <= 507) // 气表曲线
            || recv_fn == 607 || recv_fn == 608 || recv_fn == 610 // 热表曲线
            || recv_fn == 611 || recv_fn == 612   // 热表累积曲线
            || (recv_fn >= 710 && recv_fn <= 721) // RTU曲线
        ) {
            // 解析Td_c时标结构（7字节）
            if (remaining_len < sizeof(Td_c)) {
                plog_error(plugin, "数据长度不足，无法解析Td_c时标: %zu字节",
                           remaining_len);
                break;
            }

            Td_c td;
            memcpy(&td, current_pos, sizeof(Td_c));
            current_pos += sizeof(Td_c);
            remaining_len -= sizeof(Td_c);

            plog_debug(
                plugin, "时标解析: 时间=%02d%02d%02d%02d%02d, 密度=%d, 数量=%d",
                td.time.YearH * 10 + td.time.YearL,
                td.time.MonthH * 10 + td.time.MonthL,
                td.time.DayH * 10 + td.time.DayL,
                td.time.HourH * 10 + td.time.HourL,
                td.time.MinutesH * 10 + td.time.MinutesL, td.density, td.Nums);

            // 获取基准时间戳
            time_t base_time = gb_12241_mhdmytime_getutcvalue(&td.time);

            // 使用公共函数获取间隔时间
            int interval_time = get_interval_seconds_from_density(td.density);
            if (interval_time == 0) {
                plog_error(plugin, "无效的密度值: %d", td.density);
                break;
            }

            plog_debug(plugin, "基准时间: %ld, 间隔时间: %d秒", base_time,
                       interval_time);

            // 根据功能码选择不同的数据类型处理
            if (recv_fn >= 89 && recv_fn <= 91) { // 电压曲线
                // 电压曲线处理 - 使用Data_Type_7
                size_t expected_data_len = td.Nums * sizeof(Data_Type_7);
                if (remaining_len < expected_data_len) {
                    plog_error(plugin, "数据长度不足: 期望%zu字节, 实际%zu字节",
                               expected_data_len, remaining_len);
                    break;
                }

                Data_Type_7 *data_array  = (Data_Type_7 *) current_pos;
                int          valid_count = 0;

                for (int j = 0; j < td.Nums; j++) {
                    time_t current_timestamp = base_time + interval_time * j;

                    if (data_type_7_getflag(&data_array[j])) {
                        float value = data_type_7_getvalue(&data_array[j]);

                        char       time_str[32];
                        struct tm *tm_info = localtime(&current_timestamp);
                        strftime(time_str, sizeof(time_str),
                                 "%Y-%m-%d %H:%M:%S", tm_info);

                        const char *phase = "";
                        switch (recv_fn) {
                        case 89:
                            phase = "A相";
                            break;
                        case 90:
                            phase = "B相";
                            break;
                        case 91:
                            phase = "C相";
                            break;
                        }

                        plog_notice(plugin,
                                    "%s电压曲线[%d/%d]: %s.%s 时间=%s, 值=%.2f "
                                    "V, FN=%u, PN=%u",
                                    phase, j + 1, td.Nums, group_name, tag_name,
                                    time_str, value, fn, pn);

                        // 更新点位状态
                        update_tag_state(plugin, group_name, tag_name,
                                         current_timestamp);

                        valid_count++;
                    } else {
                        plog_debug(plugin, "%s电压曲线[%d/%d]: 数据无效",
                                   recv_fn == 89
                                       ? "A相"
                                       : (recv_fn == 90 ? "B相" : "C相"),
                                   j + 1, td.Nums);
                    }
                }

                current_pos += expected_data_len;
                remaining_len -= expected_data_len;

                plog_notice(plugin, "电压曲线解析完成: %s.%s, 总数=%d, 有效=%d",
                            group_name, tag_name, td.Nums, valid_count);
            } else if (recv_fn >= 81 && recv_fn <= 88) { // 功率曲线
                // 检查数据长度是否足够包含所有数据点
                size_t expected_data_len = td.Nums * sizeof(Data_Type_9);
                if (remaining_len < expected_data_len) {
                    plog_error(plugin, "数据长度不足: 期望%zu字节, 实际%zu字节",
                               expected_data_len, remaining_len);
                    break;
                }

                // 解析Data_Type_9数组
                Data_Type_9 *data_array  = (Data_Type_9 *) current_pos;
                int          valid_count = 0;

                for (int j = 0; j < td.Nums; j++) {
                    // 计算当前数据点的时间戳
                    time_t current_timestamp = base_time + interval_time * j;

                    // 检查数据有效性
                    if (data_type_9_getflag(&data_array[j])) {
                        float value = data_type_9_getvalue(&data_array[j]);

                        // 格式化时间字符串
                        char       time_str[32];
                        struct tm *tm_info = localtime(&current_timestamp);
                        strftime(time_str, sizeof(time_str),
                                 "%Y-%m-%d %H:%M:%S", tm_info);

                        plog_notice(plugin,
                                    "功率曲线[%d/%d]: %s.%s 时间=%s, 值=%.4f, "
                                    "FN=%u, PN=%u",
                                    j + 1, td.Nums, group_name, tag_name,
                                    time_str, value, fn, pn);

                        // 更新点位状态
                        update_tag_state(plugin, group_name, tag_name,
                                         current_timestamp);

                        valid_count++;
                    } else {
                        plog_debug(plugin, "功率曲线[%d/%d]: 数据无效", j + 1,
                                   td.Nums);
                    }
                }

                current_pos += expected_data_len;
                remaining_len -= expected_data_len;

                plog_notice(plugin, "功率曲线解析完成: %s.%s, 总数=%d, 有效=%d",
                            group_name, tag_name, td.Nums, valid_count);
            } else if (recv_fn >= 92 && recv_fn <= 95) { // 电流曲线 (FN 92-95)
                // 电流曲线处理 - 使用Data_Type_25
                size_t expected_data_len = td.Nums * sizeof(Data_Type_25);
                if (remaining_len < expected_data_len) {
                    plog_error(plugin,
                               "数据长度不足 (电流曲线 FN %u): 期望%zu字节, "
                               "实际%zu字节",
                               recv_fn, expected_data_len, remaining_len);
                    break;
                }

                Data_Type_25 *data_array  = (Data_Type_25 *) current_pos;
                int           valid_count = 0;

                for (int j = 0; j < td.Nums; j++) {
                    time_t current_timestamp = base_time + interval_time * j;

                    if (data_type_25_getflag(
                            &data_array[j])) { // 假设存在 data_type_25_getflag
                        float value = data_type_25_getvalue(
                            &data_array[j]); // 假设存在 data_type_25_getvalue

                        char       time_str[32];
                        struct tm *tm_info = localtime(&current_timestamp);
                        strftime(time_str, sizeof(time_str),
                                 "%Y-%m-%d %H:%M:%S", tm_info);

                        const char *phase_desc = "";
                        switch (recv_fn) {
                        case 92:
                            phase_desc = "A相";
                            break;
                        case 93:
                            phase_desc = "B相";
                            break;
                        case 94:
                            phase_desc = "C相";
                            break;
                        case 95:
                            phase_desc = "零序";
                            break;
                        default:
                            phase_desc = "未知相位";
                            break;
                        }

                        plog_notice(plugin,
                                    "%s电流曲线[%d/%d]: %s.%s 时间=%s, 值=%.3f "
                                    "A, FN=%u, PN=%u",
                                    phase_desc, j + 1, td.Nums, group_name,
                                    tag_name, time_str, value, fn, pn);

                        // 更新点位状态
                        update_tag_state(plugin, group_name, tag_name,
                                         current_timestamp);

                        valid_count++;
                    } else {
                        const char *phase_desc = "";
                        switch (recv_fn) {
                        case 92:
                            phase_desc = "A相";
                            break;
                        case 93:
                            phase_desc = "B相";
                            break;
                        case 94:
                            phase_desc = "C相";
                            break;
                        case 95:
                            phase_desc = "零序";
                            break;
                        default:
                            phase_desc = "未知相位";
                            break;
                        }
                        plog_debug(plugin,
                                   "%s电流曲线[%d/%d]: 数据无效, FN=%u, PN=%u",
                                   phase_desc, j + 1, td.Nums, fn, pn);
                    }
                }

                current_pos += expected_data_len;
                remaining_len -= expected_data_len;

                plog_notice(
                    plugin, "电流曲线解析完成: %s.%s (FN %u), 总数=%d, 有效=%d",
                    group_name, tag_name, recv_fn, td.Nums, valid_count);
            } else if (recv_fn >= 105 &&
                       recv_fn <= 108) { // 功率因数曲线 (FN 105-108)
                // 功率因数曲线处理 - 使用Data_Type_5
                size_t expected_data_len = td.Nums * sizeof(Data_Type_5);
                if (remaining_len < expected_data_len) {
                    plog_error(plugin,
                               "数据长度不足 (功率因数曲线 FN %u): "
                               "期望%zu字节, 实际%zu字节",
                               recv_fn, expected_data_len, remaining_len);
                    break;
                }

                Data_Type_5 *data_array  = (Data_Type_5 *) current_pos;
                int          valid_count = 0;

                for (int j = 0; j < td.Nums; j++) {
                    time_t current_timestamp = base_time + interval_time * j;

                    if (data_type_5_getflag(
                            &data_array[j])) { // 假设存在 data_type_5_getflag
                        float value = data_type_5_getvalue(
                            &data_array[j]); // 假设存在 data_type_5_getvalue

                        char       time_str[32];
                        struct tm *tm_info = localtime(&current_timestamp);
                        strftime(time_str, sizeof(time_str),
                                 "%Y-%m-%d %H:%M:%S", tm_info);

                        const char *desc = "";
                        switch (recv_fn) {
                        case 105:
                            desc = "总";
                            break;
                        case 106:
                            desc = "A相";
                            break;
                        case 107:
                            desc = "B相";
                            break;
                        case 108:
                            desc = "C相";
                            break;
                        default:
                            desc = "未知";
                            break;
                        }

                        plog_notice(plugin,
                                    "%s功率因数曲线[%d/%d]: %s.%s 时间=%s, "
                                    "值=%.3f, FN=%u, PN=%u",
                                    desc, j + 1, td.Nums, group_name, tag_name,
                                    time_str, value, fn, pn);

                        // 更新点位状态
                        update_tag_state(plugin, group_name, tag_name,
                                         current_timestamp);

                        valid_count++;
                    } else {
                        const char *desc = "";
                        switch (recv_fn) {
                        case 105:
                            desc = "总";
                            break;
                        case 106:
                            desc = "A相";
                            break;
                        case 107:
                            desc = "B相";
                            break;
                        case 108:
                            desc = "C相";
                            break;
                        default:
                            desc = "未知";
                            break;
                        }
                        plog_debug(
                            plugin,
                            "%s功率因数曲线[%d/%d]: 数据无效, FN=%u, PN=%u",
                            desc, j + 1, td.Nums, fn, pn);
                    }
                }

                current_pos += expected_data_len;
                remaining_len -= expected_data_len;

                plog_notice(
                    plugin,
                    "功率因数曲线解析完成: %s.%s (FN %u), 总数=%d, 有效=%d",
                    group_name, tag_name, recv_fn, td.Nums, valid_count);
            } else if (recv_fn == 101) { // 正向有功电能示值（总）曲线 (FN 101)
                // 正向有功电能示值（总）曲线处理 - 使用Data_Type_11
                size_t expected_data_len = td.Nums * sizeof(Data_Type_11);
                if (remaining_len < expected_data_len) {
                    plog_error(
                        plugin,
                        "数据长度不足 (FN 101): 期望%zu字节, 实际%zu字节",
                        expected_data_len, remaining_len);
                    break;
                }

                Data_Type_11 *data_array  = (Data_Type_11 *) current_pos;
                int           valid_count = 0;

                for (int j = 0; j < td.Nums; j++) {
                    time_t current_timestamp = base_time +
                        interval_time *
                            j; // interval_time is GetIntervalTime(td.density)

                    if (data_type_11_getflag(
                            &data_array[j])) { // 假设存在 data_type_11_getflag
                        double value = data_type_11_getvalue(
                            &data_array[j]); // 假设存在 data_type_11_getvalue,
                                             // 返回 double

                        char       time_str[32];
                        struct tm *tm_info = localtime(&current_timestamp);
                        strftime(time_str, sizeof(time_str),
                                 "%Y-%m-%d %H:%M:%S", tm_info);

                        plog_notice(plugin,
                                    "正向有功电能总曲线[%d/%d]: %s.%s 时间=%s, "
                                    "值=%.4f kWh, FN=%u, PN=%u",
                                    j + 1, td.Nums, group_name, tag_name,
                                    time_str, value, fn, pn);

                        // 更新点位状态
                        update_tag_state(plugin, group_name, tag_name,
                                         current_timestamp);

                        valid_count++;
                    } else {
                        plog_debug(
                            plugin,
                            "正向有功电能总曲线[%d/%d]: 数据无效, FN=%u, PN=%u",
                            j + 1, td.Nums, fn, pn);
                    }
                }

                current_pos += expected_data_len;
                remaining_len -= expected_data_len;

                plog_notice(plugin,
                            "正向有功电能总曲线解析完成: %s.%s (FN %u), "
                            "总数=%d, 有效=%d",
                            group_name, tag_name, recv_fn, td.Nums,
                            valid_count);
            }

            else if (recv_fn >= 801 &&
                     recv_fn <= 812) { // 扩展版电能数据 (FN 801, 809-812)
                // 扩展版电能数据处理 - 使用Data_Type_39
                size_t expected_data_len = td.Nums * sizeof(Data_Type_39);
                if (remaining_len < expected_data_len) {
                    plog_error(plugin,
                               "数据长度不足 (扩展版电能数据 FN %u): "
                               "期望%zu字节, 实际%zu字节",
                               recv_fn, expected_data_len, remaining_len);
                    break;
                }

                Data_Type_39 *data_array  = (Data_Type_39 *) current_pos;
                int           valid_count = 0;

                for (int j = 0; j < td.Nums; j++) {
                    time_t current_timestamp = base_time + interval_time * j;

                    if (data_type_39_getflag(&data_array[j])) {
                        double value = data_type_39_getvalue(&data_array[j]);

                        char       time_str[32];
                        struct tm *tm_info = localtime(&current_timestamp);
                        strftime(time_str, sizeof(time_str),
                                 "%Y-%m-%d %H:%M:%S", tm_info);

                        const char *tariff_desc = "";
                        switch (recv_fn) {
                        case 801:
                            tariff_desc = "总";
                            break;
                        case 809:
                            tariff_desc = "尖";
                            break;
                        case 810:
                            tariff_desc = "峰";
                            break;
                        case 811:
                            tariff_desc = "平";
                            break;
                        case 812:
                            tariff_desc = "谷";
                            break;
                        default:
                            tariff_desc = "未知费率";
                            break;
                        }

                        plog_notice(plugin,
                                    "扩展版正向有功电能示值（%s）曲线[%d/%d]: "
                                    "%s.%s 时间=%s, 值=%.4f kWh, FN=%u, PN=%u",
                                    tariff_desc, j + 1, td.Nums, group_name,
                                    tag_name, time_str, value, fn, pn);

                        // 更新点位状态
                        update_tag_state(plugin, group_name, tag_name,
                                         current_timestamp);

                        valid_count++;
                    } else {
                        const char *tariff_desc = "";
                        switch (recv_fn) {
                        case 801:
                            tariff_desc = "总";
                            break;
                        case 809:
                            tariff_desc = "尖";
                            break;
                        case 810:
                            tariff_desc = "峰";
                            break;
                        case 811:
                            tariff_desc = "平";
                            break;
                        case 812:
                            tariff_desc = "谷";
                            break;
                        default:
                            tariff_desc = "未知费率";
                            break;
                        }
                        plog_debug(plugin,
                                   "扩展版正向有功电能示值（%s）曲线[%d/%d]: "
                                   "数据无效, FN=%u, PN=%u",
                                   tariff_desc, j + 1, td.Nums, fn, pn);
                    }
                }

                current_pos += expected_data_len;
                remaining_len -= expected_data_len;

                plog_notice(plugin,
                            "扩展版电能示值曲线解析完成: %s.%s (FN %u), "
                            "总数=%d, 有效=%d",
                            group_name, tag_name, recv_fn, td.Nums,
                            valid_count);
            } else if (recv_fn == 900) { // FN 900: 当前有功需量曲线
                // 当前有功需量曲线处理 - 使用Data_Type_9
                size_t expected_data_len = td.Nums * sizeof(Data_Type_9);
                if (remaining_len < expected_data_len) {
                    plog_error(plugin,
                               "数据长度不足 (当前有功需量曲线 FN 900): "
                               "期望%zu字节, 实际%zu字节",
                               expected_data_len, remaining_len);
                    break;
                }

                Data_Type_9 *data_array  = (Data_Type_9 *) current_pos;
                int          valid_count = 0;

                for (int j = 0; j < td.Nums; j++) {
                    time_t current_timestamp = base_time + interval_time * j;

                    if (data_type_9_getflag(&data_array[j])) {
                        float value = data_type_9_getvalue(&data_array[j]);

                        char       time_str[32];
                        struct tm *tm_info = localtime(&current_timestamp);
                        strftime(time_str, sizeof(time_str),
                                 "%Y-%m-%d %H:%M:%S", tm_info);

                        // 需量值以kW为单位
                        plog_notice(plugin,
                                    "当前有功需量曲线[%d/%d]: %s.%s 时间=%s, "
                                    "值=%.4f kW, FN=%u, PN=%u",
                                    j + 1, td.Nums, group_name, tag_name,
                                    time_str, value, fn, pn);

                        // 更新点位状态
                        update_tag_state(plugin, group_name, tag_name,
                                         current_timestamp);

                        valid_count++;
                    } else {
                        plog_debug(plugin, "当前有功需量曲线[%d/%d]: 数据无效",
                                   j + 1, td.Nums);
                    }
                }

                current_pos += expected_data_len;
                remaining_len -= expected_data_len;

                plog_notice(plugin,
                            "当前有功需量曲线解析完成: %s.%s, 总数=%d, 有效=%d",
                            group_name, tag_name, td.Nums, valid_count);
            } else if (recv_fn == 901) { // FN 901: 电网频率曲线
                // 电网频率曲线处理 - 使用Data_Type_6
                size_t expected_data_len = td.Nums * sizeof(Data_Type_6);
                if (remaining_len < expected_data_len) {
                    plog_error(plugin,
                               "数据长度不足 (电网频率曲线 FN 901): "
                               "期望%zu字节, 实际%zu字节",
                               expected_data_len, remaining_len);
                    break;
                }

                Data_Type_6 *data_array  = (Data_Type_6 *) current_pos;
                int          valid_count = 0;

                for (int j = 0; j < td.Nums; j++) {
                    time_t current_timestamp = base_time + interval_time * j;

                    if (data_type_6_getflag(&data_array[j])) {
                        float value = data_type_6_getvalue(&data_array[j]);

                        char       time_str[32];
                        struct tm *tm_info = localtime(&current_timestamp);
                        strftime(time_str, sizeof(time_str),
                                 "%Y-%m-%d %H:%M:%S", tm_info);

                        // 频率值以Hz为单位
                        plog_notice(plugin,
                                    "电网频率曲线[%d/%d]: %s.%s 时间=%s, "
                                    "值=%.3f Hz, FN=%u, PN=%u",
                                    j + 1, td.Nums, group_name, tag_name,
                                    time_str, value, fn, pn);

                        // 更新点位状态
                        update_tag_state(plugin, group_name, tag_name,
                                         current_timestamp);

                        valid_count++;
                    } else {
                        plog_debug(plugin, "电网频率曲线[%d/%d]: 数据无效",
                                   j + 1, td.Nums);
                    }
                }

                current_pos += expected_data_len;
                remaining_len -= expected_data_len;

                plog_notice(plugin,
                            "电网频率曲线解析完成: %s.%s, 总数=%d, 有效=%d",
                            group_name, tag_name, td.Nums, valid_count);
            } else if (recv_fn == 401) { // 水表正向总累积流量曲线 (FN 401)
                // 水表正向总累积流量曲线处理 - 使用Data_Type_38
                size_t expected_data_len = td.Nums * sizeof(Data_Type_38);
                if (remaining_len < expected_data_len) {
                    plog_error(plugin,
                               "数据长度不足 (水表正向总累积流量曲线 FN %u): "
                               "期望%zu字节, 实际%zu字节",
                               recv_fn, expected_data_len, remaining_len);
                    break;
                }

                Data_Type_38 *data_array  = (Data_Type_38 *) current_pos;
                int           valid_count = 0;

                for (int j = 0; j < td.Nums; j++) {
                    time_t current_timestamp = base_time + interval_time * j;

                    if (data_type_38_getflag(&data_array[j])) {
                        float value = data_type_38_getvalue(&data_array[j]);

                        char       time_str[32];
                        struct tm *tm_info = localtime(&current_timestamp);
                        strftime(time_str, sizeof(time_str),
                                 "%Y-%m-%d %H:%M:%S", tm_info);

                        plog_notice(plugin,
                                    "水表正向总累积流量曲线[%d/%d]: %s.%s "
                                    "时间=%s, 值=%.3f, FN=%u, PN=%u",
                                    j + 1, td.Nums, group_name, tag_name,
                                    time_str, value, fn, pn);

                        // 更新点位状态
                        update_tag_state(plugin, group_name, tag_name,
                                         current_timestamp);

                        valid_count++;
                    } else {
                        plog_debug(plugin,
                                   "水表正向总累积流量曲线[%d/%d]: 数据无效",
                                   j + 1, td.Nums);
                    }
                }

                current_pos += expected_data_len;
                remaining_len -= expected_data_len;

                plog_notice(
                    plugin,
                    "水表正向总累积流量曲线解析完成: %s.%s, 总数=%d, 有效=%d",
                    group_name, tag_name, td.Nums, valid_count);
            }

            else if (recv_fn == 402) { // 水表压力曲线 (FN 402)
                // 水表压力曲线处理 - 使用Data_Type_37
                size_t expected_data_len = td.Nums * sizeof(Data_Type_37);
                if (remaining_len < expected_data_len) {
                    plog_error(plugin,
                               "数据长度不足 (水表压力曲线 FN %u): "
                               "期望%zu字节, 实际%zu字节",
                               recv_fn, expected_data_len, remaining_len);
                    break;
                }

                Data_Type_37 *data_array  = (Data_Type_37 *) current_pos;
                int           valid_count = 0;

                for (int j = 0; j < td.Nums; j++) {
                    time_t current_timestamp = base_time + interval_time * j;

                    if (data_type_37_getflag(&data_array[j])) {
                        float value = data_type_37_getvalue(&data_array[j]);

                        char       time_str[32];
                        struct tm *tm_info = localtime(&current_timestamp);
                        strftime(time_str, sizeof(time_str),
                                 "%Y-%m-%d %H:%M:%S", tm_info);

                        plog_notice(plugin,
                                    "水表压力曲线[%d/%d]: %s.%s 时间=%s, "
                                    "值=%.3f, FN=%u, PN=%u",
                                    j + 1, td.Nums, group_name, tag_name,
                                    time_str, value, fn, pn);

                        // 更新点位状态
                        update_tag_state(plugin, group_name, tag_name,
                                         current_timestamp);

                        valid_count++;
                    } else {
                        plog_debug(plugin, "水表压力曲线[%d/%d]: 数据无效",
                                   j + 1, td.Nums);
                    }
                }

                current_pos += expected_data_len;
                remaining_len -= expected_data_len;

                plog_notice(plugin,
                            "水表压力曲线解析完成: %s.%s, 总数=%d, 有效=%d",
                            group_name, tag_name, td.Nums, valid_count);
            } else if (recv_fn == 502 ||
                       recv_fn == 503) { // 气表压力和温度曲线 (FN 502-503)
                // 气表压力和温度曲线处理 - 使用Data_Type_37 ✅ 正确数据类型
                size_t expected_data_len = td.Nums * sizeof(Data_Type_37);
                if (remaining_len < expected_data_len) {
                    plog_error(plugin,
                               "数据长度不足 (气表曲线 FN %u): "
                               "期望%zu字节, 实际%zu字节",
                               recv_fn, expected_data_len, remaining_len);
                    break;
                }

                Data_Type_37 *data_array  = (Data_Type_37 *) current_pos;
                int           valid_count = 0;

                for (int j = 0; j < td.Nums; j++) {
                    time_t current_timestamp = base_time + interval_time * j;

                    if (data_type_37_getflag(
                            &data_array[j])) { // ✅ 对应您C++代码的getflag()
                        float value = data_type_37_getvalue(
                            &data_array[j]); // ✅ 对应您C++代码的getvalue()

                        char       time_str[32];
                        struct tm *tm_info = localtime(&current_timestamp);
                        strftime(time_str, sizeof(time_str),
                                 "%Y-%m-%d %H:%M:%S", tm_info);

                        const char *curve_type = (recv_fn == 502)
                            ? "气表压力"
                            : "气表温度"; // ✅ 正确区分

                        plog_notice(plugin,
                                    "%s曲线[%d/%d]: %s.%s 时间=%s, 值=%.3f, "
                                    "FN=%u, PN=%u",
                                    curve_type, j + 1, td.Nums, group_name,
                                    tag_name, time_str, value, fn, pn);

                        // 更新点位状态
                        update_tag_state(plugin, group_name, tag_name,
                                         current_timestamp);

                        valid_count++;
                    } else {
                        const char *curve_type =
                            (recv_fn == 502) ? "气表压力" : "气表温度";
                        plog_debug(plugin, "%s曲线[%d/%d]: 数据无效",
                                   curve_type, j + 1, td.Nums);
                    }
                }

                current_pos +=
                    expected_data_len; // ✅ 对应您C++代码的 i +=
                                       // sizeof(Data_Type_37) * td.Nums
                remaining_len -= expected_data_len;

                const char *curve_type =
                    (recv_fn == 502) ? "气表压力" : "气表温度";
                plog_notice(plugin, "%s曲线解析完成: %s.%s, 总数=%d, 有效=%d",
                            curve_type, group_name, tag_name, td.Nums,
                            valid_count);
            } else if (recv_fn == 504 ||
                       recv_fn == 505) { // 气表瞬时流量曲线 (FN 504-505)
                // 气表瞬时流量曲线处理 - 使用Data_Type_29 ✅ 正确数据类型
                size_t expected_data_len = td.Nums * sizeof(Data_Type_29);
                if (remaining_len < expected_data_len) {
                    plog_error(plugin,
                               "数据长度不足 (气表瞬时流量曲线 FN %u): "
                               "期望%zu字节, 实际%zu字节",
                               recv_fn, expected_data_len, remaining_len);
                    break;
                }

                Data_Type_29 *data_array  = (Data_Type_29 *) current_pos;
                int           valid_count = 0;

                for (int j = 0; j < td.Nums; j++) {
                    time_t current_timestamp = base_time + interval_time * j;

                    if (data_type_29_getflag(
                            &data_array[j])) { // ✅ 对应您C++代码的getflag()
                        float value = data_type_29_getvalue(
                            &data_array[j]); // ✅ 对应您C++代码的getvalue()

                        char       time_str[32];
                        struct tm *tm_info = localtime(&current_timestamp);
                        strftime(time_str, sizeof(time_str),
                                 "%Y-%m-%d %H:%M:%S", tm_info);

                        // ✅ 正确对应您C++代码的标况/工况区分
                        const char *flow_type = (recv_fn == 504)
                            ? "气表标况瞬时流量"
                            : "气表工况瞬时流量";

                        plog_notice(plugin,
                                    "%s曲线[%d/%d]: %s.%s 时间=%s, 值=%.3f, "
                                    "FN=%u, PN=%u",
                                    flow_type, j + 1, td.Nums, group_name,
                                    tag_name, time_str, value, fn, pn);

                        // 更新点位状态
                        update_tag_state(plugin, group_name, tag_name,
                                         current_timestamp);

                        valid_count++;
                    } else {
                        const char *flow_type = (recv_fn == 504)
                            ? "气表标况瞬时流量"
                            : "气表工况瞬时流量";
                        plog_debug(plugin, "%s曲线[%d/%d]: 数据无效", flow_type,
                                   j + 1, td.Nums);
                    }
                }

                current_pos +=
                    expected_data_len; // ✅ 对应您C++代码的 i +=
                                       // sizeof(Data_Type_29) * td.Nums
                remaining_len -= expected_data_len;

                const char *flow_type =
                    (recv_fn == 504) ? "气表标况瞬时流量" : "气表工况瞬时流量";
                plog_notice(plugin, "%s曲线解析完成: %s.%s, 总数=%d, 有效=%d",
                            flow_type, group_name, tag_name, td.Nums,
                            valid_count);
            } else if (recv_fn == 506 ||
                       recv_fn == 507) { // 气表累积流量曲线 (FN 506-507)
                // 气表累积流量曲线处理 - 使用Data_Type_38
                size_t expected_data_len = td.Nums * sizeof(Data_Type_38);
                if (remaining_len < expected_data_len) {
                    plog_error(plugin,
                               "数据长度不足 (气表累积流量曲线 FN %u): "
                               "期望%zu字节, 实际%zu字节",
                               recv_fn, expected_data_len, remaining_len);
                    break;
                }

                Data_Type_38 *data_array  = (Data_Type_38 *) current_pos;
                int           valid_count = 0;

                for (int j = 0; j < td.Nums; j++) {
                    time_t current_timestamp = base_time + interval_time * j;

                    if (data_type_38_getflag(
                            &data_array[j])) { // ✅ 对应您C++代码的getflag()
                        float value = data_type_38_getvalue(
                            &data_array[j]); // ✅ 对应您C++代码的getvalue()

                        char       time_str[32];
                        struct tm *tm_info = localtime(&current_timestamp);
                        strftime(time_str, sizeof(time_str),
                                 "%Y-%m-%d %H:%M:%S", tm_info);

                        // ✅ 正确区分标况累积流量和工况累积流量
                        const char *flow_type = (recv_fn == 506)
                            ? "气表标况累积流量"
                            : "气表工况累积流量";

                        plog_notice(plugin,
                                    "%s曲线[%d/%d]: %s.%s 时间=%s, 值=%.6f, "
                                    "FN=%u, PN=%u",
                                    flow_type, j + 1, td.Nums, group_name,
                                    tag_name, time_str, value, fn, pn);

                        // 更新点位状态
                        update_tag_state(plugin, group_name, tag_name,
                                         current_timestamp);

                        valid_count++;
                    } else {
                        const char *flow_type = (recv_fn == 506)
                            ? "气表标况累积流量"
                            : "气表工况累积流量";
                        plog_debug(plugin, "%s曲线[%d/%d]: 数据无效", flow_type,
                                   j + 1, td.Nums);
                    }
                }

                current_pos +=
                    expected_data_len; // ✅ 对应您C++代码的 i +=
                                       // sizeof(Data_Type_38) * td.Nums
                remaining_len -= expected_data_len;

                const char *flow_type =
                    (recv_fn == 506) ? "气表标况累积流量" : "气表工况累积流量";
                plog_notice(plugin, "%s曲线解析完成: %s.%s, 总数=%d, 有效=%d",
                            flow_type, group_name, tag_name, td.Nums,
                            valid_count);
            }

            else if (recv_fn == 607 ||
                     recv_fn == 608) { // 热表进水/回水温度曲线 (FN 607-608)
                // 热表温度曲线处理 - 使用Data_Type_36
                size_t expected_data_len = td.Nums * sizeof(Data_Type_36);
                if (remaining_len < expected_data_len) {
                    plog_error(plugin,
                               "数据长度不足 (热表温度曲线 FN %u): "
                               "期望%zu字节, 实际%zu字节",
                               recv_fn, expected_data_len, remaining_len);
                    break;
                }

                Data_Type_36 *data_array  = (Data_Type_36 *) current_pos;
                int           valid_count = 0;

                for (int j = 0; j < td.Nums; j++) {
                    time_t current_timestamp = base_time + interval_time * j;

                    if (data_type_36_getflag(
                            &data_array[j])) { // ✅ 对应您C++代码的getflag()
                        float value = data_type_36_getvalue(
                            &data_array[j]); // ✅ 对应您C++代码的getvalue()

                        char       time_str[32];
                        struct tm *tm_info = localtime(&current_timestamp);
                        strftime(time_str, sizeof(time_str),
                                 "%Y-%m-%d %H:%M:%S", tm_info);

                        // ✅ 正确区分进水温度和回水温度
                        const char *temp_type =
                            (recv_fn == 607) ? "热表进水温度" : "热表回水温度";

                        plog_notice(plugin,
                                    "%s曲线[%d/%d]: %s.%s 时间=%s, 值=%.2f℃, "
                                    "FN=%u, PN=%u",
                                    temp_type, j + 1, td.Nums, group_name,
                                    tag_name, time_str, value, fn, pn);

                        // 更新点位状态
                        update_tag_state(plugin, group_name, tag_name,
                                         current_timestamp);

                        valid_count++;
                    } else {
                        const char *temp_type =
                            (recv_fn == 607) ? "热表进水温度" : "热表回水温度";
                        plog_debug(plugin, "%s曲线[%d/%d]: 数据无效", temp_type,
                                   j + 1, td.Nums);
                    }
                }

                current_pos +=
                    expected_data_len; // ✅ 对应您C++代码的 i +=
                                       // sizeof(Data_Type_36) * td.Nums
                remaining_len -= expected_data_len;

                const char *temp_type =
                    (recv_fn == 607) ? "热表进水温度" : "热表回水温度";
                plog_notice(plugin, "%s曲线解析完成: %s.%s, 总数=%d, 有效=%d",
                            temp_type, group_name, tag_name, td.Nums,
                            valid_count);
            } else if (recv_fn == 610) { // 热表瞬时流量曲线 (FN 610)
                // 热表瞬时流量曲线处理 - 使用Data_Type_29
                size_t expected_data_len = td.Nums * sizeof(Data_Type_29);
                if (remaining_len < expected_data_len) {
                    plog_error(plugin,
                               "数据长度不足 (热表瞬时流量曲线 FN %u): "
                               "期望%zu字节, 实际%zu字节",
                               recv_fn, expected_data_len, remaining_len);
                    break;
                }

                Data_Type_29 *data_array  = (Data_Type_29 *) current_pos;
                int           valid_count = 0;

                for (int j = 0; j < td.Nums; j++) {
                    time_t current_timestamp = base_time + interval_time * j;

                    if (data_type_29_getflag(
                            &data_array[j])) { // ✅ 对应您C++代码的getflag()
                        float value = data_type_29_getvalue(
                            &data_array[j]); // ✅ 对应您C++代码的getvalue()

                        char       time_str[32];
                        struct tm *tm_info = localtime(&current_timestamp);
                        strftime(time_str, sizeof(time_str),
                                 "%Y-%m-%d %H:%M:%S", tm_info);

                        plog_notice(plugin,
                                    "热表瞬时流量曲线[%d/%d]: %s.%s 时间=%s, "
                                    "值=%.3f, FN=%u, PN=%u",
                                    j + 1, td.Nums, group_name, tag_name,
                                    time_str, value, fn, pn);

                        // 更新点位状态
                        update_tag_state(plugin, group_name, tag_name,
                                         current_timestamp);

                        valid_count++;
                    } else {
                        plog_debug(plugin, "热表瞬时流量曲线[%d/%d]: 数据无效",
                                   j + 1, td.Nums);
                    }
                }

                current_pos +=
                    expected_data_len; // ✅ 对应您C++代码的 i +=
                                       // sizeof(Data_Type_29) * td.Nums
                remaining_len -= expected_data_len;

                plog_notice(plugin,
                            "热表瞬时流量曲线解析完成: %s.%s, 总数=%d, 有效=%d",
                            group_name, tag_name, td.Nums, valid_count);
            } else if (recv_fn == 611) { // 热量表正向总累积热量曲线 (FN 611)
                // 热量表正向总累积热量曲线处理 - 使用Data_Type_38
                size_t expected_data_len = td.Nums * sizeof(Data_Type_38);
                if (remaining_len < expected_data_len) {
                    plog_error(plugin,
                               "数据长度不足 (热量表累积热量曲线 FN 611): "
                               "期望%zu字节, 实际%zu字节",
                               expected_data_len, remaining_len);
                    break;
                }

                Data_Type_38 *data_array  = (Data_Type_38 *) current_pos;
                int           valid_count = 0;

                for (int j = 0; j < td.Nums; j++) {
                    time_t current_timestamp = base_time + interval_time * j;

                    if (data_type_38_getflag(&data_array[j])) {
                        float value = data_type_38_getvalue(&data_array[j]);

                        char       time_str[32];
                        struct tm *tm_info = localtime(&current_timestamp);
                        strftime(time_str, sizeof(time_str),
                                 "%Y-%m-%d %H:%M:%S", tm_info);

                        plog_notice(plugin,
                                    "热量表正向总累积热量曲线[%d/%d]: %s.%s "
                                    "时间=%s, 值=%.6f, FN=%u, PN=%u",
                                    j + 1, td.Nums, group_name, tag_name,
                                    time_str, value, fn, pn);

                        // 更新点位状态
                        update_tag_state(plugin, group_name, tag_name,
                                         current_timestamp);
                        valid_count++;
                    } else {
                        plog_debug(plugin,
                                   "热量表正向总累积热量曲线[%d/%d]: 数据无效",
                                   j + 1, td.Nums);
                    }
                }

                current_pos += expected_data_len;
                remaining_len -= expected_data_len;

                plog_notice(
                    plugin,
                    "热量表正向总累积热量曲线解析完成: %s.%s, 总数=%d, 有效=%d",
                    group_name, tag_name, td.Nums, valid_count);

            } else if (recv_fn == 612) { // 热量表正向总累积流量曲线 (FN 612)
                // 热量表正向总累积流量曲线处理 - 使用Data_Type_38
                size_t expected_data_len = td.Nums * sizeof(Data_Type_38);
                if (remaining_len < expected_data_len) {
                    plog_error(plugin,
                               "数据长度不足 (热量表累积流量曲线 FN 612): "
                               "期望%zu字节, 实际%zu字节",
                               expected_data_len, remaining_len);
                    break;
                }

                Data_Type_38 *data_array  = (Data_Type_38 *) current_pos;
                int           valid_count = 0;

                for (int j = 0; j < td.Nums; j++) {
                    time_t current_timestamp = base_time + interval_time * j;

                    if (data_type_38_getflag(&data_array[j])) {
                        float value = data_type_38_getvalue(&data_array[j]);

                        char       time_str[32];
                        struct tm *tm_info = localtime(&current_timestamp);
                        strftime(time_str, sizeof(time_str),
                                 "%Y-%m-%d %H:%M:%S", tm_info);

                        plog_notice(plugin,
                                    "热量表正向总累积流量曲线[%d/%d]: %s.%s "
                                    "时间=%s, 值=%.6f, FN=%u, PN=%u",
                                    j + 1, td.Nums, group_name, tag_name,
                                    time_str, value, fn, pn);

                        // 更新点位状态
                        update_tag_state(plugin, group_name, tag_name,
                                         current_timestamp);
                        valid_count++;
                    } else {
                        plog_debug(plugin,
                                   "热量表正向总累积流量曲线[%d/%d]: 数据无效",
                                   j + 1, td.Nums);
                    }
                }

                current_pos += expected_data_len;
                remaining_len -= expected_data_len;

                plog_notice(
                    plugin,
                    "热量表正向总累积流量曲线解析完成: %s.%s, 总数=%d, 有效=%d",
                    group_name, tag_name, td.Nums, valid_count);
            } else if (recv_fn >= 710 &&
                       recv_fn <= 721) { // RTU曲线数据 (FN 710-721)
                // RTU曲线数据处理 - 统一使用Data_Type_40

                uint16_t data_type_index =
                    recv_fn - 710; // 0-11对应Data0-Data11

                plog_notice(plugin,
                            "RTU曲线数据解析开始: %s.%s, FN=%u (Data%u曲线), "
                            "PN=%u, 数量=%d",
                            group_name, tag_name, recv_fn, data_type_index,
                            recv_pn, td.Nums);

                // 所有RTU曲线数据都使用Data_Type_40
                size_t expected_data_len = td.Nums * sizeof(Data_Type_40);
                if (remaining_len < expected_data_len) {
                    plog_error(plugin,
                               "数据长度不足 (RTU Data%u曲线 FN %u): "
                               "期望%zu字节, 实际%zu字节",
                               data_type_index, recv_fn, expected_data_len,
                               remaining_len);
                    break;
                }

                Data_Type_40 *data_array  = (Data_Type_40 *) current_pos;
                int           valid_count = 0;

                // 参考您的C++代码计算时间和处理数据
                for (int j = 0; j < td.Nums; j++) {
                    int interval_time =
                        get_interval_seconds_from_density(td.density);
                    time_t current_timestamp = base_time + interval_time * j;

                    if (data_type_40_getflag(&data_array[j])) {
                        double value = (double) data_type_40_getvalue(
                            &data_array[j]); // ← 修正：使用double

                        char       time_str[32];
                        struct tm *tm_info = localtime(&current_timestamp);
                        strftime(time_str, sizeof(time_str),
                                 "%Y-%m-%d %H:%M:%S", tm_info);

                        plog_notice(
                            plugin,
                            "RTU Data%u曲线[%d/%d]: %s.%s 时间=%s, 值=%.6f, "
                            "FN=%u, PN=%u", // ← %.6f适用于double
                            data_type_index, j + 1, td.Nums, group_name,
                            tag_name, time_str, value, recv_fn, recv_pn);

                        // 更新点位状态
                        update_tag_state(plugin, group_name, tag_name,
                                         current_timestamp);
                        valid_count++;
                    } else {
                        plog_debug(plugin, "RTU Data%u曲线[%d/%d]: 数据无效",
                                   data_type_index, j + 1, td.Nums);
                    }
                }

                current_pos +=
                    expected_data_len; // 对应您C++代码的 i +=
                                       // sizeof(Data_Type_40) * td.Nums
                remaining_len -= expected_data_len;

                plog_notice(plugin,
                            "RTU Data%u曲线解析完成: %s.%s, 总数=%d, 有效=%d",
                            data_type_index, group_name, tag_name, td.Nums,
                            valid_count);
            }
        }

        break; // 处理完一个数据单元就退出
    }

    return 0;
}
/**
 * @brief 为特定组生成历史召测任务，直接从组的标签信息获取地址
 */
static void generate_polling_tasks_for_group(neu_plugin_t *      plugin,
                                             neu_plugin_group_t *group)
{
    if (!plugin->polling_enabled || !group)
        return;

    time_t      now                   = time(NULL);
    time_t      before_time           = now - plugin->current_before_time_sec;
    int         total_tasks_generated = 0;
    const char *group_name            = get_safe_group_name(group);

    // 检查是否是召测配置中的组
    bool is_polling_group = false;
    if (plugin->polling_groups) {
        for (int i = 0; i < plugin->polling_group_count; i++) {
            if (strcmp(plugin->polling_groups[i].group, group_name) == 0) {
                is_polling_group = true;
                break;
            }
        }
    }

    if (!is_polling_group) {
        plog_debug(plugin, "组 '%s' 未配置历史召测，跳过", group_name);
        return;
    }

    // 遍历组内所有标签
    utarray_foreach(group->tags, neu_datatag_t *, tag)
    {
        // 检查标签是否在召测配置中
        bool is_polling_tag = false;
        if (plugin->polling_groups) {
            for (int i = 0; i < plugin->polling_group_count; i++) {
                if (strcmp(plugin->polling_groups[i].group, group_name) == 0) {
                    for (int j = 0; j < plugin->polling_groups[i].tag_count;
                         j++) {
                        if (plugin->polling_groups[i].tags[j] &&
                            strcmp(plugin->polling_groups[i].tags[j],
                                   tag->name) == 0) {
                            is_polling_tag = true;
                            break;
                        }
                    }
                    break;
                }
            }
        }

        if (!is_polling_tag) {
            continue; // 跳过未配置召测的标签
        }

        tag_state_t *state = NULL;
        if (get_tag_state(plugin, group_name, tag->name, &state) != 0)
            continue;

        time_t last_poll   = state->last_polled_historical_time;
        time_t last_update = state->last_update_time;

        // 如果已经采集到最新数据，则跳过
        if (before_time <= last_poll)
            continue;

        // 计算召测起始时间（最多补一天的数据）
        time_t start_time = last_poll > 0 ? last_poll : before_time - 24 * 3600;
        if (before_time - start_time > 24 * 3600) {
            start_time = before_time - 24 * 3600;
        }

        // 以5分钟为步长，逐条生成召测任务
        for (time_t t = start_time; t < before_time; t += POLL_INTERVAL_SEC) {
            time_t task_end = t + POLL_INTERVAL_SEC;
            if (task_end > before_time)
                task_end = before_time;

            // 只召测未更新到的数据
            if (task_end <= last_update)
                continue;

            // 创建召测任务并加入队列
            polling_task_t new_task = { 0 };
            strncpy(new_task.group_name, group_name, NEU_GROUP_NAME_LEN - 1);
            strncpy(new_task.tag_name, tag->name, NEU_TAG_NAME_LEN - 1);
            strncpy(new_task.tag_address, tag->address,
                    NEU_TAG_ADDRESS_LEN - 1); // 直接获取标签地址！
            new_task.start_time  = t;
            new_task.end_time    = task_end;
            new_task.retry_count = 0;

            pthread_mutex_lock(&plugin->polling_task_mutex);

            // 检查队列长度限制（防止队列过大）
            const unsigned int max_queue_size = 221184; //≈ 63.7 MB
            if (utarray_len(plugin->polling_tasks) >= max_queue_size) {
                plog_warn(plugin, "召测任务队列已满(%u个)，丢弃最早的任务",
                          max_queue_size);
                utarray_erase(plugin->polling_tasks, 0, 1);
            }

            // 添加新任务到队列
            utarray_push_back(plugin->polling_tasks, &new_task);
            total_tasks_generated++;

            pthread_mutex_unlock(&plugin->polling_task_mutex);

            // 立即推进断点，防止重复生成
            state->last_polled_historical_time = task_end;
            state->dirty                       = true;
        }
    }

    if (total_tasks_generated > 0) {
        plog_notice(plugin, "组 '%s' 生成召测任务: %d个, 当前队列总数: %u个",
                    group_name, total_tasks_generated,
                    (unsigned) utarray_len(plugin->polling_tasks));
    }
}

// ===== 组级时间戳管理函数实现 =====

/**
 * @brief 检查是否应该为指定组生成召测任务
 * @param plugin 插件实例
 * @param group_name 组名
 * @return true 应该生成任务，false 不应该生成任务
 */
static bool should_generate_polling_tasks(neu_plugin_t *plugin,
                                          const char *  group_name)
{
    if (!plugin || !group_name) {
        return false;
    }

    time_t       now              = time(NULL);
    const time_t polling_interval = 60; // 60秒间隔

    pthread_mutex_lock(&plugin->group_polling_time_mutex);

    // 查找组的时间戳记录
    group_polling_time_t *group_time = NULL;
    HASH_FIND_STR(plugin->group_polling_times, group_name, group_time);

    bool should_generate = false;

    if (!group_time) {
        // 第一次调用，创建新记录
        group_time = calloc(1, sizeof(group_polling_time_t));
        if (group_time) {
            strncpy(group_time->group_name, group_name, NEU_GROUP_NAME_LEN - 1);
            group_time->last_polling_time = now;
            HASH_ADD_STR(plugin->group_polling_times, group_name, group_time);
            should_generate = true;
            plog_debug(plugin, "组 '%s' 首次召测任务生成", group_name);
        }
    } else {
        // 检查时间间隔
        if (now - group_time->last_polling_time >= polling_interval) {
            group_time->last_polling_time = now;
            should_generate               = true;
            plog_debug(plugin, "组 '%s' 满足时间间隔，生成召测任务",
                       group_name);
        } else {
            plog_debug(
                plugin,
                "组 '%s' 时间间隔不足，跳过召测任务生成 (距离上次 %ld 秒)",
                group_name, now - group_time->last_polling_time);
        }
    }

    pthread_mutex_unlock(&plugin->group_polling_time_mutex);
    return should_generate;
}

/**
 * @brief 清理组级时间戳哈希表
 * @param plugin 插件实例
 */
static void cleanup_group_polling_times(neu_plugin_t *plugin)
{
    if (!plugin) {
        return;
    }

    pthread_mutex_lock(&plugin->group_polling_time_mutex);

    group_polling_time_t *current, *tmp;
    HASH_ITER(hh, plugin->group_polling_times, current, tmp)
    {
        HASH_DEL(plugin->group_polling_times, current);
        free(current);
    }
    plugin->group_polling_times = NULL;

    pthread_mutex_unlock(&plugin->group_polling_time_mutex);
    plog_debug(plugin, "组级时间戳哈希表已清理");
}

static const size_t static_fn_mappings_size =
    sizeof(static_fn_mappings) / sizeof(static_fn_mapping_t);

/**
 * @brief 初始化FN映射哈希表
 * @return 0成功，-1失败
 */
static int init_fn_mapping_hash(neu_plugin_t *plugin)
{
    if (!plugin)
        return -1;

    pthread_mutex_lock(&plugin->fn_mapping_mutex);

    if (plugin->fn_mapping_initialized) {
        pthread_mutex_unlock(&plugin->fn_mapping_mutex);
        return 0;
    }

    // 清理现有哈希表
    fn_mapping_entry_t *entry, *tmp;
    HASH_ITER(hh, plugin->fn_mapping_hash, entry, tmp)
    {
        HASH_DEL(plugin->fn_mapping_hash, entry);
        free(entry);
    }
    plugin->fn_mapping_hash = NULL;

    // 初始化哈希表
    for (size_t i = 0; i < static_fn_mappings_size; i++) {
        fn_mapping_entry_t *entry = malloc(sizeof(fn_mapping_entry_t));
        if (!entry) {
            pthread_mutex_unlock(&plugin->fn_mapping_mutex);
            plog_error(plugin, "分配FN映射条目内存失败");
            return -1;
        }

        strncpy(entry->key.tag_name, static_fn_mappings[i].tag_name,
                NEU_TAG_NAME_LEN - 1);
        entry->key.tag_name[NEU_TAG_NAME_LEN - 1] = '\0';
        entry->key.realtime_fn = static_fn_mappings[i].realtime_fn;
        entry->historical_fn   = static_fn_mappings[i].historical_fn;
        entry->description     = static_fn_mappings[i].description;

        HASH_ADD(hh, plugin->fn_mapping_hash, key, sizeof(fn_mapping_key_t),
                 entry);
    }

    plugin->fn_mapping_initialized = true;
    pthread_mutex_unlock(&plugin->fn_mapping_mutex);

    plog_debug(plugin, "实例级FN映射哈希表初始化完成，条目数量: %zu",
               static_fn_mappings_size);
    return 0;
}

static uint16_t get_historical_fn_from_tag_and_fn(neu_plugin_t *plugin,
                                                  const char *  tag_name,
                                                  uint16_t      realtime_fn)
{
    if (!plugin || !tag_name) {
        return 0;
    }

    // ===== RTU标签特殊处理提醒 =====
    if (is_rtu_tag(tag_name)) {
        // RTU标签需要使用专用函数，需要组名信息
        plog_warn(
            plugin,
            "RTU标签 '%s' 需要使用 get_rtu_historical_fn 函数，需要组名信息",
            tag_name);
        return 0; // 返回0，提醒调用者使用专用函数
    }

    // 确保映射表已初始化
    if (!plugin->fn_mapping_initialized) {
        if (init_fn_mapping_hash(plugin) != 0) {
            plog_error(plugin, "初始化FN映射表失败");
            return 0;
        }
    }
    // ===== 普通标签使用静态映射表 =====
    pthread_mutex_lock(&plugin->fn_mapping_mutex);

    // 创建查询键
    fn_mapping_key_t key;
    strncpy(key.tag_name, tag_name, NEU_TAG_NAME_LEN - 1);
    key.tag_name[NEU_TAG_NAME_LEN - 1] = '\0';
    key.realtime_fn                    = realtime_fn;

    // 查找映射
    fn_mapping_entry_t *entry = NULL;
    HASH_FIND(hh, plugin->fn_mapping_hash, &key, sizeof(fn_mapping_key_t),
              entry);

    uint16_t historical_fn = 0;
    if (entry) {
        historical_fn = entry->historical_fn;
        plog_debug(plugin, "标签映射: %s(F%u) -> F%u (%s)", tag_name,
                   realtime_fn, historical_fn, entry->description);
    } else {
        plog_warn(plugin, "未找到标签 '%s' + 实时FN=%u 的历史映射", tag_name,
                  realtime_fn);
    }

    pthread_mutex_unlock(&plugin->fn_mapping_mutex);
    return historical_fn;
}

/**
 * @brief 获取映射的描述信息（高效版本）
 * @param tag_name 标签名称
 * @param realtime_fn 实时功能码
 * @return 映射描述字符串，如果没有映射则返回NULL
 */
static const char *get_fn_mapping_description(neu_plugin_t *plugin,
                                              const char *  tag_name,
                                              uint16_t      realtime_fn)
{
    if (!plugin || !tag_name) {
        return "参数无效";
    }

    // 确保映射表已初始化
    if (!plugin->fn_mapping_initialized) {
        if (init_fn_mapping_hash(plugin) != 0) {
            return "映射表初始化失败";
        }
    }

    // 构造查找键
    fn_mapping_key_t search_key;
    strncpy(search_key.tag_name, tag_name, sizeof(search_key.tag_name) - 1);
    search_key.tag_name[sizeof(search_key.tag_name) - 1] = '\0';
    search_key.realtime_fn                               = realtime_fn;

    // 在哈希表中查找
    fn_mapping_entry_t *entry = NULL;

    pthread_mutex_lock(&plugin->fn_mapping_mutex);
    HASH_FIND(hh, plugin->fn_mapping_hash, &search_key,
              sizeof(fn_mapping_key_t), entry);
    pthread_mutex_unlock(&plugin->fn_mapping_mutex);

    if (entry && entry->description) {
        return entry->description;
    } else {
        return "无映射描述";
    }
}

/**
 * @brief 清理FN映射哈希表
 */
static void cleanup_fn_mapping_hash(neu_plugin_t *plugin)
{
    if (!plugin)
        return;

    pthread_mutex_lock(&plugin->fn_mapping_mutex);

    fn_mapping_entry_t *entry, *tmp;
    HASH_ITER(hh, plugin->fn_mapping_hash, entry, tmp)
    {
        HASH_DEL(plugin->fn_mapping_hash, entry);
        free(entry);
    }
    plugin->fn_mapping_hash        = NULL;
    plugin->fn_mapping_initialized = false;

    pthread_mutex_unlock(&plugin->fn_mapping_mutex);

    plog_debug(plugin, "实例级FN映射哈希表清理完成");
}

static int get_interval_seconds_from_density(uint8_t density)
{
    switch (density) {
    case 1:
        return 15 * 60;
        break;
    case 2:
        return 30 * 60;
        break;
    case 3:
        return 60 * 60;
        break;
    case 254:
        return 5 * 60;
        break;
    case 255:
        return 1 * 60;
        break;
    default:
        return 0;
        break;
    }
    return 0;
}
