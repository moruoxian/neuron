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

#ifndef GB_12241_POINT_H
#define GB_12241_POINT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

struct neu_plugin;
typedef struct neu_plugin neu_plugin_t;

/* 基本数据类型定义 */
#ifndef BYTE
#define BYTE uint8_t
#endif

#ifndef WORD
#define WORD uint16_t
#endif

#ifndef DWORD
#define DWORD uint32_t
#endif

// 在头文件中使用不透明指针
struct neu_plugin;
typedef struct neu_plugin neu_plugin_t;

#ifdef __cplusplus
extern "C" {
#endif

/* GB/T 12241协议数据类型 */
#define DATA_TYPE_5 5   /* 符号XXX.X格式浮点 */
#define DATA_TYPE_6 6   /* 符号XX.XX格式浮点 */
#define DATA_TYPE_7 7   /* XXX.X格式浮点 */
#define DATA_TYPE_8 8   /* XXXX格式整数 */
#define DATA_TYPE_9 9   /* 符号XX.XXXX格式浮点 */
#define DATA_TYPE_11 11 /* XXXXXX.XX格式浮点 */
#define DATA_TYPE_14 14 /* XXXXXX.XXXX格式浮点 */
#define DATA_TYPE_23 23 /* XX.XXXX格式浮点 */
#define DATA_TYPE_25 25 /* 符号XXX.XXX格式浮点 */

/* 复合数据类型 */
#define DATA_TYPE_F25 101  /* 当前三相及总有功功率等 */
#define DATA_TYPE_F28 102  /* 电表运行状态字 */
#define DATA_TYPE_F129 103 /* 当前正向有功电能示值 */
#define DATA_TYPE_F130 104 /* 当前正向无功电能示值 */
#define DATA_TYPE_F131 105 /* 当前反向有功电能示值 */
#define DATA_TYPE_F132 106 /* 当前反向无功电能示值 */
#define DATA_TYPE_F145 107 /* 当月正向有功最大需量及发生时间 */
#define DATA_TYPE_F146 108 /* 当月正向无功最大需量及发生时间 */
#define DATA_TYPE_F147 109 /* 当月反向有功最大需量及发生时间 */
#define DATA_TYPE_F148 110 /* 当月反向无功最大需量及发生时间 */
#define DATA_TYPE_F161 111 /* 正向有功日冻结 */
#define DATA_TYPE_F162 112 /* 正向无功日冻结 */
#define DATA_TYPE_F163 113 /* 反向有功日冻结 */
#define DATA_TYPE_F164 114 /* 反向无功日冻结 */

/* 新增类型 - 电表扩展 */
#define DATA_TYPE_F900 120 /* 有功最大需量 */
#define DATA_TYPE_F901 121 /* 电网频率 */
#define DATA_TYPE_F801 122 /* 扩展精度电度曲线 */

/* 新增类型 - 水表 */
#define DATA_TYPE_F402 130 /* 水表运行状态 */
#define DATA_TYPE_ONE_F402 131 /* 一类数据F402:水表运行状态字及其变位标志 */
#define DATA_TYPE_F403 132 /* 水表流速及压力 */
#define DATA_TYPE_F404 133 /* 水表累积流量 */

/* 新增类型 - 气表 */
#define DATA_TYPE_F502 140 /* 气表运行状态 */
#define DATA_TYPE_F503 141 /* 气表流速及压力 */
#define DATA_TYPE_F504 142 /* 气表累积流量 */

/* 新增类型 - 热量表 */
#define DATA_TYPE_F602 150 /* 热量表运行状态 */
#define DATA_TYPE_F603 151 /* 热量累积值 */

/* 新增类型 - 集中器 */
#define DATA_TYPE_F12 160    /* 集中器数据 F12 */
#define DATA_TYPE_F12_DI 161 /* 集中器单个遥信点 */
#define DATA_TYPE_F12_AI 162 /* 集中器单个遥测点 */
#define DATA_TYPE_F12_CI 163 /* 集中器单个脉冲计数 */

/* 控制域功能码(启动站) */
#define BAK0 0x00     /* 备用 */
#define RESET 0x01    /* 复位命令 */
#define BAK2 0x02     /* 备用 */
#define BAK3 0x03     /* 备用 */
#define USERDATA 0x04 /* 用户数据 */
#define BAK5 0x05     /* 备用 */
#define BAK6 0x06 /* 备用 控制命令（时间设置） 威胜集中器 */
#define BAK7 0x07 /* 备用 */
#define BAK8 0x08 /* 备用 */
#define LINKTEST 0x09       /* 链路测试 */
#define REQUESTONEDATA 0x0a /* 请求一级数据 */
#define REQUESTTWODATA 0x0b /* 请求二级数据 */

/* 控制域功能码(从动站) */
#define ACK 0x00              /* 确认 */
#define RESPONSEUSERDATA 0x08 /* 用户数据 */
#define NODATA 0x09           /* 无所召唤数据 */
#define LINKREDAY 0x0b        /* 链路状态 */

/* 应用层功能码 */
#define AFN_ACK 0x00              /* 确认/否认 */
#define AFN_RESET 0x01            /* 复位 */
#define AFN_LINKTEST 0x02         /* 链路接口检测 */
#define AFN_RESTATIONCMD 0x03     /* 中继站命令 */
#define AFN_SETPARAM 0x04         /* 设置参数 */
#define AFN_CMD 0x05              /* 控制命令 */
#define AFN_CONFIRMKEY 0x06       /* 身份认证及密钥协商 */
#define AFN_REQUESTAUTODATA 0x08  /* 请求被级联终端主动上报 */
#define AFN_REQUESTCONFIG 0x09    /* 请求终端配置 */
#define AFN_QUERYPARAM 0x0a       /* 查询参数 */
#define AFN_REQUESTTASTDATA 0x0b  /* 请求任务数据 */
#define AFN_REQUESTONEDATA 0x0c   /* 请求1类数据(当前数据) */
#define AFN_REQUESTTWODATA 0x0d   /* 请求2类数据(冻结数据) */
#define AFN_REQUESTTHREEDATA 0x0e /* 请求3类数据(事件数据) */
#define AFN_ZFFILE 0x0f           /* 文件传输 */
#define AFN_ZFDATA 0x10           /* 数据转发 */

/* 附录A.5 符号XXX.X格式（功率因数） */
typedef struct {
    BYTE SFW : 4; /* 十分位 */
    BYTE GW : 4;  /* 个位 */
    BYTE SW : 4;  /* 十位 */
    BYTE BW : 3;  /* 百位 */
    BYTE S : 1;   /* 符号位 0:正，1:负 */
} Data_Type_5;

/* 附录A.6 符号XX.XX格式（功率） */
typedef struct {
    BYTE BFW : 4; /* 百分位 */
    BYTE SFW : 4; /* 十分位 */
    BYTE GW : 4;  /* 个位 */
    BYTE SW : 3;  /* 十位 */
    BYTE S : 1;   /* 符号位 0:正，1:负 */
} Data_Type_6;

/* 附录A.7 XXX.X格式（电压） */
typedef struct {
    BYTE SFW : 4; /* 十分位 */
    BYTE GW : 4;  /* 个位 */
    BYTE SW : 4;  /* 十位 */
    BYTE BW : 4;  /* 百位 */
} Data_Type_7;

/* 附录A.8 XXXX格式（电能表字数） */
typedef struct {
    BYTE GW : 4; /* 个位 */
    BYTE SW : 4; /* 十位 */
    BYTE BW : 4; /* 百位 */
    BYTE QW : 4; /* 千位 */
} Data_Type_8;

/* 附录A.9 符号XX.XXXX格式（有功功率） */
typedef struct {
    BYTE WFW : 4; /* 千分位 */
    BYTE QFW : 4; /* 万分位 */
    BYTE BFW : 4; /* 百分位 */
    BYTE SFW : 4; /* 十分位 */
    BYTE GW : 4;  /* 个位 */
    BYTE SW : 3;  /* 十位 */
    BYTE S : 1;   /* 符号位 0:正，1:负 */
} Data_Type_9;

/* 附录A.11 XXXXXX.XX格式 */
typedef struct {
    BYTE BFW : 4; /* 百分位 */
    BYTE SFW : 4; /* 十分位 */
    BYTE GW : 4;  /* 个位值 */
    BYTE SW : 4;  /* 十位值 */
    BYTE BW : 4;  /* 百位值 */
    BYTE QW : 4;  /* 千位值 */
    BYTE WW : 4;  /* 万位值 */
    BYTE SWW : 4; /* 十万位值 */
} Data_Type_11;

/* 附录A.14 XXX.XXXXX格式 */
typedef struct {
    BYTE WFW : 4; /* 万分位 */
    BYTE QFW : 4; /* 千分位 */
    BYTE BFW : 4; /* 百分位 */
    BYTE SFW : 4; /* 十分位 */
    BYTE GW : 4;  /* 个位 */
    BYTE SW : 4;  /* 十位 */
    BYTE BW : 4;  /* 百位 */
    BYTE QW : 4;  /* 千位 */
    BYTE WW : 4;  /* 万位 */
    BYTE SWW : 4; /* 十万位 */
} Data_Type_14;

/* 附录A.23 XXXX.XX格式 */
typedef struct {
    BYTE WFW : 4; /* 万分位 */
    BYTE QFW : 4; /* 千分位 */
    BYTE BFW : 4; /* 百分位 */
    BYTE SFW : 4; /* 十分位 */
    BYTE GW : 4;  /* 个位 */
    BYTE SW : 4;  /* 十位 */
} Data_Type_23;

/* 附录A.25 XX.XXXX格式（分时电价） */
typedef struct {
    BYTE QFW : 4; /* 千分位 */
    BYTE BFW : 4; /* 百分位 */
    BYTE SFW : 4; /* 十分位 */
    BYTE GW : 4;  /* 个位 */
    BYTE SW : 4;  /* 十位 */
    BYTE BW : 3;  /* 百位 */
    BYTE S : 1;   /* 符号 */
} Data_Type_25;

/* 倒序时间格式(分时日月年) */
typedef struct {
    BYTE MinutesL : 4; /* 分（低位） */
    BYTE MinutesH : 4; /* 分（高位） */
    BYTE HourL : 4;    /* 时（低位） */
    BYTE HourH : 4;    /* 时（高位） */
    BYTE DayL : 4;     /* 日（低位） */
    BYTE DayH : 4;     /* 日（高位） */
    BYTE MonthL : 4;   /* 月（低位） */
    BYTE MonthH : 4;   /* 月（高位） */
    BYTE YearL : 4;    /* 年（低位） */
    BYTE YearH : 4;    /* 年（高位） */
} GB_12241_MHDMYTIME;

/* 完整的时间字节序定义（附A.1） */
typedef struct {
    BYTE SecondL : 4;  /* 秒（低位） */
    BYTE SecondH : 4;  /* 秒（高位） */
    BYTE MinutesL : 4; /* 分（低位） */
    BYTE MinutesH : 4; /* 分（高位） */
    BYTE HourL : 4;    /* 时（低位） */
    BYTE HourH : 4;    /* 时（高位） */
    BYTE DayL : 4;     /* 日（低位） */
    BYTE DayH : 4;     /* 日（高位） */
    BYTE MonthL : 4;   /* 月（低位） */
    BYTE MonthH : 1;   /* 月（高位） */
    BYTE Week : 3;     /* 星期(0:无效 1-7:代表星期一到星期天) */
    BYTE YearL : 4;    /* 年（低位） */
    BYTE YearH : 4;    /* 年（高位） */
} GB_12241_TIME;

/* 年月日时分格式 */
typedef struct {
    BYTE MinutesL : 4; /* 分（低位） */
    BYTE MinutesH : 4; /* 分（高位） */
    BYTE HourL : 4;    /* 时（低位） */
    BYTE HourH : 4;    /* 时（高位） */
    BYTE DayL : 4;     /* 日（低位） */
    BYTE DayH : 4;     /* 日（高位） */
    BYTE MonthL : 4;   /* 月（低位） */
    BYTE MonthH : 4;   /* 月（高位） */
    BYTE YearL : 4;    /* 年（低位） */
    BYTE YearH : 4;    /* 年（高位） */
} GB_12241_YMDHM_TIME;

/* 分时日月格式 */
typedef struct {
    BYTE MinutesL : 4; /* 分（低位） */
    BYTE MinutesH : 4; /* 分（高位） */
    BYTE HourL : 4;    /* 时（低位） */
    BYTE HourH : 4;    /* 时（高位） */
    BYTE DayL : 4;     /* 日（低位） */
    BYTE DayH : 4;     /* 日（高位） */
    BYTE MonthL : 4;   /* 月（低位） */
    BYTE MonthH : 4;   /* 月（高位） */
} GB_12241_MDHM_TIME;

/* 分时日格式（附A.18） */
typedef struct {
    BYTE MinutesL : 4; /* 分（低位） */
    BYTE MinutesH : 4; /* 分（高位） */
    BYTE HourL : 4;    /* 时（低位） */
    BYTE HourH : 4;    /* 时（高位） */
    BYTE DayL : 4;     /* 日（低位） */
    BYTE DayH : 4;     /* 日（高位） */
} GB_12241_MHD_TIME;

/* 秒分时日格式（附A.16） */
typedef struct {
    BYTE SecondL : 4;  /* 秒（低位） */
    BYTE SecondH : 4;  /* 秒（高位） */
    BYTE MinutesL : 4; /* 分（低位） */
    BYTE MinutesH : 4; /* 分（高位） */
    BYTE HourL : 4;    /* 时（低位） */
    BYTE HourH : 4;    /* 时（高位） */
    BYTE DayL : 4;     /* 日（低位） */
    BYTE DayH : 4;     /* 日（高位） */
} GB_12241_SMHD_TIME;

/* 日月年格式（附A.20） */
typedef struct {
    BYTE DayL : 4;   /* 日（低位） */
    BYTE DayH : 4;   /* 日（高位） */
    BYTE MonthL : 4; /* 月（低位） */
    BYTE MonthH : 4; /* 月（高位） */
    BYTE YearL : 4;  /* 年（低位） */
    BYTE YearH : 4;  /* 年（高位） */
} GB_12241_YMD_TIME;

/* 月年格式（附A.21） */
typedef struct {
    BYTE MonthL : 4; /* 月（低位） */
    BYTE MonthH : 4; /* 月（高位） */
    BYTE YearL : 4;  /* 年（低位） */
    BYTE YearH : 4;  /* 年（高位） */
} GB_12241_MY_TIME;

/* 分时格式（附A.19） */
typedef struct {
    BYTE MinutesL : 4; /* 分（低位） */
    BYTE MinutesH : 4; /* 分（高位） */
    BYTE HourL : 4;    /* 时（低位） */
    BYTE HourH : 4;    /* 时（高位） */
} GB_12241_MH_TIME;

/* 日周格式（101日周） */
typedef struct {
    BYTE Days : 5;  /* 日 */
    BYTE Weeks : 3; /* 周 */
} GB_12241_DW;

/* 功能码Fn=25"当前三相及总有功功率"数据结构 */
typedef struct {
    GB_12241_MHDMYTIME time;     /* 时间 */
    Data_Type_9        data_P;   /* 总有功功率 */
    Data_Type_9        data_Pa;  /* A相有功功率 */
    Data_Type_9        data_Pb;  /* B相有功功率 */
    Data_Type_9        data_Pc;  /* C相有功功率 */
    Data_Type_9        data_Q;   /* 总无功功率 */
    Data_Type_9        data_Qa;  /* A相无功功率 */
    Data_Type_9        data_Qb;  /* B相无功功率 */
    Data_Type_9        data_Qc;  /* C相无功功率 */
    Data_Type_5        data_Cs;  /* 总功率因数 */
    Data_Type_5        data_Csa; /* A相功率因数 */
    Data_Type_5        data_Csb; /* B相功率因数 */
    Data_Type_5        data_Csc; /* C相功率因数 */
    Data_Type_7        data_Ua;  /* A相电压 */
    Data_Type_7        data_Ub;  /* B相电压 */
    Data_Type_7        data_Uc;  /* C相电压 */
    Data_Type_25       data_Ia;  /* A相电流 */
    Data_Type_25       data_Ib;  /* B相电流 */
    Data_Type_25       data_Ic;  /* C相电流 */
    Data_Type_25       data_I0;  /* 零序电流 */
    Data_Type_9        data_S;   /* 总视在功率 */
    Data_Type_9        data_Sa;  /* A相视在功率 */
    Data_Type_9        data_Sb;  /* B相视在功率 */
    Data_Type_9        data_Sc;  /* C相视在功率 */
} Data_ONE_F25;

/* 电表状态标志位结构 */
typedef struct {
    BYTE bit0 : 1; /* 失压 */
    BYTE bit1 : 1; /* 欠压 */
    BYTE bit2 : 1; /* 过压 */
    BYTE bit3 : 1; /* 失流 */
    BYTE bit4 : 1; /* 过流 */
    BYTE bit5 : 1; /* 过载 */
    BYTE bit6 : 1; /* 反向 */
    BYTE bit7 : 1; /* 断相 */

    BYTE byte1 : 8; /* 备用 */
} Data_Type_BS16_S4;

/* 电表S5状态标志位结构 */
typedef struct {
    BYTE bit0 : 1; /* 失压 */
    BYTE bit1 : 1; /* 欠压 */
    BYTE bit2 : 1; /* 过压 */
    BYTE bit3 : 1; /* 失流 */
    BYTE bit4 : 1; /* 过流 */
    BYTE bit5 : 1; /* 过载 */
    BYTE bit6 : 1; /* 反向 */
    BYTE bit7 : 1; /* 断相 */

    BYTE byte1 : 8; /* 备用 */
} Data_Type_BS16_S5;

/* 电表S6状态标志位结构 */
typedef struct {
    BYTE bit0 : 1; /* 失压 */
    BYTE bit1 : 1; /* 欠压 */
    BYTE bit2 : 1; /* 过压 */
    BYTE bit3 : 1; /* 失流 */
    BYTE bit4 : 1; /* 过流 */
    BYTE bit5 : 1; /* 过载 */
    BYTE bit6 : 1; /* 反向 */
    BYTE bit7 : 1; /* 断相 */

    BYTE byte1 : 8; /* 备用 */
} Data_Type_BS16_S6;

/* 电表S7状态标志位结构 */
typedef struct {
    BYTE bit0 : 1; /* 电压逆相序 */
    BYTE bit1 : 1; /* 电流逆相序 */
    BYTE bit2 : 1; /* 电压不平衡 */
    BYTE bit3 : 1; /* 电流不平衡 */
    BYTE bit4 : 1; /* 过流 */
    BYTE bit5 : 1; /* 过载 */
    BYTE bit6 : 1; /* 反向 */
    BYTE bit7 : 1; /* 断相 */

    BYTE byte1 : 8; /* 备用 */
} Data_Type_BS16_S7;

/* 功能码Fn=28"电表运行状态字及其变位标志"数据结构 */
typedef struct {
    GB_12241_MHDMYTIME time; /* 时间 */
    Data_Type_BS16_S4  BWS1; /* 变位标志1(备) */
    Data_Type_BS16_S4  BWS2; /* 变位标志2(备) */
    Data_Type_BS16_S4  BWS3; /* 变位标志3(备) */
    Data_Type_BS16_S4  BWS4; /* 变位标志4(备) */
    Data_Type_BS16_S4  BWS5; /* 变位标志5(备) */
    Data_Type_BS16_S4  BWS6; /* 变位标志6(备) */
    Data_Type_BS16_S4  BWS7; /* 变位标志7(备) */
    Data_Type_BS16_S4  S1;   /* 状态标志1(备) */
    Data_Type_BS16_S4  S2;   /* 状态标志2(备) */
    Data_Type_BS16_S4  S3;   /* 状态标志3(备) */
    Data_Type_BS16_S4  S4;   /* 状态标志4 */
    Data_Type_BS16_S5  S5;   /* 状态标志5 */
    Data_Type_BS16_S6  S6;   /* 状态标志6 */
    Data_Type_BS16_S7  S7;   /* 状态标志7 */
} Data_ONE_F28;

/* 功能码Fn=129"当前正向有功电能示值"数据结构 */
typedef struct {
    Data_Type_14 tarrif_Total;  /* 正向有功总电能 */
    Data_Type_14 tarrif_Sharp;  /* 正向有功尖电能 */
    Data_Type_14 tarrif_Peak;   /* 正向有功峰电能 */
    Data_Type_14 tarrif_Ground; /* 正向有功平电能 */
    Data_Type_14 tarrif_Valley; /* 正向有功谷电能 */
} Data_ONE_F129;

/* 功能码Fn=130"当前正向无功电能示值"数据结构 */
typedef struct {
    Data_Type_14 tarrif_Total;  /* 正向无功总电能 */
    Data_Type_14 tarrif_Sharp;  /* 正向无功尖电能 */
    Data_Type_14 tarrif_Peak;   /* 正向无功峰电能 */
    Data_Type_14 tarrif_Ground; /* 正向无功平电能 */
    Data_Type_14 tarrif_Valley; /* 正向无功谷电能 */
} Data_ONE_F130;

/* 功能码Fn=131"当前反向有功电能示值"数据结构 */
typedef struct {
    Data_Type_14 tarrif_Total;  /* 反向有功总电能 */
    Data_Type_14 tarrif_Sharp;  /* 反向有功尖电能 */
    Data_Type_14 tarrif_Peak;   /* 反向有功峰电能 */
    Data_Type_14 tarrif_Ground; /* 反向有功平电能 */
    Data_Type_14 tarrif_Valley; /* 反向有功谷电能 */
} Data_ONE_F131;

/* 功能码Fn=132"当前反向无功电能示值"数据结构 */
typedef struct {
    Data_Type_14 tarrif_Total;  /* 反向无功总电能 */
    Data_Type_14 tarrif_Sharp;  /* 反向无功尖电能 */
    Data_Type_14 tarrif_Peak;   /* 反向无功峰电能 */
    Data_Type_14 tarrif_Ground; /* 反向无功平电能 */
    Data_Type_14 tarrif_Valley; /* 反向无功谷电能 */
} Data_ONE_F132;

/* 需量及发生时间数据格式 */
typedef struct {
    Data_Type_23       data_value; /* 需量值 */
    GB_12241_MDHM_TIME data_time;  /* 发生时间 */
} MAX_DEMAND_DATA;

/* 功能码Fn=145"当月正向有功最大需量及发生时间"数据结构 */
typedef struct {
    GB_12241_MHDMYTIME time;          // 5字节时标
    uint8_t            tarrif;        // 1字节费率数量
    Data_Type_23       tarrif_Total;  // 总需量值
    GB_12241_MDHM_TIME total_time;    // 总需量发生时间
    Data_Type_23       tarrif_Sharp;  // 尖需量值
    GB_12241_MDHM_TIME sharp_time;    // 尖需量发生时间
    Data_Type_23       tarrif_Peak;   // 峰需量值
    GB_12241_MDHM_TIME peak_time;     // 峰需量发生时间
    Data_Type_23       tarrif_Ground; // 平需量值
    GB_12241_MDHM_TIME ground_time;   // 平需量发生时间
    Data_Type_23       tarrif_Valley; // 谷需量值
    GB_12241_MDHM_TIME valley_time;   // 谷需量发生时间
} Data_ONE_F145;

/* 功能码Fn=146"当月正向无功最大需量及发生时间"数据结构 */
typedef struct {
    MAX_DEMAND_DATA tarrif_Total;  /* 正向无功总最大需量 */
    MAX_DEMAND_DATA tarrif_Sharp;  /* 正向无功尖最大需量 */
    MAX_DEMAND_DATA tarrif_Peak;   /* 正向无功峰最大需量 */
    MAX_DEMAND_DATA tarrif_Ground; /* 正向无功平最大需量 */
    MAX_DEMAND_DATA tarrif_Valley; /* 正向无功谷最大需量 */
} Data_ONE_F146;

/* 功能码Fn=147"当月反向有功最大需量及发生时间"数据结构 */
typedef struct {
    MAX_DEMAND_DATA tarrif_Total;  /* 反向有功总最大需量 */
    MAX_DEMAND_DATA tarrif_Sharp;  /* 反向有功尖最大需量 */
    MAX_DEMAND_DATA tarrif_Peak;   /* 反向有功峰最大需量 */
    MAX_DEMAND_DATA tarrif_Ground; /* 反向有功平最大需量 */
    MAX_DEMAND_DATA tarrif_Valley; /* 反向有功谷最大需量 */
} Data_ONE_F147;

/* 功能码Fn=148"当月反向无功最大需量及发生时间"数据结构 */
typedef struct {
    MAX_DEMAND_DATA tarrif_Total;  /* 反向无功总最大需量 */
    MAX_DEMAND_DATA tarrif_Sharp;  /* 反向无功尖最大需量 */
    MAX_DEMAND_DATA tarrif_Peak;   /* 反向无功峰最大需量 */
    MAX_DEMAND_DATA tarrif_Ground; /* 反向无功平最大需量 */
    MAX_DEMAND_DATA tarrif_Valley; /* 反向无功谷最大需量 */
} Data_ONE_F148;

/* 正向有功日冻结(补) - 简化 */
typedef struct {
    GB_12241_YMD_TIME freeze_time;   /* 冻结时间 */
    Data_Type_14      tarrif_Total;  /* 正向有功总 */
    Data_Type_14      tarrif_Sharp;  /* 正向有功尖 */
    Data_Type_14      tarrif_Peak;   /* 正向有功峰 */
    Data_Type_14      tarrif_Ground; /* 正向有功平 */
    Data_Type_14      tarrif_Valley; /* 正向有功谷 */
} Data_TWO_F161;

/* 正向无功日冻结(补) - 简化 */
typedef struct {
    GB_12241_YMD_TIME freeze_time;   /* 冻结时间 */
    Data_Type_14      tarrif_Total;  /* 正向无功总 */
    Data_Type_14      tarrif_Sharp;  /* 正向无功尖 */
    Data_Type_14      tarrif_Peak;   /* 正向无功峰 */
    Data_Type_14      tarrif_Ground; /* 正向无功平 */
    Data_Type_14      tarrif_Valley; /* 正向无功谷 */
} Data_TWO_F162;

/* 反向有功日冻结(补) - 简化 */
typedef struct {
    GB_12241_YMD_TIME freeze_time;   /* 冻结时间 */
    Data_Type_14      tarrif_Total;  /* 反向有功总 */
    Data_Type_14      tarrif_Sharp;  /* 反向有功尖 */
    Data_Type_14      tarrif_Peak;   /* 反向有功峰 */
    Data_Type_14      tarrif_Ground; /* 反向有功平 */
    Data_Type_14      tarrif_Valley; /* 反向有功谷 */
} Data_TWO_F163;

/* 反向无功日冻结(补) - 简化 */
typedef struct {
    GB_12241_YMD_TIME freeze_time;   /* 冻结时间 */
    Data_Type_14      tarrif_Total;  /* 反向无功总 */
    Data_Type_14      tarrif_Sharp;  /* 反向无功尖 */
    Data_Type_14      tarrif_Peak;   /* 反向无功峰 */
    Data_Type_14      tarrif_Ground; /* 反向无功平 */
    Data_Type_14      tarrif_Valley; /* 反向无功谷 */
} Data_TWO_F164;

/* 功能码-点号-数据类型映射 */
typedef struct {
    int   fn;          /* 功能码 */
    int   pn;          /* 点号 */
    int   data_index;  /* 数据索引 */
    int   data_type;   /* 数据类型 */
    char *description; /* 描述 */
} gb_12241_fn_pn_map_t;

/* 一类数据F402结构需要的通用运行状态字 */
typedef struct {
    BYTE bit0 : 1;
    BYTE bit1 : 1;
    BYTE bit2 : 1;
    BYTE bit3 : 1;
    BYTE bit4 : 1;
    BYTE bit5 : 1;
    BYTE bit6 : 1;
    BYTE bit7 : 1;

    BYTE byte1 : 8;
} Data_Type_BS16;

/* 数据值获取相关函数 */
float data_type_5_getvalue(const Data_Type_5 *data);
BYTE  data_type_5_getflag(const Data_Type_5 *data);
float data_type_6_getvalue(const Data_Type_6 *data);
BYTE  data_type_6_getflag(const Data_Type_6 *data);
float data_type_7_getvalue(const Data_Type_7 *data);
BYTE  data_type_7_getflag(const Data_Type_7 *data);
int   data_type_8_getvalue(const Data_Type_8 *data);
BYTE  data_type_8_getflag(const Data_Type_8 *data);
float data_type_9_getvalue(const Data_Type_9 *data);
BYTE  data_type_9_getflag(const Data_Type_9 *data);
float data_type_11_getvalue(const Data_Type_11 *data);
float data_type_14_getvalue(const Data_Type_14 *data);
float data_type_23_getvalue(const Data_Type_23 *data);
float data_type_25_getvalue(const Data_Type_25 *data);
BYTE  data_type_25_getflag(const Data_Type_25 *data);

/* 标志位获取函数 */
BYTE data_type_11_getflag(const Data_Type_11 *data);
BYTE data_type_14_getflag(const Data_Type_14 *data);
BYTE data_type_23_getflag(const Data_Type_23 *data);

/* 时间相关函数声明，使用tm_data作为参数名避免与time()函数冲突 */
void   gb_12241_time_setvalue(GB_12241_TIME *tm_data, time_t t);
void   gb_12241_ymdhm_time_setvalue(GB_12241_YMDHM_TIME *tm_data, time_t t);
int    gb_12241_ymdhm_time_getvalue(const GB_12241_YMDHM_TIME *tm_data);
void   gb_12241_mdhm_time_setvalue(GB_12241_MDHM_TIME *tm_data, time_t t);
int    gb_12241_mdhm_time_getvalue(const GB_12241_MDHM_TIME *tm_data);
void   gb_12241_ymd_time_setvalue(GB_12241_YMD_TIME *tm_data, time_t t);
time_t gb_12241_ymd_time_getvalue(const GB_12241_YMD_TIME *tm_data);
int    gb_12241_mhdmytime_getutcvalue(const GB_12241_MHDMYTIME *tm_data);
void   gb_12241_mhdmytime_setvalue(GB_12241_MHDMYTIME *tm_data, time_t t);

/* GB/T12241数据处理函数 */
/// int gb_12241_get_data_type(int fn, int pn, int data_index);
int gb_12241_parse_data(void *plugin, BYTE *buffer, int buffer_len, int fn,
                        int pn, int data_index, void *result, int result_size);
// float gb_12241_get_value(void *plugin, void* data, int data_type);

/* 外部暴露的映射表 */
extern const gb_12241_fn_pn_map_t gb_12241_fn_pn_map[];
extern const int                  gb_12241_fn_pn_map_size;

/* 定点数类型 */
typedef struct {
    BYTE decimal;  /* 小数位数 */
    BYTE flag;     /* 符号标志 0-正数 1-负数 */
    WORD integer;  /* 整数部分 */
    WORD fraction; /* 小数部分 */
} Data_Type_12;

/* 变长浮点数类型 */
typedef struct {
    BYTE  decimal;  /* 小数位数 */
    BYTE  flag;     /* 符号标志 0-正数 1-负数 */
    DWORD integer;  /* 整数部分 */
    DWORD fraction; /* 小数部分 */
} Data_Type_13;

/* 谐波监测数据结构 */
typedef struct {
    Data_Type_7 fundamental;          /* 基波值 */
    Data_Type_5 harmonics[15];        /* 2-16次谐波含量(%) */
    Data_Type_5 total_harmonic_ratio; /* 总谐波含量(%) */
} Harmonic_Data;

/* 功能码Fn=29"谐波监测数据"数据结构 */
typedef struct {
    Harmonic_Data voltage_a; /* A相电压谐波 */
    Harmonic_Data voltage_b; /* B相电压谐波 */
    Harmonic_Data voltage_c; /* C相电压谐波 */
    Harmonic_Data current_a; /* A相电流谐波 */
    Harmonic_Data current_b; /* B相电流谐波 */
    Harmonic_Data current_c; /* C相电流谐波 */
} Data_ONE_F29;

/* 功能码Fn=30"电能质量参数"数据结构 */
typedef struct {
    Data_Type_9 unbalance_voltage;   /* 三相电压不平衡度 */
    Data_Type_9 unbalance_current;   /* 三相电流不平衡度 */
    Data_Type_7 freq_deviation;      /* 频率偏差 */
    Data_Type_7 voltage_deviation_a; /* A相电压偏差 */
    Data_Type_7 voltage_deviation_b; /* B相电压偏差 */
    Data_Type_7 voltage_deviation_c; /* C相电压偏差 */
} Data_ONE_F30;

/* 功能码Fn=31"相位角"数据结构 */
typedef struct {
    Data_Type_7 angle_ua_ub; /* A相电压与B相电压夹角 */
    Data_Type_7 angle_ub_uc; /* B相电压与C相电压夹角 */
    Data_Type_7 angle_uc_ua; /* C相电压与A相电压夹角 */
    Data_Type_7 angle_ia_ib; /* A相电流与B相电流夹角 */
    Data_Type_7 angle_ib_ic; /* B相电流与C相电流夹角 */
    Data_Type_7 angle_ic_ia; /* C相电流与A相电流夹角 */
    Data_Type_7 angle_ua_ia; /* A相电压与A相电流夹角 */
    Data_Type_7 angle_ub_ib; /* B相电压与B相电流夹角 */
    Data_Type_7 angle_uc_ic; /* C相电压与C相电流夹角 */
} Data_ONE_F31;

/* 功能码Fn=33"负荷监测数据"数据结构 */
typedef struct {
    Data_Type_9   average_power;  /* 平均功率 */
    Data_Type_9   max_power;      /* 最大功率 */
    GB_12241_TIME max_power_time; /* 最大功率发生时间 */
    Data_Type_9   min_power;      /* 最小功率 */
    GB_12241_TIME min_power_time; /* 最小功率发生时间 */
    Data_Type_7   load_rate;      /* 负载率 */
} Data_ONE_F33;

/* 功能码Fn=41"日累计电能量"数据结构 */
typedef struct {
    GB_12241_YMD_TIME date;              /* 日期 */
    Data_Type_14      pos_active_total;  /* 正向有功总电能量 */
    Data_Type_14      pos_active_peak;   /* 正向有功峰电能量 */
    Data_Type_14      pos_active_flat;   /* 正向有功平电能量 */
    Data_Type_14      pos_active_valley; /* 正向有功谷电能量 */
    Data_Type_14      neg_active_total;  /* 反向有功总电能量 */
    Data_Type_14      neg_active_peak;   /* 反向有功峰电能量 */
    Data_Type_14      neg_active_flat;   /* 反向有功平电能量 */
    Data_Type_14      neg_active_valley; /* 反向有功谷电能量 */
} Data_ONE_F41;

/* 多费率电能补充数据结构 */
typedef struct {
    Data_Type_14 tarrif_Total; /* 总电能 */
    Data_Type_14 tarrif_Rate1; /* 费率1电能 */
    Data_Type_14 tarrif_Rate2; /* 费率2电能 */
    Data_Type_14 tarrif_Rate3; /* 费率3电能 */
    Data_Type_14 tarrif_Rate4; /* 费率4电能 */
    Data_Type_14 tarrif_Rate5; /* 费率5电能 */
    Data_Type_14 tarrif_Rate6; /* 费率6电能 */
    Data_Type_14 tarrif_Rate7; /* 费率7电能 */
    Data_Type_14 tarrif_Rate8; /* 费率8电能 */
} Multi_Rate_Energy;

/* 功能码Fn=133"当前四象限无功电能示值"数据结构 */
typedef struct {
    Multi_Rate_Energy quadrant1; /* 第一象限无功电能 */
    Multi_Rate_Energy quadrant2; /* 第二象限无功电能 */
    Multi_Rate_Energy quadrant3; /* 第三象限无功电能 */
    Multi_Rate_Energy quadrant4; /* 第四象限无功电能 */
} Data_ONE_F133;

/* 功能码Fn=150"三相不平衡监测数据"数据结构 */
typedef struct {
    Data_Type_9 unbalance_voltage;         /* 三相电压不平衡度 */
    Data_Type_9 unbalance_current;         /* 三相电流不平衡度 */
    Data_Type_9 negative_sequence_voltage; /* 负序电压 */
    Data_Type_9 negative_sequence_current; /* 负序电流 */
    Data_Type_9 zero_sequence_voltage;     /* 零序电压 */
    Data_Type_9 zero_sequence_current;     /* 零序电流 */
} Data_ONE_F150;

/* 功能码Fn=194"当前正向有功电能示值(多费率)"数据结构 */
typedef struct {
    Multi_Rate_Energy energy; /* 正向有功多费率电能 */
} Data_ONE_F194;

/* 功能码Fn=195"当前正向无功电能示值(多费率)"数据结构 */
typedef struct {
    Multi_Rate_Energy energy; /* 正向无功多费率电能 */
} Data_ONE_F195;

/* 功能码Fn=196"当前反向有功电能示值(多费率)"数据结构 */
typedef struct {
    Multi_Rate_Energy energy; /* 反向有功多费率电能 */
} Data_ONE_F196;

/* 功能码Fn=197"当前反向无功电能示值(多费率)"数据结构 */
typedef struct {
    Multi_Rate_Energy energy; /* 反向无功多费率电能 */
} Data_ONE_F197;

/* 扩展数据值获取相关函数 */
float data_type_12_getvalue(const Data_Type_12 *data);
float data_type_13_getvalue(const Data_Type_13 *data);

/* 扩展标志位获取函数 */
BYTE data_type_12_getflag(const Data_Type_12 *data);
BYTE data_type_13_getflag(const Data_Type_13 *data);

/* 功能码Fn=32"三相四线和三相三线电压电流有功功率"数据结构 */
typedef struct {
    Data_Type_5 voltage_a;          /* A相电压 */
    Data_Type_5 voltage_b;          /* B相电压 */
    Data_Type_5 voltage_c;          /* C相电压 */
    Data_Type_5 voltage_ab;         /* AB线电压 */
    Data_Type_5 voltage_bc;         /* BC线电压 */
    Data_Type_5 voltage_ca;         /* CA线电压 */
    Data_Type_5 current_a;          /* A相电流 */
    Data_Type_5 current_b;          /* B相电流 */
    Data_Type_5 current_c;          /* C相电流 */
    Data_Type_6 active_power_a;     /* A相有功功率 */
    Data_Type_6 active_power_b;     /* B相有功功率 */
    Data_Type_6 active_power_c;     /* C相有功功率 */
    Data_Type_6 active_power_total; /* 总有功功率 */
} Data_ONE_F32;

/* 功能码Fn=34"三相四线和三相三线电流功率因数"数据结构 */
typedef struct {
    Data_Type_5 current_a;          /* A相电流 */
    Data_Type_5 current_b;          /* B相电流 */
    Data_Type_5 current_c;          /* C相电流 */
    Data_Type_9 power_factor_a;     /* A相功率因数 */
    Data_Type_9 power_factor_b;     /* B相功率因数 */
    Data_Type_9 power_factor_c;     /* C相功率因数 */
    Data_Type_9 power_factor_total; /* 总功率因数 */
} Data_ONE_F34;

/* 功能码Fn=35"三相四线和三相三线无功功率"数据结构 */
typedef struct {
    Data_Type_6 reactive_power_a;     /* A相无功功率 */
    Data_Type_6 reactive_power_b;     /* B相无功功率 */
    Data_Type_6 reactive_power_c;     /* C相无功功率 */
    Data_Type_6 reactive_power_total; /* 总无功功率 */
} Data_ONE_F35;

/* 功能码Fn=36"三相四线和三相三线视在功率"数据结构 */
typedef struct {
    Data_Type_6 apparent_power_a;     /* A相视在功率 */
    Data_Type_6 apparent_power_b;     /* B相视在功率 */
    Data_Type_6 apparent_power_c;     /* C相视在功率 */
    Data_Type_6 apparent_power_total; /* 总视在功率 */
} Data_ONE_F36;

/* 功能码Fn=42"单月累计电能量"数据结构 */
typedef struct {
    BYTE         year;              /* 年 */
    BYTE         month;             /* 月 */
    Data_Type_14 pos_active_total;  /* 正向有功总电能量 */
    Data_Type_14 pos_active_peak;   /* 正向有功峰电能量 */
    Data_Type_14 pos_active_flat;   /* 正向有功平电能量 */
    Data_Type_14 pos_active_valley; /* 正向有功谷电能量 */
    Data_Type_14 neg_active_total;  /* 反向有功总电能量 */
    Data_Type_14 neg_active_peak;   /* 反向有功峰电能量 */
    Data_Type_14 neg_active_flat;   /* 反向有功平电能量 */
    Data_Type_14 neg_active_valley; /* 反向有功谷电能量 */
} Data_ONE_F42;

/* 功能码Fn=43"单相电压电流功率"数据结构 */
typedef struct {
    Data_Type_5 voltage;        /* 电压 */
    Data_Type_5 current;        /* 电流 */
    Data_Type_6 active_power;   /* 有功功率 */
    Data_Type_6 reactive_power; /* 无功功率 */
    Data_Type_6 apparent_power; /* 视在功率 */
    Data_Type_9 power_factor;   /* 功率因数 */
} Data_ONE_F43;

/* 功能码Fn=44"功率和接线方式"数据结构 */
typedef struct {
    BYTE        wiring_mode;    /* 接线方式 */
    Data_Type_6 active_power;   /* 有功功率 */
    Data_Type_6 reactive_power; /* 无功功率 */
} Data_ONE_F44;

/* 功能码Fn=45"铜损铁损有功功率"数据结构 */
typedef struct {
    Data_Type_6 copper_loss; /* 铜损有功功率 */
    Data_Type_6 iron_loss;   /* 铁损有功功率 */
} Data_ONE_F45;

/* 功能码Fn=46"电压合格率统计"数据结构 */
typedef struct {
    Data_Type_9 qualification_rate; /* 电压合格率 */
    Data_Type_9 qualified_time;     /* 电压合格时间 */
    Data_Type_9 unqualified_time;   /* 电压不合格时间 */
    Data_Type_9 upper_limit_time;   /* 电压超上限时间 */
    Data_Type_9 lower_limit_time;   /* 电压超下限时间 */
    Data_Type_9 qualified_days;     /* 电压合格天数 */
    Data_Type_9 unqualified_days;   /* 电压不合格天数 */
    Data_Type_5 max_voltage;        /* 最高电压 */
    Data_Type_5 min_voltage;        /* 最低电压 */
} Data_ONE_F46;

/* 功能码Fn=49"A、B、C三相断相统计"数据结构 */
typedef struct {
    Data_Type_9 phase_a_time;  /* A相断相时间 */
    Data_Type_9 phase_b_time;  /* B相断相时间 */
    Data_Type_9 phase_c_time;  /* C相断相时间 */
    Data_Type_8 phase_a_count; /* A相断相次数 */
    Data_Type_8 phase_b_count; /* B相断相次数 */
    Data_Type_8 phase_c_count; /* C相断相次数 */
} Data_ONE_F49;

/* 功率方向数据类型 */
typedef struct {
    BYTE direction_a;     /* A相功率方向 0-正向 1-反向 */
    BYTE direction_b;     /* B相功率方向 0-正向 1-反向 */
    BYTE direction_c;     /* C相功率方向 0-正向 1-反向 */
    BYTE direction_total; /* 总功率方向 0-正向 1-反向 */
} Power_Direction;

/* 功能码Fn=83"有功功率方向和无功功率方向"数据结构 */
typedef struct {
    Power_Direction active_power;   /* 有功功率方向 */
    Power_Direction reactive_power; /* 无功功率方向 */
} Data_ONE_F83;

/* 功能码Fn=84"当前象限和当前费率"数据结构 */
typedef struct {
    BYTE current_quadrant; /* 当前象限 */
    BYTE current_tariff;   /* 当前费率 */
} Data_ONE_F84;

/* 功能码Fn=85"电表运行状态字"数据结构 */
typedef struct {
    BYTE status_bytes[7]; /* 状态字 */
} Data_ONE_F85;

/* 功能码Fn=86"电表开关状态"数据结构 */
typedef struct {
    BYTE switch_status; /* 开关状态 0-合闸 1-跳闸 */
} Data_ONE_F86;

/* 功能码Fn=87"最近一次事件发生时刻"数据结构 */
typedef struct {
    GB_12241_YMDHM_TIME event_time; /* 事件发生时刻 */
    BYTE                event_code; /* 事件代码 */
} Data_ONE_F87;

/* 功能码Fn=88"最近一次编程时刻"数据结构 */
typedef struct {
    GB_12241_YMDHM_TIME programming_time; /* 编程时刻 */
} Data_ONE_F88;

/* 功能码Fn=89"最近一次电表清零时刻"数据结构 */
typedef struct {
    GB_12241_YMDHM_TIME meter_reset_time; /* 电表清零时刻 */
} Data_ONE_F89;

/* 功能码Fn=183"当前组合有功电能"数据结构 */
typedef struct {
    Data_Type_14 forward_active_total;     /* 正向有功总电能 */
    Data_Type_14 reverse_active_total;     /* 反向有功总电能 */
    Data_Type_14 combination_active_total; /* 组合有功总电能 */
} Data_ONE_F183;

/* 功能码Fn=184"当前组合无功1电能"数据结构 */
typedef struct {
    Data_Type_14 forward_reactive1_total;     /* 正向无功1总电能 */
    Data_Type_14 reverse_reactive1_total;     /* 反向无功1总电能 */
    Data_Type_14 combination_reactive1_total; /* 组合无功1总电能 */
} Data_ONE_F184;

/* 功能码Fn=185"当前组合无功2电能"数据结构 */
typedef struct {
    Data_Type_14 forward_reactive2_total;     /* 正向无功2总电能 */
    Data_Type_14 reverse_reactive2_total;     /* 反向无功2总电能 */
    Data_Type_14 combination_reactive2_total; /* 组合无功2总电能 */
} Data_ONE_F185;

/* 功能码Fn=186"当日组合有功电能增量"数据结构 */
typedef struct {
    Data_Type_14 forward_active_increment;     /* 正向有功电能增量 */
    Data_Type_14 reverse_active_increment;     /* 反向有功电能增量 */
    Data_Type_14 combination_active_increment; /* 组合有功电能增量 */
} Data_ONE_F186;

/* 功能码Fn=187"当日组合无功1电能增量"数据结构 */
typedef struct {
    Data_Type_14 forward_reactive1_increment; /* 正向无功1电能增量 */
    Data_Type_14 reverse_reactive1_increment; /* 反向无功1电能增量 */
    Data_Type_14 combination_reactive1_increment; /* 组合无功1电能增量 */
} Data_ONE_F187;

/* 功能码Fn=188"当日组合无功2电能增量"数据结构 */
typedef struct {
    Data_Type_14 forward_reactive2_increment; /* 正向无功2电能增量 */
    Data_Type_14 reverse_reactive2_increment; /* 反向无功2电能增量 */
    Data_Type_14 combination_reactive2_increment; /* 组合无功2电能增量 */
} Data_ONE_F188;

/* 功能码Fn=189"上月组合有功电能增量"数据结构 */
typedef struct {
    Data_Type_14 forward_active_increment;     /* 正向有功电能增量 */
    Data_Type_14 reverse_active_increment;     /* 反向有功电能增量 */
    Data_Type_14 combination_active_increment; /* 组合有功电能增量 */
} Data_ONE_F189;

/* 功能码Fn=190"上月组合无功1电能增量"数据结构 */
typedef struct {
    Data_Type_14 forward_reactive1_increment; /* 正向无功1电能增量 */
    Data_Type_14 reverse_reactive1_increment; /* 反向无功1电能增量 */
    Data_Type_14 combination_reactive1_increment; /* 组合无功1电能增量 */
} Data_ONE_F190;

/* 功能码Fn=191"上月组合无功2电能增量"数据结构 */
typedef struct {
    Data_Type_14 forward_reactive2_increment; /* 正向无功2电能增量 */
    Data_Type_14 reverse_reactive2_increment; /* 反向无功2电能增量 */
    Data_Type_14 combination_reactive2_increment; /* 组合无功2电能增量 */
} Data_ONE_F191;

/* 功能码Fn=192"上年组合有功电能增量"数据结构 */
typedef struct {
    Data_Type_14 forward_active_increment;     /* 正向有功电能增量 */
    Data_Type_14 reverse_active_increment;     /* 反向有功电能增量 */
    Data_Type_14 combination_active_increment; /* 组合有功电能增量 */
} Data_ONE_F192;

/* 功能码Fn=193"上年组合无功电能增量"数据结构 */
typedef struct {
    Data_Type_14 forward_reactive_increment;     /* 正向无功电能增量 */
    Data_Type_14 reverse_reactive_increment;     /* 反向无功电能增量 */
    Data_Type_14 combination_reactive_increment; /* 组合无功电能增量 */
} Data_ONE_F193;

/* 功能码Fn=201"设备版本信息"数据结构 */
typedef struct {
    BYTE software_version[8]; /* 软件版本号 */
    BYTE hardware_version[8]; /* 硬件版本号 */
    BYTE protocol_version[8]; /* 协议版本号 */
} Data_ONE_F201;

/* 功能码Fn=202"电能表时间"数据结构 */
typedef struct {
    GB_12241_TIME meter_time; /* 电能表时间 */
} Data_ONE_F202;

/* 功能码Fn=203"当前组合有功需量"数据结构 */
typedef struct {
    Data_Type_23 forward_active_demand;     /* 正向有功需量 */
    Data_Type_23 reverse_active_demand;     /* 反向有功需量 */
    Data_Type_23 combination_active_demand; /* 组合有功需量 */
} Data_ONE_F203;

/* 功能码Fn=204"当前组合无功需量"数据结构 */
typedef struct {
    Data_Type_23 forward_reactive_demand;     /* 正向无功需量 */
    Data_Type_23 reverse_reactive_demand;     /* 反向无功需量 */
    Data_Type_23 combination_reactive_demand; /* 组合无功需量 */
} Data_ONE_F204;

/* 功能码Fn=205"电能表编号"数据结构 */
typedef struct {
    BYTE meter_number[16]; /* 电能表编号 */
} Data_ONE_F205;

/* 功能码Fn=211"用户自定义数据"数据结构 */
typedef struct {
    BYTE user_data[64]; /* 用户自定义数据 */
} Data_ONE_F211;

/* 功能码Fn=212"掉电数据"数据结构 */
typedef struct {
    Data_Type_14  last_active_energy; /* 上次掉电有功电能 */
    GB_12241_TIME power_off_time;     /* 掉电时间 */
    GB_12241_TIME power_on_time;      /* 上电时间 */
} Data_ONE_F212;

/* 功能码Fn=213"事件记录"数据结构 */
typedef struct {
    BYTE          event_code;     /* 事件代码 */
    GB_12241_TIME event_time;     /* 事件发生时间 */
    BYTE          event_data[32]; /* 事件数据 */
} Data_ONE_F213;

/* 功能码Fn=214"分时时段表"数据结构 */
typedef struct {
    BYTE period_count; /* 时段数 */
    struct {
        BYTE start_hour;   /* 起始小时 */
        BYTE start_minute; /* 起始分钟 */
        BYTE tariff;       /* 费率号 */
    } periods[14];         /* 最多14个时段 */
} Data_ONE_F214;

/* 功能码Fn=220"开关状态"数据结构 */
typedef struct {
    BYTE relay_status;   /* 继电器状态 0-断开 1-闭合 */
    BYTE control_status; /* 控制状态 0-本地 1-远程 */
} Data_ONE_F220;

/* 功能码Fn=221"告警状态"数据结构 */
typedef struct {
    DWORD alarm_status; /* 告警状态位图 */
    struct {
        BYTE          alarm_code; /* 告警代码 */
        GB_12241_TIME alarm_time; /* 告警时间 */
    } last_alarm;                 /* 最近一次告警 */
} Data_ONE_F221;

/* 功能码Fn=222"计量点状态"数据结构 */
typedef struct {
    BYTE  meter_status;         /* 计量点状态 */
    BYTE  communication_status; /* 通信状态 */
    DWORD error_code;           /* 错误代码 */
} Data_ONE_F222;

/* 功能码Fn=250"负荷控制参数"数据结构 */
typedef struct {
    Data_Type_9 max_demand_threshold; /* 最大需量限值 */
    Data_Type_9 overload_threshold;   /* 过载限值 */
    BYTE        control_mode;         /* 控制方式 */
    BYTE        action_delay;         /* 动作延时(秒) */
} Data_ONE_F250;

/* 相关函数声明 */
float data_type_250_getvalue(const Data_ONE_F250 *data);

//一字节对齐
#pragma pack(push, 1)
/* 集中器数据结构 F12 */
typedef struct {
    BYTE di_status[139]; /* DI0-DI138状态: 实际IO、外电源、预留DI和外设通信状态,
                            0xEE表示无效 */
    DWORD ai_values[4]; /* AI0-AI3数值: 电池电压和预留AI, 0xEEEEEEEE表示无效 */
    DWORD ci_values[4]; /* CI0-CI3数值: 脉冲计数, 0xEEEEEEEE表示无效 */
} Data_F12;
#pragma pack(pop)

/* 集中器单个遥信点结构 */
typedef struct {
    BYTE status; /* 遥信状态: 0或1, 0xEE表示无效 */
} Data_F12_DI;

/* 集中器单个遥测点结构 */
typedef struct {
    DWORD value; /* 遥测值, 0xEEEEEEEE表示无效 */
} Data_F12_AI;

/* 集中器单个脉冲计数结构 */
typedef struct {
    DWORD count; /* 脉冲计数值, 0xEEEEEEEE表示无效 */
} Data_F12_CI;

/* 附A.29 %数据 */
typedef struct {
    BYTE BUNIT;   /* 单位(备用) */
    BYTE BFW : 4; /* 百分位 */
    BYTE SFW : 4; /* 十分位 */
    BYTE GW : 4;  /* 个位 */
    BYTE SW : 4;  /* 十位 */
    BYTE BW : 4;  /* 百位 */
    BYTE QW : 4;  /* 千位 */
    BYTE WW : 4;  /* 万位 */
    BYTE SWW : 4; /* 十万位 */
} Data_Type_29;

float data_type_29_getvalue(const Data_Type_29 *data);
BYTE  data_type_29_getflag(const Data_Type_29 *data);

/* 附A.36 %数据 */
typedef struct {
    BYTE BUNIT;   /* 单位(备用) */
    BYTE BFW : 4; /* 百分位 */
    BYTE SFW : 4; /* 十分位 */
    BYTE GW : 4;  /* 个位 */
    BYTE SW : 3;  /* 十位 */
    BYTE S : 1;   /* 符号位 */
} Data_Type_36;

float data_type_36_getvalue(const Data_Type_36 *data);
BYTE  data_type_36_getflag(const Data_Type_36 *data);

/* 附A.37 %数据 */
typedef struct {
    BYTE BUNIT;   /* 单位(备用) */
    BYTE SFW : 4; /* 十分位 */
    BYTE GW : 4;  /* 个位 */
    BYTE SW : 4;  /* 十位 */
    BYTE BW : 4;  /* 百位 */
    BYTE QW : 4;  /* 千位 */
    BYTE WW : 4;  /* 万位 */
} Data_Type_37;

float data_type_37_getvalue(const Data_Type_37 *data);
BYTE  data_type_37_getflag(const Data_Type_37 *data);

/* 附A.38 %数据 */
typedef struct {
    BYTE BUNIT;   /* 单位(备用) */
    BYTE GW : 4;  /* 个位 */
    BYTE SW : 4;  /* 十位 */
    BYTE BW : 4;  /* 百位 */
    BYTE QW : 4;  /* 千位 */
    BYTE WW : 4;  /* 万位 */
    BYTE SWW : 4; /* 十万位 */
    BYTE BWW : 4; /* 百万位 */
    BYTE QWW : 4; /* 千万位 */
    BYTE YW : 4;  /* 亿位 */
    BYTE SYW : 4; /* 十亿位 */
    BYTE BYW : 4; /* 百亿位 */
    BYTE QYW : 4; /* 千亿位 */
} Data_Type_38;

double data_type_38_getvalue(const Data_Type_38 *data);
BYTE   data_type_38_getflag(const Data_Type_38 *data);

/* 附A.39 %数据 */
typedef struct {
    BYTE BFW : 4; /* 百分位 */
    BYTE SFW : 4; /* 十分位 */
    BYTE GW : 4;  /* 个位 */
    BYTE SW : 4;  /* 十位 */
    BYTE BW : 4;  /* 百位 */
    BYTE QW : 4;  /* 千位 */
    BYTE WW : 4;  /* 万位 */
    BYTE SWW : 4; /* 十万位 */
    BYTE BWW : 4; /* 百万位 */
    BYTE QWW : 4; /* 千万位 */
    BYTE YW : 4;  /* 亿位 */
    BYTE SYW : 4; /* 十亿位 */
} Data_Type_39;

double data_type_39_getvalue(const Data_Type_39 *data);
BYTE   data_type_39_getflag(const Data_Type_39 *data);

/* 附A.40 %数据 */
typedef struct {
    BYTE BUNIT;     /* 单位(备用) */
    BYTE BDECIMALS; /* 小数位数，0xEE：无效，0~10：小数位数 */
    BYTE GW : 4;    /* 个位 */
    BYTE SW : 4;    /* 十位 */
    BYTE BW : 4;    /* 百位 */
    BYTE QW : 4;    /* 千位 */
    BYTE WW : 4;    /* 万位 */
    BYTE SWW : 4;   /* 十万位 */
    BYTE BWW : 4;   /* 百万位 */
    BYTE QWW : 4;   /* 千万位 */
    BYTE YW : 4;    /* 亿位 */
    BYTE SYW : 3;   /* 十亿位 */
    BYTE S : 1;     /* 符号 */
} Data_Type_40;

double data_type_40_getvalue(const Data_Type_40 *data);
BYTE   data_type_40_getflag(const Data_Type_40 *data);

/* 时标Tp定义 */
typedef struct {
    BYTE PFC : 8;
    BYTE SecondL : 4; /* 秒十位 */
    BYTE SecondH : 4; /* 秒个位 */
    BYTE MinutesL : 4;
    BYTE MinutesH : 4;
    BYTE HourL : 4;
    BYTE HourH : 4;
    BYTE DayL : 4;
    BYTE DayH : 4;
    BYTE DeMin : 8;
} Tp;

/* 小时冻结类数据时标 */
typedef struct {
    BYTE HourL : 4;
    BYTE HourH : 2;
    BYTE BK : 2;      /* 备用 */
    BYTE density : 8; /* 冻结密度 */
} Td_h;

/* 日冻结类数据时标 */
typedef struct {
    GB_12241_YMD_TIME time;
} Td_d;

/* 月冻结类数据时标 */
typedef struct {
    GB_12241_MY_TIME time;
} Td_m;

/* 曲线类数据时标 */
typedef struct {
    GB_12241_MHDMYTIME time;
    BYTE               density;
    BYTE               Nums;
} Td_c;

/* 曲线类数据时标扩展 */
typedef struct {
    GB_12241_MHDMYTIME time;
    BYTE               density;
    int                Nums;
} Td_c_ex;

/* 一类数据F129 :当前正向有功电能示值（总，费率1-M） */
typedef struct {
    GB_12241_MHDMYTIME time;
    /* 费率个数,本协议中费率类型固定为尖、峰、平、谷4种，加上总一共5种 */
    BYTE tarrif;
    /* 功率 */
    Data_Type_14 tarrif_Total;  /* 总 */
    Data_Type_14 tarrif_Sharp;  /* 尖 */
    Data_Type_14 tarrif_Peak;   /* 峰 */
    Data_Type_14 tarrif_Ground; /* 平 */
    Data_Type_14 tarrif_Valley; /* 谷 */
} Data_ONE_F129_EX;

/* 一类数据F130 :当前正向无功（组合无功）电能示值（总，费率1-M） */
typedef struct {
    GB_12241_MHDMYTIME time;
    /* 费率个数,本协议中费率类型固定为尖、峰、平、谷4种，加上总一共5种 */
    BYTE tarrif;
    /* 功率 */
    Data_Type_11 tarrif_Total;  /* 总 */
    Data_Type_11 tarrif_Sharp;  /* 尖 */
    Data_Type_11 tarrif_Peak;   /* 峰 */
    Data_Type_11 tarrif_Ground; /* 平 */
    Data_Type_11 tarrif_Valley; /* 谷 */
} Data_ONE_F130_EX;

/* 通用电能数据结构：用于F829-F832这四种相同结构的电能数据 */
typedef struct {
    GB_12241_MHDMYTIME time;
    /* 费率个数,本协议中费率类型固定为尖、峰、平、谷4种，加上总一共5种 */
    BYTE tarrif;
    /* 功率 */
    Data_Type_39 tarrif_Total;  /* 总 */
    Data_Type_39 tarrif_Sharp;  /* 尖 */
    Data_Type_39 tarrif_Peak;   /* 峰 */
    Data_Type_39 tarrif_Ground; /* 平 */
    Data_Type_39 tarrif_Valley; /* 谷 */
} Data_ONE_Energy;

/* 一类数据F829 :当前正向有功电能示值（总，费率1-M） */
typedef Data_ONE_Energy Data_ONE_F829;

/* 一类数据F830 :当前正向无功电能示值（总，费率1-M） */
typedef Data_ONE_Energy Data_ONE_F830;

/* 一类数据F831 :当前反向有功电能示值（总，费率1-M） */
typedef Data_ONE_Energy Data_ONE_F831;

/* 一类数据F832 :当前反向无功电能示值（总，费率1-M） */
typedef Data_ONE_Energy Data_ONE_F832;

/* 一类数据F145 :当月正向有功最大需量及发生时间 */
typedef struct {
    GB_12241_MHDMYTIME time;
    /* 费率个数,本协议中费率类型固定为尖、峰、平、谷4种，加上总一共5种 */
    BYTE tarrif;
    /* 功率 */
    Data_Type_23       tarrif_Total; /* 总 */
    GB_12241_MDHM_TIME total_time;
    Data_Type_23       tarrif_Sharp; /* 尖 */
    GB_12241_MDHM_TIME sharp_time;
    Data_Type_23       tarrif_Peak; /* 峰 */
    GB_12241_MDHM_TIME peak_time;
    Data_Type_23       tarrif_Ground; /* 平 */
    GB_12241_MDHM_TIME ground_time;
    Data_Type_23       tarrif_Valley; /* 谷 */
    GB_12241_MDHM_TIME valley_time;
} Data_ONE_F145_EX;

/* 一类数据F146 :当月正向无功最大需量及发生时间 */
typedef struct {
    GB_12241_MHDMYTIME time;
    /* 费率个数,本协议中费率类型固定为尖、峰、平、谷4种，加上总一共5种 */
    BYTE tarrif;
    /* 功率 */
    Data_Type_23       tarrif_Total; /* 总 */
    GB_12241_MDHM_TIME total_time;
    Data_Type_23       tarrif_Sharp; /* 尖 */
    GB_12241_MDHM_TIME sharp_time;
    Data_Type_23       tarrif_Peak; /* 峰 */
    GB_12241_MDHM_TIME peak_time;
    Data_Type_23       tarrif_Ground; /* 平 */
    GB_12241_MDHM_TIME ground_time;
    Data_Type_23       tarrif_Valley; /* 谷 */
    GB_12241_MDHM_TIME valley_time;
} Data_ONE_F146_EX;

/* 一类数据F147 :当月反向有功最大需量及发生时间 */
typedef struct {
    GB_12241_MHDMYTIME time;
    /* 费率个数,本协议中费率类型固定为尖、峰、平、谷4种，加上总一共5种 */
    BYTE tarrif;
    /* 功率 */
    Data_Type_23       tarrif_Total; /* 总 */
    GB_12241_MDHM_TIME total_time;
    Data_Type_23       tarrif_Sharp; /* 尖 */
    GB_12241_MDHM_TIME sharp_time;
    Data_Type_23       tarrif_Peak; /* 峰 */
    GB_12241_MDHM_TIME peak_time;
    Data_Type_23       tarrif_Ground; /* 平 */
    GB_12241_MDHM_TIME ground_time;
    Data_Type_23       tarrif_Valley; /* 谷 */
    GB_12241_MDHM_TIME valley_time;
} Data_ONE_F147_EX;

/* 一类数据F148 :当月反向无功最大需量及发生时间 */
typedef struct {
    GB_12241_MHDMYTIME time;
    /* 费率个数,本协议中费率类型固定为尖、峰、平、谷4种，加上总一共5种 */
    BYTE tarrif;
    /* 功率 */
    Data_Type_23       tarrif_Total; /* 总 */
    GB_12241_MDHM_TIME total_time;
    Data_Type_23       tarrif_Sharp; /* 尖 */
    GB_12241_MDHM_TIME sharp_time;
    Data_Type_23       tarrif_Peak; /* 峰 */
    GB_12241_MDHM_TIME peak_time;
    Data_Type_23       tarrif_Ground; /* 平 */
    GB_12241_MDHM_TIME ground_time;
    Data_Type_23       tarrif_Valley; /* 谷 */
    GB_12241_MDHM_TIME valley_time;
} Data_ONE_F148_EX;

/* 一类数据F161 : 正向有功日冻结 */
typedef struct {
    Td_d               td_d;
    GB_12241_MHDMYTIME collecttime;
    /* 费率个数,本协议中费率类型固定为尖、峰、平、谷4种，加上总一共5种 */
    BYTE tarrif;
    /* 功率 */
    Data_Type_14 tarrif_Total;  /* 总 */
    Data_Type_14 tarrif_Sharp;  /* 尖 */
    Data_Type_14 tarrif_Peak;   /* 峰 */
    Data_Type_14 tarrif_Ground; /* 平 */
    Data_Type_14 tarrif_Valley; /* 谷 */
} Data_TWO_F161_EX;

/* 一类数据F162 : 正向无功日冻结 */
typedef struct {
    Td_d               td_d;
    GB_12241_MHDMYTIME collecttime;
    /* 费率个数,本协议中费率类型固定为尖、峰、平、谷4种，加上总一共5种 */
    BYTE tarrif;
    /* 功率 */
    Data_Type_11 tarrif_Total;  /* 总 */
    Data_Type_11 tarrif_Sharp;  /* 尖 */
    Data_Type_11 tarrif_Peak;   /* 峰 */
    Data_Type_11 tarrif_Ground; /* 平 */
    Data_Type_11 tarrif_Valley; /* 谷 */
} Data_TWO_F162_EX;

/* 一类数据F163 : 反向有功日冻结 */
typedef struct {
    Td_d               td_d;
    GB_12241_MHDMYTIME collecttime;
    /* 费率个数,本协议中费率类型固定为尖、峰、平、谷4种，加上总一共5种 */
    BYTE tarrif;
    /* 功率 */
    Data_Type_14 tarrif_Total;  /* 总 */
    Data_Type_14 tarrif_Sharp;  /* 尖 */
    Data_Type_14 tarrif_Peak;   /* 峰 */
    Data_Type_14 tarrif_Ground; /* 平 */
    Data_Type_14 tarrif_Valley; /* 谷 */
} Data_TWO_F163_EX;

/* 一类数据F164 : 反向无功日冻结 */
typedef struct {
    Td_d               td_d;
    GB_12241_MHDMYTIME collecttime;
    /* 费率个数,本协议中费率类型固定为尖、峰、平、谷4种，加上总一共5种 */
    BYTE tarrif;
    /* 功率 */
    Data_Type_11 tarrif_Total;  /* 总 */
    Data_Type_11 tarrif_Sharp;  /* 尖 */
    Data_Type_11 tarrif_Peak;   /* 峰 */
    Data_Type_11 tarrif_Ground; /* 平 */
    Data_Type_11 tarrif_Valley; /* 谷 */
} Data_TWO_F164_EX;

/* 一类数据F402:水表运行状态字及其变位标志 */
typedef struct {
    GB_12241_MHDMYTIME time;
    Data_Type_BS16     BWS1; /* 变位标志1(备) */
    Data_Type_BS16     BWS2; /* 变位标志2(备) */
    Data_Type_BS16     BWS3; /* 变位标志3(备) */
    Data_Type_BS16     BWS4; /* 变位标志4(备) */
    Data_Type_BS16     S1;   /* 状态标志1 */
    Data_Type_BS16     S2;   /* 状态标志2 */
    Data_Type_BS16     S3;   /* 状态标志3 */
    Data_Type_BS16     S4;   /* 状态标志4 */
} Data_ONE_F402;

/* 水表流速及压力结构 F403 */
typedef struct {
    Data_Type_7 flow_rate; /* 流速 */
    Data_Type_7 pressure;  /* 压力 */
} Data_F403;

/* 水表当前瞬时流量及压力结构 F403 (带时间) */
typedef struct {
    GB_12241_MHDMYTIME time;   /* 时间 */
    Data_Type_29       data_L; /* 当前瞬时流量 */
    Data_Type_37       data_P; /* 压力 */
} Data_ONE_F403;

/* 水表累积流量结构 F404 */

/* 水表当前正向总累积流量示值结构 F404 (带时间) */
typedef struct {
    GB_12241_MHDMYTIME time;    /* 时间 */
    Data_Type_38       data_ZL; /* 当前正向总累积流量示值 */
} Data_ONE_F404;

/* 气表运行状态字及其变位标志结构 F502 (带时间) */
typedef struct {
    GB_12241_MHDMYTIME time; /* 时间 */
    Data_Type_BS16     BWS1; /* 变位标志1(备) */
    Data_Type_BS16     BWS2; /* 变位标志2(备) */
    Data_Type_BS16     BWS3; /* 变位标志3(备) */
    Data_Type_BS16     BWS4; /* 变位标志4(备) */
    Data_Type_BS16     S1;   /* 状态标志1 */
    Data_Type_BS16     S2;   /* 状态标志2 */
    Data_Type_BS16     S3;   /* 状态标志3 */
    Data_Type_BS16     S4;   /* 状态标志4 */
} Data_ONE_F502;

/* 气表流速及压力结构 F503 (带时间) */
typedef struct {
    GB_12241_MHDMYTIME time;    /* 时间 */
    Data_Type_29       data_BL; /* 00 当前气体流速(标况) */
    Data_Type_29       data_GL; /* 00 当前气体流速(工况) */
    Data_Type_37       data_P;  /* 01 压力 */
    Data_Type_37       data_T;  /* 02 温度 */
} Data_ONE_F503;

/* 气表累积流量结构 F504 (带时间) */
typedef struct {
    GB_12241_MHDMYTIME time; /* 时间 */
    Data_Type_38 data_BL;    /* 00 当前正向总累积流量示值(标况) */
    Data_Type_38 data_GL;    /* 00 当前正向总累积流量示值(工况) */
} Data_ONE_F504;

/* 热量表运行状态字及其变位标志结构 F602 (带时间) */
typedef struct {
    GB_12241_MHDMYTIME time; /* 时间 */
    Data_Type_BS16     BWS1; /* 变位标志1(备) */
    Data_Type_BS16     BWS2; /* 变位标志2(备) */
    Data_Type_BS16     BWS3; /* 变位标志3(备) */
    Data_Type_BS16     BWS4; /* 变位标志4(备) */
    Data_Type_BS16     S1;   /* 状态标志1 */
    Data_Type_BS16     S2;   /* 状态标志2 */
    Data_Type_BS16     S3;   /* 状态标志3 */
    Data_Type_BS16     S4;   /* 状态标志4 */
} Data_ONE_F602;

/* 热量表累积流量、热量、冷量，温度、流速、压力结构 F603 (带时间) */
typedef struct {
    GB_12241_MHDMYTIME time;    /* 时间 */
    Data_Type_38       data_SL; /* 00 累积流量 */
    Data_Type_38       data_SH; /* 01 累积热量 */
    Data_Type_38       data_SC; /* 02 累积冷量 */
    Data_Type_36       data_GT; /* 03 当前供水温度 */
    Data_Type_36       data_HT; /* 04 当前回水温度 */
    Data_Type_29       data_L;  /* 05 当前流速 */
    Data_Type_37       data_P;  /* 06 压力 */
} Data_ONE_F603;

/* 电表扩展结构 */
typedef struct {
    GB_12241_MHDMYTIME time;    /* 时间 */
    Data_Type_9        data_PX; /* 有功功率 */
} Data_ONE_F900;

typedef struct {
    GB_12241_MHDMYTIME time;   /* 时间 */
    Data_Type_6        data_F; /* 电网频率 */
} Data_ONE_F901;

typedef struct {
    Data_Type_14 energy_data; /* 电度数据 */
    BYTE         curve_id;    /* 曲线标识 */
} Data_F801;

/* 一类数据F861 : 正向有功日冻结 */
typedef struct {
    Td_d               td_d;
    GB_12241_MHDMYTIME collecttime;
    /* 费率个数,本协议中费率类型固定为尖、峰、平、谷4种，加上总一共5种 */
    BYTE tarrif;
    /* 功率 */
    Data_Type_39 tarrif_Total;  /* 总 */
    Data_Type_39 tarrif_Sharp;  /* 尖 */
    Data_Type_39 tarrif_Peak;   /* 峰 */
    Data_Type_39 tarrif_Ground; /* 平 */
    Data_Type_39 tarrif_Valley; /* 谷 */
} Data_TWO_F861_EX;

/* 二类数据F409 : 水表日冻结正向累积流量示值 */
typedef struct {
    Td_d               td_d;
    GB_12241_MHDMYTIME collecttime;
    /* Data_Type_29 total;        //正向总流量示值.标准类型,保留 */
    Data_Type_38 total; /* 正向总流量示值 */
} Data_TWO_F409;

/* 二类数据F509 : 气表日冻结正向累积流量示值 */
typedef struct {
    Td_d               td_d;
    GB_12241_MHDMYTIME collecttime;
    /* Data_Type_29 total;        //正向总流量示值.标准类型,保留 */
    Data_Type_38 total; /* 正向总流量示值 */
} Data_TWO_F509;

/* 二类数据F601 : 热量表日冻结热量示值 */
typedef struct {
    Td_d               td_d;
    GB_12241_MHDMYTIME collecttime;
    /* Data_Type_29 total;        //日冻结热量示值.标准版,保留 */
    Data_Type_38 total; /* 日冻结热量示值 */
} Data_TWO_F601;

/* 信息点单元定义 */
typedef struct {
    unsigned char bInfoPointUnit;  /* 信息点元(按位表示8个信息点) */
    unsigned char bInfoPointGroup; /* 信息点组(按位表示8个信息组) */
    unsigned char bInfoTypeUnit; /* 信息类元(按位表示8种信息类型) */
    unsigned char bInfoTypeGroup; /* 信息类组(二进制编码) */
} DATA_UNIT_ID;

/* 位定义宏 */
#define BIT0 0x00000001
#define BIT1 0x00000002
#define BIT2 0x00000004
#define BIT3 0x00000008
#define BIT4 0x00000010
#define BIT5 0x00000020
#define BIT6 0x00000040
#define BIT7 0x00000080
#define BIT8 0x00000100
#define BIT9 0x00000200
#define BIT10 0x00000400
#define BIT11 0x00000800
#define BIT12 0x00001000
#define BIT13 0x00002000
#define BIT14 0x00004000
#define BIT15 0x00008000
#define BIT16 0x00010000
#define BIT17 0x00020000
#define BIT18 0x00040000
#define BIT19 0x00080000
#define BIT20 0x00100000
#define BIT21 0x00200000
#define BIT22 0x00400000
#define BIT23 0x00800000
#define BIT24 0x01000000
#define BIT25 0x02000000
#define BIT26 0x04000000
#define BIT27 0x08000000
#define BIT28 0x10000000
#define BIT29 0x20000000
#define BIT30 0x40000000
#define BIT31 0x80000000

/* Fn和pn定义 */
#define p0 0                /* 终端信息点 */
#define ALL_INFO_POINT 2049 /* 全体信息点 */
#define INVALID_PN_FN 65535 /* 无效的pn或Fn */

/* 功能测试宏 */
#define TEST_BIT(value, p) ((unsigned int) (value) & (p)) /* p = BIT0~31 */

#ifdef __cplusplus
}
#endif

#endif /* GB_12241_POINT_H */
