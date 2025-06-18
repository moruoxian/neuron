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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Neuron核心头文件 */
#include <adapter.h>
#include <neuron.h>
#include <plugin.h>
#include <utils/log.h>

#include "12241_point.h"

/* 检查是否有效的数字(0-9) */
#define IS_VALID_DIGIT(x) ((int) (x) < 10)

/* 定义数据类型验证宏 */
#define VALIDATE_DATA5(d)                                  \
    (IS_VALID_DIGIT((d)->SW) && IS_VALID_DIGIT((d)->GW) && \
     IS_VALID_DIGIT((d)->SFW) && IS_VALID_DIGIT((d)->BW))

#define VALIDATE_DATA6(d)                                  \
    (IS_VALID_DIGIT((d)->SW) && IS_VALID_DIGIT((d)->GW) && \
     IS_VALID_DIGIT((d)->SFW) && IS_VALID_DIGIT((d)->BFW))

#define VALIDATE_DATA7(d)                                  \
    (IS_VALID_DIGIT((d)->SW) && IS_VALID_DIGIT((d)->GW) && \
     IS_VALID_DIGIT((d)->SFW) && IS_VALID_DIGIT((d)->BW))

#define VALIDATE_DATA8(d)                                  \
    (IS_VALID_DIGIT((d)->SW) && IS_VALID_DIGIT((d)->GW) && \
     IS_VALID_DIGIT((d)->BW) && IS_VALID_DIGIT((d)->QW))

#define VALIDATE_DATA9(d)                                    \
    (IS_VALID_DIGIT((d)->SW) && IS_VALID_DIGIT((d)->GW) &&   \
     IS_VALID_DIGIT((d)->SFW) && IS_VALID_DIGIT((d)->BFW) && \
     IS_VALID_DIGIT((d)->QFW) && IS_VALID_DIGIT((d)->WFW))

#define VALIDATE_DATA11(d)                                  \
    (IS_VALID_DIGIT((d)->SWW) && IS_VALID_DIGIT((d)->WW) && \
     IS_VALID_DIGIT((d)->QW) && IS_VALID_DIGIT((d)->BW) &&  \
     IS_VALID_DIGIT((d)->SW) && IS_VALID_DIGIT((d)->GW) &&  \
     IS_VALID_DIGIT((d)->SFW) && IS_VALID_DIGIT((d)->BFW))

#define VALIDATE_DATA14(d)                                   \
    (IS_VALID_DIGIT((d)->SWW) && IS_VALID_DIGIT((d)->WW) &&  \
     IS_VALID_DIGIT((d)->QW) && IS_VALID_DIGIT((d)->BW) &&   \
     IS_VALID_DIGIT((d)->SW) && IS_VALID_DIGIT((d)->GW) &&   \
     IS_VALID_DIGIT((d)->SFW) && IS_VALID_DIGIT((d)->BFW) && \
     IS_VALID_DIGIT((d)->QFW) && IS_VALID_DIGIT((d)->WFW))

#define VALIDATE_DATA23(d)                                   \
    (IS_VALID_DIGIT((d)->SW) && IS_VALID_DIGIT((d)->GW) &&   \
     IS_VALID_DIGIT((d)->SFW) && IS_VALID_DIGIT((d)->BFW) && \
     IS_VALID_DIGIT((d)->QFW) && IS_VALID_DIGIT((d)->WFW))

#define VALIDATE_DATA25(d)                                   \
    (IS_VALID_DIGIT((d)->SW) && IS_VALID_DIGIT((d)->GW) &&   \
     IS_VALID_DIGIT((d)->SFW) && IS_VALID_DIGIT((d)->BFW) && \
     IS_VALID_DIGIT((d)->QFW) && IS_VALID_DIGIT((d)->BW))

/* 数据类型值获取函数实现 */

/* 附A.5 %数据 - 符号XXX.X格式 */
float data_type_5_getvalue(const Data_Type_5 *data)
{
    /* 只检查可能达到或超过10的字段，对于位宽小于4的字段避免检查 */
    if (data->GW < 10 && data->SFW < 10) {
        return (data->S ? (-1) : (1)) *
            (data->BW * 100 + data->SW * 10 + data->GW + data->SFW * 0.1);
    } else {
        return 0;
    }
}

uint8_t data_type_5_getflag(const Data_Type_5 *data)
{
    /* 对于位宽较小的字段(S:1位,BW:3位,SW:4位),检查>=10可能会导致编译器警告
       因此我们只检查可能达到或超过10的字段 */
    if (data->SFW >= 10 || data->GW >= 10) {
        return 0; /* 无效 */
    }
    return 1; /* 有效 */
}

/* 附A.6 %数据 - 符号XX.XX格式 */
float data_type_6_getvalue(const Data_Type_6 *data)
{
    /* 只检查可能达到或超过10的字段 */
    if (data->GW < 10 && data->SFW < 10 && data->BFW < 10) {
        return (data->S ? (-1) : (1)) *
            (data->SW * 10 + data->GW + data->SFW * 0.1 + data->BFW * 0.01);
    } else {
        return 0;
    }
}

uint8_t data_type_6_getflag(const Data_Type_6 *data)
{
    /* 同样，对于S:1位和SW:3位可能会有编译器警告，所以只检查4位字段 */
    if (data->SFW >= 10 || data->BFW >= 10 || data->GW >= 10) {
        return 0; /* 无效 */
    }
    return 1; /* 有效 */
}

/* 附A.7 %数据 - XXX.X格式 */
float data_type_7_getvalue(const Data_Type_7 *data)
{
    if (data->GW < 10 && data->SFW < 10 && data->BW < 10 && data->SW < 10) {
        return data->BW * 100 + data->SW * 10 + data->GW + data->SFW * 0.1;
    } else {
        return 0;
    }
}

uint8_t data_type_7_getflag(const Data_Type_7 *data)
{
    if (data->SFW >= 10 || data->GW >= 10 || data->SW >= 10 || data->BW >= 10) {
        return 0; /* 无效 */
    }
    return 1; /* 有效 */
}

/* 附A.8 %数据 - XXXX格式 */
int data_type_8_getvalue(const Data_Type_8 *data)
{
    if (data->SW < 10 && data->GW < 10 && data->BW < 10 && data->QW < 10) {
        return data->QW * 1000 + data->BW * 100 + data->SW * 10 + data->GW;
    } else {
        return 0;
    }
}

uint8_t data_type_8_getflag(const Data_Type_8 *data)
{
    if (data->SW >= 10 || data->GW >= 10 || data->BW >= 10 || data->QW >= 10) {
        return 0; /* 无效 */
    }
    return 1; /* 有效 */
}

/* 附A.9 %数据 - 符号XX.XXXX格式 */
float data_type_9_getvalue(const Data_Type_9 *data)
{
    /* 避免对位宽为3位的SW字段进行检查 */
    if (data->GW < 10 && data->SFW < 10 && data->BFW < 10 && data->QFW < 10 &&
        data->WFW < 10) {
        float i = (data->S ? (-1) : (1)) *
            (data->SW * 10 + data->GW + data->SFW * 0.1 + data->BFW * 0.01 +
             data->QFW * 0.001 + data->WFW * 0.0001);
        return i;
    } else {
        return 0;
    }
}

uint8_t data_type_9_getflag(const Data_Type_9 *data)
{
    /* S字段为1位宽，SW字段为3位宽，检查>=10可能会导致编译器警告 */
    if (data->WFW >= 10 || data->QFW >= 10 || data->BFW >= 10 ||
        data->SFW >= 10 || data->GW >= 10) {
        return 0; /* 无效 */
    }
    return 1; /* 有效 */
}

/* 附A.11 %数据 - XXXXXX.XX格式 */
float data_type_11_getvalue(const Data_Type_11 *data)
{
    if (data->SFW < 10 && data->BFW < 10 && data->SW < 10 && data->GW < 10 &&
        data->BW < 10 && data->QW < 10 && data->WW < 10 && data->SWW < 10) {
        float i = (data->SWW * 100000 + data->WW * 10000 + data->QW * 1000 +
                   data->BW * 100 + data->SW * 10 + data->GW + data->SFW * 0.1 +
                   data->BFW * 0.01);
        return i;
    } else {
        return 0;
    }
}

uint8_t data_type_11_getflag(const Data_Type_11 *data)
{
    if (data->SFW >= 10 || data->BFW >= 10 || data->SW >= 10 ||
        data->GW >= 10 || data->BW >= 10 || data->QW >= 10 || data->WW >= 10 ||
        data->SWW >= 10) {
        return 0; /* 无效 */
    }
    return 1; /* 有效 */
}

/* 附A.14 %数据 - XXXXXX.XXXX格式 */
float data_type_14_getvalue(const Data_Type_14 *data)
{
    if (data->SFW < 10 && data->BFW < 10 && data->SW < 10 && data->GW < 10 &&
        data->BW < 10 && data->QW < 10 && data->WW < 10 && data->SWW < 10) {
        float i = (data->SWW * 100000 + data->WW * 10000 + data->QW * 1000 +
                   data->BW * 100 + data->SW * 10 + data->GW + data->SFW * 0.1 +
                   data->BFW * 0.01 + data->QFW * 0.001 + data->WFW * 0.0001);
        return i;
    } else {
        return 0;
    }
}

uint8_t data_type_14_getflag(const Data_Type_14 *data)
{
    if (data->WFW >= 10 || data->QFW >= 10 || data->SFW >= 10 ||
        data->BFW >= 10 || data->SW >= 10 || data->GW >= 10 || data->BW >= 10 ||
        data->QW >= 10 || data->WW >= 10 || data->SWW >= 10) {
        return 0; /* 无效 */
    }
    return 1; /* 有效 */
}

/* 附A.23 %数据 - XX.XXXX格式 */
float data_type_23_getvalue(const Data_Type_23 *data)
{
    if (data->SW < 10 && data->GW < 10 && data->SFW < 10 && data->BFW < 10 &&
        data->QFW < 10 && data->WFW < 10) {
        return (data->SW * 10 + data->GW + data->SFW * 0.1 + data->BFW * 0.01 +
                data->QFW * 0.001 + data->WFW * 0.0001);
    } else {
        return 0;
    }
}

uint8_t data_type_23_getflag(const Data_Type_23 *data)
{
    if (data->SW >= 10 || data->GW >= 10 || data->SFW >= 10 ||
        data->BFW >= 10 || data->QFW >= 10 || data->WFW >= 10) {
        return 0; /* 无效 */
    }
    return 1; /* 有效 */
}

/* 附A.25 %数据 - 符号XXX.XXX格式 */
float data_type_25_getvalue(const Data_Type_25 *data)
{
    if (data->SW < 10 && data->GW < 10 && data->SFW < 10 && data->BFW < 10 &&
        data->QFW < 10) {
        return (data->S ? (-1) : (1)) *
            (data->BW * 100 + data->SW * 10 + data->GW + data->SFW * 0.1 +
             data->BFW * 0.01 + data->QFW * 0.001);
    } else {
        return 0;
    }
}

uint8_t data_type_25_getflag(const Data_Type_25 *data)
{
    /* S字段是1位宽，BW是3位宽，可能导致编译器警告，所以只检查其他字段 */
    if (data->QFW >= 10 || data->BFW >= 10 || data->SFW >= 10 ||
        data->GW >= 10 || data->SW >= 10) {
        return 0; /* 无效 */
    }
    return 1; /* 有效 */
}

/* 设置数据时区偏移量 - 北京时间(UTC+8) */
#define BEIJING_TIME_OFFSET (8 * 3600)

/* 从tm结构中给位域赋值 - 代替使用位域地址 */
static void set_time_values(struct tm *tm_ptr, GB_12241_TIME *tm_data)
{
    if (!tm_ptr || !tm_data) {
        return;
    }

    /* 年(2000年以后，00-99表示2000-2099年) */
    tm_data->YearH = (tm_ptr->tm_year - 100) / 10;
    tm_data->YearL = (tm_ptr->tm_year - 100) % 10;

    /* 月(1-12) */
    tm_data->MonthH = (tm_ptr->tm_mon + 1) / 10;
    tm_data->MonthL = (tm_ptr->tm_mon + 1) % 10;

    /* 日(1-31) */
    tm_data->DayH = tm_ptr->tm_mday / 10;
    tm_data->DayL = tm_ptr->tm_mday % 10;

    /* 时分秒 */
    tm_data->HourH    = tm_ptr->tm_hour / 10;
    tm_data->HourL    = tm_ptr->tm_hour % 10;
    tm_data->MinutesH = tm_ptr->tm_min / 10;
    tm_data->MinutesL = tm_ptr->tm_min % 10;
    tm_data->SecondH  = tm_ptr->tm_sec / 10;
    tm_data->SecondL  = tm_ptr->tm_sec % 10;

    /* 星期(1-7) */
    tm_data->Week = ((tm_ptr->tm_wday + 6) % 7 +
                     1); /* 0=星期日,1-6=星期一到星期六 -> 1-7=星期一到星期日 */
}

static void set_ymdhm_time_values(struct tm *          tm_ptr,
                                  GB_12241_YMDHM_TIME *tm_data)
{
    if (!tm_ptr || !tm_data) {
        return;
    }

    /* 年(2000年以后，00-99表示2000-2099年) */
    tm_data->YearH = (tm_ptr->tm_year - 100) / 10;
    tm_data->YearL = (tm_ptr->tm_year - 100) % 10;

    /* 月(1-12) */
    tm_data->MonthH = (tm_ptr->tm_mon + 1) / 10;
    tm_data->MonthL = (tm_ptr->tm_mon + 1) % 10;

    /* 日(1-31) */
    tm_data->DayH = tm_ptr->tm_mday / 10;
    tm_data->DayL = tm_ptr->tm_mday % 10;

    /* 时分 */
    tm_data->HourH    = tm_ptr->tm_hour / 10;
    tm_data->HourL    = tm_ptr->tm_hour % 10;
    tm_data->MinutesH = tm_ptr->tm_min / 10;
    tm_data->MinutesL = tm_ptr->tm_min % 10;
}

static void set_mdhm_time_values(struct tm *tm_ptr, GB_12241_MDHM_TIME *tm_data)
{
    if (!tm_ptr || !tm_data) {
        return;
    }

    /* 月(1-12) */
    tm_data->MonthH = (tm_ptr->tm_mon + 1) / 10;
    tm_data->MonthL = (tm_ptr->tm_mon + 1) % 10;

    /* 日(1-31) */
    tm_data->DayH = tm_ptr->tm_mday / 10;
    tm_data->DayL = tm_ptr->tm_mday % 10;

    /* 时分 */
    tm_data->HourH    = tm_ptr->tm_hour / 10;
    tm_data->HourL    = tm_ptr->tm_hour % 10;
    tm_data->MinutesH = tm_ptr->tm_min / 10;
    tm_data->MinutesL = tm_ptr->tm_min % 10;
}

static void set_ymd_time_values(struct tm *tm_ptr, GB_12241_YMD_TIME *tm_data)
{
    if (!tm_ptr || !tm_data) {
        return;
    }

    /* 年(2000年以后，00-99表示2000-2099年) */
    tm_data->YearH = (tm_ptr->tm_year - 100) / 10;
    tm_data->YearL = (tm_ptr->tm_year - 100) % 10;

    /* 月(1-12) */
    tm_data->MonthH = (tm_ptr->tm_mon + 1) / 10;
    tm_data->MonthL = (tm_ptr->tm_mon + 1) % 10;

    /* 日(1-31) */
    tm_data->DayH = tm_ptr->tm_mday / 10;
    tm_data->DayL = tm_ptr->tm_mday % 10;
}

static void set_mhdmytime_values(struct tm *tm_ptr, GB_12241_MHDMYTIME *tm_data)
{
    if (!tm_ptr || !tm_data) {
        return;
    }

    /* 年(2000年以后，00-99表示2000-2099年) */
    tm_data->YearH = (tm_ptr->tm_year - 100) / 10;
    tm_data->YearL = (tm_ptr->tm_year - 100) % 10;

    /* 月(1-12) */
    tm_data->MonthH = (tm_ptr->tm_mon + 1) / 10;
    tm_data->MonthL = (tm_ptr->tm_mon + 1) % 10;

    /* 日(1-31) */
    tm_data->DayH = tm_ptr->tm_mday / 10;
    tm_data->DayL = tm_ptr->tm_mday % 10;

    /* 时分 */
    tm_data->HourH    = tm_ptr->tm_hour / 10;
    tm_data->HourL    = tm_ptr->tm_hour % 10;
    tm_data->MinutesH = tm_ptr->tm_min / 10;
    tm_data->MinutesL = tm_ptr->tm_min % 10;
}

// /* 设置时间结构与时间戳的转换函数 */
// static time_t adjust_time_to_beijing(time_t t)
// {
//     /* 转换到北京时间(UTC+8) */
//     if (t >= BEIJING_TIME_OFFSET) {
//         t -= BEIJING_TIME_OFFSET;
//     } else {
//         t = 0;
//     }
//     return t;
// }

/* 时间相关函数实现 */
void gb_12241_time_setvalue(GB_12241_TIME *tm_data, time_t t)
{
    struct tm tm_local;

    if (!tm_data) {
        return;
    }

    // t = adjust_time_to_beijing(t);
    if (localtime_r(&t, &tm_local) == NULL) {
        return;
    }

    set_time_values(&tm_local, tm_data);
}

void gb_12241_ymdhm_time_setvalue(GB_12241_YMDHM_TIME *tm_data, time_t t)
{
    struct tm tm_local;

    if (!tm_data) {
        return;
    }

    // t = adjust_time_to_beijing(t);
    if (localtime_r(&t, &tm_local) == NULL) {
        return;
    }

    set_ymdhm_time_values(&tm_local, tm_data);
}

int gb_12241_ymdhm_time_getvalue(const GB_12241_YMDHM_TIME *tm_data)
{
    struct tm tm_time;
    time_t    current_time = 0;

    if (!tm_data) {
        return -1;
    }

    /* 获取当前时间作为基础 */
    current_time = time(NULL);
    if (current_time == (time_t) -1) {
        return -1;
    }

    localtime_r(&current_time, &tm_time);

    /* 使用时间结构中的值覆盖 */
    tm_time.tm_sec  = 0;
    tm_time.tm_min  = tm_data->MinutesH * 10 + tm_data->MinutesL;
    tm_time.tm_hour = tm_data->HourH * 10 + tm_data->HourL;
    tm_time.tm_mday = tm_data->DayH * 10 + tm_data->DayL;
    tm_time.tm_mon  = tm_data->MonthH * 10 + tm_data->MonthL - 1;
    tm_time.tm_year = tm_data->YearH * 10 + tm_data->YearL + 100;

    /* 转换为时间戳 */
    return (int) mktime(&tm_time);
}

void gb_12241_mdhm_time_setvalue(GB_12241_MDHM_TIME *tm_data, time_t t)
{
    struct tm tm_local;

    if (!tm_data) {
        return;
    }

    // t = adjust_time_to_beijing(t);
    if (localtime_r(&t, &tm_local) == NULL) {
        return;
    }

    set_mdhm_time_values(&tm_local, tm_data);
}

int gb_12241_mdhm_time_getvalue(const GB_12241_MDHM_TIME *tm_data)
{
    struct tm tm_time;
    time_t    current_time = 0;

    if (!tm_data) {
        return -1;
    }

    /* 获取当前时间作为基础 */
    current_time = time(NULL);
    if (current_time == (time_t) -1) {
        return -1;
    }

    localtime_r(&current_time, &tm_time);

    /* 使用时间结构中的值覆盖 */
    tm_time.tm_sec  = 0;
    tm_time.tm_min  = tm_data->MinutesH * 10 + tm_data->MinutesL;
    tm_time.tm_hour = tm_data->HourH * 10 + tm_data->HourL;
    tm_time.tm_mday = tm_data->DayH * 10 + tm_data->DayL;
    tm_time.tm_mon  = tm_data->MonthH * 10 + tm_data->MonthL - 1;

    /* 转换为时间戳 */
    return (int) mktime(&tm_time);
}

void gb_12241_ymd_time_setvalue(GB_12241_YMD_TIME *tm_data, time_t t)
{
    struct tm tm_local;

    if (!tm_data) {
        return;
    }

    // t = adjust_time_to_beijing(t);
    if (localtime_r(&t, &tm_local) == NULL) {
        return;
    }

    set_ymd_time_values(&tm_local, tm_data);
}

void gb_12241_mhdmytime_setvalue(GB_12241_MHDMYTIME *tm_data, time_t t)
{
    struct tm tm_local;

    if (!tm_data) {
        return;
    }

    // t = adjust_time_to_beijing(t);
    if (localtime_r(&t, &tm_local) == NULL) {
        return;
    }

    set_mhdmytime_values(&tm_local, tm_data);
}

time_t gb_12241_ymd_time_getvalue(const GB_12241_YMD_TIME *tm_data)
{
    struct tm tm_time;
    time_t    current_time = 0;

    if (!tm_data) {
        return (time_t) -1;
    }

    /* 获取当前时间作为基础 */
    current_time = time(NULL);
    if (current_time == (time_t) -1) {
        return (time_t) -1;
    }

    localtime_r(&current_time, &tm_time);

    /* 使用时间结构中的值覆盖 */
    tm_time.tm_sec  = 0;
    tm_time.tm_min  = 0;
    tm_time.tm_hour = 0;
    tm_time.tm_mday = tm_data->DayH * 10 + tm_data->DayL;
    tm_time.tm_mon  = tm_data->MonthH * 10 + tm_data->MonthL - 1;
    tm_time.tm_year = tm_data->YearH * 10 + tm_data->YearL + 100;

    /* 转换为时间戳 */
    return mktime(&tm_time);
}

/* 数据解析函数实现 */

/* 根据功能码和点号获取数据类型  弃用*/
// int gb_12241_get_data_type(int fn, int pn, int data_index)
// {
//     int i;

//     // 处理集中器特殊数据类型 (F12)
//     if (fn == 12 && pn == 0) {
//         if (data_index >= 0 && data_index <= 138) {
//             // DI数据
//             return DATA_TYPE_F12_DI;
//         } else if (data_index >= 139 && data_index <= 142) {
//             // AI数据
//             return DATA_TYPE_F12_AI;
//         } else if (data_index >= 143 && data_index <= 146) {
//             // CI数据
//             return DATA_TYPE_F12_CI;
//         }
//     }

//     // 默认映射
//     for (i = 0; i < gb_12241_fn_pn_map_size; i++) {
//         if (gb_12241_fn_pn_map[i].fn == fn &&
//             ((pn == 0 && gb_12241_fn_pn_map[i].pn == 0) || /*
//             集中器数据必须精确匹配pn=0 */
//              (pn > 0 && gb_12241_fn_pn_map[i].pn == 1)) && /*
//              其他设备使用pn=1的模板 */
//             gb_12241_fn_pn_map[i].data_index == data_index) {
//             return gb_12241_fn_pn_map[i].data_type;
//         }
//     }
//     return -1; /* 未找到映射 */
// }

/* 检查缓冲区大小并复制数据宏 */
#define CHECK_AND_COPY(type)                      \
    do {                                          \
        if ((size_t) buffer_len < sizeof(type) || \
            (size_t) result_size < sizeof(type))  \
            return -1;                            \
        memcpy(result, buffer, sizeof(type));     \
        return 0;                                 \
    } while (0)

// /* 简化的日志函数 - 在无法使用plog_error的情况下 */
// static void log_error_internal(const char* format, ...)
// {
//     va_list args;
//     va_start(args, format);
//     fprintf(stderr, "[12241_ERROR] ");
//     vfprintf(stderr, format, args);
//     fprintf(stderr, "\n");
//     va_end(args);
// }

// /* 获取解析后的数据值  弃用*/
// float gb_12241_get_value(void *plugin, void* data, int data_type)
// {
//     (void)plugin; /* 此函数只使用plugin指针进行日志记录，不访问其内部结构 */

//     if (!data) {
//         log_error_internal("数据指针为NULL");
//         return 0.0f;
//     }

//     switch (data_type) {
//         case DATA_TYPE_5:
//             return data_type_5_getvalue((Data_Type_5*)data);

//         case DATA_TYPE_6:
//             return data_type_6_getvalue((Data_Type_6*)data);

//         case DATA_TYPE_7:
//             return data_type_7_getvalue((Data_Type_7*)data);

//         case DATA_TYPE_8:
//             return (float)data_type_8_getvalue((Data_Type_8*)data);

//         case DATA_TYPE_9:
//             return data_type_9_getvalue((Data_Type_9*)data);

//         case DATA_TYPE_11:
//             return data_type_11_getvalue((Data_Type_11*)data);

//         case DATA_TYPE_14:
//             return data_type_14_getvalue((Data_Type_14*)data);

//         case DATA_TYPE_23:
//             return data_type_23_getvalue((Data_Type_23*)data);

//         case DATA_TYPE_25:
//             return data_type_25_getvalue((Data_Type_25*)data);

//         // 430集中器特殊数据类型
//         case DATA_TYPE_F12_DI: {
//             Data_F12_DI *di = (Data_F12_DI*)data;
//             if (di->status != 0xEE) {
//                 return (float)di->status;
//             }
//             return 0.0f;
//         }

//         case DATA_TYPE_F12_AI: {
//             Data_F12_AI *ai = (Data_F12_AI*)data;
//             if (ai->value != 0xEEEEEEEE) {
//                 return ai->value;
//             }
//             return 0.0f;
//         }

//         case DATA_TYPE_F12_CI: {
//             Data_F12_CI *ci = (Data_F12_CI*)data;
//             if (ci->count != 0xEEEEEEEE) {
//                 return (float)ci->count;
//             }
//             return 0.0f;
//         }

//         default:
//             log_error_internal("不支持的数据类型从浮点数转换: %d",
//             data_type); return 0.0f;
//     }
// }

/**
 * @brief 获取Data_Type_12的值
 *
 * @param data Data_Type_12类型数据指针
 * @return float 转换后的float类型值
 */
float data_type_12_getvalue(const Data_Type_12 *data)
{
    if (data == NULL) {
        return 0.0f;
    }

    float value          = 0.0f;
    float decimal_factor = 1.0f;

    // 计算小数位数因子
    for (uint8_t i = 0; i < data->decimal; i++) {
        decimal_factor *= 10.0f;
    }

    // 计算整数部分和小数部分
    value = (float) data->integer + ((float) data->fraction / decimal_factor);

    // 应用符号
    if (data->flag) {
        value = -value;
    }

    return value;
}

/**
 * @brief 获取Data_Type_13的值
 *
 * @param data Data_Type_13类型数据指针
 * @return float 转换后的float类型值
 */
float data_type_13_getvalue(const Data_Type_13 *data)
{
    if (data == NULL) {
        return 0.0f;
    }

    float value          = 0.0f;
    float decimal_factor = 1.0f;

    // 计算小数位数因子
    for (uint8_t i = 0; i < data->decimal; i++) {
        decimal_factor *= 10.0f;
    }

    // 计算整数部分和小数部分
    value = (float) data->integer + ((float) data->fraction / decimal_factor);

    // 应用符号
    if (data->flag) {
        value = -value;
    }

    return value;
}

/**
 * @brief 获取Data_Type_12的符号标志
 *
 * @param data Data_Type_12类型数据指针
 * @return uint8_t 符号标志，0为正，1为负
 */
uint8_t data_type_12_getflag(const Data_Type_12 *data)
{
    return data->flag; // 直接返回flag字段
}

/**
 * @brief 获取Data_Type_13的符号标志
 *
 * @param data Data_Type_13类型数据指针
 * @return uint8_t 符号标志，0为正，1为负
 */
uint8_t data_type_13_getflag(const Data_Type_13 *data)
{
    return data->flag; // 直接返回flag字段
}

float data_type_250_getvalue(const Data_ONE_F250 *data)
{
    if (data == NULL) {
        return 0.0f;
    }

    /* 返回最大需量限值 */
    return data_type_9_getvalue(&data->max_demand_threshold);
}

/* Data_Type_29标志位获取函数 - 流量类型 */
BYTE data_type_29_getflag(const Data_Type_29 *data)
{
    if (data == NULL) {
        return 0;
    }

    // 检查各位是否有效
    if (data->SFW >= 10 || data->BFW >= 10 || data->SW >= 10 ||
        data->GW >= 10 || data->BW >= 10 || data->QW >= 10 || data->WW >= 10 ||
        data->SWW >= 10) {
        return 0; // 无效
    }

    return 1; // 有效
}

/* Data_Type_29值获取函数 - 流量类型 */
float data_type_29_getvalue(const Data_Type_29 *data)
{
    if (data == NULL) {
        return 0.0f;
    }

    // 检查数据有效性
    if (!data_type_29_getflag(data)) {
        return 0.0f;
    }

    // 计算值
    float value = data->SWW * 100000.0f + data->WW * 10000.0f +
        data->QW * 1000.0f + data->BW * 100.0f + data->SW * 10.0f + data->GW +
        data->SFW * 0.1f + data->BFW * 0.01f;

    return value;
}

/* Data_Type_36标志位获取函数 - 带符号小数类型 */
BYTE data_type_36_getflag(const Data_Type_36 *data)
{
    if (data == NULL) {
        return 0;
    }
    // 检查各位是否有效
    if (data->BFW >= 10 || data->SFW >= 10 || data->GW >= 10) {
        return 0; // 无效
    }

    return 1; // 有效
}

/* Data_Type_36值获取函数 - 带符号小数类型 */
float data_type_36_getvalue(const Data_Type_36 *data)
{
    if (data == NULL) {
        return 0.0f;
    }

    // 检查数据有效性
    if (!data_type_36_getflag(data)) {
        return 0.0f;
    }

    // 计算值，带符号位
    float value =
        (data->SW * 10.0f + data->GW + data->SFW * 0.1f + data->BFW * 0.01f);
    return (data->S ? -1.0f : 1.0f) * value;
}

/* Data_Type_37标志位获取函数 - 压力和温度类型 */
BYTE data_type_37_getflag(const Data_Type_37 *data)
{
    if (data == NULL) {
        return 0;
    }

    // 检查各位是否有效
    if (data->SW >= 10 || data->GW >= 10 || data->BW >= 10 || data->QW >= 10 ||
        data->WW >= 10 || data->SFW >= 10) {
        return 0; // 无效
    }

    return 1; // 有效
}

/* Data_Type_37值获取函数 - 压力和温度类型 */
float data_type_37_getvalue(const Data_Type_37 *data)
{
    if (data == NULL) {
        return 0.0f;
    }

    // 检查数据有效性
    if (!data_type_37_getflag(data)) {
        return 0.0f;
    }

    // 计算值
    float value = data->WW * 10000.0f + data->QW * 1000.0f + data->BW * 100.0f +
        data->SW * 10.0f + data->GW + data->SFW * 0.1f;

    return value;
}

/* Data_Type_38标志位获取函数 - 累积流量类型 */
BYTE data_type_38_getflag(const Data_Type_38 *data)
{
    if (data == NULL) {
        return 0;
    }

    // 检查各位是否有效
    if (data->GW >= 10 || data->SW >= 10 || data->BW >= 10 || data->QW >= 10 ||
        data->WW >= 10 || data->SWW >= 10 || data->BWW >= 10 ||
        data->QWW >= 10 || data->YW >= 10 || data->SYW >= 10 ||
        data->BYW >= 10 || data->QYW >= 10) {
        return 0; // 无效
    }

    return 1; // 有效
}

/* Data_Type_38值获取函数 - 累积流量类型 */
double data_type_38_getvalue(const Data_Type_38 *data)
{
    if (data == NULL) {
        return 0.0;
    }

    // 检查数据有效性
    if (!data_type_38_getflag(data)) {
        return 0.0;
    }

    // 计算值
    double value = (double) data->QYW * 100000000000.0 +
        (double) data->BYW * 10000000000.0 + (double) data->SYW * 1000000000.0 +
        (double) data->YW * 100000000.0 + (double) data->QWW * 10000000.0 +
        (double) data->BWW * 1000000.0 + (double) data->SWW * 100000.0 +
        (double) data->WW * 10000.0 + (double) data->QW * 1000.0 +
        (double) data->BW * 100.0 + (double) data->SW * 10.0 +
        (double) data->GW;

    return value;
}

/* Data_Type_40标志位获取函数 - 带符号小数类型 */
BYTE data_type_40_getflag(const Data_Type_40 *data)
{
    if (data == NULL) {
        return 0;
    }

    // 检查各位是否有效
    if (data->GW >= 10 || data->SW >= 10 || data->BW >= 10 || data->QW >= 10 ||
        data->WW >= 10 || data->SWW >= 10 || data->BWW >= 10 ||
        data->QWW >= 10 || data->YW >= 10) {
        return 0; // 无效
    }

    return 1; // 有效
}

/* Data_Type_40值获取函数 - 带符号和小数位数的大数值类型 */
double data_type_40_getvalue(const Data_Type_40 *data)
{
    if (data == NULL) {
        return 0.0;
    }

    // 检查数据有效性
    if (!data_type_40_getflag(data)) {
        return 0.0;
    }

    // 计算小数位数系数
    double fBdecimails = 0.0;
    if (data->BDECIMALS > 10) {
        fBdecimails = 1.0;
    } else {
        // 使用pow计算10的负BDECIMALS次方
        fBdecimails = pow(0.1, data->BDECIMALS);
    }

    // 计算整数部分
    double base_value = (double) data->SYW * 1000000000.0 +
        (double) data->YW * 100000000.0 + (double) data->QWW * 10000000.0 +
        (double) data->BWW * 1000000.0 + (double) data->SWW * 100000.0 +
        (double) data->WW * 10000.0 + (double) data->QW * 1000.0 +
        (double) data->BW * 100.0 + (double) data->SW * 10.0 +
        (double) data->GW;

    // 应用符号和小数位
    double value = (data->S ? -1.0 : 1.0) * base_value * fBdecimails;

    return value;
}

/* 通用数据解析函数 */

/* 获取MHDMYTIME的UTC时间值，类似于IDC430MHDMYTIME::getUtcValue */
int gb_12241_mhdmytime_getutcvalue(const GB_12241_MHDMYTIME *tm_data)
{
    time_t     nowtime = time(NULL);
    struct tm  tr;
    struct tm *ptr = &tr;

    ptr         = localtime(&nowtime);
    ptr->tm_sec = 0; /* seconds after the minute - [0,59] */
    ptr->tm_min = tm_data->MinutesH * 10 +
        tm_data->MinutesL; /* minutes after the hour - [0,59] */
    ptr->tm_hour = tm_data->HourH * 10 +
        tm_data->HourL; /* hours since midnight - [0,23] */
    ptr->tm_mday =
        tm_data->DayH * 10 + tm_data->DayL; /* day of the month - [1,31] */
    ptr->tm_mon = tm_data->MonthH * 10 + tm_data->MonthL -
        1; /* months since January - [0,11] */
    ptr->tm_year =
        tm_data->YearH * 10 + tm_data->YearL + 100; /* years since 1900 */

    return (int) mktime(ptr); /* 返回UTC时间值 */
}

/* Data_Type_39 - XXXXXXXXXX.X格式（电能示值） */
double data_type_39_getvalue(const Data_Type_39 *data)
{
    if (data == NULL) {
        return 0.0;
    }

    // 检查数据有效性
    if (!data_type_39_getflag(data)) {
        return 0.0;
    }

    // 使用double类型计算，避免精度损失
    double value = (double) data->SYW * 10000000000.0 +
        (double) data->YW * 1000000000.0 + (double) data->QWW * 100000000.0 +
        (double) data->BWW * 10000000.0 + (double) data->SWW * 1000000.0 +
        (double) data->WW * 100000.0 + (double) data->QW * 10000.0 +
        (double) data->BW * 1000.0 + (double) data->SW * 100.0 +
        (double) data->GW * 10.0 + (double) data->SFW * 1.0;

    return value;
}

/* Data_Type_39标志位获取函数 */
BYTE data_type_39_getflag(const Data_Type_39 *data)
{
    if (data == NULL) {
        return 0;
    }

    // 检查关键位是否有效
    if (data->SFW >= 10 || data->GW >= 10 || data->SW >= 10 || data->BW >= 10 ||
        data->QW >= 10 || data->WW >= 10 || data->SWW >= 10 ||
        data->BWW >= 10 || data->QWW >= 10 || data->YW >= 10 ||
        data->SYW >= 10) {
        return 0; // 无效
    }

    return 1; // 有效
}