#include <stdlib.h>
#include <string.h>

#include <neuron/neuron.h>

#include "opcua_point.h"

int opcua_tag_to_point(const neu_datatag_t *tag, opcua_point_t *point)
{
    if (tag == NULL || point == NULL) {
        return -1;
    }

    // Copy the tag name
    point->name = strdup(tag->name);
    if (point->name == NULL) {
        return -1;
    }

    // Copy the node ID
    point->node_id = strdup(tag->address);
    if (point->node_id == NULL) {
        free(point->name);
        return -1;
    }

    // Set the data type
    point->type    = tag->type;
    point->ua_type = opcua_get_ua_type(tag->type);
    if (point->ua_type == NULL) {
        free(point->name);
        free(point->node_id);
        return -1;
    }

    return 0;
}

UA_DataType *opcua_get_ua_type(neu_type_e type)
{
    switch (type) {
    case NEU_TYPE_INT8:
        return &UA_TYPES[UA_TYPES_SBYTE];
    case NEU_TYPE_UINT8:
        return &UA_TYPES[UA_TYPES_BYTE];
    case NEU_TYPE_INT16:
        return &UA_TYPES[UA_TYPES_INT16];
    case NEU_TYPE_UINT16:
        return &UA_TYPES[UA_TYPES_UINT16];
    case NEU_TYPE_INT32:
        return &UA_TYPES[UA_TYPES_INT32];
    case NEU_TYPE_UINT32:
        return &UA_TYPES[UA_TYPES_UINT32];
    case NEU_TYPE_INT64:
        return &UA_TYPES[UA_TYPES_INT64];
    case NEU_TYPE_UINT64:
        return &UA_TYPES[UA_TYPES_UINT64];
    case NEU_TYPE_FLOAT:
        return &UA_TYPES[UA_TYPES_FLOAT];
    case NEU_TYPE_DOUBLE:
        return &UA_TYPES[UA_TYPES_DOUBLE];
    case NEU_TYPE_BIT:
        return &UA_TYPES[UA_TYPES_BOOLEAN];
    case NEU_TYPE_BOOL:
        return &UA_TYPES[UA_TYPES_BOOLEAN];
    case NEU_TYPE_STRING:
        return &UA_TYPES[UA_TYPES_STRING];
    case NEU_TYPE_TIME:
        return &UA_TYPES[UA_TYPES_DATETIME];
    case NEU_TYPE_DATA_AND_TIME:
        return &UA_TYPES[UA_TYPES_DATETIME];
    case NEU_TYPE_BYTES:
        return &UA_TYPES[UA_TYPES_BYTESTRING];
    // 添加数组类型支持
    case NEU_TYPE_ARRAY_BOOL:
        return &UA_TYPES[UA_TYPES_BOOLEAN];
    case NEU_TYPE_ARRAY_INT8:
        return &UA_TYPES[UA_TYPES_SBYTE];
    case NEU_TYPE_ARRAY_UINT8:
        return &UA_TYPES[UA_TYPES_BYTE];
    case NEU_TYPE_ARRAY_INT16:
        return &UA_TYPES[UA_TYPES_INT16];
    case NEU_TYPE_ARRAY_UINT16:
        return &UA_TYPES[UA_TYPES_UINT16];
    case NEU_TYPE_ARRAY_INT32:
        return &UA_TYPES[UA_TYPES_INT32];
    case NEU_TYPE_ARRAY_UINT32:
        return &UA_TYPES[UA_TYPES_UINT32];
    case NEU_TYPE_ARRAY_INT64:
        return &UA_TYPES[UA_TYPES_INT64];
    case NEU_TYPE_ARRAY_UINT64:
        return &UA_TYPES[UA_TYPES_UINT64];
    case NEU_TYPE_ARRAY_FLOAT:
        return &UA_TYPES[UA_TYPES_FLOAT];
    case NEU_TYPE_ARRAY_DOUBLE:
        return &UA_TYPES[UA_TYPES_DOUBLE];
    case NEU_TYPE_ARRAY_STRING:
        return &UA_TYPES[UA_TYPES_STRING];
    case NEU_TYPE_CUSTOM:
        return &UA_TYPES[UA_TYPES_VARIANT]; // 对于自定义类型，使用Variant
    default:
        return NULL;
    }
}

int opcua_convert_value_to_neu(UA_Variant *value, neu_type_e type,
                               neu_value_u *neu_value)
{
    if (value == NULL || neu_value == NULL) {
        return -1;
    }

    // 处理数组类型
    if (value->arrayLength > 0 && value->data != NULL) {
        // 将数组转换为字符串格式
        // 格式：[值1, 值2, 值3, ...]
        char   temp[sizeof(neu_value->str)] = { 0 };
        size_t offset                       = 0;

        // 添加开始括号
        temp[offset++] = '[';

        // 添加最多前10个元素
        size_t max_elements = value->arrayLength < 10 ? value->arrayLength : 10;

        for (size_t i = 0; i < max_elements; i++) {
            // 根据类型添加元素
            switch (type) {
            case NEU_TYPE_INT8: {
                UA_SByte *arr = (UA_SByte *) value->data;
                offset +=
                    snprintf(temp + offset, sizeof(temp) - offset - 1, "%d%s",
                             arr[i], (i < max_elements - 1) ? ", " : "");
                break;
            }
            case NEU_TYPE_UINT8: {
                UA_Byte *arr = (UA_Byte *) value->data;
                offset +=
                    snprintf(temp + offset, sizeof(temp) - offset - 1, "%u%s",
                             arr[i], (i < max_elements - 1) ? ", " : "");
                break;
            }
            case NEU_TYPE_INT16: {
                UA_Int16 *arr = (UA_Int16 *) value->data;
                offset +=
                    snprintf(temp + offset, sizeof(temp) - offset - 1, "%d%s",
                             arr[i], (i < max_elements - 1) ? ", " : "");
                break;
            }
            case NEU_TYPE_UINT16: {
                UA_UInt16 *arr = (UA_UInt16 *) value->data;
                offset +=
                    snprintf(temp + offset, sizeof(temp) - offset - 1, "%u%s",
                             arr[i], (i < max_elements - 1) ? ", " : "");
                break;
            }
            case NEU_TYPE_INT32: {
                UA_Int32 *arr = (UA_Int32 *) value->data;
                offset +=
                    snprintf(temp + offset, sizeof(temp) - offset - 1, "%d%s",
                             arr[i], (i < max_elements - 1) ? ", " : "");
                break;
            }
            case NEU_TYPE_UINT32: {
                UA_UInt32 *arr = (UA_UInt32 *) value->data;
                offset +=
                    snprintf(temp + offset, sizeof(temp) - offset - 1, "%u%s",
                             arr[i], (i < max_elements - 1) ? ", " : "");
                break;
            }
            case NEU_TYPE_INT64: {
                UA_Int64 *arr = (UA_Int64 *) value->data;
                offset += snprintf(temp + offset, sizeof(temp) - offset - 1,
                                   "%lld%s", (long long) arr[i],
                                   (i < max_elements - 1) ? ", " : "");
                break;
            }
            case NEU_TYPE_UINT64: {
                UA_UInt64 *arr = (UA_UInt64 *) value->data;
                offset += snprintf(temp + offset, sizeof(temp) - offset - 1,
                                   "%llu%s", (unsigned long long) arr[i],
                                   (i < max_elements - 1) ? ", " : "");
                break;
            }
            case NEU_TYPE_FLOAT: {
                UA_Float *arr = (UA_Float *) value->data;
                offset +=
                    snprintf(temp + offset, sizeof(temp) - offset - 1, "%.6g%s",
                             arr[i], (i < max_elements - 1) ? ", " : "");
                break;
            }
            case NEU_TYPE_DOUBLE: {
                UA_Double *arr = (UA_Double *) value->data;
                offset +=
                    snprintf(temp + offset, sizeof(temp) - offset - 1, "%.6g%s",
                             arr[i], (i < max_elements - 1) ? ", " : "");
                break;
            }
            case NEU_TYPE_BOOL: {
                UA_Boolean *arr = (UA_Boolean *) value->data;
                offset += snprintf(temp + offset, sizeof(temp) - offset - 1,
                                   "%s%s", arr[i] ? "true" : "false",
                                   (i < max_elements - 1) ? ", " : "");
                break;
            }
            case NEU_TYPE_STRING: {
                UA_String *arr = (UA_String *) value->data;
                offset += snprintf(temp + offset, sizeof(temp) - offset - 1,
                                   "\"%.*s\"%s", (int) arr[i].length,
                                   (char *) arr[i].data,
                                   (i < max_elements - 1) ? ", " : "");
                break;
            }
            default:
                offset += snprintf(temp + offset, sizeof(temp) - offset - 1,
                                   "?%s", (i < max_elements - 1) ? ", " : "");
                break;
            }

            // 检查是否超出缓冲区限制
            if (offset >= sizeof(temp) - 10) {
                // 留出空间添加省略号和结束括号
                offset = sizeof(temp) - 10;
                break;
            }
        }

        // 如果有更多元素未显示，添加省略号
        if (value->arrayLength > max_elements) {
            offset +=
                snprintf(temp + offset, sizeof(temp) - offset - 1, ", ...");
        }

        // 添加结束括号
        if (offset < sizeof(temp) - 1) {
            temp[offset++] = ']';
            temp[offset]   = '\0';
        } else {
            temp[sizeof(temp) - 2] = ']';
            temp[sizeof(temp) - 1] = '\0';
        }

        // 复制到输出字符串
        strncpy(neu_value->str, temp, sizeof(neu_value->str) - 1);
        neu_value->str[sizeof(neu_value->str) - 1] = '\0';

        return 0;
    }
    // 处理ByteString类型
    else if (UA_Variant_hasScalarType(value, &UA_TYPES[UA_TYPES_BYTESTRING])) {
        // 将void类型的UA_Variant数据指针转换为UA_ByteString指针
        UA_ByteString *bs = (UA_ByteString *) (value->data);

        // 初始化为空
        neu_value->bytes.length = 0;

        // 修改这里：根据neu_value_bytes_t结构体的正确定义设置bytes
        if (bs && bs->data && bs->length > 0) {
            // 确保不超过数组大小
            size_t copy_length = bs->length;
            if (copy_length > NEU_VALUE_SIZE) {
                copy_length = NEU_VALUE_SIZE;
            }

            // 复制字节数据到固定大小数组
            memcpy(neu_value->bytes.bytes, bs->data, copy_length);
            neu_value->bytes.length = (uint8_t) copy_length;
        }

        return 0;
    }
    // 处理标量类型
    else {
        switch (type) {
        case NEU_TYPE_INT8:
            neu_value->i8 = *(UA_SByte *) value->data;
            break;
        case NEU_TYPE_UINT8:
            neu_value->u8 = *(UA_Byte *) value->data;
            break;
        case NEU_TYPE_INT16:
            neu_value->i16 = *(UA_Int16 *) value->data;
            break;
        case NEU_TYPE_UINT16:
            neu_value->u16 = *(UA_UInt16 *) value->data;
            break;
        case NEU_TYPE_INT32:
            neu_value->i32 = *(UA_Int32 *) value->data;
            break;
        case NEU_TYPE_UINT32:
            neu_value->u32 = *(UA_UInt32 *) value->data;
            break;
        case NEU_TYPE_INT64:
            neu_value->i64 = *(UA_Int64 *) value->data;
            break;
        case NEU_TYPE_UINT64:
            neu_value->u64 = *(UA_UInt64 *) value->data;
            break;
        case NEU_TYPE_FLOAT:
            neu_value->f32 = *(UA_Float *) value->data;
            break;
        case NEU_TYPE_DOUBLE:
            neu_value->d64 = *(UA_Double *) value->data;
            break;
        case NEU_TYPE_BIT:
        case NEU_TYPE_BOOL:
            neu_value->u8 = *(UA_Boolean *) value->data;
            break;
        case NEU_TYPE_STRING: {
            // 确保目标字符串初始为空
            neu_value->str[0] = '\0';

            // 检查是否是STRING类型的标量
            if (UA_Variant_isScalar(value) &&
                value->type == &UA_TYPES[UA_TYPES_STRING]) {
                UA_String *str = (UA_String *) value->data;

                // 如果源字符串有效且不为空，执行复制
                if (str && str->data && str->length > 0) {
                    // 计算可以复制的最大长度（考虑目标缓冲区大小）
                    size_t copy_len = str->length < sizeof(neu_value->str) - 1
                        ? str->length
                        : sizeof(neu_value->str) - 1;

                    // 复制字符串数据
                    memcpy(neu_value->str, str->data, copy_len);

                    // 确保字符串正确终止
                    neu_value->str[copy_len] = '\0';
                }
            } else {
                return -1;
            }
            break;
        }
        default:
            return -1;
        }

        return 0;
    }
}

int opcua_convert_neu_to_value(const neu_value_u *neu_value, neu_type_e type,
                               void *value, UA_DataType *data_type)
{
    if (neu_value == NULL || value == NULL || data_type == NULL) {
        return -1;
    }

    switch (type) {
    case NEU_TYPE_INT8:
        *(UA_SByte *) value = neu_value->i8;
        break;
    case NEU_TYPE_UINT8:
        *(UA_Byte *) value = neu_value->u8;
        break;
    case NEU_TYPE_INT16:
        *(UA_Int16 *) value = neu_value->i16;
        break;
    case NEU_TYPE_UINT16:
        *(UA_UInt16 *) value = neu_value->u16;
        break;
    case NEU_TYPE_INT32:
        *(UA_Int32 *) value = neu_value->i32;
        break;
    case NEU_TYPE_UINT32:
        *(UA_UInt32 *) value = neu_value->u32;
        break;
    case NEU_TYPE_INT64:
        *(UA_Int64 *) value = neu_value->i64;
        break;
    case NEU_TYPE_UINT64:
        *(UA_UInt64 *) value = neu_value->u64;
        break;
    case NEU_TYPE_FLOAT:
        *(UA_Float *) value = neu_value->f32;
        break;
    case NEU_TYPE_DOUBLE:
        *(UA_Double *) value = neu_value->d64;
        break;
    case NEU_TYPE_BIT:
    case NEU_TYPE_BOOL:
        *(UA_Boolean *) value = neu_value->u8 > 0 ? true : false;
        break;
    case NEU_TYPE_STRING: {
        UA_String *str = (UA_String *) value;

        // 初始化字符串
        UA_String_init(str);

        // 如果源字符串不为空，执行复制
        if (neu_value->str[0] != '\0') {
            // 使用UA_String_fromChars替代UA_STRING宏处理const字符串
            UA_String     temp   = UA_String_fromChars(neu_value->str);
            UA_StatusCode status = UA_String_copy(&temp, str);
            UA_String_clear(&temp); // 清理临时字符串
            if (status != UA_STATUSCODE_GOOD) {
                return -1;
            }
        }
        break;
    }
    case NEU_TYPE_BYTES: {
        UA_ByteString *bs = (UA_ByteString *) value;

        // 设置ByteString
        if (neu_value->bytes.length > 0) {
            // 为ByteString分配内存
            bs->data = (UA_Byte *) UA_malloc(neu_value->bytes.length);
            if (bs->data == NULL) {
                return -1;
            }

            // 复制字节数据
            memcpy(bs->data, neu_value->bytes.bytes, neu_value->bytes.length);
            bs->length = neu_value->bytes.length;
        } else {
            // 空ByteString
            bs->data   = NULL;
            bs->length = 0;
        }
        break;
    }
    case NEU_TYPE_TIME:
    case NEU_TYPE_DATA_AND_TIME: {
        // 时间类型需要特殊处理
        // Neuron中时间格式不明确，可能需要根据实际情况转换
        // 这里暂时不实现
        return -1;
    }
    default:
        return -1;
    }

    return 0;
}

opcua_read_cmd_sort_t *opcua_tag_sort_create(UT_array *tags)
{
    if (tags == NULL) {
        return NULL;
    }

    opcua_read_cmd_sort_t *sort = calloc(1, sizeof(opcua_read_cmd_sort_t));
    if (sort == NULL) {
        return NULL;
    }

    // Count the number of tags
    size_t tag_count = utarray_len(tags);
    if (tag_count == 0) {
        free(sort);
        return NULL;
    }

    // Allocate memory for commands
    sort->cmd = calloc(1, sizeof(struct opcua_read_cmd));
    if (sort->cmd == NULL) {
        free(sort);
        return NULL;
    }
    sort->cmd_size = 1;

    // Allocate memory for tag pointers
    sort->cmd->tags = calloc(tag_count, sizeof(opcua_point_t *));
    if (sort->cmd->tags == NULL) {
        free(sort->cmd);
        free(sort);
        return NULL;
    }

    // Copy tag pointers
    size_t i = 0;
    utarray_foreach(tags, opcua_point_t **, tag_ptr)
    {
        sort->cmd->tags[i++] = *tag_ptr;
    }

    return sort;
}

void opcua_tag_sort_free(opcua_read_cmd_sort_t *sort)
{
    if (sort == NULL) {
        return;
    }

    if (sort->cmd != NULL) {
        free(sort->cmd->tags);
        free(sort->cmd);
    }

    free(sort);
}