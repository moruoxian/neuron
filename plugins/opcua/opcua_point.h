#ifndef _NEU_PLUGIN_OPCUA_POINT_H_
#define _NEU_PLUGIN_OPCUA_POINT_H_

#include <stdbool.h>
#include <stdint.h>

#include <neuron/neuron.h>
#include <neuron/utils/utarray.h>
#include <open62541/client.h>
#include <open62541/types.h>

typedef struct {
    char *name;
    char *node_id;
    neu_type_e type;
    UA_DataType *ua_type;
} opcua_point_t;

// Convert Neuron data tag to OPC UA point
int opcua_tag_to_point(const neu_datatag_t *tag, opcua_point_t *point);

// Get UA_DataType from Neuron data type
UA_DataType *opcua_get_ua_type(neu_type_e type);

// Convert UA value to Neuron value
int opcua_convert_value_to_neu(UA_Variant *value, neu_type_e type, neu_value_u *neu_value);

/**
 * @brief 将Neuron值转换为OPC UA值
 * 
 * @param neu_value Neuron值
 * @param type Neuron数据类型
 * @param value 输出的OPC UA值
 * @param data_type OPC UA数据类型
 * @return int 0表示成功，-1表示失败
 */
int opcua_convert_neu_to_value(const neu_value_u *neu_value, neu_type_e type, void *value, UA_DataType *data_type);

// Sort tags for efficient reading
struct opcua_read_cmd {
    opcua_point_t **tags;
};

struct opcua_read_cmd_sort {
    struct opcua_read_cmd *cmd;
    uint16_t cmd_size;
};

typedef struct opcua_read_cmd_sort opcua_read_cmd_sort_t;

// Create a new tag sort structure
opcua_read_cmd_sort_t *opcua_tag_sort_create(UT_array *tags);

// Free a tag sort structure
void opcua_tag_sort_free(opcua_read_cmd_sort_t *sort);

#endif // _NEU_PLUGIN_OPCUA_POINT_H_ 