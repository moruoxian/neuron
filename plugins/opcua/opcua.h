#ifndef _NEU_PLUGIN_OPCUA_H_
#define _NEU_PLUGIN_OPCUA_H_

#include <stdbool.h>
#include <stdint.h>

#include <neuron/neuron.h>
#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>
#include <open62541/plugin/log_stdout.h>

#include "opcua_client.h"
#include "opcua_point.h"

struct neu_plugin {
    neu_plugin_common_t common;

    opcua_client_t *client;
    void *plugin_group_data;
    
    char *endpoint_url;
    char *username;
    char *password;
    char *certificate;
    char *private_key;
    
    opcua_security_mode_e security_mode; // 安全模式
    
    bool connected;
    
    // 重连相关参数
    bool reconnect_enabled;      // 是否启用自动重连
    uint32_t reconnect_interval; // 重连间隔（毫秒）
    uint32_t reconnect_attempts; // 已尝试重连次数
    uint32_t max_reconnect_attempts; // 最大重连尝试次数，0表示无限制
};

#endif // _NEU_PLUGIN_OPCUA_H_ 