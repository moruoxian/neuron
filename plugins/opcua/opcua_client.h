#ifndef _NEU_PLUGIN_OPCUA_CLIENT_H_
#define _NEU_PLUGIN_OPCUA_CLIENT_H_

#include <stdbool.h>
#include <stdint.h>

#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>
#include <neuron/neuron.h>

// 前向声明结构体，避免循环引用
typedef struct neu_plugin neu_plugin_t;

// OPC UA连接状态变更回调函数类型
typedef void (*opcua_state_callback)(void *user_data, UA_SecureChannelState channelState, 
                                     UA_SessionState sessionState, UA_StatusCode connectStatus);

// OPC UA浏览结果结构
typedef struct opcua_browse_result {
    UA_NodeId nodeId;        // 节点ID
    UA_QualifiedName browseName; // 浏览名称
    UA_String displayName;   // 显示名称
    UA_NodeClass nodeClass;  // 节点类型
} opcua_browse_result_t;

// OPC UA支持的安全模式
typedef enum opcua_security_mode {
    OPCUA_SECURITY_MODE_NONE = 0,          // 无安全性
    OPCUA_SECURITY_MODE_SIGN,              // 仅签名
    OPCUA_SECURITY_MODE_SIGN_ENCRYPT,      // 签名和加密
} opcua_security_mode_e;

// OPC UA客户端结构体不透明声明
typedef struct opcua_client opcua_client_t;

// Create a new OPC UA client
opcua_client_t *opcua_client_create(neu_plugin_t *plugin);

// Destroy an OPC UA client
void opcua_client_destroy(opcua_client_t *client);

// Connect to an OPC UA server
int opcua_client_connect(opcua_client_t *client, const char *endpoint_url,
                         const char *username, const char *password,
                         const char *certificate, const char *private_key,
                         opcua_security_mode_e security_mode);

// Connect to an OPC UA server asynchronously (non-blocking)
int opcua_client_connect_async(opcua_client_t *client, const char *endpoint_url,
                              const char *username, const char *password,
                              const char *certificate, const char *private_key,
                              opcua_security_mode_e security_mode);

// Process pending async operations (must be called regularly after connect_async)
int opcua_client_process_async(opcua_client_t *client, uint32_t timeout_ms);

// Disconnect from an OPC UA server
void opcua_client_disconnect(opcua_client_t *client);

// Check if client is connected
bool opcua_client_is_connected(opcua_client_t *client);

/**
 * 检查OPC UA客户端是否正在连接过程中
 * 
 * @param client OPC UA客户端
 * @return 如果正在连接中返回true，否则返回false
 */
bool opcua_client_connecting(opcua_client_t *client);

// Read a value from an OPC UA server
int opcua_client_read_value(opcua_client_t *client, const char *node_id,
                           UA_DataType *data_type, void *value);

// Write a value to an OPC UA server (placeholder for future implementation)
int opcua_client_write_value(opcua_client_t *client, const char *node_id,
                            UA_DataType *data_type, const void *value);

// Browse nodes on an OPC UA server
int opcua_client_browse_node(opcua_client_t *client, const UA_NodeId *node_id,
                            UT_array *results);

// Parse a node ID string into a UA_NodeId
UA_NodeId opcua_client_parse_node_id(opcua_client_t *client, const char *node_id_str);

// Get a readable string representation of a UA_NodeId
char *opcua_client_node_id_to_string(const UA_NodeId *node_id);

/**
 * @brief 读取变量节点的DataType属性并返回对应的Neuron类型
 * 
 * @param client OPCUA客户端
 * @param nodeId 变量节点ID
 * @param type 返回的Neuron数据类型
 * @return int 0表示成功，-1表示失败
 */
int opcua_client_read_variable_datatype(opcua_client_t *client, const UA_NodeId *nodeId, neu_type_e *type);

// 读取变量值属性并返回状态码
UA_StatusCode opcua_client_read_value_attribute(opcua_client_t *client, const UA_NodeId *nodeId, UA_Variant *value);

#endif // _NEU_PLUGIN_OPCUA_CLIENT_H_ 