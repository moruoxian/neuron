#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <neuron/neuron.h>
#include <neuron/utils/log.h>
#include <neuron/utils/utarray.h>

#include "opcua.h"
#include "opcua_client.h"

// 前置声明
struct opcua_client;
typedef struct opcua_client opcua_client_t;

// 连接状态变更回调函数的前置声明
static void opcua_client_state_callback(UA_Client *           client,
                                        UA_SecureChannelState channelState,
                                        UA_SessionState       sessionState,
                                        UA_StatusCode         connectStatus);

// OPC UA客户端结构体
struct opcua_client {
    UA_Client *   client;
    bool          connected;
    neu_plugin_t *plugin; // 添加plugin指针以便在需要时访问

    // 异步连接状态
    bool                 connecting;          // 是否正在连接中
    int64_t              connect_start_time;  // 连接开始时间
    opcua_state_callback state_callback;      // 连接状态回调
    void *               state_callback_data; // 回调函数用户数据
};

// 连接状态变更回调函数
static void opcua_client_state_callback(UA_Client *           client,
                                        UA_SecureChannelState channelState,
                                        UA_SessionState       sessionState,
                                        UA_StatusCode         connectStatus)
{
    // 获取UA_Client的config，从中获取客户端上下文
    UA_ClientConfig *config       = UA_Client_getConfig(client);
    opcua_client_t * opcua_client = (opcua_client_t *) config->clientContext;

    if (!opcua_client)
        return;

    neu_plugin_t *plugin = opcua_client->plugin;

    // 记录连接状态
    if (sessionState == UA_SESSIONSTATE_ACTIVATED) {
        if (!opcua_client->connected) {
            opcua_client->connected = true;
            // 计算连接耗时
            int64_t duration = 0;
            if (opcua_client->connect_start_time > 0) {
                duration = neu_time_ms() - opcua_client->connect_start_time;
                opcua_client->connect_start_time = 0;
            }

            if (plugin) {
                plog_notice(
                    plugin,
                    "【连接成功】OPC UA连接已成功建立，会话已激活，通道状态: "
                    "%d, 会话状态: %d, 状态码: 0x%08x，耗时: %ld ms",
                    channelState, sessionState, connectStatus, duration);
            }
        }
    } else {
        if (opcua_client->connected) {
            opcua_client->connected = false;
            if (plugin) {
                plog_warn(plugin,
                          "【连接断开】OPC UA连接已断开，通道状态: %d, "
                          "会话状态: %d, 连接状态码: 0x%08x",
                          channelState, sessionState, connectStatus);
            }
        } else if (opcua_client->connecting) {
            // 如果处于连接中状态，但会话状态不是激活，且状态码不好，记录连接失败
            if (connectStatus != UA_STATUSCODE_GOOD) {
                opcua_client->connecting = false;
                // 计算连接尝试耗时
                int64_t duration = 0;
                if (opcua_client->connect_start_time > 0) {
                    duration = neu_time_ms() - opcua_client->connect_start_time;
                    opcua_client->connect_start_time = 0;
                }

                if (plugin) {
                    plog_warn(plugin,
                              "【连接失败】OPC UA连接尝试失败，通道状态: %d, "
                              "会话状态: %d, 连接状态码: 0x%08x，耗时: %ld ms",
                              channelState, sessionState, connectStatus,
                              duration);
                }
            }
        }
    }

    // 连接过程结束
    if (opcua_client->connecting &&
        (sessionState == UA_SESSIONSTATE_ACTIVATED ||
         connectStatus != UA_STATUSCODE_GOOD)) {
        opcua_client->connecting = false;
    }

    // 调用用户提供的回调函数
    if (opcua_client->state_callback) {
        opcua_client->state_callback(opcua_client->state_callback_data,
                                     channelState, sessionState, connectStatus);
    }
}

static void opcua_log_callback(void *context, UA_LogLevel level,
                               UA_LogCategory category, const char *msg,
                               va_list args)
{
    neu_plugin_t *plugin = (neu_plugin_t *) context;

    // 标记未使用的参数
    (void) category;

    // 无效上下文时跳过
    if (!plugin)
        return;

    plog_info(plugin, "^-^ opcua_log_callback");

    // 根据open62541的日志级别映射到neuron的日志级别
    switch (level) {
    case UA_LOGLEVEL_FATAL:
        plog_fatal(plugin, msg, args);
        break;
    case UA_LOGLEVEL_ERROR:
        plog_error(plugin, msg, args);
        break;
    case UA_LOGLEVEL_WARNING:
        plog_warn(plugin, msg, args);
        break;
    case UA_LOGLEVEL_INFO:
        plog_info(plugin, msg, args);
        break;
    case UA_LOGLEVEL_DEBUG:
    case UA_LOGLEVEL_TRACE:
        plog_debug(plugin, msg, args);
        break;
    default:
        plog_notice(plugin, msg, args);
        break;
    }
}
// 定义浏览结果数组元素的初始化、复制和清理函数
static void opcua_browse_result_copy(void *_dst, const void *_src)
{
    opcua_browse_result_t *dst = (opcua_browse_result_t *) _dst;
    opcua_browse_result_t *src = (opcua_browse_result_t *) _src;

    UA_NodeId_copy(&src->nodeId, &dst->nodeId);
    UA_QualifiedName_copy(&src->browseName, &dst->browseName);
    UA_String_copy(&src->displayName, &dst->displayName);
    dst->nodeClass = src->nodeClass;
}

static void opcua_browse_result_dtor(void *_elt)
{
    opcua_browse_result_t *elt = (opcua_browse_result_t *) _elt;

    UA_NodeId_clear(&elt->nodeId);
    UA_QualifiedName_clear(&elt->browseName);
    UA_String_clear(&elt->displayName);
}

UT_icd opcua_browse_result_icd = {
    sizeof(opcua_browse_result_t),
    NULL,                     // 初始化函数，这里不需要
    opcua_browse_result_copy, // 复制函数
    opcua_browse_result_dtor  // 清理函数
};

opcua_client_t *opcua_client_create(neu_plugin_t *plugin)
{
    opcua_client_t *client = calloc(1, sizeof(opcua_client_t));
    if (client == NULL) {
        return NULL;
    }

    client->client = UA_Client_new();
    if (client->client == NULL) {
        free(client);
        return NULL;
    }

    // 保存plugin指针
    client->plugin = plugin;

    UA_ClientConfig *config = UA_Client_getConfig(client->client);
    if (plugin != NULL) {
        plog_info(plugin, "OPC UA client created with default configuration");
        config->logging->log     = opcua_log_callback;
        config->logging->context = client->plugin;
    }

    UA_ClientConfig_setDefault(config);

    // 设置更短的超时时间，防止长时间阻塞
    config->timeout                   = 3000; // 3秒超时
    config->connectivityCheckInterval = 1000; // 1秒检查一次

    // 设置回调函数和上下文
    config->clientContext = client;
    // stateCallback需要直接赋值，不使用函数指针转换
    // stateCallback的类型在open62541库中已定义
    config->stateCallback = opcua_client_state_callback;

    // 初始化异步连接相关的状态变量
    client->connected           = false;
    client->connecting          = false;
    client->connect_start_time  = 0;
    client->state_callback      = NULL;
    client->state_callback_data = NULL;

    return client;
}

void opcua_client_destroy(opcua_client_t *client)
{
    if (client == NULL) {
        return;
    }

    if (client->connected) {
        opcua_client_disconnect(client);
    }

    UA_Client_delete(client->client);
    free(client);
}

int opcua_client_connect(opcua_client_t *client, const char *endpoint_url,
                         const char *username, const char *password,
                         const char *certificate, const char *private_key,
                         opcua_security_mode_e security_mode)
{
    if (client == NULL || endpoint_url == NULL) {
        return -1;
    }

    if (client->connected) {
        opcua_client_disconnect(client);
    }

    // 添加连接开始日志
    if (client->plugin) {
        plog_info(client->plugin, "Connecting to OPC UA server: %s",
                  endpoint_url);
    }

    UA_ClientConfig *config = UA_Client_getConfig(client->client);
    if (client->plugin != NULL) {
        // plog_info(client->plugin, "OPC UA client created with default
        // configuration"); config->logging->log = opcua_log_callback;
        // config->logging->context = client->plugin;
    }
    // UA_ClientConfig_setDefault(config);

    // 配置用户名/密码认证
    if (username != NULL && password != NULL && strlen(username) > 0) {
        if (client->plugin) {
            plog_debug(client->plugin,
                       "Using username authentication for OPC UA connection");
        }

        UA_UserNameIdentityToken *identityToken =
            UA_UserNameIdentityToken_new();
        identityToken->userName            = UA_STRING_ALLOC(username);
        identityToken->password            = UA_STRING_ALLOC(password);
        identityToken->encryptionAlgorithm = UA_STRING_NULL;

        UA_ExtensionObject_clear(&config->userIdentityToken);
        config->userIdentityToken.encoding = UA_EXTENSIONOBJECT_DECODED;
        config->userIdentityToken.content.decoded.type =
            &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN];
        config->userIdentityToken.content.decoded.data = identityToken;
    }

    // 配置安全模式
    switch (security_mode) {
    case OPCUA_SECURITY_MODE_NONE:
        // 默认无安全策略，不需要额外配置
        if (client->plugin) {
            plog_debug(client->plugin,
                       "Using None security mode for OPC UA connection");
        }
        break;
    case OPCUA_SECURITY_MODE_SIGN:
        // 配置签名安全模式
        if (certificate != NULL && private_key != NULL) {
            if (client->plugin) {
                plog_debug(client->plugin,
                           "Using Sign security mode for OPC UA connection");
            }
            // 在实际应用中，这里需要加载证书和私钥
            // 设置消息安全模式为签名
            config->securityMode = UA_MESSAGESECURITYMODE_SIGN;
            // 可选：设置安全策略 - Basic256Sha256 常用于签名
            config->securityPolicyUri = UA_STRING_ALLOC(
                "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
        } else {
            // 缺少证书或私钥，无法进行签名
            if (client->plugin) {
                plog_error(client->plugin,
                           "Missing certificate or private key for Sign "
                           "security mode");
            }
            return -1;
        }
        break;
    case OPCUA_SECURITY_MODE_SIGN_ENCRYPT:
        // 配置签名和加密安全模式
        if (certificate != NULL && private_key != NULL) {
            if (client->plugin) {
                plog_debug(
                    client->plugin,
                    "Using SignAndEncrypt security mode for OPC UA connection");
            }
            // 设置消息安全模式为签名和加密
            config->securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
            // 可选：设置安全策略 - Basic256Sha256 也适用于签名和加密
            config->securityPolicyUri = UA_STRING_ALLOC(
                "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
        } else {
            // 缺少证书或私钥，无法进行签名和加密
            if (client->plugin) {
                plog_error(client->plugin,
                           "Missing certificate or private key for "
                           "SignAndEncrypt security mode");
            }
            return -1;
        }
        break;
    default:
        // 未知安全模式
        if (client->plugin) {
            plog_error(client->plugin, "Unknown security mode: %d",
                       security_mode);
        }
        return -1;
    }

    UA_StatusCode status = UA_Client_connect(client->client, endpoint_url);
    if (status != UA_STATUSCODE_GOOD) {
        if (client->plugin) {
            plog_error(client->plugin,
                       "Failed to connect to OPC UA server: %s, status: 0x%08x",
                       endpoint_url, status);
        }
        return -1;
    }

    if (client->plugin) {
        plog_notice(client->plugin,
                    "Successfully connected to OPC UA server: %s",
                    endpoint_url);
    }

    client->connected = true;
    return 0;
}

void opcua_client_disconnect(opcua_client_t *client)
{
    if (client == NULL || !client->connected) {
        return;
    }

    if (client->plugin) {
        plog_info(client->plugin, "Disconnecting from OPC UA server");
    }

    UA_Client_disconnect(client->client);

    if (client->plugin) {
        plog_debug(client->plugin,
                   "Successfully disconnected from OPC UA server");
    }

    client->connected = false;
}

bool opcua_client_is_connected(opcua_client_t *client)
{
    if (client == NULL || client->client == NULL) {
        return false;
    }

    return client->connected;
}

int opcua_client_read_value(opcua_client_t *client, const char *node_id,
                            UA_DataType *data_type, void *value,
                            size_t *array_indices, size_t num_indices)
{
    if (client == NULL || node_id == NULL || data_type == NULL ||
        value == NULL) {
        return -1;
    }

    if (!client->connected) {
        return -1;
    }

    // 使用单独参数解析节点ID
    size_t local_indices[3]  = { 0 };
    size_t local_num_indices = 0;

    // 如果调用者提供了索引数组，使用调用者的数组
    // 否则，从节点ID字符串中解析索引
    if (array_indices && num_indices > 0) {
        local_num_indices = num_indices;
        memcpy(local_indices, array_indices,
               sizeof(size_t) * num_indices < sizeof(local_indices)
                   ? sizeof(size_t) * num_indices
                   : sizeof(local_indices));
    }

    // Parse the node ID string
    UA_NodeId ua_node_id = opcua_client_parse_node_id(
        client, node_id, array_indices == NULL ? local_indices : NULL,
        array_indices == NULL ? &local_num_indices : NULL);

    if (UA_NodeId_isNull(&ua_node_id)) {
        return -1;
    }

    // Read the value
    UA_Variant variant;
    UA_Variant_init(&variant);
    UA_StatusCode status =
        UA_Client_readValueAttribute(client->client, ua_node_id, &variant);
    UA_NodeId_clear(&ua_node_id);

    if (status != UA_STATUSCODE_GOOD) {
        return -1;
    }

    // 检查是否为空值
    if (UA_Variant_isEmpty(&variant)) {
        UA_Variant_clear(&variant);
        return -1;
    }

    // 处理数组索引，如果有的话
    if (local_num_indices > 0 && !UA_Variant_isScalar(&variant) &&
        variant.arrayLength > 0) {
        if (client->plugin) {
            plog_debug(
                client->plugin,
                "尝试读取数组元素: 索引=%lu,%lu,%lu 数组长度=%lu",
                (unsigned long) local_indices[0],
                local_num_indices > 1 ? (unsigned long) local_indices[1] : 0UL,
                local_num_indices > 2 ? (unsigned long) local_indices[2] : 0UL,
                (unsigned long) variant.arrayLength);
        }

        // 检查索引是否有效
        if (local_indices[0] >= variant.arrayLength) {
            if (client->plugin) {
                plog_error(client->plugin,
                           "数组索引越界: 索引=%lu 数组长度=%lu",
                           (unsigned long) local_indices[0],
                           (unsigned long) variant.arrayLength);
            }
            UA_Variant_clear(&variant);
            return -1;
        }

        // 计算基于索引的偏移量
        size_t offset = local_indices[0];

        // 目前只支持一维数组的特定元素访问
        const uint8_t *ptr = (const uint8_t *) variant.data;
        ptr += offset * variant.type->memSize;

        // 使用UA_copy函数统一处理所有类型
        if (variant.type == data_type) {
            // 类型匹配，使用UA_copy复制数据
            UA_StatusCode status = UA_copy(ptr, value, data_type);
            if (status != UA_STATUSCODE_GOOD) {
                if (client->plugin) {
                    plog_error(client->plugin, "复制数组元素失败: 状态码=%d",
                               status);
                }
                UA_Variant_clear(&variant);
                return -1;
            }
            UA_Variant_clear(&variant);
            return 0;
        } else {
            // 类型不匹配，尝试转换
            // 创建临时变量存储数组元素
            UA_Variant element;
            UA_Variant_init(&element);
            UA_Variant_setScalarCopy(&element, ptr, variant.type);

            // 清理原始变量
            UA_Variant_clear(&variant);

            // 从临时变量中转换类型
            if (element.type == &UA_TYPES[UA_TYPES_BOOLEAN] &&
                data_type == &UA_TYPES[UA_TYPES_BYTE]) {
                *(UA_Byte *) value = *(UA_Boolean *) element.data ? 1 : 0;
            }
            // ... 保留其他类型转换代码 ...
            else {
                UA_Variant_clear(&element);
                return -1;
            }

            UA_Variant_clear(&element);
            return 0;
        }
    }

    // 处理整个数组类型（当未指定索引时）
    if (!UA_Variant_isScalar(&variant) && variant.arrayLength > 0) {
        // 检查是否与预期类型匹配
        if (variant.type == data_type) {
            // 使用UA_Array_copy统一复制所有类型的数组
            UA_StatusCode status =
                UA_Array_copy(variant.data, variant.arrayLength,
                              (void **) value, variant.type);

            if (status != UA_STATUSCODE_GOOD) {
                if (client->plugin) {
                    plog_error(client->plugin, "复制数组失败: 状态码=%d",
                               status);
                }
                UA_Variant_clear(&variant);
                return -1;
            }

            if (client->plugin) {
                plog_debug(client->plugin, "成功复制数组，元素数量: %zu",
                           variant.arrayLength);
            }

            UA_Variant_clear(&variant);
            return 0;
        }
        // 类型不匹配，直接返回错误
        else {
            if (client->plugin) {
                plog_error(client->plugin, "数组类型不匹配，期望%s，实际%s",
                           data_type->typeName, variant.type->typeName);
            }
            UA_Variant_clear(&variant);
            return -1;
        }
    }

    // 标量类型处理：检查类型是否匹配
    if (UA_Variant_hasScalarType(&variant, data_type)) {
        // 使用UA_copy统一处理所有标量类型
        UA_StatusCode status = UA_copy(variant.data, value, data_type);
        if (status != UA_STATUSCODE_GOOD) {
            if (client->plugin) {
                plog_error(client->plugin, "复制标量值失败: 类型=%s, 状态码=%d",
                           data_type->typeName, status);
            }
            UA_Variant_clear(&variant);
            return -1;
        }

        if (client->plugin &&
            (data_type == &UA_TYPES[UA_TYPES_STRING] ||
             data_type == &UA_TYPES[UA_TYPES_BYTESTRING])) {
            // 记录字符串和字节字符串类型的复制结果
            if (data_type == &UA_TYPES[UA_TYPES_STRING]) {
                UA_String *str = (UA_String *) value;
                plog_debug(client->plugin, "字符串已深拷贝: 长度=%u",
                           (unsigned) str->length);
            } else {
                UA_ByteString *bs = (UA_ByteString *) value;
                plog_debug(client->plugin, "字节字符串已深拷贝: 长度=%u",
                           (unsigned) bs->length);
            }
        }

        UA_Variant_clear(&variant);
        return 0;
    }

    // 检查类型是否匹配
    if (UA_Variant_hasScalarType(&variant, data_type)) {
        // 类型匹配，但需要特殊处理String和ByteString类型
        if (data_type == &UA_TYPES[UA_TYPES_STRING]) {
            // String类型需要深拷贝
            UA_String *src_str = (UA_String *) variant.data;
            UA_String *dst_str = (UA_String *) value;

            // 初始化目标字符串
            UA_String_init(dst_str);

            // 只有当源字符串不为空时才复制内容
            if (src_str->length > 0 && src_str->data != NULL) {
                UA_StatusCode status = UA_String_copy(src_str, dst_str);
                if (status != UA_STATUSCODE_GOOD) {
                    if (client->plugin) {
                        plog_error(client->plugin, "复制字符串失败: 长度=%u",
                                   (unsigned) src_str->length);
                    }
                    UA_Variant_clear(&variant);
                    return -1;
                }

                if (client->plugin) {
                    plog_debug(client->plugin, "字符串已深拷贝: 长度=%u",
                               (unsigned) dst_str->length);
                }
            }
        }
        // 处理ByteString类型
        else if (data_type == &UA_TYPES[UA_TYPES_BYTESTRING]) {
            UA_ByteString *src_bs = (UA_ByteString *) variant.data;
            UA_ByteString *dst_bs = (UA_ByteString *) value;

            // 初始化目标字节字符串
            UA_ByteString_init(dst_bs);

            // 只有当源字节字符串不为空时才复制内容
            if (src_bs->length > 0 && src_bs->data != NULL) {
                UA_StatusCode status = UA_ByteString_copy(src_bs, dst_bs);
                if (status != UA_STATUSCODE_GOOD) {
                    if (client->plugin) {
                        plog_error(client->plugin,
                                   "复制字节字符串失败: 长度=%u",
                                   (unsigned) src_bs->length);
                    }
                    UA_Variant_clear(&variant);
                    return -1;
                }

                if (client->plugin) {
                    plog_debug(client->plugin, "字节字符串已深拷贝: 长度=%u",
                               (unsigned) dst_bs->length);
                }
            }
        } else {
            // 其他基本类型可以直接内存复制
            memcpy(value, variant.data, data_type->memSize);
        }
        UA_Variant_clear(&variant);
        return 0;
    }

    // 类型不匹配，尝试直接转换
    // 不使用UA_Variant_setScalarCopy，而是直接在目标内存上操作

    // 布尔值转换
    if (variant.type == &UA_TYPES[UA_TYPES_BOOLEAN] &&
        data_type == &UA_TYPES[UA_TYPES_BYTE]) {
        // 布尔值转字节 (Boolean -> UINT8)
        *(UA_Byte *) value = *(UA_Boolean *) variant.data ? 1 : 0;
    } else if (variant.type == &UA_TYPES[UA_TYPES_BYTE] &&
               data_type == &UA_TYPES[UA_TYPES_BOOLEAN]) {
        // 字节转布尔值 (UINT8 -> Boolean)
        *(UA_Boolean *) value = *(UA_Byte *) variant.data != 0;
    }
    // 整数类型转换
    else if (variant.type == &UA_TYPES[UA_TYPES_SBYTE] &&
             data_type == &UA_TYPES[UA_TYPES_BYTE]) {
        // SByte转Byte (INT8 -> UINT8)
        *(UA_Byte *) value = (UA_Byte) * (UA_SByte *) variant.data;
    } else if (variant.type == &UA_TYPES[UA_TYPES_BYTE] &&
               data_type == &UA_TYPES[UA_TYPES_SBYTE]) {
        // Byte转SByte (UINT8 -> INT8)
        *(UA_SByte *) value = (UA_SByte) * (UA_Byte *) variant.data;
    } else if (variant.type == &UA_TYPES[UA_TYPES_INT16] &&
               data_type == &UA_TYPES[UA_TYPES_UINT16]) {
        // INT16转UINT16
        *(UA_UInt16 *) value = (UA_UInt16) * (UA_Int16 *) variant.data;
    } else if (variant.type == &UA_TYPES[UA_TYPES_UINT16] &&
               data_type == &UA_TYPES[UA_TYPES_INT16]) {
        // UINT16转INT16
        *(UA_Int16 *) value = (UA_Int16) * (UA_UInt16 *) variant.data;
    } else if (variant.type == &UA_TYPES[UA_TYPES_INT32] &&
               data_type == &UA_TYPES[UA_TYPES_UINT32]) {
        // INT32转UINT32
        *(UA_UInt32 *) value = (UA_UInt32) * (UA_Int32 *) variant.data;
    } else if (variant.type == &UA_TYPES[UA_TYPES_UINT32] &&
               data_type == &UA_TYPES[UA_TYPES_INT32]) {
        // UINT32转INT32
        *(UA_Int32 *) value = (UA_Int32) * (UA_UInt32 *) variant.data;
    } else if (variant.type == &UA_TYPES[UA_TYPES_INT64] &&
               data_type == &UA_TYPES[UA_TYPES_UINT64]) {
        // INT64转UINT64
        *(UA_UInt64 *) value = (UA_UInt64) * (UA_Int64 *) variant.data;
    } else if (variant.type == &UA_TYPES[UA_TYPES_UINT64] &&
               data_type == &UA_TYPES[UA_TYPES_INT64]) {
        // UINT64转INT64
        *(UA_Int64 *) value = (UA_Int64) * (UA_UInt64 *) variant.data;
    }
    // 浮点数类型转换
    else if (variant.type == &UA_TYPES[UA_TYPES_FLOAT] &&
             data_type == &UA_TYPES[UA_TYPES_DOUBLE]) {
        // FLOAT转DOUBLE
        *(UA_Double *) value = (UA_Double) * (UA_Float *) variant.data;
    } else if (variant.type == &UA_TYPES[UA_TYPES_DOUBLE] &&
               data_type == &UA_TYPES[UA_TYPES_FLOAT]) {
        // DOUBLE转FLOAT
        *(UA_Float *) value = (UA_Float) * (UA_Double *) variant.data;
    }
    // 特殊类型转换
    else if (variant.type == &UA_TYPES[UA_TYPES_DATETIME] &&
             data_type == &UA_TYPES[UA_TYPES_UINT32]) {
        // DateTime转UINT32 (时间戳转换为秒)
        UA_DateTime dt = *(UA_DateTime *) variant.data;
        // 将OPC
        // UA时间戳（1601年1月1日以来的100纳秒数）转换为Unix时间戳（1970年1月1日以来的秒数）
        // OPC UA时间戳比Unix时间戳早11644473600秒
        *(UA_UInt32 *) value = (UA_UInt32)((dt / 10000000ULL) - 11644473600ULL);
    } else if (variant.type == &UA_TYPES[UA_TYPES_LOCALIZEDTEXT] &&
               data_type == &UA_TYPES[UA_TYPES_STRING]) {
        // LocalizedText转String - 这个需要特殊处理
        UA_LocalizedText *lt  = (UA_LocalizedText *) variant.data;
        UA_String *       str = (UA_String *) value;

        // 初始化目标字符串
        UA_String_init(str);

        // 只有当文本不为空时才复制
        if (lt->text.length > 0 && lt->text.data != NULL) {
            // 直接使用UA_String_copy复制文本内容
            UA_String_copy(&lt->text, str);
            if (str->data == NULL) {
                UA_Variant_clear(&variant);
                return -1;
            }
        }
    } else {
        // 其他类型转换暂不支持
        UA_Variant_clear(&variant);
        return -1;
    }

    UA_Variant_clear(&variant);
    return 0;
}

int opcua_client_write_value(opcua_client_t *client, const char *node_id,
                             UA_DataType *data_type, const void *value,
                             size_t *array_indices, size_t num_indices)
{
    if (client == NULL || client->client == NULL || node_id == NULL ||
        data_type == NULL || value == NULL) {
        return -1;
    }

    // 检查连接状态
    if (!client->connected) {
        if (client->plugin) {
            plog_error(client->plugin, "尝试写入值到未连接的OPC UA服务器");
        }
        return -1;
    }

    // 使用单独参数解析节点ID
    size_t local_indices[3]  = { 0 };
    size_t local_num_indices = 0;

    // 如果调用者提供了索引数组，使用调用者的数组
    if (array_indices && num_indices > 0) {
        local_num_indices = num_indices;
        memcpy(local_indices, array_indices,
               sizeof(size_t) * (num_indices < 3 ? num_indices : 3));
    }

    // 解析节点ID
    UA_NodeId uaNodeId = opcua_client_parse_node_id(
        client, node_id, array_indices == NULL ? local_indices : NULL,
        array_indices == NULL ? &local_num_indices : NULL);

    if (UA_NodeId_isNull(&uaNodeId)) {
        if (client->plugin) {
            plog_error(client->plugin, "无效的OPC UA节点ID: %s", node_id);
        }
        return -1;
    }

    // 如果有数组索引，则处理数组元素写入
    if (local_num_indices > 0) {
        if (client->plugin) {
            plog_debug(client->plugin, "写入数组元素: 索引=%lu, 节点=%s",
                       (unsigned long) local_indices[0], node_id);
        }

        // 首先读取当前数组值
        UA_Variant arrayValue;
        UA_Variant_init(&arrayValue);

        UA_StatusCode status =
            UA_Client_readValueAttribute(client->client, uaNodeId, &arrayValue);
        if (status != UA_STATUSCODE_GOOD) {
            if (client->plugin) {
                plog_error(client->plugin,
                           "读取数组失败，无法更新元素: %s, 状态码: %d",
                           node_id, status);
            }
            UA_NodeId_clear(&uaNodeId);
            return -1;
        }

        // 检查是否是数组
        if (UA_Variant_isScalar(&arrayValue)) {
            if (client->plugin) {
                plog_error(client->plugin, "节点不是数组，无法按索引写入: %s",
                           node_id);
            }
            UA_Variant_clear(&arrayValue);
            UA_NodeId_clear(&uaNodeId);
            return -1;
        }

        // 检查索引范围
        if (local_indices[0] >= arrayValue.arrayLength) {
            if (client->plugin) {
                plog_error(client->plugin,
                           "数组索引超出范围: 索引=%lu, 长度=%lu",
                           (unsigned long) local_indices[0],
                           (unsigned long) arrayValue.arrayLength);
            }
            UA_Variant_clear(&arrayValue);
            UA_NodeId_clear(&uaNodeId);
            return -1;
        }

        // 获取数组元素类型
        const UA_DataType *elementType = arrayValue.type;

        // 检查数据类型是否匹配
        if (elementType != data_type) {
            if (client->plugin) {
                plog_error(client->plugin, "数据类型不匹配: 预期=%s, 实际=%s",
                           data_type->typeName, elementType->typeName);
            }
            UA_Variant_clear(&arrayValue);
            UA_NodeId_clear(&uaNodeId);
            return -1;
        }

        // 计算数组元素偏移
        size_t   index       = local_indices[0];
        uint8_t *arrayData   = (uint8_t *) arrayValue.data;
        size_t   elementSize = elementType->memSize;
        uint8_t *elementPtr  = arrayData + (index * elementSize);

        // 更新数组元素值
        memcpy(elementPtr, value, elementSize);

        // 写回整个数组
        status = UA_Client_writeValueAttribute(client->client, uaNodeId,
                                               &arrayValue);

        // 清理资源
        UA_Variant_clear(&arrayValue);
        UA_NodeId_clear(&uaNodeId);

        if (status != UA_STATUSCODE_GOOD) {
            if (client->plugin) {
                plog_error(client->plugin,
                           "写入数组元素失败: %s[%lu], 状态码: %d", node_id,
                           (unsigned long) index, status);
            }
            return -1;
        }

        if (client->plugin) {
            plog_debug(client->plugin, "成功写入数组元素: %s[%lu]", node_id,
                       (unsigned long) index);
        }

        return 0;
    }

    // 正常写入（非数组元素）
    UA_Variant variant;
    UA_Variant_init(&variant);
    UA_Variant_setScalarCopy(&variant, value, data_type);

    // 写入值
    UA_StatusCode status =
        UA_Client_writeValueAttribute(client->client, uaNodeId, &variant);

    // 清理资源
    UA_Variant_clear(&variant);
    UA_NodeId_clear(&uaNodeId);

    if (status != UA_STATUSCODE_GOOD) {
        if (client->plugin) {
            plog_error(client->plugin, "写入OPC UA节点失败: %s, 状态码: %d",
                       node_id, status);
        }
        return -1;
    }

    if (client->plugin) {
        plog_debug(client->plugin, "成功写入值到OPC UA节点: %s", node_id);
    }

    return 0;
}

// 将节点ID字符串解析为UA_NodeId结构
UA_NodeId opcua_client_parse_node_id(opcua_client_t *client,
                                     const char *    node_id_str,
                                     size_t *array_indices, size_t *num_indices)
{
    UA_NodeId nodeId = UA_NODEID_NULL;

    if (client == NULL || node_id_str == NULL || strlen(node_id_str) == 0) {
        return nodeId;
    }

    // 初始化索引计数
    if (num_indices) {
        *num_indices = 0;
    }

    // 检查是否包含数组索引 [x,y,z]
    char *node_id_copy = strdup(node_id_str);
    if (node_id_copy) {
        char *open_bracket  = strchr(node_id_copy, '[');
        char *close_bracket = strchr(node_id_copy, ']');

        // 如果找到匹配的方括号，解析数组索引
        if (open_bracket && close_bracket && open_bracket < close_bracket &&
            array_indices && num_indices) {
            *close_bracket    = '\0'; // 暂时截断字符串
            char *indices_str = open_bracket + 1;

            // 解析索引值，格式如 [0], [1,2], [3,4,5]
            char *saveptr = NULL;
            char *token   = strtok_r(indices_str, ",", &saveptr);

            while (token && (*num_indices) < 3) {
                array_indices[*num_indices] = atoi(token);
                (*num_indices)++;
                token = strtok_r(NULL, ",", &saveptr);
            }

            // 重建不带索引的节点ID字符串
            *open_bracket  = '\0';
            char temp[256] = { 0 };
            strncpy(temp, node_id_copy, sizeof(temp) - 1);
            strncat(temp, close_bracket + 1, sizeof(temp) - strlen(temp) - 1);

            // 使用重建的节点ID继续解析
            char *rebuilt_node_id = strdup(temp);
            free(node_id_copy);
            if (!rebuilt_node_id) {
                return nodeId;
            }
            node_id_copy = rebuilt_node_id;

            if (client->plugin) {
                plog_debug(client->plugin,
                           "数组索引节点检测: 原始=%s, 重建=%s, 索引数=%zu",
                           node_id_str, node_id_copy, *num_indices);
            }
        }

        // 使用处理后的节点ID继续标准解析
        node_id_str = node_id_copy;
    }

    // 如果是根节点ID，返回默认节点
    if (strcmp(node_id_str, "root") == 0) {
        if (node_id_copy)
            free(node_id_copy);
        nodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
        return nodeId;
    }

    // 标准节点ID格式解析，如: "0!85"格式（命名空间!标识符）
    if (strchr(node_id_str, '!') != NULL) {
        unsigned short ns;
        unsigned int   id;
        if (sscanf(node_id_str, "%hu!%u", &ns, &id) == 2) {
            if (node_id_copy)
                free(node_id_copy);
            nodeId = UA_NODEID_NUMERIC(ns, id);
            return nodeId;
        }
    }

    // 尝试使用UA_NodeId_parse解析标准OPC UA格式
    UA_String     uaString = UA_STRING_ALLOC(node_id_str);
    UA_StatusCode status   = UA_NodeId_parse(&nodeId, uaString);
    UA_String_clear(&uaString);

    if (node_id_copy)
        free(node_id_copy);

    if (status == UA_STATUSCODE_GOOD) {
        return nodeId;
    }

    // 标准解析失败，尝试其他格式

    // 尝试ns=x;s=xxx格式
    const char *ns_part = strstr(node_id_str, "ns=");
    const char *s_part  = strstr(node_id_str, "s=");
    if (ns_part && s_part) {
        uint16_t ns             = 0;
        char     str_value[256] = { 0 };
        if (sscanf(ns_part, "ns=%hu", &ns) == 1 &&
            sscanf(s_part, "s=%255[^;]", str_value) == 1) {
            nodeId = UA_NODEID_STRING(ns, str_value);
            return nodeId;
        }
    }

    // 尝试只有s=xxx格式
    if (s_part) {
        char str_value[256] = { 0 };
        if (sscanf(s_part, "s=%255[^;]", str_value) == 1) {
            nodeId = UA_NODEID_STRING_ALLOC(0, str_value);
            return nodeId;
        }
    }

    // 尝试ns=x;i=xxx格式
    const char *i_part = strstr(node_id_str, "i=");
    if (ns_part && i_part) {
        uint16_t ns = 0;
        uint32_t id = 0;
        if (sscanf(ns_part, "ns=%hu", &ns) == 1 &&
            sscanf(i_part, "i=%u", &id) == 1) {
            nodeId = UA_NODEID_NUMERIC(ns, id);
            return nodeId;
        }
    }

    // 尝试只有i=xxx格式
    if (i_part) {
        uint32_t id = 0;
        if (sscanf(i_part, "i=%u", &id) == 1) {
            nodeId = UA_NODEID_NUMERIC(0, id);
            return nodeId;
        }
    }

    // 简单的i=xxx格式
    if (strncmp(node_id_str, "i=", 2) == 0) {
        uint32_t id = 0;
        if (sscanf(node_id_str + 2, "%u", &id) == 1) {
            nodeId = UA_NODEID_NUMERIC(0, id);
            return nodeId;
        }
    }

    // 简单的s=xxx格式
    if (strncmp(node_id_str, "s=", 2) == 0) {
        nodeId = UA_NODEID_STRING_ALLOC(0, node_id_str + 2);
        return nodeId;
    }

    // 所有解析方法都失败，记录错误
    nodeId = UA_NODEID_NULL;

    return nodeId;
}

// 将UA_NodeId转换为字符串
char *opcua_client_node_id_to_string(const UA_NodeId *node_id)
{
    if (node_id == NULL) {
        return NULL;
    }

    char *result = NULL;

    // 处理不同类型的节点ID
    switch (node_id->identifierType) {
    case UA_NODEIDTYPE_NUMERIC:
        // 数字类型，格式：ns=命名空间;i=id (完整OPC UA标准字符串格式)
        result = malloc(30); // 足够存储大多数数字ID
        if (result) {
            if (node_id->namespaceIndex != 0) {
                // 非默认命名空间，包含ns=前缀
                snprintf(result, 30, "ns=%hu;i=%u", node_id->namespaceIndex,
                         node_id->identifier.numeric);
            } else {
                // 默认命名空间，可以省略ns=0
                snprintf(result, 30, "i=%u", node_id->identifier.numeric);
            }
        }
        break;

    case UA_NODEIDTYPE_STRING:
        // 字符串类型，格式：ns=命名空间;s=字符串 (完整OPC UA标准字符串格式)
        {
            size_t len = node_id->identifier.string.length;
            result     = malloc(len + 30); // 额外空间用于格式标记
            if (result) {
                if (node_id->namespaceIndex != 0) {
                    // 非默认命名空间，包含ns=前缀
                    snprintf(result, len + 30, "ns=%hu;s=%.*s",
                             node_id->namespaceIndex,
                             (int) node_id->identifier.string.length,
                             (char *) node_id->identifier.string.data);
                } else {
                    // 默认命名空间，可以省略ns=0
                    snprintf(result, len + 30, "s=%.*s",
                             (int) node_id->identifier.string.length,
                             (char *) node_id->identifier.string.data);
                }
            }
        }
        break;

    case UA_NODEIDTYPE_GUID:
        // GUID类型，格式：ns=命名空间;g=GUID
        {
            UA_Guid guid = node_id->identifier.guid;
            result       = malloc(60); // GUID字符串大约需要36个字符
            if (result) {
                if (node_id->namespaceIndex != 0) {
                    // 非默认命名空间，包含ns=前缀
                    snprintf(result, 60,
                             "ns=%hu;g=%08x-%04x-%04x-%02x%02x-%02x%02x%02x%"
                             "02x%02x%02x",
                             node_id->namespaceIndex, guid.data1, guid.data2,
                             guid.data3, guid.data4[0], guid.data4[1],
                             guid.data4[2], guid.data4[3], guid.data4[4],
                             guid.data4[5], guid.data4[6], guid.data4[7]);
                } else {
                    // 默认命名空间，可以省略ns=0
                    snprintf(
                        result, 60,
                        "g=%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        guid.data1, guid.data2, guid.data3, guid.data4[0],
                        guid.data4[1], guid.data4[2], guid.data4[3],
                        guid.data4[4], guid.data4[5], guid.data4[6],
                        guid.data4[7]);
                }
            }
        }
        break;

    case UA_NODEIDTYPE_BYTESTRING:
        // 二进制数据类型，格式：ns=命名空间;b=十六进制字符串
        {
            size_t len = node_id->identifier.byteString.length;
            result = malloc(2 * len + 30); // 每个字节转为2个十六进制字符
            if (result) {
                char *pos = result;

                if (node_id->namespaceIndex != 0) {
                    // 非默认命名空间，包含ns=前缀
                    pos +=
                        snprintf(pos, 30, "ns=%hu;b=", node_id->namespaceIndex);
                } else {
                    // 默认命名空间，可以省略ns=0
                    pos += snprintf(pos, 30, "b=");
                }

                for (size_t i = 0; i < len; i++) {
                    pos += snprintf(pos, 3, "%02x",
                                    node_id->identifier.byteString.data[i]);
                }
            }
        }
        break;

    default:
        // 不支持的类型
        result = malloc(50);
        if (result) {
            snprintf(result, 50, "未知类型的节点ID (类型: %d)",
                     node_id->identifierType);
        }
        break;
    }

    return result;
}

// 浏览节点实现
int opcua_client_browse_node(opcua_client_t *client, const UA_NodeId *node_id,
                             UT_array *results)
{
    if (client == NULL || client->client == NULL || !client->connected ||
        node_id == NULL || results == NULL) {
        if (client && client->plugin) {
            plog_error(client->plugin, "Invalid parameters for browse_node");
        }
        return -1;
    }

    // 获取节点ID的字符串表示，用于日志记录
    char *nodeIdStr = NULL;
    if (client->plugin) {
        nodeIdStr = opcua_client_node_id_to_string(node_id);
        if (nodeIdStr) {
            plog_debug(client->plugin, "Browsing node: %s", nodeIdStr);
        }
    }

    // 创建浏览请求
    UA_BrowseRequest bReq;
    UA_BrowseRequest_init(&bReq);
    bReq.requestedMaxReferencesPerNode = 0; // 返回所有引用

    bReq.nodesToBrowse = UA_BrowseDescription_new();
    if (bReq.nodesToBrowse == NULL) {
        if (client->plugin) {
            plog_error(client->plugin,
                       "Failed to allocate memory for browse description");
            if (nodeIdStr)
                free(nodeIdStr);
        }
        return -1;
    }

    bReq.nodesToBrowseSize = 1;

    UA_BrowseDescription_init(bReq.nodesToBrowse);
    UA_NodeId_copy(node_id, &(bReq.nodesToBrowse[0].nodeId));
    bReq.nodesToBrowse[0].resultMask = UA_BROWSERESULTMASK_ALL; // 返回所有属性
    bReq.nodesToBrowse[0].browseDirection = UA_BROWSEDIRECTION_FORWARD;
    bReq.nodesToBrowse[0].includeSubtypes = true;
    bReq.nodesToBrowse[0].referenceTypeId =
        UA_NODEID_NUMERIC(0, UA_NS0ID_HIERARCHICALREFERENCES);

    // 发送浏览请求
    if (client->plugin) {
        plog_debug(client->plugin, "Sending browse request");
    }

    UA_BrowseResponse bResp = UA_Client_Service_browse(client->client, bReq);

    if (bResp.responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
        if (client->plugin) {
            plog_error(client->plugin, "Browse service failed, status: 0x%08x",
                       bResp.responseHeader.serviceResult);
            if (nodeIdStr)
                free(nodeIdStr);
        }

        UA_BrowseRequest_clear(&bReq);
        UA_BrowseResponse_clear(&bResp);
        return -1;
    }

    // 检查结果状态
    if (bResp.resultsSize != 1) {
        if (client->plugin) {
            plog_error(client->plugin,
                       "Browse response has unexpected result size: %zu",
                       bResp.resultsSize);
            if (nodeIdStr)
                free(nodeIdStr);
        }

        UA_BrowseRequest_clear(&bReq);
        UA_BrowseResponse_clear(&bResp);
        return -1;
    }

    if (bResp.results[0].statusCode != UA_STATUSCODE_GOOD) {
        if (client->plugin) {
            plog_error(client->plugin,
                       "Browse result has error, status: 0x%08x",
                       bResp.results[0].statusCode);
            if (nodeIdStr)
                free(nodeIdStr);
        }

        UA_BrowseRequest_clear(&bReq);
        UA_BrowseResponse_clear(&bResp);
        return -1;
    }

    // 处理结果
    size_t referencesCount = bResp.results[0].referencesSize;
    if (client->plugin) {
        plog_debug(client->plugin, "Browse node %s returned %zu references",
                   nodeIdStr ? nodeIdStr : "unknown", referencesCount);
    }

    for (size_t i = 0; i < referencesCount; i++) {
        UA_ReferenceDescription *ref = &bResp.results[0].references[i];

        // 创建结果对象
        opcua_browse_result_t result;

        // 复制节点ID
        UA_NodeId_copy(&ref->nodeId.nodeId, &result.nodeId);

        // 复制浏览名称
        UA_QualifiedName_copy(&ref->browseName, &result.browseName);

        // 复制显示名称
        UA_String_copy(&ref->displayName.text, &result.displayName);

        // 复制节点类型
        result.nodeClass = ref->nodeClass;

        // 对于调试，记录一些节点信息
        if (client->plugin) {
            char *childNodeStr = opcua_client_node_id_to_string(&result.nodeId);
            char *displayName  = NULL;

            if (result.displayName.data && result.displayName.length > 0) {
                displayName = (char *) malloc(result.displayName.length + 1);
                if (displayName) {
                    memcpy(displayName, result.displayName.data,
                           result.displayName.length);
                    displayName[result.displayName.length] = '\0';
                }
            }

            char nodeClassStr[20] = { 0 };
            switch (result.nodeClass) {
            case UA_NODECLASS_OBJECT:
                strcpy(nodeClassStr, "Object");
                break;
            case UA_NODECLASS_VARIABLE:
                strcpy(nodeClassStr, "Variable");
                break;
            case UA_NODECLASS_METHOD:
                strcpy(nodeClassStr, "Method");
                break;
            case UA_NODECLASS_OBJECTTYPE:
                strcpy(nodeClassStr, "ObjectType");
                break;
            case UA_NODECLASS_VARIABLETYPE:
                strcpy(nodeClassStr, "VariableType");
                break;
            case UA_NODECLASS_REFERENCETYPE:
                strcpy(nodeClassStr, "ReferenceType");
                break;
            case UA_NODECLASS_DATATYPE:
                strcpy(nodeClassStr, "DataType");
                break;
            case UA_NODECLASS_VIEW:
                strcpy(nodeClassStr, "View");
                break;
            default:
                strcpy(nodeClassStr, "Unknown");
            }

            plog_debug(client->plugin,
                       "Browse result[%zu]: Node=%s, Name=%s, Class=%s", i,
                       childNodeStr ? childNodeStr : "unknown",
                       displayName ? displayName : "unknown", nodeClassStr);

            if (childNodeStr)
                free(childNodeStr);
            if (displayName)
                free(displayName);
        }

        // 添加到结果数组
        utarray_push_back(results, &result);
    }

    // 清理资源
    UA_BrowseRequest_clear(&bReq);
    UA_BrowseResponse_clear(&bResp);

    if (nodeIdStr)
        free(nodeIdStr);

    return 0;
}

// 根据UA DataType NodeId获取对应的Neuron数据类型
static neu_type_e
opcua_datatype_nodeid_to_neuron_type(const UA_NodeId *dataTypeId)
{
    // 安全检查
    if (dataTypeId == NULL) {
        return NEU_TYPE_STRING; // 默认返回字符串类型
    }

    // 方法1: 根据节点的命名空间和数字标识符映射
    // OPC UA标准数据类型都在命名空间0(ns=0)中，使用数字标识符
    if (dataTypeId->namespaceIndex == 0 &&
        dataTypeId->identifierType == UA_NODEIDTYPE_NUMERIC) {
        uint32_t id = dataTypeId->identifier.numeric;

        // OPC UA规范中定义的标准数据类型
        switch (id) {
        case 1: // Boolean (i=1)
            return NEU_TYPE_BOOL;
        case 2: // SByte (i=2)
            return NEU_TYPE_INT8;
        case 3: // Byte (i=3)
            return NEU_TYPE_UINT8;
        case 4: // Int16 (i=4)
            return NEU_TYPE_INT16;
        case 5: // UInt16 (i=5)
            return NEU_TYPE_UINT16;
        case 6: // Int32 (i=6)
            return NEU_TYPE_INT32;
        case 7: // UInt32 (i=7)
            return NEU_TYPE_UINT32;
        case 8: // Int64 (i=8)
            return NEU_TYPE_INT64;
        case 9: // UInt64 (i=9)
            return NEU_TYPE_UINT64;
        case 10: // Float (i=10)
            return NEU_TYPE_FLOAT;
        case 11: // Double (i=11)
            return NEU_TYPE_DOUBLE;
        case 12: // String (i=12)
            return NEU_TYPE_STRING;
        case 13:                    // DateTime (i=13)
            return NEU_TYPE_UINT32; // DateTime映射为UINT32作为时间戳
        case 15:                    // ByteString (i=15)
            return NEU_TYPE_BYTES;  // ByteString映射为BYTES
        case 16:                    // XmlElement (i=16)
        case 17:                    // NodeId (i=17)
        case 18:                    // ExpandedNodeId (i=18)
            return NEU_TYPE_STRING;
        case 19: // StatusCode (i=19)
            return NEU_TYPE_UINT32;
        case 20: // QualifiedName (i=20)
        case 21: // LocalizedText (i=21)
            return NEU_TYPE_STRING;
        case 22:                    // Structure/ExtensionObject (i=22)
            return NEU_TYPE_CUSTOM; // 扩展对象映射为CUSTOM类型（JSON）

        // 数组类型相关
        case 27: // Boolean Array (i=27)
            return NEU_TYPE_ARRAY_BOOL;
        case 28: // SByte Array (i=28)
            return NEU_TYPE_ARRAY_INT8;
        case 29: // Byte Array (i=29)
            return NEU_TYPE_ARRAY_UINT8;
        case 30: // Int16 Array (i=30)
            return NEU_TYPE_ARRAY_INT16;
        case 31: // UInt16 Array (i=31)
            return NEU_TYPE_ARRAY_UINT16;
        case 32: // Int32 Array (i=32)
            return NEU_TYPE_ARRAY_INT32;
        case 33: // UInt32 Array (i=33)
            return NEU_TYPE_ARRAY_UINT32;
        case 34: // Int64 Array (i=34)
            return NEU_TYPE_ARRAY_INT64;
        case 35: // UInt64 Array (i=35)
            return NEU_TYPE_ARRAY_UINT64;
        case 36: // Float Array (i=36)
            return NEU_TYPE_ARRAY_FLOAT;
        case 37: // Double Array (i=37)
            return NEU_TYPE_ARRAY_DOUBLE;
        case 38: // String Array (i=38)
            return NEU_TYPE_ARRAY_STRING;

        // OPC UA Reference Types数据类型
        case 47:                    // HasComponent (i=47)
        case 49:                    // HasOrderedComponent (i=49)
        case 40:                    // HasTypeDefinition (i=40)
        case 39:                    // HasDescription (i=39)
        case 45:                    // HasSubtype (i=45)
        case 46:                    // HasProperty (i=46)
        case 48:                    // HasNotifier (i=48)
            return NEU_TYPE_STRING; // 引用类型默认当作字符串处理

        // 特定的衍生数据类型
        case 26:                    // Number (i=26)
            return NEU_TYPE_DOUBLE; // 通用数字类型使用DOUBLE以兼容更多数值

        default:
            return NEU_TYPE_STRING; // 对于其他类型，使用STRING作为默认类型
        }
    }

    // 方法2: 尝试通过字符串标识符判断类型
    // 对于使用字符串标识符的节点，检查是否包含关键字
    if (dataTypeId->identifierType == UA_NODEIDTYPE_STRING) {
        UA_String identifier = dataTypeId->identifier.string;

        // 安全检查
        if (identifier.length == 0 || identifier.data == NULL) {
            return NEU_TYPE_STRING;
        }

        char *str = (char *) UA_malloc(identifier.length + 1);
        if (str) {
            memcpy(str, identifier.data, identifier.length);
            str[identifier.length] = '\0';

            // 转换为小写进行比较
            for (size_t i = 0; i < identifier.length; i++) {
                str[i] = tolower(str[i]);
            }

            neu_type_e result = NEU_TYPE_STRING;

            // 根据字符串标识符匹配类型
            if (strstr(str, "bool")) {
                result = NEU_TYPE_BOOL;
            } else if (strstr(str, "sbyte")) {
                result = NEU_TYPE_INT8;
            } else if (strstr(str, "bytestring")) {
                result = NEU_TYPE_BYTES; // 确保ByteString优先于Byte匹配
            } else if (strstr(str, "byte")) {
                result = NEU_TYPE_UINT8;
            } else if (strstr(str, "int16")) {
                result = NEU_TYPE_INT16;
            } else if (strstr(str, "uint16")) {
                result = NEU_TYPE_UINT16;
            } else if (strstr(str, "int32")) {
                result = NEU_TYPE_INT32;
            } else if (strstr(str, "uint32")) {
                result = NEU_TYPE_UINT32;
            } else if (strstr(str, "int64")) {
                result = NEU_TYPE_INT64;
            } else if (strstr(str, "uint64")) {
                result = NEU_TYPE_UINT64;
            } else if (strstr(str, "float")) {
                result = NEU_TYPE_FLOAT;
            } else if (strstr(str, "double")) {
                result = NEU_TYPE_DOUBLE;
            } else if (strstr(str, "string")) {
                result = NEU_TYPE_STRING;
            } else if (strstr(str, "bytes")) {
                result = NEU_TYPE_BYTES;
            } else if (strstr(str, "date") || strstr(str, "time")) {
                result = NEU_TYPE_UINT32; // 日期/时间类型映射为UINT32
            } else if (strstr(str, "extension") || strstr(str, "object")) {
                result = NEU_TYPE_CUSTOM; // 扩展对象映射为CUSTOM类型（JSON）
            } else if (strstr(str, "array")) {
                // 尝试处理数组类型
                if (strstr(str, "boolarray")) {
                    result = NEU_TYPE_ARRAY_BOOL;
                } else if (strstr(str, "bytestringarray")) {
                    result =
                        NEU_TYPE_BYTES; // 字节数组类型，Neuron可能没有专门的数组字节类型
                } else if (strstr(str, "bytearray")) {
                    result = NEU_TYPE_ARRAY_UINT8;
                } else if (strstr(str, "sbytesarray")) {
                    result = NEU_TYPE_ARRAY_INT8;
                } else if (strstr(str, "int16array")) {
                    result = NEU_TYPE_ARRAY_INT16;
                } else if (strstr(str, "uint16array")) {
                    result = NEU_TYPE_ARRAY_UINT16;
                } else if (strstr(str, "int32array")) {
                    result = NEU_TYPE_ARRAY_INT32;
                } else if (strstr(str, "uint32array")) {
                    result = NEU_TYPE_ARRAY_UINT32;
                } else if (strstr(str, "int64array")) {
                    result = NEU_TYPE_ARRAY_INT64;
                } else if (strstr(str, "uint64array")) {
                    result = NEU_TYPE_ARRAY_UINT64;
                } else if (strstr(str, "floatarray")) {
                    result = NEU_TYPE_ARRAY_FLOAT;
                } else if (strstr(str, "doublearray")) {
                    result = NEU_TYPE_ARRAY_DOUBLE;
                } else if (strstr(str, "stringarray")) {
                    result = NEU_TYPE_ARRAY_STRING;
                } else {
                    // 未能识别的数组类型，默认为字符串数组
                    result = NEU_TYPE_ARRAY_STRING;
                }
            }

            UA_free(str);
            return result;
        }
    }

    // 默认使用STRING类型
    return NEU_TYPE_STRING;
}

// 读取节点的数据类型属性并返回对应的Neuron类型
int opcua_client_read_variable_datatype(opcua_client_t * client,
                                        const UA_NodeId *nodeId,
                                        neu_type_e *     type)
{
    if (client == NULL || nodeId == NULL || type == NULL ||
        !client->connected) {
        if (client && client->plugin) {
            plog_error(client->plugin,
                       "Invalid parameters for read_variable_datatype");
        }
        return -1;
    }

    // 获取节点ID的字符串表示，用于日志记录
    char *nodeIdStr = NULL;
    if (client->plugin) {
        nodeIdStr = opcua_client_node_id_to_string(nodeId);
        if (nodeIdStr) {
            plog_debug(client->plugin,
                       "Reading DataType attribute for node: %s", nodeIdStr);
        }
    }

    // 初始化为默认类型
    *type = NEU_TYPE_STRING;

    // 用于存储DataType属性的NodeId
    UA_NodeId dataTypeId;
    UA_NodeId_init(&dataTypeId);

    // 首先尝试读取DataType属性
    UA_StatusCode status =
        UA_Client_readDataTypeAttribute(client->client, *nodeId, &dataTypeId);

    if (status == UA_STATUSCODE_GOOD) {
        // 转换为Neuron类型
        *type = opcua_datatype_nodeid_to_neuron_type(&dataTypeId);

        if (client->plugin) {
            char *typeIdStr = opcua_client_node_id_to_string(&dataTypeId);
            if (typeIdStr) {
                plog_debug(client->plugin,
                           "Node %s dataType NodeId: %s, Neuron type: %d",
                           nodeIdStr ? nodeIdStr : "unknown", typeIdStr, *type);
                free(typeIdStr);
            }
        }
    } else {
        if (client->plugin) {
            plog_debug(client->plugin,
                       "Failed to read DataType attribute, status: %d", status);
        }
    }

    // 然后检查ValueRank属性，判断是否为数组
    UA_Int32 valueRank = -1;
    status =
        UA_Client_readValueRankAttribute(client->client, *nodeId, &valueRank);

    UA_Boolean isArray = UA_FALSE;
    if (status == UA_STATUSCODE_GOOD) {
        // valueRank > 0 表示这是一个数组
        // valueRank = 1 表示一维数组
        // valueRank > 1 表示多维数组
        // valueRank = 0 表示这是一个标量
        // valueRank = -1 表示值的维度不受限制
        // valueRank = -2 表示维度不与类型定义匹配
        // valueRank = -3 表示类型定义的维度是可选的
        if (valueRank > 0) {
            isArray = UA_TRUE;
            if (client->plugin) {
                plog_debug(client->plugin,
                           "Node %s is an array with valueRank = %d",
                           nodeIdStr ? nodeIdStr : "unknown", valueRank);
            }
        }
    } else if (client->plugin) {
        plog_debug(client->plugin,
                   "Failed to read ValueRank attribute, status: %d", status);
    }

    // 如果ValueRank不能确定是否为数组，我们尝试读取值本身
    if (!isArray || status != UA_STATUSCODE_GOOD) {
        UA_Variant value;
        UA_Variant_init(&value);

        status = UA_Client_readValueAttribute(client->client, *nodeId, &value);

        if (status == UA_STATUSCODE_GOOD) {
            // 检查是否为数组
            if (value.arrayLength > 0 ||
                (value.arrayDimensionsSize > 0 && value.arrayDimensions &&
                 value.arrayDimensions[0] > 0)) {
                isArray = UA_TRUE;
                if (client->plugin) {
                    plog_debug(
                        client->plugin,
                        "Detected array by reading value, array length: %d",
                        (int) value.arrayLength);
                }
            }

            // 如果未能通过DataType属性获取类型，尝试从值获取
            if (*type == NEU_TYPE_STRING && value.type &&
                !UA_NodeId_isNull(&value.type->typeId)) {
                *type =
                    opcua_datatype_nodeid_to_neuron_type(&value.type->typeId);
                if (client->plugin) {
                    char *valueTypeIdStr =
                        opcua_client_node_id_to_string(&value.type->typeId);
                    if (valueTypeIdStr) {
                        plog_debug(
                            client->plugin,
                            "Detected type from value: %s, Neuron type: %d",
                            valueTypeIdStr, *type);
                        free(valueTypeIdStr);
                    }
                }
            }
        }
        UA_Variant_clear(&value);
    }

    // 如果是ByteString类型，保持不变
    if (*type == NEU_TYPE_BYTES) {
        if (client->plugin) {
            plog_debug(client->plugin, "Node %s is ByteString type",
                       nodeIdStr ? nodeIdStr : "unknown");
        }
    }
    // 如果是数组，将类型设置为相应的数组类型
    else if (isArray) {
        if (client->plugin) {
            plog_debug(client->plugin,
                       "Node %s is array type with base type %d",
                       nodeIdStr ? nodeIdStr : "unknown", *type);
        }

        // 根据基本类型设置数组类型
        neu_type_e base_type = *type;
        switch (base_type) {
        case NEU_TYPE_BOOL:
            *type = NEU_TYPE_ARRAY_BOOL;
            break;
        case NEU_TYPE_INT8:
            *type = NEU_TYPE_ARRAY_INT8;
            break;
        case NEU_TYPE_UINT8:
            *type = NEU_TYPE_ARRAY_UINT8;
            break;
        case NEU_TYPE_INT16:
            *type = NEU_TYPE_ARRAY_INT16;
            break;
        case NEU_TYPE_UINT16:
            *type = NEU_TYPE_ARRAY_UINT16;
            break;
        case NEU_TYPE_INT32:
            *type = NEU_TYPE_ARRAY_INT32;
            break;
        case NEU_TYPE_UINT32:
            *type = NEU_TYPE_ARRAY_UINT32;
            break;
        case NEU_TYPE_INT64:
            *type = NEU_TYPE_ARRAY_INT64;
            break;
        case NEU_TYPE_UINT64:
            *type = NEU_TYPE_ARRAY_UINT64;
            break;
        case NEU_TYPE_FLOAT:
            *type = NEU_TYPE_ARRAY_FLOAT;
            break;
        case NEU_TYPE_DOUBLE:
            *type = NEU_TYPE_ARRAY_DOUBLE;
            break;
        case NEU_TYPE_STRING:
            *type = NEU_TYPE_ARRAY_STRING;
            break;
        default:
            // 对于其他类型，保持原类型不变
            if (client->plugin) {
                plog_warn(client->plugin,
                          "Node %s is array of unsupported type %d, keeping "
                          "original type",
                          nodeIdStr ? nodeIdStr : "unknown", base_type);
            }
            break;
        }

        if (client->plugin) {
            plog_debug(client->plugin,
                       "Node %s array type mapped to Neuron type %d",
                       nodeIdStr ? nodeIdStr : "unknown", *type);
        }
    }

    // 如果最终仍未能确定类型，使用默认的STRING类型
    if (*type == 0) {
        *type = NEU_TYPE_STRING;
        if (client->plugin) {
            plog_debug(client->plugin, "Using default STRING type for node %s",
                       nodeIdStr ? nodeIdStr : "unknown");
        }
    }

    if (nodeIdStr) {
        free(nodeIdStr);
    }

    UA_NodeId_clear(&dataTypeId);
    return 0;
}

// 读取变量值属性的函数实现
UA_StatusCode opcua_client_read_value_attribute(opcua_client_t * client,
                                                const UA_NodeId *nodeId,
                                                UA_Variant *     value)
{
    if (client == NULL || nodeId == NULL || value == NULL ||
        !client->connected) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    return UA_Client_readValueAttribute(client->client, *nodeId, value);
}

// 读取节点显示名称属性的函数实现
UA_StatusCode
opcua_client_read_display_name_attribute(opcua_client_t *  client,
                                         const UA_NodeId * nodeId,
                                         UA_LocalizedText *displayName)
{
    if (client == NULL || nodeId == NULL || displayName == NULL ||
        !client->connected) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    return UA_Client_readDisplayNameAttribute(client->client, *nodeId,
                                              displayName);
}

int opcua_client_connect_async(opcua_client_t *client, const char *endpoint_url,
                               const char *username, const char *password,
                               const char *certificate, const char *private_key,
                               opcua_security_mode_e security_mode)
{
    if (client == NULL || endpoint_url == NULL) {
        return -1;
    }

    // 如果已连接，先断开连接
    if (client->connected) {
        opcua_client_disconnect(client);
    }

    // 如果正在连接中，返回错误
    if (client->connecting) {
        if (client->plugin) {
            plog_warn(client->plugin, "异步连接已在进行中，请等待完成");
        }
        return -1;
    }

    // 添加连接开始日志
    if (client->plugin) {
        plog_info(client->plugin, "正在异步连接到OPC UA服务器: %s",
                  endpoint_url);
    }

    UA_ClientConfig *config = UA_Client_getConfig(client->client);

    // 配置用户名/密码认证
    if (username != NULL && password != NULL && strlen(username) > 0) {
        if (client->plugin) {
            plog_debug(client->plugin, "使用用户名认证进行OPC UA连接");
        }

        UA_UserNameIdentityToken *identityToken =
            UA_UserNameIdentityToken_new();
        identityToken->userName            = UA_STRING_ALLOC(username);
        identityToken->password            = UA_STRING_ALLOC(password);
        identityToken->encryptionAlgorithm = UA_STRING_NULL;

        UA_ExtensionObject_clear(&config->userIdentityToken);
        config->userIdentityToken.encoding = UA_EXTENSIONOBJECT_DECODED;
        config->userIdentityToken.content.decoded.type =
            &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN];
        config->userIdentityToken.content.decoded.data = identityToken;
    }

    // 配置安全模式
    switch (security_mode) {
    case OPCUA_SECURITY_MODE_NONE:
        if (client->plugin) {
            plog_debug(client->plugin, "使用None安全模式进行OPC UA连接");
        }
        config->securityMode = UA_MESSAGESECURITYMODE_NONE;
        break;
    case OPCUA_SECURITY_MODE_SIGN:
        if (certificate != NULL && private_key != NULL) {
            if (client->plugin) {
                plog_debug(client->plugin, "使用Sign安全模式进行OPC UA连接");
            }
            config->securityMode = UA_MESSAGESECURITYMODE_SIGN;
        } else {
            if (client->plugin) {
                plog_error(client->plugin, "缺少证书或私钥进行Sign安全模式");
            }
            return -1;
        }
        break;
    case OPCUA_SECURITY_MODE_SIGN_ENCRYPT:
        if (certificate != NULL && private_key != NULL) {
            if (client->plugin) {
                plog_debug(client->plugin,
                           "使用SignAndEncrypt安全模式进行OPC UA连接");
            }
            config->securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
        } else {
            if (client->plugin) {
                plog_error(client->plugin,
                           "缺少证书或私钥进行SignAndEncrypt安全模式");
            }
            return -1;
        }
        break;
    default:
        if (client->plugin) {
            plog_error(client->plugin, "未知安全模式: %d", security_mode);
        }
        return -1;
    }

    // 记录连接开始时间
    client->connect_start_time = neu_time_ms();
    client->connecting         = true;

    // 使用异步连接方法
    UA_StatusCode status = UA_Client_connectAsync(client->client, endpoint_url);
    if (status != UA_STATUSCODE_GOOD) {
        client->connecting = false;
        if (client->plugin) {
            plog_error(client->plugin,
                       "启动异步连接到OPC UA服务器失败: %s, 状态码: 0x%08x",
                       endpoint_url, status);
        }
        return -1;
    }

    if (client->plugin) {
        plog_notice(client->plugin, "已成功启动到OPC UA服务器的异步连接: %s",
                    endpoint_url);
    }

    return 0;
}

int opcua_client_process_async(opcua_client_t *client, uint32_t timeout_ms)
{
    if (client == NULL || client->client == NULL) {
        return -1;
    }

    // 处理客户端异步操作
    UA_StatusCode status = UA_Client_run_iterate(client->client, timeout_ms);
    if (status != UA_STATUSCODE_GOOD) {
        if (client->plugin) {
            plog_error(client->plugin,
                       "处理OPC UA客户端异步操作失败, 状态码: 0x%08x", status);
        }
        return -1;
    }

    // 增加主动检查连接状态
    UA_SecureChannelState channelState;
    UA_SessionState       sessionState;
    UA_StatusCode         connectStatus;
    UA_Client_getState(client->client, &channelState, &sessionState,
                       &connectStatus);

    // 根据实际状态更新连接标志
    bool new_state = (sessionState == UA_SESSIONSTATE_ACTIVATED);
    if (new_state != client->connected) {
        if (new_state) {
            // 连接状态从断开变为连接
            client->connected  = true;
            client->connecting = false;
            // 计算连接时间
            int64_t duration = 0;
            if (client->connect_start_time > 0) {
                duration = neu_time_ms() - client->connect_start_time;
                client->connect_start_time = 0;
            }
            if (client->plugin) {
                plog_notice(client->plugin,
                            "OPC UA连接已成功建立，会话已激活，通道状态: %d, "
                            "会话状态: %d, 状态码: 0x%08x，耗时: %ld ms",
                            channelState, sessionState, connectStatus,
                            duration);
            }
        } else {
            // 连接状态从连接变为断开
            client->connected = false;
            if (client->plugin) {
                plog_warn(client->plugin,
                          "OPC UA连接已主动检测到断开，通道状态: %d, 会话状态: "
                          "%d, 连接状态码: 0x%08x",
                          channelState, sessionState, connectStatus);
            }
        }
    } else if (client->connecting &&
               sessionState == UA_SESSIONSTATE_ACTIVATED) {
        // 连接中状态已变为已连接
        client->connecting = false;
        client->connected  = true;
        // 计算连接时间
        int64_t duration = 0;
        if (client->connect_start_time > 0) {
            duration = neu_time_ms() - client->connect_start_time;
            client->connect_start_time = 0;
        }
        if (client->plugin) {
            plog_notice(client->plugin,
                        "OPC UA连接过程完成，会话已激活，通道状态: %d, "
                        "会话状态: %d, 状态码: 0x%08x，耗时: %ld ms",
                        channelState, sessionState, connectStatus, duration);
        }
    }

    // 检查连接是否在进行中
    if (client->connecting) {
        // 检查连接是否超时
        if (client->connect_start_time > 0) {
            int64_t duration = neu_time_ms() - client->connect_start_time;

            // 定义连接超时阈值，默认10秒，未来可配置
            static const int64_t CONNECTION_TIMEOUT_MS = 10000; // 10秒超时

            // 如果连接时间超过阈值，认为连接超时
            if (duration > CONNECTION_TIMEOUT_MS) {
                client->connecting         = false;
                client->connect_start_time = 0;

                if (client->plugin) {
                    plog_error(
                        client->plugin,
                        "异步连接到OPC UA服务器超时，已经尝试了%ld ms (%ld 秒)",
                        duration, duration / 1000);

                    // 获取服务器状态信息帮助诊断
                    plog_error(client->plugin,
                               "连接失败状态: 通道=%d, 会话=%d, 状态码=0x%08x",
                               channelState, sessionState, connectStatus);
                }
                return -1;
            }

            // 如果已经尝试了一段时间，但仍在连接中，提供状态更新日志
            if (duration > 3000 && duration % 3000 < 100) { // 每3秒打印一次
                if (client->plugin) {
                    plog_notice(client->plugin,
                                "正在连接OPC UA服务器，已经尝试了 %ld 秒... "
                                "(通道=%d, 会话=%d, 状态码=0x%08x)",
                                duration / 1000, channelState, sessionState,
                                connectStatus);
                }
            }
        }

        // 连接仍在进行中
        return 0;
    }

    // 连接过程已结束，返回连接状态
    return client->connected ? 1 : -1;
}

bool opcua_client_connecting(opcua_client_t *client)
{
    if (client == NULL || client->client == NULL) {
        return false;
    }

    return client->connecting;
}