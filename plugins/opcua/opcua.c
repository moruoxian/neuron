#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <neuron/neuron.h>
#include <neuron/utils/time.h>
#include <neuron/errcodes.h>

#include "opcua.h"
#include "opcua_client.h"
#include "opcua_point.h"

// 添加UT_icd定义
static UT_icd neu_scan_tag_icd = {sizeof(neu_scan_tag_t), NULL, NULL, NULL};

// 引用opcua_browse_result_icd，在opcua_client.c中定义
extern UT_icd opcua_browse_result_icd;

struct opcua_group_data {
    UT_array *tags;
    char *group;
    opcua_read_cmd_sort_t *cmd_sort;
};

static neu_plugin_t *driver_open(void);
static int driver_close(neu_plugin_t *plugin);
static int driver_init(neu_plugin_t *plugin, bool load);
static int driver_uninit(neu_plugin_t *plugin);
static int driver_start(neu_plugin_t *plugin);
static int driver_stop(neu_plugin_t *plugin);
static int driver_config(neu_plugin_t *plugin, const char *config);
static int driver_request(neu_plugin_t *plugin, neu_reqresp_head_t *head,
                          void *data);

static int driver_validate_tag(neu_plugin_t *plugin, neu_datatag_t *tag);
static int driver_group_timer(neu_plugin_t *plugin, neu_plugin_group_t *group);
static int driver_write(neu_plugin_t *plugin, void *req, neu_datatag_t *tag,
                        neu_value_u value);
static int driver_write_tags(neu_plugin_t *plugin, void *req, UT_array *tags);
static int driver_test_read_tag(neu_plugin_t *plugin, void *req,
                                neu_datatag_t tag);
static int driver_add_tags(neu_plugin_t *plugin, const char *group, neu_datatag_t *tags, int n_tag);
static int driver_scan_tags(neu_plugin_t *plugin, void *req, char *id, char *ctx);

static const neu_plugin_intf_funs_t plugin_intf_funs = {
    .open    = driver_open,
    .close   = driver_close,
    .init    = driver_init,
    .uninit  = driver_uninit,
    .start   = driver_start,
    .stop    = driver_stop,
    .setting = driver_config,
    .request = driver_request,

    .driver.validate_tag  = driver_validate_tag,
    .driver.group_timer   = driver_group_timer,
    .driver.group_sync    = driver_group_timer,
    .driver.write_tag     = driver_write,
    .driver.tag_validator = NULL,
    .driver.write_tags    = driver_write_tags,
    .driver.test_read_tag = driver_test_read_tag,
    .driver.add_tags      = driver_add_tags,
    .driver.load_tags     = NULL,
    .driver.del_tags      = NULL,
    .driver.directory     = NULL,
    .driver.fup_open      = NULL,
    .driver.fup_data      = NULL,
    .driver.fdown_open    = NULL,
    .driver.fdown_data    = NULL,
    .driver.scan_tags     = driver_scan_tags,
};

const neu_plugin_module_t neu_plugin_module = {
    .version     = NEURON_PLUGIN_VER_1_0,
    .schema      = "opcua",
    .module_name = "OPC UA",
    .module_descr =
        "This plugin is used to connect to OPC UA servers. "
        "It supports authentication with username/password and certificates.",
    .module_descr_zh =
        "该插件用于连接 OPC UA 服务器。"
        "支持用户名/密码和证书认证。",
    .intf_funs = &plugin_intf_funs,
    .kind      = NEU_PLUGIN_KIND_SYSTEM,
    .type      = NEU_NA_TYPE_DRIVER,
    .display   = true,
    .single    = false,
};

static void plugin_group_free(neu_plugin_group_t *pgp);

static neu_plugin_t *driver_open(void)
{
    neu_plugin_t *plugin = calloc(1, sizeof(neu_plugin_t));

    neu_plugin_common_init(&plugin->common);
    
    // calloc 已经将所有内存初始化为 0，所以指针字段已经是 NULL
    plugin->client = NULL;
    plugin->plugin_group_data = NULL;
    
    // 默认安全模式为None
    plugin->security_mode = OPCUA_SECURITY_MODE_NONE;
    
    // 初始化重连参数
    plugin->reconnect_enabled = true;         // 默认启用自动重连
    plugin->reconnect_interval = 5000;        // 默认5秒重连一次
    plugin->reconnect_attempts = 0;           // 初始化重连次数
    plugin->max_reconnect_attempts = 0;       // 默认无限重连

    return plugin;
}

static int driver_close(neu_plugin_t *plugin)
{
    free(plugin);
    return 0;
}

static int driver_init(neu_plugin_t *plugin, bool load)
{
    (void) load;

    plugin->client = opcua_client_create(plugin);
    if (plugin->client == NULL) {
        plog_error(plugin, "Failed to create OPC UA client");
        return -1;
    }
    
    // 注册延时度量指标
    NEU_PLUGIN_REGISTER_METRIC(plugin, NEU_METRIC_LAST_RTT_MS, NEU_METRIC_LAST_RTT_MS_MAX);

    plog_notice(plugin, "%s init success", plugin->common.name);
    return 0;
}

static int driver_uninit(neu_plugin_t *plugin)
{
    plog_notice(plugin, "%s uninit start", plugin->common.name);

    if (plugin->client != NULL) {
        opcua_client_destroy(plugin->client);
        plugin->client = NULL;
    }

    if (plugin->endpoint_url != NULL) {
        free(plugin->endpoint_url);
        plugin->endpoint_url = NULL;
    }

    if (plugin->username != NULL) {
        free(plugin->username);
        plugin->username = NULL;
    }

    if (plugin->password != NULL) {
        free(plugin->password);
        plugin->password = NULL;
    }

    if (plugin->certificate != NULL) {
        free(plugin->certificate);
        plugin->certificate = NULL;
    }

    if (plugin->private_key != NULL) {
        free(plugin->private_key);
        plugin->private_key = NULL;
    }
    
    // 注意：不需要释放plugin->plugin_group_data
    // 因为它已经被设置为group->user_data，会在group_free回调中被释放

    plog_notice(plugin, "%s uninit success", plugin->common.name);
    return 0;
}

static int driver_start(neu_plugin_t *plugin)
{
    if (plugin->client == NULL) {
        plog_error(plugin, "OPC UA client not initialized");
        return -1;
    }
    
    plog_notice(plugin, "Starting OPC UA client and connecting to server: %s", plugin->endpoint_url);
    
    // 使用异步方式连接到服务器
    int ret = opcua_client_connect_async(plugin->client, plugin->endpoint_url,
                                        plugin->username, plugin->password,
                                        plugin->certificate, plugin->private_key,
                                        plugin->security_mode);
    
    if (ret != 0) {
        plog_error(plugin, "Failed to start async connection to OPC UA server: %s", 
                  plugin->endpoint_url);
        
        // 如果启用了自动重连，虽然连接失败，但仍然启动插件
        if (plugin->reconnect_enabled) {
            plog_notice(plugin, "Auto reconnect is enabled, plugin will start and try to reconnect later");
            plugin->reconnect_attempts = 0; // 重置重连计数
            plugin->connected = false;
            plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
            return 0; // 返回成功，让插件继续运行
        }
        
        return -1;
    }
    
    // 处理异步连接，最多等待3秒
    int connect_wait_count = 30; // 30次 * 100ms = 3秒
    int connect_status = 0;
    
    while (connect_wait_count > 0) {
        connect_status = opcua_client_process_async(plugin->client, 100);
        
        // 连接成功
        if (connect_status > 0) {
            plugin->connected = true;
            plugin->common.link_state = NEU_NODE_LINK_STATE_CONNECTED;
            plugin->reconnect_attempts = 0; // 重置重连计数
            plog_notice(plugin, "Successfully connected to OPC UA server: %s", plugin->endpoint_url);
            return 0;
        }
        // 连接失败
        else if (connect_status < 0) {
            break;
        }
        
        // 连接中，继续等待
        connect_wait_count--;
    }
    
    // 如果连接未完成或失败，但启用了自动重连，仍然返回成功
    if (plugin->reconnect_enabled) {
        plog_notice(plugin, "OPC UA connection not established yet, but auto reconnect is enabled. Plugin will start and connection will continue in background.");
        plugin->connected = false;
        plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
        return 0;
    }
    
    // 未启用自动重连，返回失败
    plog_error(plugin, "Failed to connect to OPC UA server: %s and auto reconnect is disabled", 
              plugin->endpoint_url);
    plugin->connected = false;
    plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
    return -1;
}

static int driver_stop(neu_plugin_t *plugin)
{
    if (plugin->client != NULL) {
        opcua_client_disconnect(plugin->client);
    }

    plugin->connected = false;
    plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
    plog_notice(plugin, "%s stop success", plugin->common.name);
    return 0;
}

static int driver_config(neu_plugin_t *plugin, const char *config)
{
    int              ret       = 0;
    char *           err_param = NULL;
    neu_json_elem_t  endpoint_url = { .name = "endpoint_url", .t = NEU_JSON_STR };
    neu_json_elem_t  username = { .name = "username", .t = NEU_JSON_STR };
    neu_json_elem_t  password = { .name = "password", .t = NEU_JSON_STR };
    neu_json_elem_t  security_mode = { .name = "security_mode", .t = NEU_JSON_INT };
    neu_json_elem_t  certificate = { .name = "certificate", .t = NEU_JSON_STR };
    neu_json_elem_t  private_key = { .name = "private_key", .t = NEU_JSON_STR };
    neu_json_elem_t  reconnect_enabled = { .name = "reconnect_enabled", .t = NEU_JSON_INT };
    neu_json_elem_t  reconnect_interval = { .name = "reconnect_interval", .t = NEU_JSON_INT };
    neu_json_elem_t  max_reconnect_attempts = { .name = "max_reconnect_attempts", .t = NEU_JSON_INT };

    ret = neu_parse_param((char *) config, &err_param, 9, &endpoint_url, &username,
                          &password, &security_mode, &certificate, &private_key,
                          &reconnect_enabled, &reconnect_interval, &max_reconnect_attempts);

    if (ret != 0) {
        plog_error(plugin, "config: %s, decode error: %s", config, err_param);
        free(err_param);
        if (endpoint_url.v.val_str != NULL) {
            free(endpoint_url.v.val_str);
        }
        if (username.v.val_str != NULL) {
            free(username.v.val_str);
        }
        if (password.v.val_str != NULL) {
            free(password.v.val_str);
        }
        if (certificate.v.val_str != NULL) {
            free(certificate.v.val_str);
        }
        if (private_key.v.val_str != NULL) {
            free(private_key.v.val_str);
        }
        return -1;
    }

    // Free old values
    if (plugin->endpoint_url != NULL) {
        free(plugin->endpoint_url);
    }
    if (plugin->username != NULL) {
        free(plugin->username);
    }
    if (plugin->password != NULL) {
        free(plugin->password);
    }
    if (plugin->certificate != NULL) {
        free(plugin->certificate);
        plugin->certificate = NULL;
    }
    if (plugin->private_key != NULL) {
        free(plugin->private_key);
        plugin->private_key = NULL;
    }

    // Set new values
    plugin->endpoint_url = endpoint_url.v.val_str;
    plugin->username = username.v.val_str;
    plugin->password = password.v.val_str;
    
    // 设置安全模式
    switch (security_mode.v.val_int) {
    case 1: // None
        plugin->security_mode = OPCUA_SECURITY_MODE_NONE;
        plog_notice(plugin, "Security mode: None");
        break;
    case 2: // Sign
        plugin->security_mode = OPCUA_SECURITY_MODE_SIGN;
        plog_notice(plugin, "Security mode: Sign");
        break;
    case 3: // Sign & Encrypt
        plugin->security_mode = OPCUA_SECURITY_MODE_SIGN_ENCRYPT;
        plog_notice(plugin, "Security mode: Sign and Encrypt");
        break;
    default:
        plugin->security_mode = OPCUA_SECURITY_MODE_NONE;
        plog_notice(plugin, "Unknown security mode: %ld, using None", security_mode.v.val_int);
        break;
    }
    
    // 设置重连参数
    plugin->reconnect_enabled = reconnect_enabled.v.val_int == 1 ? true : false;
    plugin->reconnect_interval = (uint32_t)reconnect_interval.v.val_int;
    plugin->max_reconnect_attempts = (uint32_t)max_reconnect_attempts.v.val_int;
    plugin->reconnect_attempts = 0; // 重置重连尝试次数
    
    plog_notice(plugin, "Auto reconnect: %s, interval: %u ms, max attempts: %u", 
               plugin->reconnect_enabled ? "enabled" : "disabled",
               plugin->reconnect_interval,
               plugin->max_reconnect_attempts);
    
    // 设置证书和私钥
    if (certificate.v.val_str != NULL) {
        plugin->certificate = certificate.v.val_str;
        plog_debug(plugin, "Certificate provided");
    }
    
    if (private_key.v.val_str != NULL) {
        plugin->private_key = private_key.v.val_str;
        plog_debug(plugin, "Private key provided");
    }

    plog_notice(plugin, "config: endpoint_url: %s", plugin->endpoint_url);
    
    return 0;
}

static int driver_request(neu_plugin_t *plugin, neu_reqresp_head_t *head,
                          void *data)
{
    (void) plugin;
    (void) head;
    (void) data;
    return 0;
}

static int driver_validate_tag(neu_plugin_t *plugin, neu_datatag_t *tag)
{
    (void) plugin;
    
    opcua_point_t point = { 0 };
    int ret = opcua_tag_to_point(tag, &point);
    
    if (ret != 0) {
        return NEU_ERR_TAG_ADDRESS_FORMAT_INVALID;
    }

    // Free allocated memory
    free(point.name);
    free(point.node_id);

    return 0;
}

static int try_reconnect(neu_plugin_t *plugin)
{
    // 如果未启用重连，直接返回
    if (!plugin->reconnect_enabled) {
        return -1;
    }
    
    // 检查客户端是否在连接过程中，避免重复发起连接
    if (plugin->client && opcua_client_connecting(plugin->client)) {
        plog_debug(plugin, "OPC UA客户端正在连接中，跳过本次重连尝试");
        return 0; // 返回0表示已经有连接在进行，不需要重新启动
    }
    
    // 如果达到最大重连次数（非0），则不再尝试
    if (plugin->max_reconnect_attempts > 0 && 
        plugin->reconnect_attempts >= plugin->max_reconnect_attempts) {
        // 使用静态变量控制日志输出频率
        static int64_t last_warning_time = 0;
        int64_t current_time = neu_time_ms();
        
        // 每10分钟最多输出一次警告
        if (last_warning_time == 0 || 
            (current_time - last_warning_time) > 600000) {
            plog_warn(plugin, "最大重连尝试次数 (%u) 已达到，放弃重连。可通过重启插件或设置较大的最大重连次数解决。", 
                     plugin->max_reconnect_attempts);
            last_warning_time = current_time;
        }
        return -1;
    }
    
    // 使用静态变量记录上次尝试重连的时间
    static int64_t last_reconnect_time = 0;
    int64_t current_time = neu_time_ms();
    
    // 实现指数退避重试策略
    // 连续失败次数越多，等待时间越长（但不超过设定的最大间隔）
    int64_t actual_interval = plugin->reconnect_interval;
    if (plugin->reconnect_attempts > 1) {
        // 计算指数增长的时间间隔，但不超过设定间隔的5倍
        int multiplier = 1;
        for (uint32_t i = 1; i < plugin->reconnect_attempts && i < 5; i++) {
            multiplier *= 2;
        }
        actual_interval = plugin->reconnect_interval * multiplier;
        
        // 确保不超过最大间隔（1分钟）
        if (actual_interval > 60000) {
            actual_interval = 60000;
        }
    }
    
    // 检查是否已经过了足够的重连间隔时间
    if (last_reconnect_time > 0 && 
        (current_time - last_reconnect_time) < actual_interval) {
        // 间隔时间不够，本次不尝试重连
        return -1;
    }
    
    // 更新上次尝试重连的时间
    last_reconnect_time = current_time;
    
    // 在尝试新连接前，检查客户端状态
    if (plugin->client == NULL) {
        plog_error(plugin, "OPC UA客户端未初始化，无法进行重连");
        return -1;
    }
    
    // 确保先断开任何现有连接
    if (opcua_client_is_connected(plugin->client)) {
        plog_debug(plugin, "在重连前断开现有连接");
        opcua_client_disconnect(plugin->client);
    }
    
    // 增加重连计数
    plugin->reconnect_attempts++;
    
    char max_attempts_str[32];
    if (plugin->max_reconnect_attempts > 0) {
        snprintf(max_attempts_str, sizeof(max_attempts_str), "%u", plugin->max_reconnect_attempts);
    } else {
        strcpy(max_attempts_str, "无限");
    }
    
    plog_notice(plugin, "尝试异步重连到OPC UA服务器 (尝试 %u/%s)，间隔: %ld ms", 
                plugin->reconnect_attempts, max_attempts_str, actual_interval);
    
    // 使用异步方式重新连接
    int ret = opcua_client_connect_async(plugin->client, plugin->endpoint_url,
                                        plugin->username, plugin->password,
                                        plugin->certificate, plugin->private_key,
                                        plugin->security_mode);
    
    if (ret != 0) {
        // 启动异步连接失败
        plog_error(plugin, "启动异步重连到OPC UA服务器失败: %s (尝试 %u)", 
                  plugin->endpoint_url, plugin->reconnect_attempts);
        
        // 即使启动失败，也要保持重连状态，以便下次尝试
        return -1;
    }
    
    plog_notice(plugin, "已成功启动到OPC UA服务器的异步连接: %s", plugin->endpoint_url);
    
    // 客户端可能在状态回调中更新连接状态，但我们可以在这里进行初始化
    plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
    
    // 返回成功，表示异步连接已启动
    return 0;
}

static int driver_group_timer(neu_plugin_t *plugin, neu_plugin_group_t *group)
{
    // 处理异步操作，包括连接、请求等
    if (plugin->client) {
        // 处理异步操作，获取处理结果
        int async_result = opcua_client_process_async(plugin->client, 10); // 10ms超时
        
        // 连接状态变化检测
        if (async_result > 0 && !plugin->connected) {
            // 连接已经恢复
            plugin->connected = true;
            plugin->common.link_state = NEU_NODE_LINK_STATE_CONNECTED;
            plugin->reconnect_attempts = 0; // 重置重连计数
            plog_notice(plugin, "【状态更新】OPC UA连接已成功恢复，重置重连尝试计数");
        } 
        else if (async_result < 0 && plugin->connected) {
            // 连接已经断开
            plugin->connected = false;
            plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
            plog_error(plugin, "【状态更新】OPC UA连接已断开");
        }
        // 如果已连接，重置重连尝试次数，确保系统在下次断开时从0开始计数
        else if (async_result > 0 && plugin->connected && plugin->reconnect_attempts > 0) {
            plugin->reconnect_attempts = 0;
            plog_debug(plugin, "OPC UA连接稳定，重置重连尝试计数为0");
        }
    }
    
    // 检查连接状态，如果断开且启用了重连，尝试重连
    if (!plugin->connected && plugin->reconnect_enabled) {
        // 添加最大重连次数检查，避免在达到最大次数后继续尝试
        if (plugin->max_reconnect_attempts == 0 || 
            plugin->reconnect_attempts < plugin->max_reconnect_attempts) {
            int reconnect_result = try_reconnect(plugin);
            if (reconnect_result == 0) {
                // 重连已启动，本次不处理数据
                neu_dvalue_t dvalue = { 0 };
                dvalue.type = NEU_TYPE_ERROR;
                dvalue.value.i32 = NEU_ERR_PLUGIN_DISCONNECTED;
                plugin->common.adapter_callbacks->driver.update(
                    plugin->common.adapter, group->group_name, NULL, dvalue);
                return 0;
            }
        } else if (plugin->reconnect_attempts >= plugin->max_reconnect_attempts) {
            // 已达到最大重连次数，只记录一次状态（使用静态变量避免重复记录）
            static int64_t last_max_reached_log_time = 0;
            int64_t current_time = neu_time_ms();
            
            // 每10分钟最多记录一次日志，避免日志泛滥
            if (last_max_reached_log_time == 0 || 
                (current_time - last_max_reached_log_time) > 600000) {
                plog_warn(plugin, "已达到最大重连尝试次数(%u)，暂停重连尝试。请检查网络或服务器状态，或重启插件重置重连计数。", 
                         plugin->max_reconnect_attempts);
                last_max_reached_log_time = current_time;
            }
        }
    }

    // 如果仍然断开连接，报告错误并返回
    if (!plugin->connected) {
        neu_dvalue_t dvalue = { 0 };
        dvalue.type = NEU_TYPE_ERROR;
        dvalue.value.i32 = NEU_ERR_PLUGIN_DISCONNECTED;
        plugin->common.adapter_callbacks->driver.update(
            plugin->common.adapter, group->group_name, NULL, dvalue);
        return 0;
    }

    // 获取或创建组数据
    struct opcua_group_data *gd = (struct opcua_group_data *) group->user_data;
    
    // 如果组数据为空或者是第一次运行，初始化它
    if (gd == NULL) {
        gd = calloc(1, sizeof(struct opcua_group_data));
        if (gd == NULL) {
            plog_error(plugin, "Failed to allocate memory for group data");
            return -1;
        }

        gd->group = strdup(group->group_name);
        if (gd->group == NULL) {
            free(gd);
            plog_error(plugin, "Failed to allocate memory for group name");
            return -1;
        }

        // 创建标签数组
        utarray_new(gd->tags, &ut_ptr_icd);
        
        // 从group->tags中获取标签并转换为opcua_point_t
        utarray_foreach(group->tags, neu_datatag_t *, tag) {
            opcua_point_t *point = calloc(1, sizeof(opcua_point_t));
            if (point == NULL) {
                plog_error(plugin, "Failed to allocate memory for point");
                continue;
            }
            
            int ret = opcua_tag_to_point(tag, point);
            if (ret != 0) {
                free(point);
                plog_error(plugin, "Failed to convert tag to point: %s", tag->name);
                continue;
            }
            
            utarray_push_back(gd->tags, &point);
            plog_debug(plugin, "Added tag %s to group %s", point->name, group->group_name);
        }

        // 设置组数据
        group->user_data = gd;
        group->group_free = plugin_group_free;
        
        plog_notice(plugin, "Initialized group data for %s, total tags: %d", 
                   group->group_name, utarray_len(gd->tags));
    }

    // 如果没有标签，直接返回
    if (utarray_len(gd->tags) == 0) {
        plog_debug(plugin, "No tags in group: %s", group->group_name);
        return 0;
    }

    // 如果没有命令排序，创建它
    if (gd->cmd_sort == NULL) {
        gd->cmd_sort = opcua_tag_sort_create(gd->tags);
        if (gd->cmd_sort == NULL) {
            plog_error(plugin, "Failed to create command sort for group: %s", group->group_name);
            return -1;
        }
    }

    // 记录开始时间，用于计算延时
    int64_t start_time_ms = neu_time_ms();
    
    // 读取每个标签的值
    plog_debug(plugin, "Reading values for %d tags in group: %s", 
              utarray_len(gd->tags), group->group_name);
    
    int success_count = 0; // 成功读取的标签数量
    int total_count = 0;   // 总标签数量
    
    for (uint16_t i = 0; i < gd->cmd_sort->cmd_size; i++) {
        utarray_foreach(gd->tags, opcua_point_t **, p_tag) {
            opcua_point_t *tag = *p_tag;
            total_count++;
            
            // 分配内存用于存储值
            void *value = calloc(1, tag->ua_type->memSize);
            if (value == NULL) {
                plog_error(plugin, "Failed to allocate memory for tag value: %s", tag->name);
                continue;
            }

            // 读取值
            int ret = opcua_client_read_value(plugin->client, tag->node_id,
                                             tag->ua_type, value);
            
            neu_dvalue_t dvalue = { 0 };
            
            if (ret != 0) {
                dvalue.type = NEU_TYPE_ERROR;
                dvalue.value.i32 = NEU_ERR_PLUGIN_READ_FAILURE;
                plog_error(plugin, "Failed to read value for tag: %s, node_id: %s", 
                          tag->name, tag->node_id);
                
                // 如果读取失败，可能是连接断开，尝试检查连接状态
                if (!opcua_client_is_connected(plugin->client)) {
                    // 更新连接状态，以便下次循环重新连接
                    plugin->connected = false;
                    plugin->common.link_state = NEU_NODE_LINK_STATE_DISCONNECTED;
                    plog_error(plugin, "读取标签期间检测到连接断开，将尝试重连");
                }
            } else {
                success_count++;
                dvalue.type = tag->type;
                
                // 转换值为Neuron格式
                UA_Variant variant;
                UA_Variant_init(&variant);
                UA_Variant_setScalar(&variant, value, tag->ua_type);
                opcua_convert_value_to_neu(&variant, tag->type, &dvalue.value);
                
                plog_debug(plugin, "Read value for tag: %s, node_id: %s", 
                          tag->name, tag->node_id);
            }

            // 更新值
            plugin->common.adapter_callbacks->driver.update(
                plugin->common.adapter, group->group_name, tag->name, dvalue);
            
            free(value);
            
            // 如果连接中断，不再继续读取剩余标签
            if (!plugin->connected) {
                break;
            }
        }
        
        // 如果连接中断，不再继续执行
        if (!plugin->connected) {
            break;  // 不需要释放value，因为已经在循环内释放过了
        }
    }
    
    // 计算延时
    int64_t end_time_ms = neu_time_ms();
    long duration_ms = (long)(end_time_ms - start_time_ms);
    
    // 只有在成功读取了至少一个标签的情况下才更新延时指标
    if (success_count > 0) {
        NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_LAST_RTT_MS, duration_ms, NULL);
        plog_debug(plugin, "Group %s read complete. Duration: %ld ms, Success: %d/%d", 
                  group->group_name, duration_ms, success_count, total_count);
        
        // 如果有成功读取，重置重连计数
        if (plugin->reconnect_attempts > 0) {
            plugin->reconnect_attempts = 0;
        }
    } else {
        // 如果没有成功读取任何标签，将延时设置为最大值
        NEU_PLUGIN_UPDATE_METRIC(plugin, NEU_METRIC_LAST_RTT_MS, NEU_METRIC_LAST_RTT_MS_MAX, NULL);
        plog_warn(plugin, "Group %s read failed. All %d tags failed to read", 
                 group->group_name, total_count);
    }

    return 0;
}

static int driver_write(neu_plugin_t *plugin, void *req, neu_datatag_t *tag,
                        neu_value_u value)
{
    // 检查连接状态
    if (!plugin->connected) {
        plog_error(plugin, "尝试写入值到未连接的OPC UA服务器");
        plugin->common.adapter_callbacks->driver.write_response(
            plugin->common.adapter, req, NEU_ERR_PLUGIN_DISCONNECTED);
        return 0;
    }
    
    // 转换tag为opcua_point
    opcua_point_t point = { 0 };
    int ret = opcua_tag_to_point(tag, &point);
    if (ret != 0) {
        plog_error(plugin, "标签格式无效: %s", tag->name);
        plugin->common.adapter_callbacks->driver.write_response(
            plugin->common.adapter, req, NEU_ERR_TAG_ADDRESS_FORMAT_INVALID);
        return 0;
    }
    
    // 分配内存用于存储OPC UA值
    void *ua_value = calloc(1, point.ua_type->memSize);
    if (ua_value == NULL) {
        plog_error(plugin, "内存分配失败");
        free(point.name);
        free(point.node_id);
        plugin->common.adapter_callbacks->driver.write_response(
            plugin->common.adapter, req, NEU_ERR_EINTERNAL);
        return 0;
    }
    
    // 将Neuron值转换为OPC UA值
    ret = opcua_convert_neu_to_value(&value, tag->type, ua_value, point.ua_type);
    if (ret != 0) {
        plog_error(plugin, "值类型转换失败: %s", tag->name);
        free(ua_value);
        free(point.name);
        free(point.node_id);
        plugin->common.adapter_callbacks->driver.write_response(
            plugin->common.adapter, req, NEU_ERR_PLUGIN_WRITE_FAILURE);
        return 0;
    }
    
    // 写入值
    plog_debug(plugin, "正在写入值到OPC UA节点: %s (%s)", point.name, point.node_id);
    ret = opcua_client_write_value(plugin->client, point.node_id, point.ua_type, ua_value);
    
    // 清理资源
    if (tag->type == NEU_TYPE_STRING) {
        // 字符串类型需要特殊清理
        UA_String_clear((UA_String *)ua_value);
    }
    free(ua_value);
    free(point.name);
    free(point.node_id);
    
    // 返回结果
    if (ret == 0) {
        plog_notice(plugin, "成功写入值到标签: %s", tag->name);
        plugin->common.adapter_callbacks->driver.write_response(
            plugin->common.adapter, req, NEU_ERR_SUCCESS);
    } else {
        plog_error(plugin, "写入值到标签失败: %s", tag->name);
        plugin->common.adapter_callbacks->driver.write_response(
            plugin->common.adapter, req, NEU_ERR_PLUGIN_WRITE_FAILURE);
    }
    
    return 0;
}

static int driver_write_tags(neu_plugin_t *plugin, void *req, UT_array *tags)
{
    // 检查连接状态
    if (!plugin->connected) {
        plog_error(plugin, "尝试批量写入值到未连接的OPC UA服务器");
        plugin->common.adapter_callbacks->driver.write_response(
            plugin->common.adapter, req, NEU_ERR_PLUGIN_DISCONNECTED);
        return 0;
    }
    
    // 检查标签数组是否为空
    if (utarray_len(tags) == 0) {
        plog_warn(plugin, "尝试批量写入空标签数组");
        plugin->common.adapter_callbacks->driver.write_response(
            plugin->common.adapter, req, NEU_ERR_SUCCESS);
        return 0;
    }
    
    int success_count = 0;
    int total_count = utarray_len(tags);
    int error_code = NEU_ERR_SUCCESS;
    
    // 遍历所有标签并逐个写入
    utarray_foreach(tags, neu_plugin_tag_value_t *, tag_value) {
        // 转换tag为opcua_point
        opcua_point_t point = { 0 };
        int ret = opcua_tag_to_point(tag_value->tag, &point);
        if (ret != 0) {
            plog_error(plugin, "标签格式无效: %s", tag_value->tag->name);
            error_code = NEU_ERR_TAG_ADDRESS_FORMAT_INVALID;
            continue;
        }
        
        // 分配内存用于存储OPC UA值
        void *ua_value = calloc(1, point.ua_type->memSize);
        if (ua_value == NULL) {
            plog_error(plugin, "内存分配失败");
            free(point.name);
            free(point.node_id);
            error_code = NEU_ERR_EINTERNAL;
            continue;
        }
        
        // 将Neuron值转换为OPC UA值
        ret = opcua_convert_neu_to_value(&tag_value->value, tag_value->tag->type, ua_value, point.ua_type);
        if (ret != 0) {
            plog_error(plugin, "值类型转换失败: %s", tag_value->tag->name);
            free(ua_value);
            free(point.name);
            free(point.node_id);
            error_code = NEU_ERR_PLUGIN_WRITE_FAILURE;
            continue;
        }
        
        // 写入值
        plog_debug(plugin, "正在写入值到OPC UA节点: %s (%s)", point.name, point.node_id);
        ret = opcua_client_write_value(plugin->client, point.node_id, point.ua_type, ua_value);
        
        // 清理资源
        if (tag_value->tag->type == NEU_TYPE_STRING) {
            // 字符串类型需要特殊清理
            UA_String_clear((UA_String *)ua_value);
        }
        free(ua_value);
        free(point.name);
        free(point.node_id);
        
        // 检查写入结果
        if (ret == 0) {
            plog_debug(plugin, "成功写入值到标签: %s", tag_value->tag->name);
            success_count++;
        } else {
            plog_error(plugin, "写入值到标签失败: %s", tag_value->tag->name);
            error_code = NEU_ERR_PLUGIN_WRITE_FAILURE;
        }
    }
    
    // 返回总体结果
    if (success_count == total_count) {
        plog_notice(plugin, "成功写入所有 %d 个标签", total_count);
        plugin->common.adapter_callbacks->driver.write_response(
            plugin->common.adapter, req, NEU_ERR_SUCCESS);
    } else if (success_count > 0) {
        plog_warn(plugin, "部分写入成功: %d/%d 个标签", success_count, total_count);
        plugin->common.adapter_callbacks->driver.write_response(
            plugin->common.adapter, req, error_code);
    } else {
        plog_error(plugin, "所有 %d 个标签写入失败", total_count);
        plugin->common.adapter_callbacks->driver.write_response(
            plugin->common.adapter, req, error_code);
    }
    
    return 0;
}

static int driver_test_read_tag(neu_plugin_t *plugin, void *req,
                                neu_datatag_t tag)
{
    if (!plugin->connected) {
        plugin->common.adapter_callbacks->driver.test_read_tag_response(
            plugin->common.adapter, req, NEU_JSON_INT, NEU_TYPE_ERROR, 
            (neu_json_value_u){.val_int = NEU_ERR_PLUGIN_DISCONNECTED}, 0);
        return 0;
    }

    opcua_point_t point = { 0 };
    int ret = opcua_tag_to_point(&tag, &point);
    
    if (ret != 0) {
        plugin->common.adapter_callbacks->driver.test_read_tag_response(
            plugin->common.adapter, req, NEU_JSON_INT, NEU_TYPE_ERROR, 
            (neu_json_value_u){.val_int = NEU_ERR_TAG_ADDRESS_FORMAT_INVALID}, 0);
        return 0;
    }

    // Allocate memory for value
    void *value = calloc(1, point.ua_type->memSize);
    if (value == NULL) {
        plugin->common.adapter_callbacks->driver.test_read_tag_response(
            plugin->common.adapter, req, NEU_JSON_INT, NEU_TYPE_ERROR, 
            (neu_json_value_u){.val_int = NEU_ERR_EINTERNAL}, 0);
        free(point.name);
        free(point.node_id);
        return 0;
    }

    // Read value
    ret = opcua_client_read_value(plugin->client, point.node_id,
                                 point.ua_type, value);
    
    if (ret != 0) {
        plugin->common.adapter_callbacks->driver.test_read_tag_response(
            plugin->common.adapter, req, NEU_JSON_INT, NEU_TYPE_ERROR, 
            (neu_json_value_u){.val_int = NEU_ERR_PLUGIN_READ_FAILURE}, 0);
        free(point.name);
        free(point.node_id);
        free(value);
        return 0;
    }

    // Convert value to Neuron format
    neu_value_u neu_value = { 0 };
    
    UA_Variant variant;
    UA_Variant_init(&variant);
    UA_Variant_setScalar(&variant, value, point.ua_type);
    opcua_convert_value_to_neu(&variant, point.type, &neu_value);

    // Send response
    neu_json_type_e json_type = NEU_JSON_INT;
    neu_json_value_u json_value = { 0 };
    
    // Convert neu_value to json_value based on type
    switch (point.type) {
    case NEU_TYPE_INT8:
        json_type = NEU_JSON_INT;
        json_value.val_int = neu_value.i8;
        break;
    case NEU_TYPE_UINT8:
        json_type = NEU_JSON_INT;
        json_value.val_int = neu_value.u8;
        break;
    case NEU_TYPE_INT16:
        json_type = NEU_JSON_INT;
        json_value.val_int = neu_value.i16;
        break;
    case NEU_TYPE_UINT16:
        json_type = NEU_JSON_INT;
        json_value.val_int = neu_value.u16;
        break;
    case NEU_TYPE_INT32:
        json_type = NEU_JSON_INT;
        json_value.val_int = neu_value.i32;
        break;
    case NEU_TYPE_UINT32:
        json_type = NEU_JSON_INT;
        json_value.val_int = neu_value.u32;
        break;
    case NEU_TYPE_INT64:
        json_type = NEU_JSON_INT;
        json_value.val_int = neu_value.i64;
        break;
    case NEU_TYPE_UINT64:
        json_type = NEU_JSON_INT;
        json_value.val_int = neu_value.u64;
        break;
    case NEU_TYPE_FLOAT:
        json_type = NEU_JSON_DOUBLE;
        json_value.val_double = neu_value.f32;
        break;
    case NEU_TYPE_DOUBLE:
        json_type = NEU_JSON_DOUBLE;
        json_value.val_double = neu_value.d64;
        break;
    case NEU_TYPE_BOOL:
    case NEU_TYPE_BIT:
        json_type = NEU_JSON_BOOL;
        json_value.val_bool = neu_value.u8 > 0;
        break;
    case NEU_TYPE_STRING:
        json_type = NEU_JSON_STR;
        json_value.val_str = neu_value.str;
        break;
    default:
        json_type = NEU_JSON_INT;
        json_value.val_int = 0;
        break;
    }
    
    plugin->common.adapter_callbacks->driver.test_read_tag_response(
        plugin->common.adapter, req, json_type, point.type, json_value, 0);
    
    free(point.name);
    free(point.node_id);
    free(value);
    
    return 0;
}

static int driver_add_tags(neu_plugin_t *plugin, const char *group, neu_datatag_t *tags, int n_tag)
{
    (void) tags; // 标记未使用的参数
    (void) n_tag; // 标记未使用的参数
    
    plog_notice(plugin, "Adding tags to group %s", group);
    
    // 这个函数不需要实现，因为Neuron框架会自动将标签添加到组中
    // 在driver_group_timer函数中，我们可以直接从group->tags中获取标签
    
    // 参考Modbus插件的实现，我们不需要在这里做任何事情
    // 标签的处理会在driver_group_timer函数中完成
    
    return 0;
}

static void plugin_group_free(neu_plugin_group_t *pgp)
{
    struct opcua_group_data *gd = (struct opcua_group_data *) pgp->user_data;

    if (gd == NULL) {
        return;
    }

    if (gd->cmd_sort != NULL) {
        opcua_tag_sort_free(gd->cmd_sort);
    }

    utarray_foreach(gd->tags, opcua_point_t **, tag) {
        free((*tag)->name);
        free((*tag)->node_id);
        free(*tag);
    }

    utarray_free(gd->tags);
    free(gd->group);
    free(gd);
}

/**
 * @brief OPCUA 点位扫描功能实现
 * 
 * @param plugin 插件实例
 * @param req 请求上下文
 * @param id 节点ID，如果为空，则获取根节点
 * @param ctx 上下文信息，可用于向前端传递额外信息
 * @return int 执行结果
 */
static int driver_scan_tags(neu_plugin_t *plugin, void *req, char *id, char *ctx)
{
    plog_debug(plugin, "-------------------------------------------------------");
    plog_debug(plugin, "scan tags started, id: %s, ctx: %s", 
              id == NULL ? "null" : id, ctx == NULL ? "null" : ctx);
    
    // 输出id指针值和字符串长度以便调试
    if (id != NULL) {
        plog_debug(plugin, "id pointer: %p, id length: %d", (void*)id, (int)strlen(id));
    } else {
        plog_debug(plugin, "id pointer: NULL");
    }
    
    // 初始化响应结构
    neu_resp_scan_tags_t resp = { 0 };
    resp.type = NEU_TYPE_STRING;
    resp.is_array = false;
    resp.error = NEU_ERR_SUCCESS;
    
    // 设置上下文
    if (ctx != NULL) {
        strncpy(resp.ctx, ctx, NEU_VALUE_SIZE);
    }
    
    // 分配扫描标签数组
    plog_debug(plugin, "creating scan_tags array");
    utarray_new(resp.scan_tags, &neu_scan_tag_icd);
    if (resp.scan_tags == NULL) {
        plog_error(plugin, "Failed to allocate memory for scan_tags");
        resp.error = NEU_ERR_EINTERNAL;
        goto response;
    }
    
    // 检查连接状态
    plog_debug(plugin, "checking connection status");
    if (!plugin->connected || plugin->client == NULL) {
        plog_error(plugin, "plugin not connected");
        resp.error = NEU_ERR_PLUGIN_DISCONNECTED;
        goto response;
    }
    
    // 处理ID为空的情况
    if (id == NULL || strlen(id) == 0) {
        plog_debug(plugin, "ID IS EMPTY - Manually returning three root nodes");
        
        // 创建并添加Objects节点
        neu_scan_tag_t objects_node = { 0 };
        strncpy(objects_node.name, "Objects", NEU_TAG_NAME_LEN - 1);
        strncpy(objects_node.id, "i=85", sizeof(objects_node.id) - 1);
        objects_node.tag = 1;  // 文件夹
        objects_node.is_last_layer = false;
        utarray_push_back(resp.scan_tags, &objects_node);
        
        // 创建并添加Types节点
        neu_scan_tag_t types_node = { 0 };
        strncpy(types_node.name, "Types", NEU_TAG_NAME_LEN - 1);
        strncpy(types_node.id, "i=86", sizeof(types_node.id) - 1);
        types_node.tag = 1;  // 文件夹
        types_node.is_last_layer = false;
        utarray_push_back(resp.scan_tags, &types_node);
        
        // 创建并添加Views节点
        neu_scan_tag_t views_node = { 0 };
        strncpy(views_node.name, "Views", NEU_TAG_NAME_LEN - 1);
        strncpy(views_node.id, "i=87", sizeof(views_node.id) - 1);
        views_node.tag = 1;  // 文件夹
        views_node.is_last_layer = false;
        utarray_push_back(resp.scan_tags, &views_node);
        
        plog_debug(plugin, "Manually added three root nodes: Objects (i=85), Types (i=86), Views (i=87)");
    }
    // 处理ID不为空的情况
    else {
        plog_debug(plugin, "ID IS NOT EMPTY - Browsing node: %s", id);
        
        // 解析节点ID
        UA_NodeId node_id = opcua_client_parse_node_id(plugin->client, id);
        
        // 检查节点ID是否有效
        if (UA_NodeId_isNull(&node_id)) {
            plog_error(plugin, "Invalid node ID: %s", id);
            resp.error = NEU_ERR_TAG_ADDRESS_FORMAT_INVALID;
            goto response;
        }
        
        // 输出解析后的node_id信息
        UA_String nodeIdStr = UA_STRING_NULL;
        UA_NodeId_print(&node_id, &nodeIdStr);
        plog_debug(plugin, "Parsed node ID: %.*s", (int)nodeIdStr.length, nodeIdStr.data);
        UA_String_clear(&nodeIdStr);
        
        // 创建浏览结果数组
        UT_array* browse_results = NULL;
        utarray_new(browse_results, &opcua_browse_result_icd);
        if (browse_results == NULL) {
            plog_error(plugin, "Failed to allocate memory for browse results");
            resp.error = NEU_ERR_EINTERNAL;
            UA_NodeId_clear(&node_id);
            goto response;
        }
        
        // 浏览节点
        if (opcua_client_browse_node(plugin->client, &node_id, browse_results) != 0) {
            plog_error(plugin, "Failed to browse node: %s", id);
            resp.error = NEU_ERR_PLUGIN_READ_FAILURE;
            UA_NodeId_clear(&node_id);
            utarray_free(browse_results);
            goto response;
        }
        
        // 清理节点ID
        UA_NodeId_clear(&node_id);
        
        // 获取浏览结果数量
        int result_count = utarray_len(browse_results);
        plog_debug(plugin, "Browse results count: %d", result_count);
        
        // 处理浏览结果
        utarray_foreach(browse_results, opcua_browse_result_t *, result) {
            neu_scan_tag_t scan_tag = { 0 };
            
            // 设置标签类型 (0: 叶子节点/变量，1: 文件夹/对象/类型)
            scan_tag.tag = (result->nodeClass == UA_NODECLASS_VARIABLE) ? 0 : 1;
            
            // 设置名称
            if (result->displayName.length > 0) {
                size_t name_len = result->displayName.length < NEU_TAG_NAME_LEN ? 
                                  result->displayName.length : NEU_TAG_NAME_LEN - 1;
                memcpy(scan_tag.name, result->displayName.data, name_len);
                scan_tag.name[name_len] = '\0';
                plog_debug(plugin, "using display name: %s", scan_tag.name);
            } else if (result->browseName.name.length > 0) {
                size_t name_len = result->browseName.name.length < NEU_TAG_NAME_LEN ? 
                                  result->browseName.name.length : NEU_TAG_NAME_LEN - 1;
                memcpy(scan_tag.name, result->browseName.name.data, name_len);
                scan_tag.name[name_len] = '\0';
                plog_debug(plugin, "using browse name: %s", scan_tag.name);
            } else {
                strcpy(scan_tag.name, "Unknown");
                plog_debug(plugin, "using default name: Unknown");
            }
            
            // 读取变量类型和值
            if (result->nodeClass == UA_NODECLASS_VARIABLE) {
                // 尝试读取数据类型
                neu_type_e detected_type = NEU_TYPE_STRING;
                bool is_array_type = false;  // 重命名变量以避免混淆
                
                // 使用改进的函数获取数据类型
                if (opcua_client_read_variable_datatype(plugin->client, &result->nodeId, &detected_type) == 0) {
                    scan_tag.type = detected_type;
                    
                    // 设置节点ID作为地址
                    char *node_id_str = opcua_client_node_id_to_string(&result->nodeId);
                    if (node_id_str) {
                        strncpy(scan_tag.id, node_id_str, sizeof(scan_tag.id) - 1);
                        scan_tag.id[sizeof(scan_tag.id) - 1] = '\0';
                        free(node_id_str);
                    }
                    
                    // 尝试读取变量值，以获取更多信息
                    UA_Variant value;
                    UA_Variant_init(&value);
                    
                    if (opcua_client_read_value_attribute(plugin->client, &result->nodeId, &value) == UA_STATUSCODE_GOOD) {
                        // 检查是否是数组类型
                        if (value.arrayLength > 0) {
                            is_array_type = true;
                            // 注意：该数组标志会在下一层处理，而不是直接设置到scan_tag
                            plog_debug(plugin, "Node %s is an array with length %lu", 
                                      scan_tag.name, (unsigned long)value.arrayLength);
                        }
                        // 检查是否是ByteString类型
                        else if (value.type && value.type->typeName && strcmp(value.type->typeName, "ByteString") == 0) {
                            scan_tag.type = NEU_TYPE_BYTES;
                        }
                        
                        UA_Variant_clear(&value);
                    }
                } else {
                    // 读取数据类型失败，使用默认类型
                    // 将UA_String转换为C字符串并打印
                    char name_buf[64] = "unknown";
                    if (result->displayName.length > 0 && result->displayName.data != NULL) {
                        size_t copy_len = result->displayName.length < sizeof(name_buf) - 1 ? 
                                         result->displayName.length : sizeof(name_buf) - 1;
                        memcpy(name_buf, result->displayName.data, copy_len);
                        name_buf[copy_len] = '\0';
                    }
                    plog_debug(plugin, "Failed to read data type for node %s", name_buf);
                    scan_tag.type = NEU_TYPE_STRING;  // 默认使用字符串类型
                    
                    // 仍然设置节点ID
                    char *node_id_str = opcua_client_node_id_to_string(&result->nodeId);
                    if (node_id_str) {
                        strncpy(scan_tag.id, node_id_str, sizeof(scan_tag.id) - 1);
                        scan_tag.id[sizeof(scan_tag.id) - 1] = '\0';
                        free(node_id_str);
                    }
                }
                
                // 判断是否为特殊的变量节点，可能包含子节点
                bool is_special_node = false;
                
                // 检查是否为Server节点(i=2253)或类似的特殊节点
                if (result->nodeId.namespaceIndex == 0 && 
                    result->nodeId.identifierType == UA_NODEIDTYPE_NUMERIC) {
                    uint32_t id = result->nodeId.identifier.numeric;
                    if (id == 2253) { // Server节点
                        is_special_node = true;
                        plog_debug(plugin, "Node %s is a special node (Server), will check for children", scan_tag.name);
                    }
                }
                
                // 检查节点是否有子节点
                if (is_special_node) {
                    // 尝试浏览子节点
                    UT_array* temp_results = NULL;
                    utarray_new(temp_results, &opcua_browse_result_icd);
                    
                    if (temp_results != NULL) {
                        if (opcua_client_browse_node(plugin->client, &result->nodeId, temp_results) == 0) {
                            int child_count = utarray_len(temp_results);
                            if (child_count > 0) {
                                // 有子节点，标记为非最后一层
                                scan_tag.is_last_layer = false;
                                plog_debug(plugin, "Node %s has %d children, marking as not last layer", scan_tag.name, child_count);
                            } else {
                                // 无子节点，标记为最后一层
                                scan_tag.is_last_layer = true;
                                plog_debug(plugin, "Node %s has no children, marking as last layer", scan_tag.name);
                            }
                        } else {
                            // 浏览失败，假设为最后一层
                            scan_tag.is_last_layer = true;
                            plog_debug(plugin, "Failed to browse children of node %s, assuming it's a last layer", scan_tag.name);
                        }
                        
                        utarray_free(temp_results);
                    } else {
                        // 内存分配失败，假设为最后一层
                        scan_tag.is_last_layer = true;
                        plog_debug(plugin, "Failed to allocate memory for temporary browse results, assuming node %s is a last layer", scan_tag.name);
                    }
                } else {
                    // 普通变量节点是最后一层
                    scan_tag.is_last_layer = true;
                    plog_debug(plugin, "Node %s is a regular variable node, marking as last layer", scan_tag.name);
                }
                
                // 记录是否是数组类型，供日志使用
                if (is_array_type) {
                    plog_debug(plugin, "Node %s is array type", scan_tag.name);
                }
            } else {
                // 非变量节点（如对象、类型等）不是最后一层
                scan_tag.is_last_layer = false;
                plog_debug(plugin, "Node %s is not a variable node (class: %d), marking as not last layer", scan_tag.name, result->nodeClass);
                
                // 设置节点ID
                char *node_id_str = opcua_client_node_id_to_string(&result->nodeId);
                if (node_id_str) {
                    strncpy(scan_tag.id, node_id_str, sizeof(scan_tag.id) - 1);
                    scan_tag.id[sizeof(scan_tag.id) - 1] = '\0';
                    free(node_id_str);
                }
            }
            
            // 添加扫描结果到数组
            utarray_push_back(resp.scan_tags, &scan_tag);
            
            plog_debug(plugin, "Found node: %s, id: %s, class: %d, type: %d", 
                      scan_tag.name, scan_tag.id, result->nodeClass, scan_tag.type);
        }
        
        // 清理浏览结果
        utarray_free(browse_results);
    }

response:
    plog_debug(plugin, "Sending scan_tags response");
    plugin->common.adapter_callbacks->driver.scan_tags_response(
        plugin->common.adapter, req, &resp);
    
    plog_debug(plugin, "Scan tags completed");
    return 0;
} 