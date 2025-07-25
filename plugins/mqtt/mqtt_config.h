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

#ifndef NEURON_PLUGIN_MQTT_CONFIG_H
#define NEURON_PLUGIN_MQTT_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>

#include "connection/mqtt_client.h"
#include "plugin.h"

#include "schema.h"

typedef enum {
    MQTT_UPLOAD_FORMAT_VALUES   = 0,
    MQTT_UPLOAD_FORMAT_TAGS     = 1,
    MQTT_UPLOAD_FORMAT_ECP      = 2,
    MQTT_UPLOAD_FORMAT_CUSTOM   = 3,
    MQTT_UPLOAD_FORMAT_PROTOBUF = 4,
} mqtt_upload_format_e;

static inline const char *mqtt_upload_format_str(mqtt_upload_format_e f)
{
    switch (f) {
    case MQTT_UPLOAD_FORMAT_VALUES:
        return "format-values";
    case MQTT_UPLOAD_FORMAT_TAGS:
        return "format-tags";
    case MQTT_UPLOAD_FORMAT_ECP:
        return "ECP-format";
    case MQTT_UPLOAD_FORMAT_CUSTOM:
        return "custom";
    case MQTT_UPLOAD_FORMAT_PROTOBUF:
        return "protobuf";
    default:
        return NULL;
    }
}

#define ACTION_REQ_TOPIC "action/req"
#define ACTION_RESP_TOPIC "action/resp"
#define FILES_REQ_TOPIC "flist/req"
#define FILES_RESP_TOPIC "flist/resp"

#define FILE_UP_REQ_TOPIC "fup/req"
#define FILE_UP_RESP_TOPIC "fup/resp"
#define FILE_UP_DATA_REQ_TOPIC "fupdata/req"
#define FILE_UP_DATA_RESP_TOPIC "fupdata/resp"

#define FILE_DOWN_REQ_TOPIC "fdown/req"
#define FILE_DOWN_RESP_TOPIC "fdown/resp"
#define FILE_DOWN_DATA_REQ_TOPIC "fdowndata/req"
#define FILE_DOWN_DATA_RESP_TOPIC "fdowndata/resp"

typedef struct {
    char action_req[256];
    char action_resp[256];

    char files_req[256];
    char files_resp[256];

    char file_up_req[256];
    char file_up_resp[256];

    char file_up_data_req[256];
    char file_up_data_resp[256];

    char file_down_req[256];
    char file_down_resp[256];

    char file_down_data_req[256];
    char file_down_data_resp[256];
} mqtt_driver_topic_t;

typedef struct {
    neu_mqtt_version_e   version;   // mqtt version
    char *               client_id; // client id
    neu_mqtt_qos_e       qos;       // message QoS
    mqtt_upload_format_e format;    // upload format

    bool                enable_topic;        // default true
    char *              write_req_topic;     // write request topic
    char *              write_resp_topic;    // write response topic
    char *              driver_topic_prefix; // driver topic prefix
    mqtt_driver_topic_t driver_topic;

    bool     upload_err;          // Upload tag error code flag
    bool     upload_drv_state;    // upload driver state flag
    char *   heartbeat_topic;     // upload driver state topic
    uint16_t heartbeat_interval;  // upload driver state interval
    size_t   cache;               // cache enable flag
    size_t   cache_mem_size;      // cache memory size in bytes
    size_t   cache_disk_size;     // cache disk size in bytes
    size_t   cache_sync_interval; // cache sync interval
    char *   host;                // broker host
    uint16_t port;                // broker port
    char *   username;            // user name
    char *   password;            // user password
    bool     ssl;                 // ssl flag
    char *   ca;                  // CA
    char *   cert;                // client cert
    char *   key;                 // client key
    char *   keypass;             // client key password
                                  // remove in 2.6, keep it here
                                  // for backward compatibility
    size_t            n_schema_vt;
    mqtt_schema_vt_t *schema_vts;
} mqtt_config_t;

int decode_b64_param(neu_plugin_t *plugin, neu_json_elem_t *el);
int parse_b64_param(neu_plugin_t *plugin, const char *setting,
                    neu_json_elem_t *el);

int  mqtt_config_parse(neu_plugin_t *plugin, const char *setting,
                       mqtt_config_t *config);
void mqtt_config_fini(mqtt_config_t *config);

#ifdef __cplusplus
}
#endif

#endif
