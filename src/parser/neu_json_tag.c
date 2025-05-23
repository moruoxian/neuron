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

/*
 * DO NOT EDIT THIS FILE MANUALLY!
 * It was automatically generated by `json-autotype`.
 */

#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include "json/json.h"

#include "neu_json_tag.h"
#include "tag.h"
#include "type.h"

int neu_json_encode_tag(void *json_obj, void *param)
{
    int             ret = 0;
    neu_json_tag_t *tag = param;

    neu_json_elem_t tag_elems[] = {
        {
            .name      = "type",
            .t         = NEU_JSON_INT,
            .v.val_int = tag->type,
        },
        {
            .name      = "name",
            .t         = NEU_JSON_STR,
            .v.val_str = tag->name,
        },
        {
            .name      = "attribute",
            .t         = NEU_JSON_INT,
            .v.val_int = tag->attribute,
        },
        {
            .name      = "precision",
            .t         = NEU_JSON_INT,
            .v.val_int = tag->precision,
        },
        {
            .name         = "decimal",
            .t            = NEU_JSON_DOUBLE,
            .v.val_double = tag->decimal,
        },
        {
            .name         = "bias",
            .t            = NEU_JSON_DOUBLE,
            .v.val_double = tag->bias,
        },
        {
            .name      = "address",
            .t         = NEU_JSON_STR,
            .v.val_str = tag->address,
        },
        {
            .name      = "description",
            .t         = NEU_JSON_STR,
            .v.val_str = tag->description,
        },
        {
            .name = "value",
            .t    = tag->t,
            .v    = tag->value,
        },
    };

    ret = neu_json_encode_field(json_obj, tag_elems,
                                NEU_JSON_ELEM_SIZE(tag_elems));

    return ret;
}

int neu_json_decode_tag_json(void *json_obj, neu_json_tag_t *tag_p)
{
    if (NULL == tag_p) {
        return -1;
    }

    neu_json_elem_t tag_elems[] = {
        {
            .name = "type",
            .t    = NEU_JSON_INT,
        },
        {
            .name = "name",
            .t    = NEU_JSON_STR,
        },
        {
            .name = "attribute",
            .t    = NEU_JSON_INT,
        },
        {
            .name = "address",
            .t    = NEU_JSON_STR,
        },
        {
            .name      = "decimal",
            .t         = NEU_JSON_DOUBLE,
            .attribute = NEU_JSON_ATTRIBUTE_OPTIONAL,
        },
        {
            .name      = "precision",
            .t         = NEU_JSON_INT,
            .attribute = NEU_JSON_ATTRIBUTE_OPTIONAL,
        },
        {
            .name      = "description",
            .t         = NEU_JSON_STR,
            .attribute = NEU_JSON_ATTRIBUTE_OPTIONAL,
        },
        {
            .name      = "value",
            .t         = NEU_JSON_VALUE,
            .attribute = NEU_JSON_ATTRIBUTE_OPTIONAL,
        },
        {
            .name      = "bias",
            .t         = NEU_JSON_DOUBLE,
            .attribute = NEU_JSON_ATTRIBUTE_OPTIONAL,
        },
    };

    int ret = neu_json_decode_by_json(json_obj, NEU_JSON_ELEM_SIZE(tag_elems),
                                      tag_elems);

    // set the fields before check for easy clean up on error
    neu_json_tag_t tag = {
        .type        = tag_elems[0].v.val_int,
        .name        = tag_elems[1].v.val_str,
        .attribute   = tag_elems[2].v.val_int,
        .address     = tag_elems[3].v.val_str,
        .decimal     = tag_elems[4].v.val_double,
        .precision   = tag_elems[5].v.val_int,
        .description = tag_elems[6].v.val_str,
        .t           = tag_elems[7].t,
        .value       = tag_elems[7].v,
        .bias        = tag_elems[8].v.val_double,
    };

    if (0 != ret) {
        goto decode_fail;
    }

    if (!neu_json_tag_check_type(&tag)) {
        goto decode_fail;
    }

    *tag_p = tag;
    return 0;

decode_fail:
    neu_json_decode_tag_fini(&tag);
    return -1;
}

void neu_json_decode_tag_fini(neu_json_tag_t *tag)
{
    free(tag->name);
    free(tag->address);
    free(tag->description);
    if (NEU_JSON_STR == tag->t) {
        free(tag->value.val_str);
    }
}

int neu_json_tag_check_type(neu_json_tag_t *tag)
{
    // non-static tag should have no initial value
    return NEU_JSON_UNDEFINE == tag->t;
}

int neu_json_encode_tag_array(void *json_obj, void *param)
{
    neu_json_tag_array_t *array = param;

    if (!json_is_array((json_t *) json_obj)) {
        return -1;
    }

    for (int i = 0; i < array->len; i++) {
        json_t *tag_obj = json_object();
        if (NULL == tag_obj || 0 != json_array_append_new(json_obj, tag_obj)) {
            return -1;
        }
        if (0 != neu_json_encode_tag(tag_obj, &array->tags[i])) {
            return -1;
        }
    }

    return 0;
}

int neu_json_decode_tag_array_json(void *json_obj, neu_json_tag_array_t *arr)
{
    int             len  = 0;
    neu_json_tag_t *tags = NULL;

    if (!json_is_array((json_t *) json_obj)) {
        return -1;
    }

    len = json_array_size(json_obj);
    if (0 == len) {
        // success on empty tag array
        arr->len  = 0;
        arr->tags = NULL;
        return 0;
    }

    tags = calloc(len, sizeof(*tags));
    if (NULL == tags) {
        return -1;
    }

    int i = 0;
    for (i = 0; i < len; i++) {
        json_t *tag_obj = json_array_get(json_obj, i);
        if (0 != neu_json_decode_tag_json(tag_obj, &tags[i])) {
            goto decode_fail;
        }
    }

    arr->len  = len;
    arr->tags = tags;
    return 0;

decode_fail:
    while (--i > 0) {
        neu_json_decode_tag_fini(&tags[i]);
    }
    free(tags);
    return -1;
}

void neu_json_decode_tag_array_fini(neu_json_tag_array_t *arr)
{
    for (int i = 0; i < arr->len; ++i) {
        neu_json_decode_tag_fini(&arr->tags[i]);
    }
    free(arr->tags);
}

int neu_json_encode_add_tags_req(void *json_object, void *param)
{
    int                      ret       = 0;
    neu_json_add_tags_req_t *req       = param;
    void *                   tag_array = neu_json_array();
    if (NULL == tag_array) {
        return -1;
    }
    neu_json_tag_array_t arr = {
        .len  = req->n_tag,
        .tags = req->tags,
    };
    ret = neu_json_encode_tag_array(tag_array, &arr);
    if (0 != ret) {
        neu_json_encode_free(tag_array);
        return ret;
    }
    neu_json_elem_t req_elems[] = { {
                                        .name      = "node",
                                        .t         = NEU_JSON_STR,
                                        .v.val_str = req->node,
                                    },
                                    {
                                        .name      = "group",
                                        .t         = NEU_JSON_STR,
                                        .v.val_str = req->group,
                                    },
                                    {
                                        .name         = "tags",
                                        .t            = NEU_JSON_OBJECT,
                                        .v.val_object = tag_array,
                                    } };
    ret                         = neu_json_encode_field(json_object, req_elems,
                                NEU_JSON_ELEM_SIZE(req_elems));
    return ret;
}

int neu_json_decode_add_tags_req(char *buf, neu_json_add_tags_req_t **result)
{
    int                      ret      = 0;
    void *                   json_obj = NULL;
    neu_json_add_tags_req_t *req = calloc(1, sizeof(neu_json_add_tags_req_t));
    if (req == NULL) {
        return -1;
    }

    json_obj = neu_json_decode_new(buf);
    if (NULL == json_obj) {
        free(req);
        return -1;
    }

    neu_json_elem_t req_elems[] = {
        {
            .name = "node",
            .t    = NEU_JSON_STR,
        },
        {
            .name = "group",
            .t    = NEU_JSON_STR,
        },
        {
            .name = "tags",
            .t    = NEU_JSON_OBJECT,
        },
    };
    ret = neu_json_decode_by_json(json_obj, NEU_JSON_ELEM_SIZE(req_elems),
                                  req_elems);
    if (ret != 0) {
        goto decode_fail;
    }

    neu_json_tag_array_t arr = { 0 };
    ret = neu_json_decode_tag_array_json(req_elems[2].v.val_object, &arr);
    if (ret != 0) {
        goto decode_fail;
    }
    if (arr.len <= 0) {
        goto decode_fail;
    }

    req->node  = req_elems[0].v.val_str;
    req->group = req_elems[1].v.val_str;
    req->n_tag = arr.len;
    req->tags  = arr.tags;
    *result    = req;
    goto decode_exit;

decode_fail:
    free(req);
    free(req_elems[0].v.val_str);
    free(req_elems[1].v.val_str);
    ret = -1;

decode_exit:
    if (json_obj != NULL) {
        neu_json_decode_free(json_obj);
    }
    return ret;
}

void neu_json_decode_add_tags_req_free(neu_json_add_tags_req_t *req)
{
    if (NULL == req) {
        return;
    }

    neu_json_tag_array_t arr = {
        .len  = req->n_tag,
        .tags = req->tags,
    };
    neu_json_decode_tag_array_fini(&arr);

    free(req->node);
    free(req->group);
    free(req);
}

int neu_json_encode_au_tags_resp(void *json_object, void *param)
{
    int                     ret          = 0;
    neu_json_add_tag_res_t *resp         = (neu_json_add_tag_res_t *) param;
    neu_json_elem_t         resp_elems[] = {
        {
            .name      = "index",
            .t         = NEU_JSON_INT,
            .v.val_int = resp->index,
        },
        {
            .name      = "error",
            .t         = NEU_JSON_INT,
            .v.val_int = resp->error,

        },
    };

    ret = neu_json_encode_field(json_object, resp_elems,
                                NEU_JSON_ELEM_SIZE(resp_elems));

    return ret;
}

int neu_json_encode_gtag(void *json_obj, void *param)
{
    neu_json_gtag_t *gtag      = param;
    json_t *         gtag_json = json_obj;

    if (!json_is_object(gtag_json)) {
        return -1;
    }

    json_t *tags_json = json_array();
    if (NULL == tags_json ||
        0 != json_object_set_new(gtag_json, "tags", tags_json)) {
        return -1;
    }

    neu_json_tag_array_t arr = {
        .len  = gtag->n_tag,
        .tags = gtag->tags,
    };
    if (0 != neu_json_encode_tag_array(tags_json, &arr)) {
        return -1;
    }

    neu_json_elem_t gtag_elems[] = {
        {
            .name      = "group",
            .t         = NEU_JSON_STR,
            .v.val_str = gtag->group,
        },
        {
            .name      = "interval",
            .t         = NEU_JSON_INT,
            .v.val_int = gtag->interval,
        },
    };

    return neu_json_encode_field(gtag_json, gtag_elems,
                                 NEU_JSON_ELEM_SIZE(gtag_elems));
}

int neu_json_decode_gtag_json(void *json_obj, neu_json_gtag_t *gtag_p)
{
    if (NULL == gtag_p) {
        return -1;
    }

    neu_json_elem_t gtag_elems[] = { {
                                         .name = "group",
                                         .t    = NEU_JSON_STR,
                                     },
                                     {
                                         .name = "interval",
                                         .t    = NEU_JSON_INT,
                                     },
                                     {
                                         .name = "tags",
                                         .t    = NEU_JSON_OBJECT,
                                     } };

    int ret = neu_json_decode_by_json(json_obj, NEU_JSON_ELEM_SIZE(gtag_elems),
                                      gtag_elems);

    if (0 != ret) {
        goto decode_fail;
    }

    neu_json_tag_array_t arr = { 0 };
    ret = neu_json_decode_tag_array_json(gtag_elems[2].v.val_object, &arr);
    if (ret != 0) {
        goto decode_fail;
    }
    if (arr.len < 0) {
        goto decode_fail;
    }

    gtag_p->group    = gtag_elems[0].v.val_str;
    gtag_p->interval = gtag_elems[1].v.val_int;
    gtag_p->n_tag    = arr.len;
    gtag_p->tags     = arr.tags;

    return 0;

decode_fail:
    free(gtag_elems[0].v.val_str);
    return -1;
}

void neu_json_decode_gtag_fini(neu_json_gtag_t *gtag)
{
    free(gtag->group);
    for (int i = 0; i < gtag->n_tag; i++) {
        neu_json_decode_tag_fini(&(gtag->tags[i]));
    }
    free(gtag->tags);
}

int neu_json_encode_gtag_array(void *json_obj, void *param)
{
    neu_json_gtag_array_t *arr = param;

    if (!json_is_array((json_t *) json_obj)) {
        return -1;
    }

    for (int i = 0; i < arr->len; i++) {
        json_t *gtag_json = json_object();
        if (NULL == gtag_json ||
            0 != json_array_append_new(json_obj, gtag_json)) {
            return -1;
        }
        if (0 != neu_json_encode_gtag(gtag_json, &arr->gtags[i])) {
            return -1;
        }
    }

    return 0;
}

int neu_json_decode_gtag_array_json(void *json_obj, neu_json_gtag_array_t *arr)
{
    int              len   = 0;
    neu_json_gtag_t *gtags = NULL;

    if (!json_is_array((json_t *) json_obj)) {
        return -1;
    }

    len = json_array_size(json_obj);
    if (0 == len) {
        arr->len   = 0;
        arr->gtags = NULL;
        return 0;
    }

    gtags = calloc(len, sizeof(*gtags));
    if (NULL == gtags) {
        return -1;
    }

    int i = 0;
    for (i = 0; i < len; i++) {
        json_t *tag_obj = json_array_get(json_obj, i);
        if (0 != neu_json_decode_gtag_json(tag_obj, &gtags[i])) {
            goto decode_fail;
        }
    }

    arr->len   = len;
    arr->gtags = gtags;
    return 0;

decode_fail:
    while (--i > 0) {
        neu_json_decode_gtag_fini(&gtags[i]);
    }
    free(gtags);
    return -1;
}

void neu_json_decode_gtag_array_fini(neu_json_gtag_array_t *arr)
{
    for (int i = 0; i < arr->len; ++i) {
        neu_json_decode_gtag_fini(&arr->gtags[i]);
    }
    free(arr->gtags);
}

int neu_json_encode_add_gtags_req(void *json_object, void *param)
{
    int                       ret        = 0;
    neu_json_add_gtags_req_t *req        = param;
    neu_json_gtag_array_t     gtag_array = { .len   = req->n_group,
                                         .gtags = req->groups };

    neu_json_elem_t req_elems[] = { {
        .name      = "node",
        .t         = NEU_JSON_STR,
        .v.val_str = req->node,
    } };
    ret                         = neu_json_encode_field(json_object, req_elems,
                                NEU_JSON_ELEM_SIZE(req_elems));

    json_t *groups_json = json_array();
    if (NULL == groups_json ||
        0 != json_object_set_new(json_object, "groups", groups_json)) {
        return -1;
    }

    neu_json_encode_gtag_array(groups_json, &gtag_array);

    for (int i = 0; i < req->n_group; i++) {
        free(req->groups[i].group);
        free(req->groups[i].tags);
    }
    free(req->groups);

    return ret;
}

int neu_json_decode_add_gtags_req(char *buf, neu_json_add_gtags_req_t **result)
{
    int                       ret      = 0;
    void *                    json_obj = NULL;
    neu_json_add_gtags_req_t *req = calloc(1, sizeof(neu_json_add_gtags_req_t));
    if (req == NULL) {
        return -1;
    }

    json_obj = neu_json_decode_new(buf);
    if (NULL == json_obj) {
        free(req);
        return -1;
    }

    neu_json_elem_t req_elems[] = {
        {
            .name = "node",
            .t    = NEU_JSON_STR,
        },
        {
            .name = "groups",
            .t    = NEU_JSON_OBJECT,
        },
    };
    ret = neu_json_decode_by_json(json_obj, NEU_JSON_ELEM_SIZE(req_elems),
                                  req_elems);
    if (ret != 0) {
        goto decode_fail;
    }

    neu_json_gtag_array_t arr = { 0 };
    ret = neu_json_decode_gtag_array_json(req_elems[1].v.val_object, &arr);
    if (ret != 0) {
        goto decode_fail;
    }
    if (arr.len <= 0) {
        goto decode_fail;
    }

    req->node    = req_elems[0].v.val_str;
    req->n_group = arr.len;
    req->groups  = arr.gtags;
    *result      = req;
    goto decode_exit;

decode_fail:
    free(req);
    free(req_elems[0].v.val_str);
    ret = -1;

decode_exit:
    if (json_obj != NULL) {
        neu_json_decode_free(json_obj);
    }
    return ret;
}

void neu_json_decode_add_gtags_req_free(neu_json_add_gtags_req_t *req)
{
    if (NULL == req) {
        return;
    }
    neu_json_gtag_array_t arr = {
        .len   = req->n_group,
        .gtags = req->groups,
    };
    neu_json_decode_gtag_array_fini(&arr);

    free(req->node);
    free(req);
}

int neu_json_encode_au_gtags_resp(void *json_object, void *param)
{
    int                      ret          = 0;
    neu_json_add_gtag_res_t *resp         = (neu_json_add_gtag_res_t *) param;
    neu_json_elem_t          resp_elems[] = {
        {
            .name      = "index",
            .t         = NEU_JSON_INT,
            .v.val_int = resp->index,
        },
        {
            .name      = "error",
            .t         = NEU_JSON_INT,
            .v.val_int = resp->error,
        },
    };

    ret = neu_json_encode_field(json_object, resp_elems,
                                NEU_JSON_ELEM_SIZE(resp_elems));

    return ret;
}

int neu_json_encode_del_tags_req(void *json_object, void *param)
{
    int                           ret       = 0;
    neu_json_del_tags_req_t *     req       = param;
    void *                        tag_array = neu_json_array();
    neu_json_del_tags_req_name_t *p_name    = req->tags;
    for (int i = 0; i < req->n_tags; i++) {
        neu_json_elem_t tag_elems[] = {
            {
                .name      = NULL,
                .t         = NEU_JSON_STR,
                .v.val_str = *p_name,
            },
        };
        tag_array = neu_json_encode_array_value(tag_array, tag_elems,
                                                NEU_JSON_ELEM_SIZE(tag_elems));
        p_name++;
    }
    neu_json_elem_t req_elems[] = { {
                                        .name      = "node",
                                        .t         = NEU_JSON_STR,
                                        .v.val_str = req->node,
                                    },
                                    {
                                        .name      = "group",
                                        .t         = NEU_JSON_STR,
                                        .v.val_str = req->group,
                                    },
                                    {
                                        .name         = "tags",
                                        .t            = NEU_JSON_OBJECT,
                                        .v.val_object = tag_array,
                                    } };
    ret                         = neu_json_encode_field(json_object, req_elems,
                                NEU_JSON_ELEM_SIZE(req_elems));
    return ret;
}

int neu_json_decode_del_tags_req(char *buf, neu_json_del_tags_req_t **result)
{
    int                      ret      = 0;
    void *                   json_obj = NULL;
    neu_json_del_tags_req_t *req = calloc(1, sizeof(neu_json_del_tags_req_t));
    if (req == NULL) {
        return -1;
    }

    json_obj = neu_json_decode_new(buf);
    if (NULL == json_obj) {
        free(req);
        return -1;
    }

    neu_json_elem_t req_elems[] = { {
                                        .name = "node",
                                        .t    = NEU_JSON_STR,
                                    },
                                    {
                                        .name = "group",
                                        .t    = NEU_JSON_STR,
                                    } };
    ret = neu_json_decode_by_json(json_obj, NEU_JSON_ELEM_SIZE(req_elems),
                                  req_elems);
    if (ret != 0) {
        goto decode_fail;
    }

    req->node  = req_elems[0].v.val_str;
    req->group = req_elems[1].v.val_str;

    req->n_tags = neu_json_decode_array_size_by_json(json_obj, "tags");
    if (req->n_tags <= 0) {
        goto decode_fail;
    }

    req->tags = calloc(req->n_tags, sizeof(neu_json_del_tags_req_name_t));
    neu_json_del_tags_req_name_t *p_tag = req->tags;
    for (int i = 0; i < req->n_tags; i++) {
        neu_json_elem_t id_elems[] = { {
            .name = NULL,
            .t    = NEU_JSON_STR,
        } };
        ret                        = neu_json_decode_array_by_json(
            json_obj, "tags", i, NEU_JSON_ELEM_SIZE(id_elems), id_elems);
        if (ret != 0) {
            goto decode_fail;
        }

        *p_tag = id_elems[0].v.val_str;
        p_tag++;
    }

    *result = req;
    goto decode_exit;

decode_fail:
    if (req->tags != NULL) {
        free(req->tags);
    }
    if (req != NULL) {
        free(req);
    }
    ret = -1;

decode_exit:
    if (json_obj != NULL) {
        neu_json_decode_free(json_obj);
    }
    return ret;
}

void neu_json_decode_del_tags_req_free(neu_json_del_tags_req_t *req)
{
    free(req->node);
    free(req->group);

    for (int i = 0; i < req->n_tags; i++) {
        free(req->tags[i]);
    }
    free(req->tags);

    free(req);
}

int neu_json_encode_get_tags_resp(void *json_object, void *param)
{
    int                       ret  = 0;
    neu_json_get_tags_resp_t *resp = (neu_json_get_tags_resp_t *) param;

    void *tag_array = neu_json_array();
    if (NULL == tag_array) {
        return -1;
    }

    neu_json_tag_array_t arr = {
        .len  = resp->n_tag,
        .tags = resp->tags,
    };
    ret = neu_json_encode_tag_array(tag_array, &arr);
    if (0 != ret) {
        neu_json_encode_free(tag_array);
        return ret;
    }

    neu_json_elem_t resp_elems[] = { {
        .name         = "tags",
        .t            = NEU_JSON_OBJECT,
        .v.val_object = tag_array,
    } };
    ret = neu_json_encode_field(json_object, resp_elems,
                                NEU_JSON_ELEM_SIZE(resp_elems));

    return ret;
}

int neu_json_decode_update_tags_req(char *                       buf,
                                    neu_json_update_tags_req_t **result)
{
    int                         ret      = 0;
    void *                      json_obj = NULL;
    neu_json_update_tags_req_t *req =
        calloc(1, sizeof(neu_json_update_tags_req_t));
    if (req == NULL) {
        return -1;
    }

    json_obj = neu_json_decode_new(buf);
    if (NULL == json_obj) {
        free(req);
        return -1;
    }

    neu_json_elem_t req_elems[] = {
        {
            .name = "node",
            .t    = NEU_JSON_STR,
        },
        {
            .name = "group",
            .t    = NEU_JSON_STR,
        },
        {
            .name = "tags",
            .t    = NEU_JSON_OBJECT,
        },
    };
    ret = neu_json_decode_by_json(json_obj, NEU_JSON_ELEM_SIZE(req_elems),
                                  req_elems);
    if (ret != 0) {
        goto decode_fail;
    }

    neu_json_tag_array_t arr = { 0 };
    ret = neu_json_decode_tag_array_json(req_elems[2].v.val_object, &arr);
    if (ret != 0) {
        goto decode_fail;
    }
    if (arr.len <= 0) {
        goto decode_fail;
    }

    req->node  = req_elems[0].v.val_str;
    req->group = req_elems[1].v.val_str;
    req->n_tag = arr.len;
    req->tags  = arr.tags;
    *result    = req;
    goto decode_exit;

decode_fail:
    free(req);
    free(req_elems[0].v.val_str);
    free(req_elems[1].v.val_str);
    ret = -1;

decode_exit:
    if (json_obj != NULL) {
        neu_json_decode_free(json_obj);
    }
    return ret;
}

void neu_json_decode_update_tags_req_free(neu_json_update_tags_req_t *req)
{
    if (NULL == req) {
        return;
    }

    neu_json_tag_array_t arr = {
        .len  = req->n_tag,
        .tags = req->tags,
    };
    neu_json_decode_tag_array_fini(&arr);

    free(req->group);
    free(req->node);

    free(req);
}
