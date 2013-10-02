/**
 *
 * Copyright (C) 2013 Nulab, Inc.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_flag_t           enable;
    ngx_int_t            max;
    ngx_hash_t           types;
    ngx_array_t          *types_keys;    
} ngx_http_length_hiding_conf_t;

typedef struct {
    ngx_str_t            comment;
} ngx_http_length_hiding_ctx_t;

static void* ngx_http_length_hiding_create_conf(ngx_conf_t *cf);
static char* ngx_http_length_hiding_merge_conf(ngx_conf_t *cf,void *parent, void *child);
static ngx_int_t ngx_http_length_hiding_filter_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_length_hiding_generate_random(ngx_http_request_t *r, ngx_http_length_hiding_ctx_t *ctx, ngx_http_length_hiding_conf_t *conf);

static ngx_conf_num_bounds_t  ngx_http_length_hiding_max_bounds = {
    ngx_conf_check_num_bounds, 256, 2048
};

static ngx_command_t  ngx_http_length_hiding_filter_commands[] = {
    { ngx_string("length_hiding"),
       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_length_hiding_conf_t, enable),
      NULL },

    { ngx_string("length_hiding_max"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_length_hiding_conf_t, max),
      &ngx_http_length_hiding_max_bounds },

    { ngx_string("length_hiding_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_length_hiding_conf_t, types_keys),
      &ngx_http_html_default_types[0] },      

      ngx_null_command
};

static ngx_http_module_t  ngx_http_length_hiding_filter_module_ctx = {
    NULL,                                         /* preconfiguration */
    ngx_http_length_hiding_filter_init,           /* postconfiguration */

    NULL,                                         /* create main configuration */
    NULL,                                         /* init main configuration */

    NULL,                                         /* create server configuration */
    NULL,                                         /* merge server configuration */

    ngx_http_length_hiding_create_conf,           /* create location configuration */
    ngx_http_length_hiding_merge_conf             /* merge location configuration */
};

ngx_module_t  ngx_http_length_hiding_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_length_hiding_filter_module_ctx,      /* module context */
    ngx_http_length_hiding_filter_commands,         /* module directives */
    NGX_HTTP_MODULE,                                /* module type */
    NULL,                                           /* init master */
    NULL,                                           /* init module */
    NULL,                                           /* init process */
    NULL,                                           /* init thread */
    NULL,                                           /* exit thread */
    NULL,                                           /* exit process */
    NULL,                                           /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static ngx_int_t
ngx_http_length_hiding_header_filter(ngx_http_request_t *r)
{
    ngx_http_length_hiding_ctx_t   *ctx;
    ngx_http_length_hiding_conf_t  *cf;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_length_hiding_filter_module);

    if(!cf->enable
        || ( r->headers_out.status != NGX_HTTP_OK || r->headers_out.status == NGX_HTTP_NO_CONTENT )
        || r->header_only
        || (r->method & NGX_HTTP_HEAD)
        || r != r->main
        || ngx_http_test_content_type(r, &cf->types) == NULL )
    {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_length_hiding_ctx_t));
    if(ctx == NULL){
        return NGX_ERROR;
    }

    /* generate random string comment to make it difficult for attackers to detect size change during BREACH attach */
    if( ngx_http_length_hiding_generate_random(r, ctx, cf) != NGX_OK ){
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_length_hiding_filter_module);    

    if (r->headers_out.content_length_n != -1) {
        r->headers_out.content_length_n += ctx->comment.len;
    }

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    ngx_http_clear_accept_ranges(r);

    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_length_hiding_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_buf_t                      *buf;
    ngx_uint_t                     last;
    ngx_chain_t                    *cl, *nl;    
    ngx_http_length_hiding_ctx_t   *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_length_hiding_filter_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http length hiding filter : random length %d", ctx->comment.len);

    last = 0;
    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            last = 1;
            break;
        }
    }

    if(!last){
        return ngx_http_next_body_filter(r, in);
    }

    buf = ngx_calloc_buf(r->pool);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    buf->pos = ctx->comment.data;
    buf->last = buf->pos + ctx->comment.len;
    buf->start = buf->pos;
    buf->end = buf->last;
    buf->last_buf = 1;
    buf->memory = 1;

    if (ngx_buf_size(cl->buf) == 0) {
        cl->buf = buf;
    } else {
        nl = ngx_alloc_chain_link(r->pool);
        if (nl == NULL) {
            return NGX_ERROR;
        }
        nl->buf = buf;
        nl->next = NULL;
        cl->next = nl;
        cl->buf->last_buf = 0;
    }    

    return ngx_http_next_body_filter(r, in);
}

static void *
ngx_http_length_hiding_create_conf(ngx_conf_t *cf)
{
    ngx_http_length_hiding_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_length_hiding_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    
    conf->enable = NGX_CONF_UNSET;
    conf->max = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_length_hiding_merge_conf(ngx_conf_t *cf, void *parent, void *child){
    ngx_http_length_hiding_conf_t *prev = parent;
    ngx_http_length_hiding_conf_t *conf = child;

    if(ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys,&prev->types,
                             ngx_http_html_default_types) != NGX_OK){
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->max, prev->max, 2048);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_length_hiding_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_length_hiding_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_length_hiding_body_filter;

    return NGX_OK;
}

static ngx_int_t
ngx_http_length_hiding_generate_random(ngx_http_request_t *r, ngx_http_length_hiding_ctx_t *ctx,
    ngx_http_length_hiding_conf_t *cf)
{

    u_int          len;
    u_char          *s, *d;

    static u_char base[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static u_int base_len = sizeof(base) - 1;

    len = ngx_random() % cf->max + 1;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http length hiding filter : length %d", len);

    s = d = ngx_palloc(r->pool, len + 37);
    if( s == NULL ){
        return NGX_ERROR;
    }

    s = ngx_copy(s,"<!-- random-length HTML comment: ",33);
    while(len > 0){
        *s++ = base[ngx_random() % base_len];
        len--;
    }
    s = ngx_copy(s, " -->", 4);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http length hiding filter : str %s", d);    
    ctx->comment.data = d;
    ctx->comment.len = s - d;

    return NGX_OK;
}

