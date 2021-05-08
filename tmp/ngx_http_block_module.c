#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct
{
    ngx_flag_t      enable;
    ngx_msec_t      duration;//conf中配置的周期
    ngx_uint_t      err_times;//conf中的错误次数
    ngx_shm_zone_t  *shm_zone;
} ngx_http_block_conf_t;

//slab存储
typedef struct {
    ngx_flag_t      is_block;//是否被阻塞
    ngx_int_t       error_times;//出现错误的次数
    time_t          err_time;//第一次错误出现的时间
    ngx_flag_t      recover;//是否恢复
    time_t          recover_time;//恢复时间
} ngx_http_block_ctx_t;

static ngx_command_t ngx_http_block_commands[] =
{
    {
        ngx_string("blcok_enable"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_block_conf_t, enable),
        NULL
    },
    {
        ngx_string("block_duration"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_block_conf_t, duration),
        NULL
    },
    {
        ngx_string("block_errtimes"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_block_conf_t, err_times),
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_block_module_ctx =
{
    NULL,
    ngx_http_block_init,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_block_create_conf,
    ngx_http_block_merge_conf
};

static ngx_int_t ngx_http_block_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_block_header_filter;

    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL)
    {
        return NGX_ERROR;
    }

    *h = ngx_http_block_handler;
    return NGX_OK;
}

static void *ngx_http_block_create_conf(ngx_conf_t *cf)
{
    ngx_http_block_conf_t *blockcf;

    blockcf = (ngx_http_block_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_block_conf_t));

    if (blockcf == NULL)
    {
        return NULL;
    }

    blockcf->enable      = NGX_CONF_UNSET;
    blockcf->duration     = NGX_CONF_UNSET_MSEC;
    blockcf->err_times   = NGX_CONF_UNSET_UINT;

    return blockcf;
}

static char *ngx_http_block_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_block_conf_t *prev = parent;
    ngx_http_block_conf_t *conf = child;

    //初始化配置
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->duration, prev->duration, 0);
    ngx_conf_merge_value(conf->err_times, prev->err_times, 0);

    //初始化slab
    ngx_shm_zone_t *shm_zone;
    ngx_str_t *shm_name;
    shm_name = ngx_palloc(cf->pool, sizeof *shm_name);
    //设置内存池标识
    shm_name->len = sizeof("block_shared_memory") - 1;
    shm_name->data = (unsigned char *) "block_shared_memory";
    shm_zone = ngx_shared_memory_add(cf, shm_name, 8 * ngx_pagesize, &ngx_http_block_module);
    if(shm_zone == NULL)
    {
        return NGX_CONF_ERROR;
    }
    //内存池初始化回调函数
    shm_zone->init = ngx_http_block_init_shm_zone;
    conf->shm_zone = shm_zone;
    ngx_conf_merge_ptr_value(conf->shm_zone, prev->shm_zone, NULL);

    return NGX_CONF_OK;
}

//内存池数据初始化
static ngx_int_t ngx_http_block_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t *shpool;
    ngx_http_block_ctx_t *ctx;
    time_t now;
    now = ngx_time();
    if(data)
    {
        shm_zone->data = data;
        return NGX_OK;
    }
    shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
    ctx = ngx_slab_alloc(shpool, sizeof *ctx);
    ctx->is_block = 0;
    ctx->error_times = 0;
    ctx->err_time = 0;
    ctx->recover = 0;
    ctx->recover_time = 0;
    shm_zone->data = ctx;

    return NGX_OK;
}

static ngx_int_t ngx_http_block_header_filter(ngx_http_request_t *r)
{
    ngx_connection_t *c;
    c = r->connection;
    ngx_http_block_conf_t *conf;
    ngx_shm_zone_t *shm_zone;
    time_t now;
    ngx_flag_t now_is_block;
    time_t now_err_time;
    ngx_int_t now_error_times;
    time_t  now_recover_time;
    ngx_flag_t now_recover;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_block_module);
    if (conf->enable == 0)
    {
        return ngx_http_next_header_filter(r);
    }

    if(conf->shm_zone == NULL)
    {
        return NGX_DECLINED;
    }

    shm_zone = conf->shm_zone;
    now = ngx_time();
    now_is_block = ((ngx_http_block_ctx_t *)shm_zone->data)->is_block;
    now_err_time = ((ngx_http_block_ctx_t *)shm_zone->data)->err_time;
    now_error_times = ((ngx_http_block_ctx_t *)shm_zone->data)->error_times;
    now_recover = ((ngx_http_block_ctx_t *)shm_zone->data)->recover;
    now_recover_time = ((ngx_http_block_ctx_t *)shm_zone->data)->recover_time;

    // 是否开启半开通道
    if (now_recover == 1)
    {
        ((ngx_http_block_ctx_t *)shm_zone->data)->recover = 0;
    }

    if (r->headers_out.status == NGX_HTTP_OK)
    {
        ((ngx_http_block_ctx_t *)shm_zone->data)->is_block = 0;
        ((ngx_http_block_ctx_t *)shm_zone->data)->err_time = 0;
    }
    else if (r->headers_out.status == 503)
    {
        if ((now - now_recover_time) > 10 && now_recover == 0)
        {
            ((ngx_http_block_ctx_t *)shm_zone->data)->recover = 1;
            ((ngx_http_block_ctx_t *)shm_zone->data)->recover_time = now;
        }
    }
    else
    {
        ((ngx_http_block_ctx_t *)shm_zone->data)->err_time = now;
        ((ngx_http_block_ctx_t *)shm_zone->data)->error_times = ++now_error_times;
    }

    return ngx_http_next_header_filter(r);
}

//挂载在NGX_HTTP_POST_READ_PHASE阶段
static ngx_int_t ngx_http_block_handler(ngx_http_request_t *r)
{
    ngx_connection_t *c;
    c = r->connection;
    ngx_http_block_conf_t *conf;
    ngx_shm_zone_t *shm_zone;
    time_t now;
    ngx_flag_t now_is_block;
    time_t now_err_time;
    ngx_int_t now_error_times;
    time_t now_recover_time;
    ngx_flag_t now_recover;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_block_module);
    if (conf->enable == 0 || conf->shm_zone == NULL)
    {
        return NGX_DECLINED;
    }

    // 内存池中读取数据
    shm_zone = conf->shm_zone;
    now  = ngx_time();
    now_is_block = ((ngx_http_block_ctx_t *)shm_zone->data)->is_block;
    now_error_times = ((ngx_http_block_ctx_t *)shm_zone->data)->now_error_times;
    now_err_time = ((ngx_http_block_ctx_t *)shm_zone->data)->err_time;
    now_recover  = ((ngx_http_block_ctx_t *)shm_zone->data)->recover;
    now_recover_time = ((ngx_http_block_ctx_t *)shm_zone->data)->recover_time;

    if (now_is_block == 1 && now_recover == 0)
    {
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }
    else
    {
        if ((now - now_err_time) <= conf->duration)
        {
            if (now_error_times >= conf->err_times)
            {
                now_is_block = 1;
                ((ngx_http_block_ctx_t *)shm_zone->data)->is_block = now_is_block;
                ((ngx_http_block_ctx_t *)shm_zone->data)->recover_time = now;
                return NGX_HTTP_SERVICE_UNAVAILABLE;
            }
        }
    }

    return NGX_DECLINED;
}