#include "miniSBC.h"
#include <signal.h>
#include <pjsip.h>
#include <pjsip_ua.h>

static pjsip_endpoint* sbc_endpt;
static pj_caching_pool ch_pool;
static pjsip_transport* in_transport;
static pjsip_transport* out_transport;
static pjsip_inv_session* cur_inv;

static pjsip_module mod_minisbc;
static volatile char is_end = 0;


static pj_status_t create_endpoint();
static pj_status_t create_transport(pj_sockaddr*, pj_sockaddr*);
static pj_status_t init_modules();
static void create_sbc_module();

static void call_on_state_changed(pjsip_inv_session*, pjsip_event*);
static pj_bool_t on_rx_request(pjsip_rx_data*);

void cleanup()
{
    if (in_transport)
    {
        pjsip_transport_shutdown(in_transport);
    }
    if (out_transport)
    {
        pjsip_transport_shutdown(out_transport);
    }
    if (sbc_endpt)
    {
        pjsip_endpt_destroy(sbc_endpt);
    }
    if (&ch_pool)
    {
        pj_caching_pool_destroy(&ch_pool);
    }
    pj_shutdown();
}

void sig_handler()
{
    is_end = 1;
}

int start_sbc(pj_sockaddr* in_addr, pj_sockaddr* out_addr)
{
    pj_status_t status = -1;
    status = pj_init();
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "pj_init error"));
        goto _exit;
    }
    pj_log_set_level(5);

    status = create_endpoint();
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "create_endpoint error"));
        goto _exit;
    }
    status = create_transport(in_addr, out_addr);
    if (status != PJ_SUCCESS)
    {
        goto _exit;
    }
    status = init_modules();
    if (status != PJ_SUCCESS)
    {
        goto _exit;
    }

    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    
    pj_time_val delay = {0, 100};
    while (!is_end)
    {
        pjsip_endpt_handle_events(sbc_endpt, &delay);
    }

_exit:
    cleanup();
    return status;
}

static pj_status_t create_endpoint()
{
    pj_status_t status = -1;
    pj_caching_pool_init(&ch_pool, &pj_pool_factory_default_policy, 0);
    if (!(&ch_pool))
    {
        return status;
    }
    
    status = pjsip_endpt_create(&ch_pool.factory, ENDPOINT_NAME, &sbc_endpt);
    return status;
}

static pj_status_t create_transport(pj_sockaddr* in_addr, pj_sockaddr* out_addr)
{
    pj_status_t status;
    status = pjsip_udp_transport_start(sbc_endpt, &in_addr->ipv4, NULL, 1, &in_transport);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "create internal transport error"));
        return status;
    }

    status = pjsip_udp_transport_start(sbc_endpt, &out_addr->ipv4, NULL, 1, &out_transport);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "create outer transport error"));
        return status;
    }

    return status;
}

static pj_status_t init_modules()
{
    pj_status_t status;
    status = pjsip_tsx_layer_init_module(sbc_endpt);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "pjsip_tsx_layer_init_module error"));
        return status;
    }

    status = pjsip_ua_init_module(sbc_endpt, NULL);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "pjsip_ua_init_module error"));
        return status;
    }

    pjsip_inv_callback inv_cb;
    pj_bzero(&inv_cb, sizeof(inv_cb));
    inv_cb.on_state_changed = &call_on_state_changed;
    status = pjsip_inv_usage_init(sbc_endpt, &inv_cb);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "pjsip_inv_usage_init error"));
        return status;
    }

    status = pjsip_100rel_init_module(sbc_endpt);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "pjsip_100rel_init_module error"));
        return status;
    }

    create_sbc_module();
    status = pjsip_endpt_register_module(sbc_endpt, &mod_minisbc);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "pjsip_endpt_register_module [miniSBC] error"));
    }

    return status;
}

static void create_sbc_module()
{
    mod_minisbc.prev = NULL;
    mod_minisbc.next = NULL;
    mod_minisbc.name = pj_str("mod-miniSBC");
    mod_minisbc.id = -1;
    mod_minisbc.priority = PJSIP_MOD_PRIORITY_APPLICATION;
    mod_minisbc.start = NULL;
    mod_minisbc.load = NULL;
    mod_minisbc.stop = NULL;
    mod_minisbc.unload = NULL;
    mod_minisbc.on_rx_request = &on_rx_request;
    mod_minisbc.on_rx_response = NULL;
    mod_minisbc.on_tsx_state = NULL;
    mod_minisbc.on_tx_request = NULL;
    mod_minisbc.on_tx_response = NULL;
}


//Callbacks
static void call_on_state_changed(pjsip_inv_session* inv, pjsip_event* e)
{
    PJ_UNUSED_ARG(e);
    if (inv->state == PJSIP_INV_STATE_DISCONNECTED)
    {
        PJ_LOG(2, (__FILE__, "Call disconnected | reason=%d [%s]", inv->cause, inv->cause_text.ptr));
    }
    else
    {
        PJ_LOG(2, (__FILE__, "Call state changed to %d", inv->state));
    }
}

static pj_bool_t on_rx_request(pjsip_rx_data* rdata)
{
    pjsip_method_e method = rdata->msg_info.msg->line.req.method.id;
    if (method != PJSIP_INVITE_METHOD && method != PJSIP_ACK_METHOD)
    {
        pj_str_t st_text = pj_str("SBC can't handle such request");
        pjsip_endpt_respond_stateless(sbc_endpt, rdata, 500, &st_text, NULL, NULL);
        return PJ_TRUE;
    }

    if (cur_inv)
    {
        pj_str_t st_text = pj_str("Another call is in progress");
        pjsip_endpt_respond_stateless(sbc_endpt, rdata, 486, &st_text, NULL, NULL);
        return PJ_TRUE;
    }

    unsigned int options = 0;
    pj_status_t status = pjsip_inv_verify_request(rdata, &options, NULL, NULL, sbc_endpt, NULL);
    if (status != PJ_SUCCESS)
    {
        pj_str_t st_text = pj_str("Can't verify this invite");
        pjsip_endpt_respond_stateless(sbc_endpt, rdata, 500, &st_text, NULL, NULL);
        return PJ_TRUE;
    }

    ////
}
