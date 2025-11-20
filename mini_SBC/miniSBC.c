#include "miniSBC.h"
#include "registartor.h"
#include <signal.h>
#include <pjsip.h>
#include <pjsip_ua.h>
#include <pjmedia.h>

static pjsip_endpoint* sbc_endpt;
static pjmedia_endpt* med_endpt;

static pj_caching_pool ch_pool;

static pjsip_transport* in_transport;
static pjmedia_transport* in_med_transport;
static pjmedia_transport_info in_med_tpinfo;
static pjmedia_sock_info in_med_sockinfo;
static pjsip_transport* out_transport;
static pjmedia_transport* out_med_transport;
static pjmedia_transport_info out_med_tpinfo;
static pjmedia_sock_info out_med_sockinfo;
static pjsip_inv_session* uas_inv;
static pjsip_inv_session* uac_inv;

static pj_sockaddr* in_addr;
static pj_sockaddr* out_addr;

static pjsip_module mod_minisbc;
static volatile char is_in_connection_established = 0;
static volatile char is_end = 0;


static pj_status_t create_endpoint();
static pj_status_t create_transport();
static pj_status_t init_modules();
static void create_sbc_module();
static pj_status_t create_registrator();

static void call_on_state_changed(pjsip_inv_session*, pjsip_event*);
static pj_bool_t on_rx_request(pjsip_rx_data*);
static pj_bool_t on_rx_response(pjsip_rx_data*);

void cleanup()
{
    if (in_transport)
    {
        pjsip_transport_shutdown(in_transport);
    }
    if (in_med_transport)
    {
        pjmedia_transport_close(in_med_transport);
    }
    if (out_transport)
    {
        pjsip_transport_shutdown(out_transport);
    }
    if (out_med_transport)
    {
        pjmedia_transport_close(out_med_transport);
    }

    registrator_destroy();
    
    if (med_endpt)
    {
        pjmedia_endpt_destroy(med_endpt);
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

int start_sbc(pj_sockaddr* inner_addr, pj_sockaddr* outer_addr)
{
    pj_status_t status = -1;
    in_addr = inner_addr;
    out_addr = outer_addr;

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
    status = create_registrator();
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
    if (status != PJ_SUCCESS)
    {
        return status;
    }

    pj_ioqueue_t* ioqueue = pjsip_endpt_get_ioqueue(sbc_endpt);
    if (ioqueue)
    {
        status = pjmedia_endpt_create(&ch_pool.factory, ioqueue, 0, &med_endpt);
    }
    else
    {
        status = pjmedia_endpt_create(&ch_pool.factory, NULL, 1, &med_endpt);
    }

    if (status != PJ_SUCCESS)
    {
        return status;
    }

    status = pjmedia_codec_g711_init(med_endpt);
    return status;
}

static pj_status_t create_transport()
{
    pj_status_t status;
    status = pjsip_udp_transport_start(sbc_endpt, &in_addr->ipv4, NULL, 1, &in_transport);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "create inner transport error"));
        return status;
    }

    status = pjsip_udp_transport_start(sbc_endpt, &out_addr->ipv4, NULL, 1, &out_transport);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "create outer transport error"));
        return status;
    }

    status = pjmedia_transport_udp_create(med_endpt, "Inner media transport", RTP_PORT, 0, &in_med_transport);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "create inner media transport error"));
        return status;
    }

    pjmedia_transport_info_init(&in_med_tpinfo);
    status = pjmedia_transport_get_info(in_med_transport, &in_med_tpinfo);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "can't get info about inner media transport"));
        return status;
    }
    pj_memcpy(&in_med_sockinfo, &in_med_tpinfo.sock_info, sizeof(pjmedia_sock_info));

    status = pjmedia_transport_udp_create(med_endpt, "Outer media transport", RTP_PORT + 2, 0, &out_med_transport);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "create outer media transport error"));
        return status;
    }

    pjmedia_transport_info_init(&out_med_tpinfo);
    status = pjmedia_transport_get_info(out_med_transport, &out_med_tpinfo);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "can't get info about outer media transport"));
    }
    pj_memcpy(&out_med_sockinfo, &out_med_tpinfo.sock_info, sizeof(pjmedia_sock_info));

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
    mod_minisbc.on_rx_response = &on_rx_response;
    mod_minisbc.on_tsx_state = NULL;
    mod_minisbc.on_tx_request = NULL;
    mod_minisbc.on_tx_response = NULL;
}

static pj_status_t create_registrator()
{
    pj_status_t status;
    status = registrator_init(&ch_pool.factory);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "Registrator init error"));
        return status;
    }
    
    pj_str_t name = pj_str("tester");
    pj_str_t addr_str = pj_str("127.0.0.1");
    pj_in_addr addr;
    pj_inet_aton(&addr_str, &addr);
    pj_uint16_t port = 5063;
    pj_str_t password = pj_str(DEFAULT_PASS);

    status = add_contact(&name, &addr, port, &password);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "Can't add equal contacts to registrator"));
    }

    name = pj_str("user1");
    addr_str = pj_str("127.0.0.2");
    pj_inet_aton(&addr_str, &addr);
    port = 5063;
    password = pj_str(DEFAULT_PASS);

    status = add_contact(&name, &addr, port, &password);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "Can't add equal contacts to registrator"));
    }


    return PJ_SUCCESS;
}


//Callbacks
static void call_on_state_changed(pjsip_inv_session* inv, pjsip_event* e)
{
    PJ_UNUSED_ARG(e);
    if (inv->state == PJSIP_INV_STATE_DISCONNECTED)
    {
        PJ_LOG(2, (__FILE__, "Call disconnected | reason=%d [%.*s]", inv->cause, (int)inv->cause_text.slen, inv->cause_text.ptr));
        //// Need to add correct end of dialog
    }
    else if (inv->state == PJSIP_INV_STATE_CONFIRMED)
    {
        is_in_connection_established = (inv == uas_inv) ? 1 : is_in_connection_established;
    }
    else
    {
        PJ_LOG(2, (__FILE__, "Call state changed to %d", inv->state));
    }
}

static pj_bool_t on_rx_request(pjsip_rx_data* rdata)
{
    pjsip_method_e method = rdata->msg_info.msg->line.req.method.id;
    if (method == PJSIP_REGISTER_METHOD)
    {
        pjsip_authorization_hdr* hdr = pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_AUTHORIZATION, NULL);
        if (!hdr)
        {
            try_register(sbc_endpt, rdata);
            return PJ_TRUE;
        }
        else
        {
            try_auth(sbc_endpt, rdata);
            return PJ_TRUE;
        }
    }
    else if (method != PJSIP_INVITE_METHOD)
    {
        pj_str_t st_text = pj_str("SBC can't handle such request");
        pjsip_endpt_respond_stateless(sbc_endpt, rdata, 500, &st_text, NULL, NULL);
        return PJ_TRUE;
    }

    //// Sync
    if (uas_inv)
    {
        pj_str_t st_text = pj_str("Another call is in progress");
        pjsip_endpt_respond_stateless(sbc_endpt, rdata, 486, &st_text, NULL, NULL);
        return PJ_TRUE;
    }
    PJ_LOG(2, (__FILE__, "[TRANSPORT] request from %s:%d is being processed", pj_inet_ntoa(rdata->pkt_info.src_addr.ipv4.sin_addr), rdata->pkt_info.src_port));

    unsigned int options = 0;
    pj_status_t status = pjsip_inv_verify_request(rdata, &options, NULL, NULL, sbc_endpt, NULL);
    if (status != PJ_SUCCESS)
    {
        pj_str_t st_text = pj_str("Can't verify this invite");
        pjsip_endpt_respond_stateless(sbc_endpt, rdata, 500, &st_text, NULL, NULL);
        return PJ_TRUE;
    }

    pjsip_dialog* uas_dlg;
    status = pjsip_dlg_create_uas_and_inc_lock(pjsip_ua_instance(), rdata, NULL, &uas_dlg);
    if (status != PJ_SUCCESS)
    {
        pj_str_t st_text = pj_str("Can't create UAS dialog");
        pjsip_endpt_respond_stateless(sbc_endpt, rdata, 500, &st_text, NULL, NULL);
        return PJ_TRUE;
    }

    pjmedia_sdp_session* local_sdp;
    pjmedia_sock_info* cur_sock_info = rdata->tp_info.transport == in_transport ? &in_med_sockinfo : &out_med_sockinfo;
    status = pjmedia_endpt_create_sdp(med_endpt, rdata->tp_info.pool, 1, cur_sock_info, &local_sdp);
    if (status != PJ_SUCCESS)
    {
        pjsip_dlg_dec_lock(uas_dlg);
        return PJ_TRUE;
    }

    status = pjsip_inv_create_uas(uas_dlg, rdata, local_sdp, 0, &uas_inv);
    pjsip_dlg_dec_lock(uas_dlg);
    if (status != PJ_SUCCESS)
    {
        return PJ_TRUE;
    }

    pjsip_tx_data* tdata;
    pjsip_inv_initial_answer(uas_inv, rdata, 180, NULL, NULL, &tdata);
    pjsip_inv_send_msg(uas_inv, tdata);

    //// Establish connection with other side
    pjsip_dialog* uac_dlg;
    char local_uri[64], remote_uri[64];
    snprintf(local_uri, 64, "sip:sbc@%s", pj_inet_ntoa(rdata->tp_info.transport->local_addr.ipv4.sin_addr));
    pjsip_uri_print(PJSIP_URI_IN_REQ_URI, rdata->msg_info.msg->line.req.uri, remote_uri, 64);
    pj_str_t loc = pj_str(local_uri);
    pj_str_t rem = pj_str(remote_uri);
    status = pjsip_dlg_create_uac(pjsip_ua_instance(), &loc, NULL, &rem, NULL, &uac_dlg);
    if (status != PJ_SUCCESS)
    {
        pj_str_t st_text = pj_str("Can't create UAC dialog");
        pjsip_inv_end_session(uas_inv, 500, &st_text, &tdata);
        return PJ_TRUE;
    }

    status = pjsip_inv_create_uac(uac_dlg, local_sdp, 0, &uac_inv);
    pjsip_inv_invite(uac_inv, &tdata);
    pjsip_inv_send_msg(uac_inv, tdata);

    pjsip_inv_end_session(uas_inv, 500, NULL, &tdata);
    pjsip_inv_send_msg(uas_inv, tdata);

    return PJ_TRUE;
}

static pj_bool_t on_rx_response(pjsip_rx_data *rdata)
{

    return PJ_TRUE;
}
