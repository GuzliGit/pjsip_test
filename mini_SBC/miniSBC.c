#include "miniSBC.h"
#include "registartor.h"
#include <signal.h>
#include <pjsip.h>
#include <pjsip_ua.h>
#include <pjmedia.h>

static pjsip_endpoint* sbc_endpt;
static pjmedia_endpt* med_endpt;
static pjmedia_conf* conf_bridge;
static pjmedia_event_mgr* event_mgr;

static pj_caching_pool ch_pool;
static pj_pool_t* main_pool;
static pj_pool_t* sdp_pool;

static pjsip_transport* in_transport;
static pjmedia_transport* in_med_transport;
static pjmedia_transport_info in_med_tpinfo;
static pjmedia_sock_info in_med_sockinfo;

static pjmedia_stream* in_stream;
static pjmedia_port* in_stream_port;
static unsigned int in_slot;

static pjsip_inv_session* uas_inv = NULL;
static pjmedia_sdp_session* local_sdp_in;
static pjmedia_sdp_session* remote_sdp_in;

static pjsip_transport* out_transport;
static pjmedia_transport* out_med_transport;
static pjmedia_transport_info out_med_tpinfo;
static pjmedia_sock_info out_med_sockinfo;

static pjmedia_stream* out_stream;
static pjmedia_port* out_stream_port;
static unsigned int out_slot;

static pjsip_inv_session* uac_inv = NULL;
static pjmedia_sdp_session* local_sdp_out;
static pjmedia_sdp_session* remote_sdp_out;

static pj_sockaddr* in_addr;
static pj_sockaddr* out_addr;

static pjsip_module mod_minisbc;
static volatile char is_end = 0;


static pj_status_t create_endpoint();
static pj_status_t create_pools();
static pj_status_t create_med_endpoit();
static pj_status_t create_transport();
static pj_status_t init_conf();
static pj_status_t init_modules();
static void create_sbc_module();
static pj_status_t create_registrator();

static pj_status_t start_uas_dlg(pjsip_rx_data*);
static pj_status_t start_uac_dlg(pjsip_rx_data*, pjsip_tx_data*);

static pj_status_t initialize_media_bridge();

static void call_on_state_changed(pjsip_inv_session*, pjsip_event*);
static pj_bool_t on_rx_request(pjsip_rx_data*);
static pj_bool_t on_rx_response(pjsip_rx_data*);

void cleanup()
{
    if (in_stream)
    {
        pjmedia_stream_destroy(in_stream);
    }
    if (out_stream)
    {
        pjmedia_stream_destroy(out_stream);
    }
    if (conf_bridge)
    {
        pjmedia_conf_destroy(conf_bridge);
    }
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
    
    if (event_mgr)
    {
        pjmedia_event_mgr_destroy(event_mgr);
    }
    if (med_endpt)
    {
        pjmedia_endpt_destroy(med_endpt);
    }
    if (sbc_endpt)
    {
        pjsip_endpt_destroy(sbc_endpt);
    }
    if (main_pool)
    {
        pj_pool_release(main_pool);
    }
    if (sdp_pool)
    {
        pj_pool_release(sdp_pool);
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
    status = create_pools();
    if (status != PJ_SUCCESS)
    {
        goto _exit;
    }
    status = create_med_endpoit();
    if (status != PJ_SUCCESS)
    {
        goto _exit;
    }
    status = create_transport(in_addr, out_addr);
    if (status != PJ_SUCCESS)
    {
        goto _exit;
    }
    status = init_conf();
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
    return status;
}

static pj_status_t create_pools()
{
    main_pool = pj_pool_create(&ch_pool.factory, "main_pool", MAIN_POOL_SIZE, MAIN_POOL_SIZE, NULL);
    if (!main_pool)
    {
        return -1;
    }

    sdp_pool = pj_pool_create(&ch_pool.factory, "sdp_pool", SDP_POOL_SIZE, SDP_POOL_SIZE, NULL);
    if (!sdp_pool)
    {
        return -1;
    }

    return PJ_SUCCESS;
}

static pj_status_t create_med_endpoit()
{
    pj_status_t status;
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

    status = pjmedia_event_mgr_create(main_pool, 0, &event_mgr);
    if (status != PJ_SUCCESS)
    {
        return status;
    }    
    pjmedia_event_mgr_set_instance(event_mgr);

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

    pj_str_t inner_addr = pj_str(pj_inet_ntoa(in_addr->ipv4.sin_addr));
    status = pjmedia_transport_udp_create2(med_endpt, "Inner media transport", &inner_addr, RTP_PORT_IN, 0, &in_med_transport);
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

    pj_str_t outer_addr = pj_str(pj_inet_ntoa(out_addr->ipv4.sin_addr));
    status = pjmedia_transport_udp_create2(med_endpt, "Outer media transport", &outer_addr, RTP_PORT_OUT, 0, &out_med_transport);
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

static pj_status_t init_conf()
{
    pj_status_t status;

    status = pjmedia_conf_create(main_pool, MAX_SLOTS, 8000, 1, 160, 16, PJMEDIA_CONF_NO_DEVICE, &conf_bridge);
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
    mod_minisbc.priority = PJSIP_MOD_PRIORITY_TRANSPORT_LAYER + 1;
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
    port = 5080;
    password = pj_str(DEFAULT_PASS);

    status = add_contact(&name, &addr, port, &password);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "Can't add equal contacts to registrator"));
    }

    return PJ_SUCCESS;
}

static pj_status_t start_uas_dlg(pjsip_rx_data* rdata)
{
    pjsip_dialog* uas_dlg;
    pj_status_t status = pjsip_dlg_create_uas_and_inc_lock(pjsip_ua_instance(), rdata, NULL, &uas_dlg);
    if (status != PJ_SUCCESS)
    {
        pj_str_t st_text = pj_str("Can't create UAS dialog");
        pjsip_endpt_respond_stateless(sbc_endpt, rdata, 500, &st_text, NULL, NULL);
        return status;
    }

    pjmedia_sock_info* cur_sock_info = (rdata->tp_info.transport == in_transport) ? &in_med_sockinfo : &out_med_sockinfo;
    status = pjmedia_endpt_create_sdp(med_endpt, sdp_pool, 1, cur_sock_info, &local_sdp_in);
    if (status != PJ_SUCCESS)
    {
        pjsip_dlg_dec_lock(uas_dlg);
        return status;
    }

    status = pjsip_inv_create_uas(uas_dlg, rdata, local_sdp_in, 0, &uas_inv);
    pjsip_dlg_dec_lock(uas_dlg);

    return status;
}

static pj_status_t start_uac_dlg(pjsip_rx_data* rdata, pjsip_tx_data* tdata)
{
    pjsip_dialog* uac_dlg;
    char local_uri[128], remote_uri[128];
    pj_in_addr dest_addr;
    pj_uint16_t dest_port;
    pjsip_sip_uri* req_uri = (pjsip_sip_uri*) rdata->msg_info.msg->line.req.uri;
    if (!req_uri)
    {
        pj_str_t st_text = pj_str("Can't find username");
        pjsip_inv_end_session(uas_inv, 500, &st_text, &tdata);
        pjsip_inv_send_msg(uas_inv, tdata);
        return -1;
    }
    else if (get_info_by_name(req_uri->user, &dest_addr, &dest_port) != PJ_SUCCESS)
    {
        pj_str_t st_text = pj_str("Can't find info about contact with such name");
        pjsip_inv_end_session(uas_inv, 404, &st_text, &tdata);
        pjsip_inv_send_msg(uas_inv, tdata);
        return -1;
    }

    pjmedia_sock_info* cur_sock_info = (rdata->tp_info.transport == in_transport) ? &out_med_sockinfo : &in_med_sockinfo;
    pj_status_t status = pjmedia_endpt_create_sdp(med_endpt, sdp_pool, 1, cur_sock_info, &local_sdp_out);
    if (status != PJ_SUCCESS)
    {
        return -3;
    }

    snprintf(local_uri, 128, "sip:sbc@%s", pj_inet_ntoa(rdata->tp_info.transport->local_addr.ipv4.sin_addr));
    pj_ansi_snprintf(remote_uri, 128, "sip:%.*s@%s:%d", (int) req_uri->user.slen, req_uri->user.ptr, pj_inet_ntoa(dest_addr), dest_port);
    pj_str_t loc = pj_str(local_uri);
    pj_str_t rem = pj_str(remote_uri);

    status = pjsip_dlg_create_uac(pjsip_ua_instance(), &loc, NULL, &rem, NULL, &uac_dlg);
    if (status != PJ_SUCCESS)
    {
        return -2;
    }

    status = pjsip_inv_create_uac(uac_dlg, local_sdp_out, 0, &uac_inv);
    if (status != PJ_SUCCESS)
    {
        return -2;
    }

    status = pjsip_inv_set_local_sdp(uac_inv, local_sdp_out);

    status = pjsip_inv_invite(uac_inv, &tdata);
    if (status != PJ_SUCCESS)
    {
        return -3;
    }
    
    status = pjsip_inv_send_msg(uac_inv, tdata);
    if (status != PJ_SUCCESS)
    {
        return -3;
    }

    return PJ_SUCCESS;
}

static pj_status_t initialize_media_bridge()
{
    pj_status_t status;
    pjmedia_stream_info info;
    const pjmedia_codec_info* codec_info = pj_pool_zalloc(sdp_pool, sizeof(pjmedia_codec_info));
    pjmedia_codec_mgr_get_codec_info(pjmedia_endpt_get_codec_mgr(med_endpt), 0, &codec_info);

    info.type = PJMEDIA_TYPE_AUDIO;
    info.dir = PJMEDIA_DIR_ENCODING_DECODING;
    pj_memcpy(&info.fmt, codec_info, sizeof(pjmedia_codec_info));
    info.fmt.pt = codec_info->pt;
    info.ssrc = pj_rand();
    pj_memcpy(&info.rem_addr, in_addr, sizeof(pj_sockaddr_in));

    status = pjmedia_stream_create(med_endpt, main_pool, &info, in_med_transport, NULL, &in_stream);
    if (status != PJ_SUCCESS)
    {
        return status;
    }
    pj_memcpy(&info.rem_addr, out_addr, sizeof(pj_sockaddr_in));
    status = pjmedia_stream_create(med_endpt, main_pool, &info, out_med_transport, NULL, &out_stream);
    if (status != PJ_SUCCESS)
    {
        return status;
    }

    status = pjmedia_stream_get_port(in_stream, &in_stream_port);
    if (status != PJ_SUCCESS)
    {
        return status;
    }
    status = pjmedia_stream_get_port(out_stream, &out_stream_port);
    if (status != PJ_SUCCESS)
    {
        return status;
    }

    status = pjmedia_conf_add_port(conf_bridge, main_pool, in_stream_port, NULL, &in_slot);
    if (status != PJ_SUCCESS)
    {
        return status;
    }
    status = pjmedia_conf_add_port(conf_bridge, main_pool, out_stream_port, NULL, &out_slot);
    if (status != PJ_SUCCESS)
    {
        return status;
    }

    status = pjmedia_conf_connect_port(conf_bridge, in_slot, out_slot, 0);
    if (status != PJ_SUCCESS)
    {
        return status;
    }
    status = pjmedia_conf_connect_port(conf_bridge, out_slot, in_slot, 0);
    if (status != PJ_SUCCESS)
    {
        return status;
    }

    status = pjmedia_transport_media_start(in_med_transport, sdp_pool, local_sdp_in, remote_sdp_in, 0);
    if (status != PJ_SUCCESS)
    {
        return status;
    }
    status = pjmedia_transport_media_start(out_med_transport, sdp_pool, local_sdp_out, remote_sdp_out, 0);
    if (status != PJ_SUCCESS)
    {
        return status;
    }

    status = pjmedia_stream_start(in_stream);
    if (status != PJ_SUCCESS)
    {
        return status;
    }

    status = pjmedia_stream_start(out_stream);
    return status;
}


//Callbacks
static void call_on_state_changed(pjsip_inv_session* inv, pjsip_event* e)
{
    PJ_UNUSED_ARG(e);
    if (inv->state == PJSIP_INV_STATE_DISCONNECTED)
    {
        PJ_LOG(2, (__FILE__, "Call disconnected | reason=%d [%.*s]", inv->cause, (int)inv->cause_text.slen, inv->cause_text.ptr));
        if (uas_inv && uac_inv && uac_inv->state == PJSIP_INV_STATE_DISCONNECTED && uas_inv->state == PJSIP_INV_STATE_DISCONNECTED)
        {
            pj_pool_release(sdp_pool);
        }
    }
    else if (uas_inv && uac_inv && uas_inv->state == PJSIP_INV_STATE_CONFIRMED && uac_inv->state == PJSIP_INV_STATE_CONFIRMED)
    {
        PJ_LOG(2, (__FILE__, "===== Connection established | media bridge initializing ====="));
        pj_status_t status = initialize_media_bridge();
        if (status != PJ_SUCCESS)
        {
            PJ_LOG(2, (__FILE__, "===== Media bridge initialization error ====="));
        }
        else
        {
            PJ_LOG(2, (__FILE__, "===== Media bridge was successfully initialized ====="));
        }
    }
    else
    {
        PJ_LOG(2, (__FILE__, "Call state changed to %d", inv->state));
    }
}

static pj_bool_t on_rx_request(pjsip_rx_data* rdata)
{
    PJ_LOG(2,(__FILE__, "== REQUEST %d bytes %s from %s %s:%d ==",
                         rdata->msg_info.len,
                         pjsip_rx_data_get_info(rdata),
                         rdata->tp_info.transport->type_name,
                         rdata->pkt_info.src_name,
                         rdata->pkt_info.src_port));

    pjsip_method_e method = rdata->msg_info.msg->line.req.method.id;
    if (method == PJSIP_REGISTER_METHOD)
    {
        pjsip_authorization_hdr* hdr = pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_AUTHORIZATION, NULL);
        if (!hdr)
        {
            try_register(sbc_endpt, rdata);
            return PJ_FALSE;
        }
        else
        {
            try_auth(sbc_endpt, rdata);
            return PJ_FALSE;
        }
    }
    else if (method == PJSIP_BYE_METHOD && (uas_inv || uac_inv))
    {
        pjsip_tx_data* tdata;
        if (uas_inv && uac_inv)
        {
            pjsip_inv_end_session(uac_inv, 200, NULL, &tdata);
            pjsip_inv_send_msg(uac_inv, tdata);
        }
        uas_inv = NULL;
        uac_inv = NULL;

        return PJ_FALSE;
    }
    else if (method != PJSIP_INVITE_METHOD)
    {
        return PJ_FALSE;
    }

    if (uas_inv)
    {
        pj_str_t st_text = pj_str("Another call is in progress");
        pjsip_endpt_respond_stateless(sbc_endpt, rdata, 486, &st_text, NULL, NULL);
        return PJ_FALSE;
    }
    PJ_LOG(2, (__FILE__, "[TRANSPORT] request from %s:%d is being processed", pj_inet_ntoa(rdata->pkt_info.src_addr.ipv4.sin_addr), rdata->pkt_info.src_port));

    unsigned int options = 0;
    pj_status_t status = pjsip_inv_verify_request(rdata, &options, NULL, NULL, sbc_endpt, NULL);
    if (status != PJ_SUCCESS)
    {
        pj_str_t st_text = pj_str("Can't verify this invite");
        pjsip_endpt_respond_stateless(sbc_endpt, rdata, 500, &st_text, NULL, NULL);
        return PJ_FALSE;
    }

    if (start_uas_dlg(rdata) != PJ_SUCCESS)
    {
        return PJ_FALSE;
    }

    remote_sdp_in = pjsip_get_sdp_info(sdp_pool, rdata->msg_info.msg->body, NULL, NULL)->sdp;
    if (!remote_sdp_in)
    {
        goto clean_uas;
    }

    pjsip_tx_data* tdata;
    status = pjsip_inv_initial_answer(uas_inv, rdata, 100, NULL, NULL, &tdata);
    if (status != PJ_SUCCESS)
    {
        goto clean_uas;
    }

    status = pjsip_inv_send_msg(uas_inv, tdata);
    if (status != PJ_SUCCESS)
    {
        goto clean_uas;
    }

    switch (start_uac_dlg(rdata, tdata))
    {
    case -1:
        return PJ_FALSE;
    
    case -2:
        goto clean_uas;
        break;

    case -3:
        goto clean_uac_and_uas;
        break;

    default:
        break;
    }

    return PJ_FALSE;

clean_uas:
    pjsip_inv_end_session(uas_inv, 500, NULL, &tdata);
    pjsip_inv_send_msg(uas_inv, tdata);
    return PJ_FALSE;

clean_uac_and_uas:
    pjsip_inv_end_session(uas_inv, 500, NULL, &tdata);
    pjsip_inv_send_msg(uas_inv, tdata);
    pjsip_inv_end_session(uac_inv, 500, NULL, &tdata);
    pjsip_inv_send_msg(uac_inv, tdata);
    return PJ_FALSE;
}

static pj_bool_t on_rx_response(pjsip_rx_data* rdata)
{
    PJ_LOG(2,(__FILE__, "== RESPONSE %d bytes %s from %s %s:%d ==\n %.*s\n == end of msg ==",
                         rdata->msg_info.len,
                         pjsip_rx_data_get_info(rdata),
                         rdata->tp_info.transport->type_name,
                         rdata->pkt_info.src_name,
                         rdata->pkt_info.src_port,
                         (int)rdata->msg_info.len,
                         rdata->msg_info.msg_buf));

    pj_status_t status;
    if (uas_inv && uac_inv)
    {
        pjsip_tx_data* tdata;
        pjsip_inv_session* answer_sess = (pjsip_rdata_get_dlg(rdata) == uas_inv->dlg) ? uac_inv : uas_inv;
        pjmedia_sdp_session* cur_sdp_sess; 
        cur_sdp_sess = pjsip_get_sdp_info(sdp_pool, rdata->msg_info.msg->body, NULL, NULL)->sdp;
        if (cur_sdp_sess)
        {
            if (answer_sess == uas_inv)
            {
                remote_sdp_out = cur_sdp_sess;
                pjsip_inv_set_sdp_answer(answer_sess, local_sdp_in);
            }
            else
            {
                remote_sdp_in = cur_sdp_sess;
                pjsip_inv_set_sdp_answer(answer_sess, local_sdp_out);
            }
        }
        
        status = pjsip_inv_answer(answer_sess, rdata->msg_info.msg->line.status.code, NULL, NULL, &tdata);
        status = pjsip_inv_send_msg(answer_sess, tdata);

        return PJ_FALSE;
    }
    
    return PJ_FALSE;
}