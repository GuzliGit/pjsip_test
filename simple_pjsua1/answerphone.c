#include "answerphone.h"
#include <signal.h>
#include <pjsua-lib/pjsua.h>

static pj_caching_pool ch_pool;
static pj_pool_t* main_pool;
static pj_timer_heap_t* t_heap;

static pjsua_acc_id acc_id;

static pjsua_config cfg;
static pjsua_media_config med_cfg;
static pjsua_logging_config log_cfg;
static pjsua_transport_config t_cfg;
static pjsua_acc_config acc_cfg;

static int send_tone(pjsua_call_id);
static int create_transport();
static int create_pools();
static int create_timer_heap();
static int add_account(const char*, const char*);

static void cleanup_resources()
{
    pj_timer_heap_destroy(t_heap);
    pj_pool_release(main_pool);
    pj_caching_pool_destroy(&ch_pool);
    pjsua_destroy();
}

static void signal_handler()
{
    pjsua_call_hangup_all();
    cleanup_resources();
    exit(PJ_SUCCESS);
}

static void answer_timer_callback(pj_timer_heap_t* timer_heap, pj_timer_entry* entry)
{
    pjsua_call_id call_id = (pjsua_call_id)(long)entry->user_data;

    PJ_LOG(1, (__FILE__, "==Answer_timer_callback=="));
    pjsua_call_answer(call_id, 200, NULL, NULL);
    
    if (send_tone(call_id) != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "pjsua_call_answer error (200)"));
    }
}

static void timer_callback(pj_timer_heap_t* timer_heap, pj_timer_entry* entry)
{
    PJ_LOG(1, (__FILE__, "==Timer_callback=="));
}

static void on_incoming_call(pjsua_acc_id acc_id, pjsua_call_id call_id, pjsip_rx_data* rdata)
{
    pj_status_t status;
    pjsua_call_info info;

    PJ_UNUSED_ARG(acc_id);
    PJ_UNUSED_ARG(rdata);

    status = pjsua_call_get_info(call_id, &info);
    if (status != PJ_SUCCESS)
    {
        pjsua_call_hangup(call_id, 486, NULL, NULL);
        return;
    }

    PJ_LOG(3, (__FILE__, "Call %d state=%.*s", call_id, (int)info.state_text.slen, info.state_text.ptr));

    pjsua_call_answer(call_id, 180, NULL, NULL);

    pj_timer_entry* timer = pj_pool_zalloc(main_pool, sizeof(pj_timer_entry));
    pj_time_val delay = {3, 100};
    pj_timer_entry_init(timer, PJSUA_INVALID_ID, NULL, &answer_timer_callback);
    timer->user_data = (void*)(long)call_id;

    status = pj_timer_heap_schedule(t_heap, timer, &delay);
    if (status != PJ_SUCCESS)
    {
        pjsua_call_hangup(call_id, 486, NULL, NULL);
        return;
    }
}

static int send_tone(pjsua_call_id call_id)
{
    pj_status_t status;
    char temp[16];
    snprintf(temp, 16, "%dpl", call_id);

    pj_pool_t* media_pool = pj_pool_create(&ch_pool.factory, temp, MEDIA_POOL_SIZE, MEDIA_POOL_INC_SIZE, NULL);
    if (!media_pool)
    {
        PJ_LOG(1, (__FILE__, "==pj_pool_create error=="));
        pjsua_call_hangup(call_id, 486, NULL, NULL);
        return -1;
    }

    pjmedia_port* tone_port = pj_pool_alloc(media_pool, sizeof(pjmedia_port));
    status = pjmedia_tonegen_create(media_pool, PJSUA_DEFAULT_CLOCK_RATE, 1, PJSUA_CALL_SEND_DTMF_DURATION_DEFAULT, 16, 0, &tone_port);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pjmedia_tonegen_create error=="));
        pj_pool_release(media_pool);
        pjsua_call_hangup(call_id, 486, NULL, NULL);
        return -1;
    }

    pjsua_conf_port_id conf_slot;
    status = pjsua_conf_add_port(media_pool, tone_port, &conf_slot);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pjsua_conf_add_port error=="));
        pj_pool_release(media_pool);
        pjsua_call_hangup(call_id, 486, NULL, NULL);
        return -1;
    }

    status = pjsua_set_null_snd_dev();

    pjsua_call_info call_info;
    status = pjsua_call_get_info(call_id, &call_info);

    status = pjsua_conf_connect(conf_slot, call_info.conf_slot);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pjsua_conf_connect error=="));
        pjsua_conf_remove_port(conf_slot);
        pj_pool_release(media_pool);
        pjsua_call_hangup(call_id, 486, NULL, NULL);
        return -1;
    }
    PJ_LOG(3, (__FILE__, "Tone 425Hz started for call %d, conf_slot=%d", call_id, conf_slot));

    pjmedia_tone_desc tone;
    tone.freq1 = 425;
    tone.freq2 = 0;
    tone.off_msec = 0;
    tone.on_msec = 10000;

    status = pjmedia_tonegen_play(tone_port, 1, &tone, PJMEDIA_TONEGEN_LOOP);
    pj_thread_sleep(tone.on_msec);

    pjsua_conf_disconnect(conf_slot, call_info.conf_slot);
    pjsua_conf_remove_port(conf_slot);
    pj_pool_release(media_pool);
    pjsua_call_hangup(call_id, 486, NULL, NULL);
    return PJ_SUCCESS;
}

int init_answerphone()
{
    pj_status_t status;

    status = pjsua_create();
    if (status != PJ_SUCCESS)
    {
        printf("pjsua_create error\n");
        return -1;
    }

    pjsua_config_default(&cfg);
    cfg.cb.on_incoming_call = &on_incoming_call;

    pjsua_media_config_default(&med_cfg);

    pjsua_logging_config_default(&log_cfg);
    log_cfg.msg_logging = PJ_TRUE;
    log_cfg.console_level = 4;

    status = pjsua_init(&cfg, &log_cfg, &med_cfg);
    if (status != PJ_SUCCESS)
    {
        printf("pjsua_init error\n");
        pjsua_destroy();
        return -1;
    }

    if (create_transport() != PJ_SUCCESS)
    {
        pjsua_destroy();
        return -1;
    }

    if (create_pools() != PJ_SUCCESS)
    {
        pj_caching_pool_destroy(&ch_pool);
        pjsua_destroy();
        return -1;
    }

    if (create_timer_heap() != PJ_SUCCESS)
    {
        pj_pool_release(main_pool);
        pj_caching_pool_destroy(&ch_pool);
        pjsua_destroy();
        return -1;
    }

    return PJ_SUCCESS;
}

static int create_transport()
{
    pj_status_t status;

    pjsua_transport_config_default(&t_cfg);
    t_cfg.port = 5061;
    status = pjsua_transport_create(PJSIP_TRANSPORT_UDP, &t_cfg, NULL);
    if (status != PJ_SUCCESS)
    {
        printf("pjsua_transport_create error\n");
    }

    return status;
}

static int create_pools()
{
    pj_caching_pool_init(&ch_pool, pj_pool_factory_get_default_policy(), 0);
    main_pool = pj_pool_create(&ch_pool.factory, "main", MAIN_POOL_SIZE, MAIN_POOL_SIZE, NULL);
    if (!main_pool)
    {
        printf("pj_pool_create error\n");
        return -1;
    }

    return PJ_SUCCESS;
}

static int create_timer_heap()
{
    pj_status_t status = pj_timer_heap_create(main_pool, 10, &t_heap);
    if (status != PJ_SUCCESS)
    {
        printf("pj_timer_heap_create error\n");
    }

    return status;
}

static int add_account(const char* sip_user, const char* sip_domain)
{
    pj_status_t status;
    char temp[MAIN_POOL_SIZE];

    pjsua_acc_config_default(&acc_cfg);

    pj_str_t id, reg_uri;
    pj_ansi_snprintf(temp, MAIN_POOL_SIZE, "sip:%s@%s", sip_user, sip_domain);
    pj_ansi_snprintf(temp, MAIN_POOL_SIZE, "sip:%s", sip_domain);
    pj_strdup2(main_pool, &id, temp);
    pj_strdup2(main_pool, &reg_uri, temp);

    acc_cfg.id = id;
    acc_cfg.reg_uri = reg_uri;
    
    pj_str_t realm, username;
    pj_strdup2(main_pool, &realm, sip_domain);
    pj_strdup2(main_pool, &username, sip_user);
    acc_cfg.cred_count = 1;
    acc_cfg.cred_info[0].realm = pj_str("*");
    acc_cfg.cred_info[0].scheme = pj_str("digest");
    acc_cfg.cred_info[0].username = username;
    acc_cfg.cred_info[0].data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
    acc_cfg.cred_info[0].data = pj_str(DEFAULT_PASSWD);
    acc_cfg.register_on_acc_add = PJ_FALSE;

    status = pjsua_acc_add(&acc_cfg, PJ_TRUE, &acc_id);
    if (status != PJ_SUCCESS)
    {
        printf("pjsua_acc_add error\n");
    }

    return status;
}

int start_answerphone(const char* sip_user, const char* sip_domain)
{
    pj_status_t status;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (init_answerphone() != PJ_SUCCESS)
    {
        return -1;
    }

    status = pjsua_start();
    if (status != PJ_SUCCESS)
    {
        printf("pjsua_start error\n");
        cleanup_resources();
        return -1;
    }

    if (add_account(sip_user, sip_domain) != PJ_SUCCESS)
    {
        cleanup_resources();
        return -1;
    }

    while (1)
    {
        pj_timer_heap_poll(t_heap, NULL);
    }

    pjsua_call_hangup_all();
    cleanup_resources();
    return PJ_SUCCESS;
}
