#include "answerphone.h"
#include <signal.h>
#include <pjsua-lib/pjsua.h>
#include <pjmedia/conference.h>

typedef enum response_mode
{
    CONTINUOUS_SIGNAL,
    FROM_WAV_SIGNAL,
    RBT_SIGNAL
} response_mode;

typedef struct dlg_info 
{
    pjsua_call_id call_id;
    response_mode call_mode;
    unsigned int duration;
    const char* filename;
    pj_pool_t* thread_pool;
} dlg_info;

static pj_mutex_t* mut;

static pj_caching_pool ch_pool;
static pj_pool_t* main_pool;
static pj_timer_heap_t* t_heap;

static pjsua_acc_id acc_id;

static pjsua_config cfg;
static pjsua_media_config med_cfg;
static pjsua_logging_config log_cfg;
static pjsua_transport_config t_cfg;
static pjsua_acc_config acc_cfg;

static int send_media(void*);
static int create_transport();
static int create_pools();
static int create_timer_heap();
static int add_account(const char*, const char*);

static void cleanup_resources()
{
    pj_mutex_destroy(mut);
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
    pj_status_t status;
    pjsua_call_id call_id = (pjsua_call_id)(long)entry->user_data;

    PJ_LOG(1, (__FILE__, "==Answer_timer_callback=="));
    status = pjsua_call_answer(call_id, 200, NULL, NULL);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pjsua_call_answer error (200)=="));
        return;
    }

    char* temp_pn = pj_pool_zalloc(main_pool, 16);
    snprintf(temp_pn, 16, "%dtp", call_id);
    pj_pool_t* thread_pool = pj_pool_create(&ch_pool.factory, temp_pn, THREAD_POOL_SIZE, THREAD_POOL_INC_SIZE, NULL);
    if (!thread_pool)
    {
        PJ_LOG(1, (__FILE__, "==pj_pool_create error=="));
        return;
    }

    dlg_info* cur_dlg_info = pj_pool_zalloc(thread_pool, sizeof(dlg_info));
    cur_dlg_info->call_id = call_id;
    cur_dlg_info->call_mode = CONTINUOUS_SIGNAL;
    cur_dlg_info->duration = 2000;
    cur_dlg_info->filename = DEFAULT_WAV_PATH;
    cur_dlg_info->thread_pool = thread_pool;
    
    pj_thread_t* thread;
    char* temp_tn = pj_pool_zalloc(main_pool, 16);
    snprintf(temp_tn, 16, "%dt", call_id);
    status = pj_thread_create(thread_pool, temp_tn, &send_media, (void*)cur_dlg_info, PJ_THREAD_DEFAULT_STACK_SIZE, 0, &thread);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pj_thread_create error=="));
        pj_pool_release(thread_pool);
        return;
    }
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

    //PJ_LOG(3, (__FILE__, "Call %d state=%.*s", call_id, (int)info.state_text.slen, info.state_text.ptr));

    status = pjsua_call_answer(call_id, 180, NULL, NULL);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pjsua_call_answer error (180)=="));
        return;
    }

    pj_timer_entry* timer = pj_pool_zalloc(main_pool, sizeof(pj_timer_entry));
    if (!timer)
    {
        PJ_LOG(1, (__FILE__, "==pj_pool_zalloc for timer error=="));
        return;
    }

    pj_timer_entry_init(timer, PJSUA_INVALID_ID, NULL, &answer_timer_callback);
    timer->user_data = (void*)(long)call_id;

    pj_time_val delay = {3, 100};
    status = pj_timer_heap_schedule(t_heap, timer, &delay);
    if (status != PJ_SUCCESS)
    {
        pjsua_call_hangup(call_id, 486, NULL, NULL);
        return;
    }
}

static int send_media(void* data)
{
    pj_mutex_lock(mut);
    dlg_info* cur_info = (dlg_info*)data;

    pj_status_t status;
    char* temp = pj_pool_zalloc(main_pool, 16);
    snprintf(temp, 16, "%dms", cur_info->call_id);

    pj_pool_t* media_session_pool = pj_pool_create(&ch_pool.factory, temp, MEDIA_POOL_SIZE, MEDIA_POOL_INC_SIZE, NULL);
    if (!media_session_pool)
    {
        PJ_LOG(1, (__FILE__, "==pj_pool_create error=="));
        pjsua_call_hangup(cur_info->call_id, 486, NULL, NULL);
        return -1;
    }

    pjmedia_port* media_port = pj_pool_zalloc(media_session_pool, sizeof(pjmedia_port));
    if (!media_port)
    {
        PJ_LOG(1, (__FILE__, "==pj_pool_zalloc for media_port error=="));
        pj_pool_release(media_session_pool);
        pjsua_call_hangup(cur_info->call_id, 486, NULL, NULL);
        return -1;
    }

    if (cur_info->call_mode == CONTINUOUS_SIGNAL || cur_info->call_mode == RBT_SIGNAL)
    {
        status = pjmedia_tonegen_create(media_session_pool, PJSUA_DEFAULT_CLOCK_RATE, 1, PJSUA_CALL_SEND_DTMF_DURATION_DEFAULT, 16, 0, &media_port);
        if (status != PJ_SUCCESS)
        {
            PJ_LOG(1, (__FILE__, "==pjmedia_tonegen_create error=="));
            pj_pool_release(media_session_pool);
            pjsua_call_hangup(cur_info->call_id, 486, NULL, NULL);
            return -1;
        }
    }
    else if (cur_info->call_mode == FROM_WAV_SIGNAL)
    {
        status = pjmedia_wav_player_port_create(media_session_pool, cur_info->filename, 0, 0, 0, &media_port);
        if (status != PJ_SUCCESS)
        {
            PJ_LOG(1, (__FILE__, "==pjmedia_wav_player_port_create error=="));
            pj_pool_release(media_session_pool);
            pjsua_call_hangup(cur_info->call_id, 486, NULL, NULL);
            return -1;
        }
    }
    else
    {
        PJ_LOG(1, (__FILE__, "==Can't find such response mode: %d==", cur_info->call_mode));
        pj_pool_release(media_session_pool);
        pjsua_call_hangup(cur_info->call_id, 486, NULL, NULL);
        return -1;
    }

    pjsua_conf_port_id conf_slot;
    status = pjsua_conf_add_port(media_session_pool, media_port, &conf_slot);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pjsua_conf_add_port error=="));
        pj_pool_release(media_session_pool);
        pjsua_call_hangup(cur_info->call_id, 486, NULL, NULL);
        return -1;
    }

    pjsua_call_info call_info;
    status = pjsua_call_get_info(cur_info->call_id, &call_info);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pjsua_call_get_info error=="));
        pjsua_conf_remove_port(conf_slot);
        pj_pool_release(media_session_pool);
        pjsua_call_hangup(cur_info->call_id, 486, NULL, NULL);
        return -1;
    }

    status = pjsua_conf_connect(conf_slot, call_info.conf_slot);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pjsua_conf_connect error=="));
        pjsua_conf_remove_port(conf_slot);
        pj_pool_release(media_session_pool);
        pjsua_call_hangup(cur_info->call_id, 486, NULL, NULL);
        return -1;
    }
    pj_mutex_unlock(mut);

    switch (cur_info->call_mode)
    {
        case FROM_WAV_SIGNAL:
        {
            pj_thread_sleep(cur_info->duration);
            break;
        }

        case CONTINUOUS_SIGNAL:
        case RBT_SIGNAL: 
        {
            PJ_LOG(3, (__FILE__, "Tone 425Hz started for call %d | call_mode=%d, conf_slot=%d", cur_info->call_id, cur_info->call_mode, conf_slot));

            pjmedia_tone_desc tone;
            tone.freq1 = 425;
            tone.freq2 = 0;
            tone.off_msec = cur_info->call_mode == CONTINUOUS_SIGNAL ? 0 : 4000;
            tone.on_msec = 1000;

            status = pjmedia_tonegen_play(media_port, 1, &tone, PJMEDIA_TONEGEN_LOOP);
            if (status == PJ_SUCCESS)
            {
                pj_thread_sleep(cur_info->duration);
            }
            break;
        }
    }

    pj_mutex_lock(mut);
    status = pjsua_call_get_info(cur_info->call_id, &call_info);
    if (status == PJ_SUCCESS)
    {
        pjsua_conf_disconnect(conf_slot, call_info.conf_slot);
        pjsua_conf_remove_port(conf_slot);
        pjsua_call_hangup(cur_info->call_id, 486, NULL, NULL);
    }
    else
    {
        pjsua_conf_remove_port(conf_slot);
    }
    pj_pool_release(media_session_pool);
    pj_pool_release(cur_info->thread_pool);
    PJ_LOG(1, (__FILE__, "==ACTIVE_PORTS=%d==", pjsua_conf_get_active_ports()));
    pj_mutex_unlock(mut);

    return PJ_SUCCESS;
}

int init_answerphone()
{
    pj_status_t status;
    
    status = pjsua_create();
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pjsua_create error=="));
        return -1;
    }

    pjsua_config_default(&cfg);
    cfg.max_calls = MAX_CALLS;
    cfg.cb.on_incoming_call = &on_incoming_call;

    pjsua_media_config_default(&med_cfg);
    med_cfg.max_media_ports = MAX_CALLS + 2;

    pjsua_logging_config_default(&log_cfg);
    log_cfg.msg_logging = PJ_TRUE;
    log_cfg.console_level = 4;

    status = pjsua_init(&cfg, &log_cfg, &med_cfg);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pjsua_init error=="));
        pjsua_destroy();
        return -1;
    }

    PJ_LOG(1, (__FILE__, "==max_conf_ports=%d==", pjsua_conf_get_max_ports()));
    status = pjsua_set_null_snd_dev();
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pjsua_set_null_snd_dev error=="));
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

    status = pj_mutex_create(main_pool, "mutex", PJ_MUTEX_SIMPLE, &mut);
    if (status != PJ_SUCCESS)
    {
        pj_pool_release(main_pool);
        pj_caching_pool_destroy(&ch_pool);
        pjsua_destroy();
        return -1;
    }

    if (create_timer_heap() != PJ_SUCCESS)
    {
        pj_mutex_destroy(mut);
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
        PJ_LOG(1, (__FILE__, "==pjsua_transport_create error=="));
    }

    return status;
}

static int create_pools()
{
    pj_caching_pool_init(&ch_pool, pj_pool_factory_get_default_policy(), 0);
    main_pool = pj_pool_create(&ch_pool.factory, "main", MAIN_POOL_SIZE, MAIN_POOL_SIZE, NULL);
    if (!main_pool)
    {
        PJ_LOG(1, (__FILE__, "==pj_pool_create error=="));
        return -1;
    }

    return PJ_SUCCESS;
}

static int create_timer_heap()
{
    pj_status_t status = pj_timer_heap_create(main_pool, 10, &t_heap);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pj_timer_heap_create error=="));
    }

    return status;
}

static int add_account(const char* sip_user, const char* sip_domain)
{
    pj_status_t status;
    pjsua_acc_config_default(&acc_cfg);

    char* id = pj_pool_zalloc(main_pool, MAIN_POOL_SIZE);
    char* reg_uri = pj_pool_zalloc(main_pool, MAIN_POOL_SIZE);
    char* realm = pj_pool_zalloc(main_pool, MAX_DOMAIN_LEN); 
    char* username = pj_pool_zalloc(main_pool, MAX_USERNAME_LEN);
    
    snprintf(id, MAIN_POOL_SIZE, "sip:%s@%s", sip_user, sip_domain);
    snprintf(reg_uri, MAIN_POOL_SIZE, "sip:%s", sip_domain);
    snprintf(realm, MAX_DOMAIN_LEN, "%s", sip_domain);
    snprintf(username, MAX_USERNAME_LEN, "%s", sip_user);
    
    acc_cfg.id = pj_str(id);
    acc_cfg.reg_uri = pj_str(reg_uri);
    acc_cfg.cred_count = 1;
    acc_cfg.cred_info[0].realm = pj_str("*");
    acc_cfg.cred_info[0].scheme = pj_str("digest");
    acc_cfg.cred_info[0].username = pj_str(username);
    acc_cfg.cred_info[0].data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
    acc_cfg.cred_info[0].data = pj_str(DEFAULT_PASSWD);
    acc_cfg.register_on_acc_add = PJ_FALSE;

    status = pjsua_acc_add(&acc_cfg, PJ_TRUE, &acc_id);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pjsua_acc_add error=="));
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
        PJ_LOG(1, (__FILE__, "==pjsua_start error=="));
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
