#include "answerphone.h"
#include <signal.h>
#include <pjsua-lib/pjsua.h>
#include <pjmedia/conference.h>

typedef enum response_mode
{
    CONTINUOUS_SIGNAL,
    FROM_WAV_SIGNAL,
    RBT_SIGNAL,
    MODE_COUNT
} response_mode;

typedef struct slot_info
{
    pjmedia_port* port;
    pjsua_conf_port_id conf_slot;
    char is_enabled;
} slot_info;

static pj_caching_pool ch_pool;
static pj_pool_t* main_pool;
static pj_pool_t* media_session_pool;
static pj_timer_heap_t* t_heap;
static pj_pool_t* timers_pools[2];

static pjsua_acc_id acc_id;

static pjsua_config cfg;
static pjsua_media_config med_cfg;
static pjsua_logging_config log_cfg;
static pjsua_transport_config t_cfg;
static pjsua_acc_config acc_cfg;

static slot_info* slots;

static pj_time_val call_timestamp[PJSUA_MAX_CALLS];
static pj_mutex_t* update_mut[UPDATERS_COUNT];
static pj_thread_t* updaters[UPDATERS_COUNT];

static volatile char is_cleanup = 0;
static volatile char active_timers_pool = 0;

static int enable_conf_slot(response_mode, const char*);
static int create_transport();
static int create_pools();
static int create_timer_heap();
static int add_account(const char*, const char*);
static int create_updaters();

static void cleanup_resources()
{
    for (int i = 0; i < UPDATERS_COUNT; i++)
    {   
        if (updaters[i])
        {
            pj_thread_join(updaters[i]);
            pj_thread_destroy(updaters[i]);
        }

        if (update_mut[i])
            pj_mutex_destroy(update_mut[i]);
    }

    for (int i = 0; i < MODE_COUNT; i++)
    {
        if (!slots[i].is_enabled)
            continue;
        
        pjsua_conf_remove_port(slots[i].conf_slot);
    }

    pj_timer_heap_destroy(t_heap);
    pjsua_destroy();
}

static void signal_handler()
{
    is_cleanup = 1;
}

static void answer_timer_callback(pj_timer_heap_t* timer_heap, pj_timer_entry* entry)
{
    pj_status_t status;
    pjsua_call_id call_id = (pjsua_call_id)((long)entry->user_data);
    
    status = pjsua_call_answer(call_id, 200, NULL, NULL);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pjsua_call_answer error(200)=="));
        pjsua_call_hangup(call_id, 500, NULL, NULL);
        return;
    }
    
    pjsua_call_info call_info;
    status = pjsua_call_get_info(call_id, &call_info);
    if (status != PJ_SUCCESS || call_info.state == PJSIP_INV_STATE_DISCONNECTED)
    {
        PJ_LOG(1, (__FILE__, "==pjsua_call_get_info error=="));
        pjsua_call_hangup(call_id, 500, NULL, NULL);
        return;
    }

    int call_mode = (int)(pj_hash_calc(0, (void*)call_info.remote_contact.ptr, PJ_HASH_KEY_STRING) % MODE_COUNT);
    switch (call_mode)
    {
        case CONTINUOUS_SIGNAL:
            if (enable_conf_slot(CONTINUOUS_SIGNAL, NULL) != PJ_SUCCESS)
            {
                PJ_LOG(1, (__FILE__, "==enable_conf_slot error(CONTINUOUS_SIGNAL)=="));
                pjsua_call_hangup(call_id, 500, NULL, NULL);
                return;
            }
            break;
        
        case RBT_SIGNAL:
            if (enable_conf_slot(RBT_SIGNAL, NULL) != PJ_SUCCESS)
            {
                PJ_LOG(1, (__FILE__, "==enable_conf_slot error(RBT_SIGNAL)=="));
                pjsua_call_hangup(call_id, 500, NULL, NULL);
                return;
            }
            break;

        case FROM_WAV_SIGNAL:
            if (enable_conf_slot(FROM_WAV_SIGNAL, DEFAULT_WAV_PATH) != PJ_SUCCESS)
            {
                PJ_LOG(1, (__FILE__, "==enable_conf_slot error(FROM_WAV_SIGNAL)=="));
                pjsua_call_hangup(call_id, 500, NULL, NULL);
                return;
            }
            break;

        default:
            PJ_LOG(1, (__FILE__, "==can't find such response mode=="));
            pjsua_call_hangup(call_id, 500, NULL, NULL);
            return;
    }

    status = pjsua_conf_connect(slots[call_mode].conf_slot, call_info.conf_slot);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pjsua_conf_connect error=="));
        pjsua_call_hangup(call_id, 500, NULL, NULL);
        return;
    }
}

static int enable_conf_slot(response_mode mode, const char* filename)
{
    if (slots[mode].is_enabled)
    {
        return PJ_SUCCESS;
    }

    pj_status_t status;
    pjmedia_port* media_port = NULL;
    switch (mode)
    {
        case CONTINUOUS_SIGNAL:
        case RBT_SIGNAL:
            {
                status = pjmedia_tonegen_create(media_session_pool, PJSUA_DEFAULT_CLOCK_RATE, 1, PJSUA_CALL_SEND_DTMF_DURATION_DEFAULT, 16, 0, &media_port);
                if (status != PJ_SUCCESS)
                {
                    PJ_LOG(1, (__FILE__, "==pjmedia_tonegen_create error=="));
                    return -1;
                }

                pjmedia_tone_desc* tone = pj_pool_zalloc(media_session_pool, sizeof(pjmedia_tone_desc));
                tone->freq1 = 425;
                tone->freq2 = 0;
                tone->off_msec = mode == CONTINUOUS_SIGNAL ? 0 : 2000;
                tone->on_msec = 1000;

                status = pjmedia_tonegen_play(media_port, 1, tone, PJMEDIA_TONEGEN_LOOP);
                if (status != PJ_SUCCESS)
                {
                    PJ_LOG(1, (__FILE__, "==pjmedia_tonegen_play error=="));
                    pjmedia_tonegen_stop(media_port);
                    return -1;
                }
                break;
            }
        case FROM_WAV_SIGNAL:
            {
                status = pjmedia_wav_player_port_create(media_session_pool, filename, 0, 0, 0, &media_port);
                if (status != PJ_SUCCESS)
                {
                    PJ_LOG(1, (__FILE__, "==pjmedia_wav_player_port_create error=="));
                    return -1;
                }
                break;
            }
    }
    slots[mode].port = media_port;

    status = pjsua_conf_add_port(media_session_pool, media_port, &slots[mode].conf_slot);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pjsua_conf_add_port error=="));
        return -1;
    }
    slots[mode].is_enabled = 1;

    return PJ_SUCCESS;
}

static void on_incoming_call(pjsua_acc_id acc_id, pjsua_call_id call_id, pjsip_rx_data* rdata)
{
    pj_status_t status;
    pjsua_call_info info;
    pj_time_val delay = {1, 0};

    PJ_UNUSED_ARG(acc_id);
    PJ_UNUSED_ARG(rdata);

    if (pj_pool_get_used_size(timers_pools[active_timers_pool]) >= TIMERS_POOL_SIZE * 0.9)
    {
        active_timers_pool = active_timers_pool == 0 ? 1 : 0; 
        pj_pool_reset(timers_pools[active_timers_pool]);
    }

    status = pjsua_call_get_info(call_id, &info);
    if (status != PJ_SUCCESS)
    {
        pjsua_call_hangup(call_id, 486, NULL, NULL);
        return;
    }

    status = pjsua_call_answer(call_id, 180, NULL, NULL);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pjsua_call_answer error (180)=="));
        pjsua_call_hangup(call_id, 500, NULL, NULL);
        return;
    }

    pj_timer_entry* timer = pj_pool_zalloc(timers_pools[active_timers_pool], sizeof(pj_timer_entry));
    if (!timer)
    {
        PJ_LOG(1, (__FILE__, "==pj_pool_zalloc for timer error=="));
        pjsua_call_hangup(call_id, 500, NULL, NULL);
        return;
    }
    
    pj_timer_entry_init(timer, PJSUA_INVALID_ID, (void*)(long)call_id, &answer_timer_callback);
    
    status = pj_timer_heap_schedule(t_heap, timer, &delay);
    if (status != PJ_SUCCESS)
    {
        pjsua_call_hangup(call_id, 500, NULL, NULL);
        return;
    }
}

static void on_call_state(pjsua_call_id call_id, pjsip_event* e)
{
    PJ_UNUSED_ARG(e);

    pj_status_t status;
    pjsua_call_info call_info;
    status = pjsua_call_get_info(call_id, &call_info);

    if (status != PJ_SUCCESS)
    {
        return;
    }
    
    pj_time_val cur_time = {-1, -1};
    int thread_to_lock = call_id % UPDATERS_COUNT;

    if (call_info.state == PJSIP_INV_STATE_EARLY || call_info.state == PJSIP_INV_STATE_CONFIRMED)
    {
        pj_gettimeofday(&cur_time);

        pj_mutex_lock(update_mut[thread_to_lock]);
        call_timestamp[call_id] = cur_time;
        pj_mutex_unlock(update_mut[thread_to_lock]);
    }
    else if (call_info.state == PJSIP_INV_STATE_DISCONNECTED)
    {
        pj_mutex_lock(update_mut[thread_to_lock]);
        call_timestamp[call_id] = cur_time;
        pj_mutex_unlock(update_mut[thread_to_lock]);
    }
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
    cfg.max_calls = PJSUA_MAX_CALLS;
    cfg.cb.on_incoming_call = &on_incoming_call;
    cfg.cb.on_call_state = &on_call_state;

    pjsua_media_config_default(&med_cfg);
    med_cfg.max_media_ports = PJSUA_MAX_CONF_PORTS;

    pjsua_logging_config_default(&log_cfg);
    log_cfg.msg_logging = PJ_TRUE;
    log_cfg.console_level = 2;

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

    if (create_timer_heap() != PJ_SUCCESS)
    {
        pj_pool_release(timers_pools[0]);
        pj_pool_release(timers_pools[1]);
        pj_pool_release(media_session_pool);
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
        PJ_LOG(1, (__FILE__, "==pj_pool_create error(main_pool)=="));
        return -1;
    }

    media_session_pool = pj_pool_create(&ch_pool.factory, "media_session", MEDIA_POOL_SIZE, MEDIA_POOL_INC_SIZE, NULL);
    if (!media_session_pool)
    {
        PJ_LOG(1, (__FILE__, "==pj_pool_create error(media_session_pool)=="));
        return -1;
    }

    timers_pools[0] = pj_pool_create(&ch_pool.factory, "timers_pool", TIMERS_POOL_SIZE, TIMERS_POOL_SIZE, NULL);
    if (!timers_pools[0])
    {
        PJ_LOG(1, (__FILE__, "==pj_pool_create error(timers_pool)=="));
        return -1;
    }

    timers_pools[1] = pj_pool_create(&ch_pool.factory, "timers_pool", TIMERS_POOL_SIZE, TIMERS_POOL_SIZE, NULL);
    if (!timers_pools[1])
    {
        PJ_LOG(1, (__FILE__, "==pj_pool_create error(timers_pool)=="));
        return -1;
    }

    return PJ_SUCCESS;
}

static int create_timer_heap()
{
    pj_status_t status = pj_timer_heap_create(main_pool, PJSUA_MAX_CALLS, &t_heap);
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

    char* id = pj_pool_zalloc(main_pool, MAX_ID_LEN);
    char* reg_uri = pj_pool_zalloc(main_pool, MAX_REG_URI_LEN);
    char* username = pj_pool_zalloc(main_pool, MAX_USERNAME_LEN);
    
    snprintf(id, MAX_ID_LEN, "sip:%s@%s", sip_user, sip_domain);
    snprintf(reg_uri, MAX_REG_URI_LEN, "sip:%s", sip_domain);
    snprintf(username, MAX_USERNAME_LEN, "%s", sip_user);
    
    acc_cfg.id = pj_str(id);
    acc_cfg.reg_uri = pj_str(reg_uri);
    acc_cfg.cred_count = 1;
    acc_cfg.cred_info[0].realm = pj_str("*");
    acc_cfg.cred_info[0].scheme = pj_str("digest");
    acc_cfg.cred_info[0].username = pj_str(username);
    acc_cfg.cred_info[0].data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
    acc_cfg.cred_info[0].data = pj_str(DEFAULT_PASSWD);
    //acc_cfg.register_on_acc_add = PJ_FALSE;

    status = pjsua_acc_add(&acc_cfg, PJ_TRUE, &acc_id);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(1, (__FILE__, "==pjsua_acc_add error=="));
    }

    return status;
}

static int update_calls_status(void* data)
{
    int tid = *(int*)data;
    pj_status_t status;
    pj_time_val result_time;

    while (!is_cleanup)
    {
        for (int i = tid; i < PJSUA_MAX_CALLS; i+=UPDATERS_COUNT)
        {
            pj_gettimeofday(&result_time);
            
            pj_mutex_lock(update_mut[tid]);
            if (call_timestamp[i].sec == -1)
            {
                pj_mutex_unlock(update_mut[tid]);
                continue;
            }
            PJ_TIME_VAL_SUB(result_time, call_timestamp[i]);
            pj_mutex_unlock(update_mut[tid]);
            
            if (result_time.sec >= MAX_ANSWER_DURATION_SEC)
            {
                pjsua_call_hangup(i, 500, NULL, NULL);
            }
        }

        pj_thread_sleep(1000);
    }
    
    return 0;
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

    slots = pj_pool_zalloc(media_session_pool, sizeof(slot_info) * MODE_COUNT);
    if (!slots)
    {
        PJ_LOG(1, (__FILE__, "==pj_pool_zalloc error(slots)=="));
        cleanup_resources();
        return -1;
    }

    if (create_updaters() != PJ_SUCCESS)
    {
        cleanup_resources();
        return -1;
    }

    if (add_account(sip_user, sip_domain) != PJ_SUCCESS)
    {
        cleanup_resources();
        return -1;
    }

    pj_time_val delay = {0, 10};
    while (!is_cleanup)
    {
        pj_timer_heap_poll(t_heap, NULL);
        pjsip_endpt_handle_events(pjsua_get_pjsip_endpt(), &delay);
        PJ_LOG(1, (__FILE__, "==TIMERS POOL[1] SIZE: %ld==", pj_pool_get_used_size(timers_pools[0])));
        PJ_LOG(1, (__FILE__, "==TIMERS POOL[2] SIZE: %ld==", pj_pool_get_used_size(timers_pools[1])));
        pj_thread_sleep(10);
    }

    pjsua_call_hangup_all();
    cleanup_resources();
    return PJ_SUCCESS;
}

static int create_updaters()
{
    pj_status_t status;
    for (int i = 0; i < UPDATERS_COUNT; i++)
    {
        status = pj_mutex_create(media_session_pool, "upd_mut", PJ_MUTEX_DEFAULT, &update_mut[i]);
        if (status != PJ_SUCCESS)
        {
            PJ_LOG(1, (__FILE__, "==pj_mutex_create error=="));
            return -1;
        }
    }
    
    for (int i = 0; i < UPDATERS_COUNT; i++)
    {
        int* tid = pj_pool_zalloc(media_session_pool, sizeof(int)); 
        if (!tid)
        {
            PJ_LOG(1, (__FILE__, "==pj_pool_zalloc error(tid)=="));
            return -1;
        }

        *tid = i;
        status = pj_thread_create(media_session_pool, "updater", &update_calls_status, (void*)tid, PJ_THREAD_DEFAULT_STACK_SIZE, 0, &updaters[i]);
        if (status != PJ_SUCCESS)
        {
            PJ_LOG(1, (__FILE__, "==pj_thread_create error(updater)=="));
            return -1;
        }
    }

    for (int i = 0; i < PJSUA_MAX_CALLS; i++)
    {
        call_timestamp[i].sec = -1;
        call_timestamp[i].msec = -1;
    }

    return status;
}

