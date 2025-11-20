#include "registartor.h"

#include <pj/hash.h>
#include <pj/os.h>

static pj_pool_t* contacts_pool;
static pj_hash_table_t* contacts;
static pj_mutex_t* contacts_mut;
static pj_thread_t* observer;
static volatile pj_bool_t is_end = PJ_FALSE;


static contact_info* get_contact(pj_str_t* key);
static int observe_contacts(void*);

pj_status_t registrator_init(pj_pool_factory* factory)
{
    contacts_pool = pj_pool_create(factory, "contacts_pool", CONTACTS_POOL_SIZE, CONTACTS_POOL_SIZE, NULL);
    if (!contacts_pool)
    {
        PJ_LOG(2, (__FILE__, "pj_pool_create[contacts_pool] error"));
        return -1;
    }

    contacts = pj_hash_create(contacts_pool, MAX_EXPECTED_CONTACTS);
    if (!contacts)
    {
        PJ_LOG(2, (__FILE__, "pj_hash_create[contacts] error"));
        return -1; 
    }

    pj_status_t status = pj_mutex_create(contacts_pool, "contacts_tab_mutex", PJ_MUTEX_DEFAULT, &contacts_mut);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "pj_mutex_create error"));
        return status; 
    }

    status = pj_thread_create(contacts_pool, "observer_thread", &observe_contacts, NULL, PJ_THREAD_DEFAULT_STACK_SIZE, 0, &observer);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "pj_thread_create error"));
        return status; 
    }

    return PJ_SUCCESS;
}

pj_status_t add_contact(pj_str_t* name, pj_in_addr* addr, pj_uint16_t port, pj_str_t* password)
{
    contact_info* temp = get_contact(name);
    if (temp)
    {
        PJ_LOG(2, (__FILE__, "Contact is already registered [%.*s]", (int) name->slen, name->ptr));
        return -1;
    }

    contact_info* info = pj_pool_zalloc(contacts_pool, sizeof(contact_info));
    info->name = *name;
    info->addr = *addr;
    info->port = port;
    info->password = *password;
    info->is_active_reg = PJ_FALSE;
    info->expires = 0;
    info->lifetime = 0;
    info->reg_timestamp.sec = 0;
    info->reg_timestamp.msec = 0;

    pj_mutex_lock(contacts_mut);
    pj_hash_set(contacts_pool, contacts, name->ptr, PJ_HASH_KEY_STRING, 0, info);
    pj_mutex_unlock(contacts_mut);
    return PJ_SUCCESS;
}

pj_status_t try_register(pjsip_endpoint* endpt, pjsip_rx_data* rdata)
{
    pjsip_tx_data* tdata;
    pjsip_response_addr resp_addr;
    pj_status_t status;

    pjsip_from_hdr* from_hdr = pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_FROM, NULL);
    pjsip_sip_uri* sip_uri = (pjsip_sip_uri*) pjsip_uri_get_uri(from_hdr->uri);
    contact_info* contact = get_contact(&sip_uri->user);
    if (contact && contact->is_active_reg == PJ_TRUE)
    {
        status = pjsip_endpt_create_response(endpt, rdata, 200, NULL, &tdata);
        if (status != PJ_SUCCESS)
        {
            PJ_LOG(2, (__FILE__, "pjsip_endpt_create_response error"));
            return status;
        }
        pjsip_contact_hdr* con_hdr = pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTACT, NULL);
        
        char uri_buf[128];
        pj_ansi_snprintf(uri_buf, 64, "sip:%.*s@%s:%d", (int) contact->name.slen, contact->name.ptr, pj_inet_ntoa(contact->addr), contact->port);
        if (!con_hdr)
        {
            con_hdr = pjsip_contact_hdr_create(tdata->pool);
            if (!con_hdr)
            {
                PJ_LOG(2, (__FILE__, "pjsip_contact_hdr_create error"));
                return -1;
            }
            con_hdr->uri = pjsip_parse_uri(tdata->pool, uri_buf, pj_ansi_strlen(uri_buf), PJSIP_PARSE_URI_AS_NAMEADDR);
            con_hdr->expires = contact->expires;

            pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*) con_hdr);
        }
        else
        {
            pj_mutex_lock(contacts_mut);
            pj_gettimeofday(&contact->reg_timestamp);
            contact->lifetime = con_hdr->expires;
            contact->expires = con_hdr->expires;
            pj_mutex_unlock(contacts_mut);
        }

        status = pjsip_get_response_addr(tdata->pool, rdata, &resp_addr);
        if (status != 0)
        {
            PJ_LOG(2, (__FILE__, "pjsip_get_response_addr error"));
            return status;
        }
        pjsip_endpt_send_response(endpt, &resp_addr, tdata, NULL, NULL);
        if (status != PJ_SUCCESS)
        {
            PJ_LOG(2, (__FILE__, "pjsip_endpt_send_response error"));
            return status;
        }
        return PJ_SUCCESS;
    }

    status = pjsip_endpt_create_response(endpt, rdata, 401, NULL, &tdata);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "pjsip_endpt_create_response[401] error"));
        return status;
    }

    pjsip_www_authenticate_hdr* hdr = pjsip_www_authenticate_hdr_create(tdata->pool);
    hdr->scheme = pj_str("Digest");
    hdr->challenge.digest.realm = pj_str(REALM);
    hdr->challenge.digest.algorithm = pj_str("MD5");
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*) hdr);

    status = pjsip_get_response_addr(tdata->pool, rdata, &resp_addr);
    if (status != 0)
    {
        PJ_LOG(2, (__FILE__, "pjsip_get_response_addr error"));
        return status;
    }

    status = pjsip_endpt_send_response(endpt, &resp_addr, tdata, NULL, NULL);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "pjsip_endpt_send_response error"));        
    }
    return status;
}

pj_status_t try_auth(pjsip_endpoint* endpt, pjsip_rx_data* rdata)
{
    pjsip_authorization_hdr* auth_hdr = pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_AUTHORIZATION, NULL);
    if (!auth_hdr)
    {
        PJ_LOG(2, (__FILE__, "Can't find authorization hdr in recv msg"));
        return -1;
    }

    contact_info* contact = get_contact(&auth_hdr->credential.digest.username);
    if (!contact)
    {
        PJ_LOG(2, (__FILE__, "Can't find contact with such name"));
        return -1;
    }

    pjsip_cred_info cred;
    cred.username = contact->name;
    cred.realm = pj_str(REALM);
    cred.data = contact->password;
    cred.data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;

    char buf[33];
    pj_str_t expected_response;
    expected_response.ptr = buf;
    expected_response.slen = 32;
    pjsip_auth_create_digest2(&expected_response, &auth_hdr->credential.digest.nonce, &auth_hdr->credential.digest.nc,
                              &auth_hdr->credential.digest.cnonce, &auth_hdr->credential.digest.qop, &auth_hdr->credential.digest.uri,
                              &auth_hdr->credential.digest.realm, &cred, &rdata->msg_info.msg->line.req.method.name,
                              PJSIP_CRED_DATA_DIGEST);

    pjsip_tx_data* tdata;
    pjsip_response_addr resp_addr;
    pj_status_t status;
    if (pj_strcmp(&auth_hdr->credential.digest.response, &expected_response) != 0)
    {
        status = pjsip_endpt_create_response(endpt, rdata, 403, NULL, &tdata);
        pj_mutex_lock(contacts_mut);
        contact->is_active_reg = PJ_FALSE;
        PJ_LOG(2, (__FILE__, "Contact [%.*s] now has inactive registration", (int) contact->name.slen, contact->name.ptr));
        pj_mutex_unlock(contacts_mut);
    }
    else 
    {
        status = pjsip_endpt_create_response(endpt, rdata, 200, NULL, &tdata);
        pj_mutex_lock(contacts_mut);
        contact->is_active_reg = PJ_TRUE;
        pj_gettimeofday(&contact->reg_timestamp);
        PJ_LOG(2, (__FILE__, "Contact [%.*s] now has active registration", (int) contact->name.slen, contact->name.ptr));
        pj_mutex_unlock(contacts_mut);
    }

    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "pjsip_endpt_create_response error"));
        goto _exit;
    }

    status = pjsip_get_response_addr(tdata->pool, rdata, &resp_addr);
    if (status != 0)
    {
        PJ_LOG(2, (__FILE__, "pjsip_get_response_addr error"));
        goto _exit;
    }

    pjsip_contact_hdr* con_hdr = pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTACT, NULL);
    if (!con_hdr)
    {
        pj_pool_release(tdata->pool);
        pjsip_endpt_create_response(endpt, rdata, 407, NULL, &tdata);
        pjsip_endpt_send_response(endpt, &resp_addr, tdata, NULL, NULL);
        status = -1;
        goto _exit;
    }

    pj_mutex_lock(contacts_mut);
    contact->lifetime = con_hdr->expires;
    con_hdr->expires = contact->expires;
    pj_mutex_unlock(contacts_mut);

    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*) con_hdr);

    status = pjsip_endpt_send_response(endpt, &resp_addr, tdata, NULL, NULL);
    if (status != PJ_SUCCESS)
    {
        PJ_LOG(2, (__FILE__, "pjsip_endpt_send_response error"));    
        goto _exit;
    }

    return PJ_SUCCESS;

_exit:
    pj_mutex_lock(contacts_mut);
    contact->is_active_reg = PJ_FALSE;
    pj_mutex_unlock(contacts_mut);
    return status;
}

void registrator_destroy()
{
    is_end = PJ_TRUE;

    if (observer)
    {
        pj_thread_join(observer);
        pj_thread_destroy(observer);
    }
    if (contacts_mut)
    {
        pj_mutex_destroy(contacts_mut);
    }
    if (contacts_pool)
    {
        pj_pool_release(contacts_pool);
    }
    PJ_LOG(2, (__FILE__, "Registrator was destoyed successfully"));
}

static contact_info* get_contact(pj_str_t* key)
{
    pj_mutex_lock(contacts_mut);
    contact_info* contact = pj_hash_get(contacts, key->ptr, key->slen, NULL);
    pj_mutex_unlock(contacts_mut);
    if (!contact)
    {
        return NULL;
    }

    return contact;
}

static int observe_contacts(void*)
{
    pj_hash_iterator_t it_buf;
    pj_hash_iterator_t* it;
    contact_info* contact;
    pj_time_val cur_time;
    
    while (!is_end)
    {
        it = pj_hash_first(contacts, &it_buf);
        while (it)
        {
            pj_mutex_lock(contacts_mut);
            contact = pj_hash_this(contacts, it);
            if (contact && contact->is_active_reg == PJ_TRUE)
            {
                pj_gettimeofday(&cur_time);
                PJ_TIME_VAL_SUB(cur_time, contact->reg_timestamp);
                if (cur_time.sec >= contact->lifetime)
                {
                    contact->is_active_reg = PJ_FALSE;
                    contact->expires = 0;
                    PJ_LOG(2, (__FILE__, "Contact [%.*s] now has inactive registration", (int) contact->name.slen, contact->name.ptr));
                }
                else
                {
                    contact->expires = contact->lifetime - cur_time.sec;
                }
            }
            pj_mutex_unlock(contacts_mut);

            it = pj_hash_next(contacts, it);
        }
        it = NULL;
        pj_thread_sleep(1000);
    }
}
