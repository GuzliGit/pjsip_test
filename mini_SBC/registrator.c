#include "registartor.h"

#include <pj/hash.h>

static pj_pool_t* contacts_pool;
static pj_hash_table_t* contacts;


static void add_contact(pj_str_t*, pj_in_addr*, pj_uint16_t, pj_str_t*);

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

    pj_str_t name = pj_str("tester");
    pj_str_t addr_str = pj_str("127.0.0.1");
    pj_in_addr addr;
    pj_inet_aton(&addr_str, &addr);
    pj_uint16_t port = 5063;
    pj_str_t password = pj_str(DEFAULT_PASS);
    add_contact(&name, &addr, port, &password);

    return PJ_SUCCESS;
}

static void add_contact(pj_str_t* name, pj_in_addr* addr, pj_uint16_t port, pj_str_t* password)
{
    contact_info* info = pj_pool_zalloc(contacts_pool, sizeof(contact_info));
    info->name = *name;
    info->addr = *addr;
    info->port = port;
    info->password = *password;
    info->is_active = PJ_FALSE;

    pj_hash_set(contacts_pool, contacts, name->ptr, PJ_HASH_KEY_STRING, 0, info);
}

pj_status_t try_register(pjsip_endpoint* endpt, pjsip_rx_data* rdata)
{
    pjsip_tx_data* tdata;
    pj_status_t status;
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

    pjsip_response_addr resp_addr;
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

    contact_info* contact = pj_hash_get(contacts, &auth_hdr->name, PJ_HASH_KEY_STRING, NULL);
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

    // pj_str_t expected_response;
    // pjsip_auth_create_digest2();

    // pjsip_tx_data* tdata;
    // pj_status_t status;
    // if (pj_strcmp(&contact->password, password) != 0)
    // {
    //     status = pjsip_endpt_create_response(endpt, rdata, 403, NULL, &tdata);
    //     contact->is_active = PJ_FALSE;
    // }
    // else 
    // {
    //     status = pjsip_endpt_create_response(endpt, rdata, 200, NULL, &tdata);
    //     contact->is_active = PJ_TRUE;
    // }

    // if (status != PJ_SUCCESS)
    // {
    //     PJ_LOG(2, (__FILE__, "pjsip_endpt_create_response error"));
    //     return status;
    // }

    // pjsip_response_addr resp_addr;
    // status = pjsip_get_response_addr(tdata->pool, rdata, &resp_addr);
    // if (status != 0)
    // {
    //     PJ_LOG(2, (__FILE__, "pjsip_get_response_addr error"));
    //     return status;
    // }

    // status = pjsip_endpt_send_response(endpt, &resp_addr, tdata, NULL, NULL);
    // if (status != PJ_SUCCESS)
    // {
    //     PJ_LOG(2, (__FILE__, "pjsip_endpt_send_response error"));        
    // }

    // return PJ_SUCCESS;
}

void registrator_destroy()
{
    if (contacts_pool)
    {
        pj_pool_release(contacts_pool);
    }
    PJ_LOG(2, (__FILE__, "Registrator was destoyed successfully"));
}
