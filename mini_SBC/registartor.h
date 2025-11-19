#ifndef REGISTRATOR_H
#define REGISTRATOR_H

#include <pjsip.h>

#define REALM "sbc.local"
#define DEFAULT_PASS "passwd"
#define MAX_EXPECTED_CONTACTS 100

#define CONTACTS_POOL_SIZE 256

typedef struct contact_info
{
    pj_str_t name;
    pj_in_addr addr;
    pj_uint16_t port;
    pj_str_t password;
    pj_bool_t is_active;
} contact_info;


pj_status_t registrator_init(pj_pool_factory*);

pj_status_t try_register(pjsip_endpoint*, pjsip_rx_data*);

pj_status_t try_auth(pjsip_endpoint*, pjsip_rx_data*);

void registrator_destroy();

#endif