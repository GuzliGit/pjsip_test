#ifndef ANSWERPHONE_H
#define ANSWERPHONE_H

#define DEFAULT_PASSWD "passwd"
#define MAIN_POOL_SIZE 128
#define MAX_USERNAME_LEN 32
#define MAX_DOMAIN_LEN 64

int init_answerphone();

int start_answerphone(const char*, const char*);

#endif 