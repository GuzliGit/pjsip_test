#ifndef ANSWERPHONE_H
#define ANSWERPHONE_H

#define MAIN_POOL_SIZE 256
#define MEDIA_POOL_SIZE 512
#define MEDIA_POOL_INC_SIZE 128

#define UPDATERS_COUNT 3
#define MAX_ANSWER_DURATION_SEC 2

#define MAX_USERNAME_LEN 32
#define MAX_DOMAIN_LEN 64
#define MAX_REG_URI_LEN (MAX_DOMAIN_LEN + 4)
#define MAX_ID_LEN (MAX_USERNAME_LEN + MAX_DOMAIN_LEN + 5)

#define DEFAULT_PASSWD "Passwd123"
#define DEFAULT_WAV_PATH "./media/test.wav"

int init_answerphone();

int start_answerphone(const char*, const char*);

#endif 