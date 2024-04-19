#ifndef LIBMYCRYPTO_H_
#define LIBMYCRYPTO_H_

#include <stdbool.h>
#include <openssl/seed.h>

#define BUFFER_SIZE 80
#define PUB_KEY_LEN 64
#define BIN_P_LEN 64
#define BIN_G_LEN 1
#define PRIME_LENGTH_512 512
#define GENERATOR_VALUE_2 2
#define VKO_UKM_LEN 8
#define GOST_MIN_KEY_LEN 256
#define GOST_MIN_KEY_LEN_BYTE 32
#define GOST_KUZNYECHIK_BLOCK_SIZE_BYTE 16
#define GOST_KUZNYECHIK_KEY_SIZE_BYTE 32


typedef struct dh_params {
    unsigned char *p_param;
    unsigned char *g_param;
} dh_params_t;

typedef struct peer_pub_key {
    unsigned char *key;
} peer_pub_key_t;

int seed_shared_key_read(const char *key_path);

const unsigned char *seed_encrypt_with_shared_key(const char *msg);
bool seed_decrypt_with_shared_key(const unsigned char *msg_block, unsigned char *decr_msg);

int dh_generate_params(int p_len_bits, int g);
int dh_set_params(const unsigned char *prime, const unsigned char *generator);
int dh_get_params(dh_params_t *params);
int dh_generate_keys();
int dh_get_public_key(unsigned char *key);
int dh_derive_shared_key(unsigned char *key);

int gost_init();
void gost_deinit();
void gost_generate_vko_ukm();
int gost_get_vko_ukm(unsigned char *buf);
int gost_set_vko_ukm(unsigned char *buf);
int gost_get_pub_key(char **key);
int gost_set_peer_key(const char *key);
int gost_derive_vko_key();
int gost_generate_priv_key();
int gost_get_encrypted_priv_key(unsigned char **buf);
int gost_decrypt_and_set_priv_key(unsigned char *key);
int gost_kuznyechik_encrypt(const char *msg, unsigned char* enc_msg, int *enc_len);
int gost_kuznyechik_decrypt(const unsigned char* enc_msg, unsigned char *dec_msg);

#endif // LIBMYCRYPTO_H_