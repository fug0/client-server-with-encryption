#include <string.h>
#include <stdio.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/dh.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "libmycrypto.h"

#define __GLIBC_USE

// Private lib's structure contatining DH params
typedef struct dh_params_private {
    BIGNUM *p_param;
    BIGNUM *g_param;
} dh_params_private_t;

// Private lib's structure conatining DH private and session keys
typedef struct dh_keys_private {
    EVP_PKEY *key_pair;
    unsigned char *session_key;
} dh_keys_private_t;

// Private lib's structure containing GOST engine and needed keys
typedef struct gost_context {
    ENGINE *gost_engine;
    EVP_PKEY *key_pair;
    EVP_PKEY *peer_key;
    unsigned char vko_session_key[32];
    unsigned char private_key[32];
    unsigned char vko_ukm[8];
} gost_context_t;

static SEED_KEY_SCHEDULE seed_key;
static dh_params_private_t dh_params_priv = {};
static dh_keys_private_t dh_keys = {};
static gost_context_t gost_ctx = {};

static int dh_create_domain_param_key(EVP_PKEY **domainParamKey);

// Sets seed_raw_key with DH derived key
static void seed_set_dh_session_key() {
    unsigned char seed_raw_key[SEED_KEY_LENGTH] = {};

    for(int i = 0; i < SEED_KEY_LENGTH; ++i) {
        seed_raw_key[i] = dh_keys.session_key[i];
    }

    SEED_set_key(seed_raw_key, &seed_key);
}

//Calculates the length of a decoded base64 string
static int calc_decod_len(const char* b64input) { 
    int len = strlen(b64input);
    int padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
    else if (b64input[len-1] == '=') //last char is =
    padding = 1;

    return (int)len*0.75 - padding;
}

// Decodes a base64 encoded string
static int base64_decode(char* b64message, char** buffer) { 
    BIO *bio, *b64;
    int decodeLen = calc_decod_len(b64message),
        len = 0;
    *buffer = (char*)malloc(decodeLen+1);
    FILE* stream = fmemopen(b64message, strlen(b64message), "r");

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stream, BIO_NOCLOSE);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
    len = BIO_read(bio, *buffer, strlen(b64message));
    //Can test here if len == decodeLen - if not, then return an error
    (*buffer)[len] = '\0';

    BIO_free_all(bio);
    fclose(stream);

    return (0); //success
}

// Reads private key for SEED encrypting from file
int seed_shared_key_read(const char *key_path) {
    unsigned char seed_raw_key[SEED_KEY_LENGTH] = {};

    FILE* sh_key_file = fopen(key_path, "r");

    if(sh_key_file != NULL) {
        if(fread(seed_raw_key, sizeof(unsigned char), SEED_KEY_LENGTH, sh_key_file) < SEED_KEY_LENGTH) {
            return -1;
        };
    } else {
        return -1;
    }

    SEED_set_key(seed_raw_key, &seed_key);

    return 0;
}

// Encrypts passed message by SEED algo (block by block with 128 bit size) a
// and returns encrypted message
const unsigned char *seed_encrypt_with_shared_key(const char *message) {
    unsigned char message_block[BUFFER_SIZE / SEED_BLOCK_SIZE + 1][SEED_BLOCK_SIZE] = {};
    unsigned char message_block_encrypt[SEED_BLOCK_SIZE] = {};

    unsigned char (*message_full_encrypt)[SEED_BLOCK_SIZE] 
        = calloc(BUFFER_SIZE / SEED_BLOCK_SIZE + 1, sizeof *message_full_encrypt);

    for(int j = 0; j < strlen(message); ++j) {
        message_block[j / SEED_BLOCK_SIZE][j % SEED_BLOCK_SIZE] = message[j];
        if(((j + 1) % SEED_BLOCK_SIZE == 0) || (message[j] == '\n')) {
            SEED_encrypt(message_block[j / SEED_BLOCK_SIZE], message_block_encrypt, &seed_key);
            memcpy(message_full_encrypt[j / SEED_BLOCK_SIZE], message_block_encrypt, SEED_BLOCK_SIZE);
        }
    }

    return message_full_encrypt;
}

// Decrypts passed message block (with size of 128 bit) and writes it to decr_msg
bool seed_decrypt_with_shared_key(const unsigned char *msg_block, unsigned char *decr_msg) {

    unsigned char encrypt_msg[SEED_BLOCK_SIZE] = {};
    for(int j = 0; j < SEED_BLOCK_SIZE; ++j) {
        encrypt_msg[j] = msg_block[j];
    }

    unsigned char decrypt_msg_block[SEED_BLOCK_SIZE] = {};

    SEED_decrypt(encrypt_msg, decrypt_msg_block, &seed_key);

    for(int k = 0; k < BUFFER_SIZE; ++k) {
        if(*decr_msg == '\0') {
            *decr_msg = decrypt_msg_block[k % SEED_BLOCK_SIZE];
            if(decrypt_msg_block[k % SEED_BLOCK_SIZE] == '\n') {
                return true;
            } else if(((k + 1) % SEED_BLOCK_SIZE) == 0) {
                return false;
            }
        }
        decr_msg++;
    }
    
    return false;
}

// Generates DH's prime and generator numbers and writes it to DH params structure
int dh_generate_params(int p_len_bits, int g) {
    BIGNUM *big_add = BN_new();
    BIGNUM *big_rem = BN_new();

    if(g == DH_GENERATOR_2) {
        if(!BN_set_word(big_add, 24)) {
            return -1;
        }

        if(!BN_set_word(big_rem, 23)) {
            return -1;
        }
    }

    BIGNUM *prime_ = BN_new();
    BIGNUM *generator_ = BN_new();

    if(!BN_generate_prime_ex(prime_, p_len_bits, 1, big_add, big_rem, NULL)) {
        return -2;
    }

    if (!BN_set_word(generator_, (BN_ULONG)(g))) {
        return -3;
    }

    dh_params_priv.p_param = prime_;
    dh_params_priv.g_param = generator_;

    

    return 0;
}

// Converts passed prime and generator numbers to BIGNUM format and writes it to DH params srtucture
int dh_set_params(const unsigned char *prime, const unsigned char *generator) {
    dh_params_priv.p_param = BN_new();
    dh_params_priv.g_param = BN_new();

    if(!BN_bin2bn(prime, BIN_P_LEN, dh_params_priv.p_param)) {
        return -1;
    }

    if(!BN_bin2bn(generator, BIN_G_LEN, dh_params_priv.g_param)) {
        return -1;
    }

    return 0;
}

// Converts DH params frim BIGNUM fromat into string format and returns it
int dh_get_params(dh_params_t *params) {
    BN_bn2bin(dh_params_priv.p_param, params->p_param);
    BN_bn2bin(dh_params_priv.g_param, params->g_param);

    return 0;
}

// Generate DH private/public key-pair
int dh_generate_keys() {
    EVP_PKEY *domain_param_key = NULL;
    if(dh_create_domain_param_key(&domain_param_key) < 0) {
        return -1;
    } 

    EVP_PKEY_CTX *keyGenCtx = EVP_PKEY_CTX_new_from_pkey(NULL, domain_param_key, NULL);

    if(EVP_PKEY_keygen_init(keyGenCtx) <= 0) {
        return -2;
    }

    if (!EVP_PKEY_generate(keyGenCtx, &dh_keys.key_pair)) {
        return -3;
    }

    return 0;
}

// Reads DH public key from DH structure
int dh_get_public_key(unsigned char *key) {
    BIGNUM* publicKey = NULL;
    if (!EVP_PKEY_get_bn_param(dh_keys.key_pair, OSSL_PKEY_PARAM_PUB_KEY, &publicKey)) {
        return -1;
    }

    BN_bn2bin(publicKey, key);

    return 0;
}

// Creates DH domain param key needed for derivating session key
static int dh_create_domain_param_key(EVP_PKEY **domainParamKey) {
    OSSL_PARAM_BLD *paramBuild = OSSL_PARAM_BLD_new();

    if(!OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_P, dh_params_priv.p_param)) {
        return -1;
    }

    if(!OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_G, dh_params_priv.g_param)) {
        return -2;
    }

    OSSL_PARAM *param = OSSL_PARAM_BLD_to_param(paramBuild);

    EVP_PKEY_CTX *domainParamKeyCtx = EVP_PKEY_CTX_new_from_name(NULL, "DHX", NULL);

    if(EVP_PKEY_fromdata_init(domainParamKeyCtx) <= 0) {
        return -3;
    }

    if (EVP_PKEY_fromdata(domainParamKeyCtx, domainParamKey, EVP_PKEY_KEY_PARAMETERS, param) <= 0) {
        return -4;
    }

    OSSL_PARAM_BLD_free(paramBuild);
    OSSL_PARAM_free(param);
    EVP_PKEY_CTX_free(domainParamKeyCtx);

    return 0;
}

// Derives DH session key
int dh_derive_shared_key(unsigned char *key) {
    EVP_PKEY *peer_public_key = NULL;
    
    BIGNUM *bn_peer_pub_key = BN_new();
    BN_bin2bn(key, PUB_KEY_LEN, bn_peer_pub_key);

    OSSL_PARAM_BLD *param_build = OSSL_PARAM_BLD_new();

    if(!OSSL_PARAM_BLD_push_BN(param_build, OSSL_PKEY_PARAM_PUB_KEY, bn_peer_pub_key)) {
        return -1;
    }

    if (!OSSL_PARAM_BLD_push_BN(param_build, OSSL_PKEY_PARAM_FFC_P, dh_params_priv.p_param) ||
      !OSSL_PARAM_BLD_push_BN(param_build, OSSL_PKEY_PARAM_FFC_G, dh_params_priv.g_param)) {
        return -2;
    }

    OSSL_PARAM *param = OSSL_PARAM_BLD_to_param(param_build);

    EVP_PKEY_CTX *peer_pub_key_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DHX", NULL);

    if(EVP_PKEY_fromdata_init(peer_pub_key_ctx) <= 0) {
        return -3;
    }

    if (EVP_PKEY_fromdata(peer_pub_key_ctx, &peer_public_key, EVP_PKEY_PUBLIC_KEY, param) <= 0) {
        return -4;
    }

    EVP_PKEY_CTX *derivation_ctx = EVP_PKEY_CTX_new(dh_keys.key_pair, NULL);

    if (EVP_PKEY_derive_init(derivation_ctx) <= 0) {
        return -5;
    }

    if (EVP_PKEY_derive_set_peer(derivation_ctx, peer_public_key) <= 0) {
        return -6;
    }

    size_t len = 0;
    if (EVP_PKEY_derive(derivation_ctx, NULL, &len) <= 0) {
        return -7;
    }

    if (len == 0) {
        return -8;
    }

    dh_keys.session_key = calloc(len, sizeof(unsigned char));
    if (EVP_PKEY_derive(derivation_ctx, dh_keys.session_key, &len) <= 0) {
        return -9;
    }
    
    seed_set_dh_session_key();

    return 0;
}

// Loads GOST engine and generating private/public key-pair for derivating session key
int gost_init() {
    ENGINE_load_builtin_engines();
    gost_ctx.gost_engine = ENGINE_by_id("gost");
    if (!gost_ctx.gost_engine) {
        return -1;
    }

    // Initialize the GOST engine
    if (!ENGINE_init(gost_ctx.gost_engine)) {
        ENGINE_free(gost_ctx.gost_engine);
        return -2;
    }

    ENGINE_set_default(gost_ctx.gost_engine, ENGINE_METHOD_ALL);
    OpenSSL_add_all_algorithms();

    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_id(NID_id_GostR3410_2001, gost_ctx.gost_engine);
    if (!ctx) {
        ENGINE_free(gost_ctx.gost_engine);
        return -3;
    }

    EVP_PKEY_paramgen_init(ctx);

    EVP_PKEY_CTX_ctrl(ctx,
        NID_id_GostR3410_2001,
        EVP_PKEY_OP_PARAMGEN,
        EVP_PKEY_ALG_CTRL + 1,
        NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet,
        NULL);

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -4;
    }

    if (EVP_PKEY_keygen(ctx, &gost_ctx.key_pair) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -5;
    }


    EVP_PKEY_CTX_free(ctx);
    return 0;
}

// Unloads GOST engine
void gost_deinit() {
    ENGINE_finish(gost_ctx.gost_engine);
    ENGINE_free(gost_ctx.gost_engine);
    OPENSSL_cleanup();
}

// Generates 64 bits of User Key Material needed for VKO session key derivation algo
void gost_generate_vko_ukm() {
    RAND_bytes(gost_ctx.vko_ukm, sizeof(gost_ctx.vko_ukm));
}

int gost_get_vko_ukm(unsigned char *buf) {
    memcpy(buf, gost_ctx.vko_ukm, sizeof(gost_ctx.vko_ukm));

    return 0;
}

// Sets 64 bits of passed User Key Material
int gost_set_vko_ukm(unsigned char *buf) {
    memcpy(gost_ctx.vko_ukm, buf, sizeof(gost_ctx.vko_ukm));

    return 0;
}

// Reads GOST public key into key buffer
int gost_get_pub_key(char **key) {
    BUF_MEM *bptr;
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, gost_ctx.key_pair);
    int pubKeyDataLength = BIO_get_mem_data(bio, key);

#ifdef DEBUG_MODE 
    BIO* fp = BIO_new_fp(stdout, BIO_NOCLOSE);
    EVP_PKEY_print_private(fp, gost_ctx.key_pair, 0, NULL);
#endif

    BIO_get_mem_ptr(bio, &bptr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free(bio);
    bptr->data = NULL;
    BUF_MEM_free(bptr);

    return 0;
}

// Sets peer public key for derivating session key
int gost_set_peer_key(const char *key) {
    BIO *bio = BIO_new_mem_buf(key, strlen(key));
    PEM_read_bio_PUBKEY(bio, &gost_ctx.peer_key, NULL, NULL);

#ifdef DEBUG_MODE 
    BIO* fp = BIO_new_fp(stdout, BIO_NOCLOSE);
    EVP_PKEY_print_public(fp, gost_ctx.peer_key, 0, NULL);
#endif

    BIO_free(bio);

    return 0;
}

// Derives VKO session key for encrypting shared private key for symmetric encryption
int gost_derive_vko_key() {
    EVP_PKEY_CTX *vko_derivation_ctx = EVP_PKEY_CTX_new(gost_ctx.key_pair, NULL);

    if (EVP_PKEY_derive_init(vko_derivation_ctx) <= 0) {
        return -1;
    }

    if (EVP_PKEY_derive_set_peer(vko_derivation_ctx, gost_ctx.peer_key) <= 0) {
        return -2;
    }

    if(EVP_PKEY_CTX_ctrl(vko_derivation_ctx, -1, -1, EVP_PKEY_CTRL_SET_IV, 8, gost_ctx.vko_ukm) <= 0) {
        return -3;
    }

    size_t len = 0;
    if (EVP_PKEY_derive(vko_derivation_ctx, gost_ctx.vko_session_key, &len) <= 0) {
        return -4;
    }

    EVP_PKEY_CTX_free(vko_derivation_ctx);

    return 0;
}

// Generates 256 bit shared private key for symmetric encryption
int gost_generate_priv_key() {
    EVP_PKEY *priv_key = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_id(NID_id_GostR3410_2012_256, gost_ctx.gost_engine);
    if (!ctx) {
        return -1;
    }

    EVP_PKEY_paramgen_init(ctx);

    EVP_PKEY_CTX_ctrl(ctx,
        NID_id_GostR3410_2012_256,
        EVP_PKEY_OP_PARAMGEN,
        EVP_PKEY_ALG_CTRL + 1,
        NID_id_tc26_gost_3410_2012_256_paramSetA,
        NULL);

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -2;
    }

    if (EVP_PKEY_keygen(ctx, &priv_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -3;
    }

#ifdef DEBUG_MODE
    BIO* fp = BIO_new_fp(stdout, BIO_NOCLOSE);
    EVP_PKEY_print_private(fp, priv_key, 0, NULL);
#endif

    // BIO* fp = BIO_new_fp(stdout, BIO_NOCLOSE);
    // EVP_PKEY_print_private(fp, priv_key, 0, NULL);

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, priv_key, 0, 0, 0, 0, 0);
    int priv_key_len = BIO_get_mem_data(bio, NULL);
    char *buf;
    BIO_get_mem_data(bio, &buf);
    
    char *encoded_str = calloc(priv_key_len, sizeof(char));
    char *encoded_buf;
    encoded_buf = strtok(buf, "\n");
    encoded_buf = strtok(NULL, "\n");
    strcat(encoded_str, encoded_buf);
    encoded_buf = strtok(NULL, "\n");
    strcat(encoded_str, encoded_buf);


    char *decoded_str = NULL;
    base64_decode(encoded_str, &decoded_str);

    for(int i = 0; i < GOST_MIN_KEY_LEN_BYTE; ++i) {
        gost_ctx.private_key[i] = decoded_str[GOST_MIN_KEY_LEN_BYTE * 2 - i - 1];
    }

    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free(bio);
    bptr->data = NULL;
    BUF_MEM_free(bptr);

    free(buf);
    free(encoded_str);
    free(decoded_str);

    EVP_PKEY_free(priv_key);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

// Reads generated shared private key for symmetric encryption into buf
int gost_get_encrypted_priv_key(unsigned char **buf) {
    *buf = calloc(GOST_MIN_KEY_LEN_BYTE, sizeof(unsigned char));

    EVP_CIPHER *ciph;
    ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_ecb);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    OPENSSL_assert(ctx);

    EVP_CIPHER_CTX_init(ctx);
    if(!EVP_CipherInit_ex(ctx, ciph, NULL, gost_ctx.vko_session_key, NULL, 1)) {
        return -1;
    }

    if(!EVP_CIPHER_CTX_set_padding(ctx, 0)) {
        return -2;
    }

    int outlen = 0, tmplen = 0;
    if(!EVP_CipherUpdate(ctx, *buf, &outlen, gost_ctx.private_key, GOST_MIN_KEY_LEN_BYTE)) {
        return -3;
    }

    if(!EVP_CipherFinal_ex(ctx, *buf + outlen, &tmplen)) {
        return -4;
    }

    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

// Decrypts passed private key using VKO session key and sets it to structure
int gost_decrypt_and_set_priv_key(unsigned char *key) {
    EVP_CIPHER *ciph;
    ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_ecb);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    OPENSSL_assert(ctx);

    EVP_CIPHER_CTX_init(ctx);

    if(!EVP_CipherInit_ex(ctx, ciph, NULL, gost_ctx.vko_session_key, NULL, 0)) {
        return -1;
    }

    if(!EVP_CIPHER_CTX_set_padding(ctx, 0)) {
        return -2;
    }


    int outlen = 0, tmplen = 0;
    if(!EVP_CipherUpdate(ctx, gost_ctx.private_key, &outlen, key, GOST_KUZNYECHIK_KEY_SIZE_BYTE)) {
        return -3;
    }

    if(!EVP_CipherFinal_ex(ctx, gost_ctx.private_key + outlen, &tmplen)) {
        return -4;
    }

    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    
    return 0;
}

// Encrypts passed message with shared private key and returns it
int gost_kuznyechik_encrypt(const char *msg, unsigned char* enc_msg, int *enc_len) {
    EVP_CIPHER *ciph;
    ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_ecb);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    OPENSSL_assert(ctx);

    EVP_CIPHER_CTX_init(ctx);

    if(!EVP_CipherInit_ex(ctx, ciph, NULL, gost_ctx.private_key, NULL, 1)) {
        return -1;
    }

    if(!EVP_CIPHER_CTX_set_padding(ctx, 0)) {
        return -2;
    }

    int outlen = 0, tmplen = 0;
    if(!EVP_CipherUpdate(ctx, enc_msg, &outlen, (const unsigned char *)msg, GOST_MIN_KEY_LEN_BYTE * ((strlen(msg) / GOST_KUZNYECHIK_BLOCK_SIZE_BYTE) + 1))) {
        return -3;
    }

    if(!EVP_CipherFinal_ex(ctx, enc_msg + outlen, &tmplen)) {
        return -4;
    }

    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);

    *enc_len = outlen;

    return 0;
}

// Decrypts passed encrypted message with shared private key and returns it
int gost_kuznyechik_decrypt(const unsigned char* enc_msg, unsigned char *dec_msg) {
    EVP_CIPHER *ciph;
    ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_ecb);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    OPENSSL_assert(ctx);

    EVP_CIPHER_CTX_init(ctx);

    if(!EVP_CipherInit_ex(ctx, ciph, NULL, gost_ctx.private_key, NULL, 0)) {
        return -1;
    }

    if(!EVP_CIPHER_CTX_set_padding(ctx, 0)) {
        return -2;
    }

    int outlen = 0, tmplen = 0;
    if(!EVP_CipherUpdate(ctx, dec_msg, &outlen, enc_msg, GOST_KUZNYECHIK_KEY_SIZE_BYTE)) {
        return -3;
    }

    if(!EVP_CipherFinal_ex(ctx, dec_msg + outlen, &tmplen)) {
        return -4;
    }

    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}