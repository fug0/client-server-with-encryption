#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <signal.h>
#include <netdb.h>

#include <libmycrypto.h>

#define OPENSSL_NO_IDEA

#define MAX_CLIENTS 2
#define BUFFER_SIZE 80
#define SEED_SKEY_PATH "../shared_key"
#define PUB_KEY_LEN 64

static _Atomic unsigned int cli_count = 0;
static _Atomic bool is_crypto = false;
static _Atomic bool is_diffie_hellman = false;
static _Atomic bool is_gost = false;
// static unsigned char raw_key[SEED_KEY_LENGTH] = {};
static int uid = 10;

/* Client structure */
typedef struct {
    struct sockaddr_in addr; /* Client remote address */
    int connfd;              /* Connection file descriptor */
    int uid;                 /* Client unique identifier */
    char name[32];
} client_t;

client_t *clients[MAX_CLIENTS];

pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

static void safe_ucharcat(unsigned char *dst, const unsigned char *src, int num) {
    int offset = strlen(dst);
    for(int i = offset; i < num + offset; ++i) {
        dst[i] = src[i - offset];
    }
}

/* Send message to sender */
void send_message_back(const char *s, int connfd){
    if(*s == '\0') {
        return;
    }
    if (write(connfd, s, strlen(s)) < 0) {
        syslog(LOG_ERR, "Error in sending message to client");        
    }
}

void send_fixed_len_uchar(const unsigned char *s, int connfd, int len) {
    if(*s == '\0') {
        return;
    }
    if (write(connfd, s, len) < 0) {
        syslog(LOG_ERR, "Error in sending fixed size uchar message to client");        
    }
}

/* Strip CRLF */
void strip_newline(char *s){
    while (*s != '\0') {
        if (*s == '\r' || *s == '\n') {
            *s = '\0';
        }
        s++;
    }
}

/* Receives messages from client */
void *recv_msg_from_client(void *arg) {
    unsigned char buffer_recv[BUFFER_SIZE] = {};
    int rlen = 0;
    client_t *cli = (client_t *)arg;

    syslog(LOG_INFO, "New client");
    
    unsigned char seed_decrypted_msg[BUFFER_SIZE] = {};
    /* Receive input from client */
    while((rlen = read(cli->connfd, buffer_recv, sizeof(buffer_recv) - 1)) > 0) {
        if(is_crypto || is_diffie_hellman) {
            if(seed_decrypt_with_shared_key(buffer_recv, seed_decrypted_msg)) {
                printf("Message from client: %s", (char *)seed_decrypted_msg);
                memset(seed_decrypted_msg, 0, BUFFER_SIZE);
            };
        } else if(is_gost) {
            if(!gost_kuznyechik_decrypt(buffer_recv, seed_decrypted_msg)) {
                printf("Message from client: %s", (char *)seed_decrypted_msg);
                memset(seed_decrypted_msg, 0, BUFFER_SIZE);
            }
        } else {
            printf("Message from client: %s", (char *)buffer_recv);
        }
    }

    /* Cleanup: close connection and etc */
    syslog(LOG_INFO, "Client disconnected");
    shutdown(cli->connfd, SHUT_RDWR);
    close(cli->connfd);
    cli_count--;

    return NULL;
}

void *send_msg_to_client(void *arg) {
    char message[BUFFER_SIZE + 2] = {};
    
    client_t *cli = (client_t *)arg;

    int i, c;

    while(1) {
        if(cli_count == 0) {
            break;
        }

        for (i = 0; i < BUFFER_SIZE; ++i) {
            c = getchar();

            // Check for newline or EOF
            if (c == '\n' || c == EOF) {
                message[i] = '\n';
                message[i + 1] = '\0';
                break;
            }
            message[i] = c;
        }

        if (i == BUFFER_SIZE && c != '\n' && c != EOF) {\
            syslog(LOG_WARNING, "User-input message cannot be more than %d characters", BUFFER_SIZE);
            while (c != '\n' || c != EOF)
            {
                c = getchar();
            }
        } else {
            if(is_crypto || is_diffie_hellman) {
                unsigned char encrypted_message[BUFFER_SIZE / SEED_BLOCK_SIZE + 1][SEED_BLOCK_SIZE] = {};
                memcpy(encrypted_message, seed_encrypt_with_shared_key(message), (BUFFER_SIZE / SEED_BLOCK_SIZE + 1)*(SEED_BLOCK_SIZE));

                for(int j = 0; *encrypted_message[j] != '\0'; ++j) {
                    send_fixed_len_uchar(encrypted_message[j], cli->connfd, SEED_BLOCK_SIZE);
                    usleep(1);
                }
            } else if(is_gost) {
                unsigned char *encrypted_message = calloc(GOST_MIN_KEY_LEN_BYTE * 
                    ((strlen(message) / GOST_KUZNYECHIK_BLOCK_SIZE_BYTE) + 1), sizeof(unsigned char));
                    
                int enc_msg_len;
                gost_kuznyechik_encrypt(message, encrypted_message, &enc_msg_len);
                send_fixed_len_uchar(encrypted_message, cli->connfd, enc_msg_len);
                free(encrypted_message);
                enc_msg_len = 0;
            } else {
                send_message_back(message, cli->connfd);
            }
        }
    }

    free(cli);

    return NULL;
}

static unsigned char *parse_dh_proto_vals(unsigned char *value, dh_params_t *p, peer_pub_key_t *peer_key) {
    if(value[0] == 'p' && value[1] == ':') {
        for(int i = 2; value[i] != '\0'; ++i) {
            p->p_param[i-2] = value[i];
            value[i] = '\0';
        }

    } else if (value[0] == 'g' && value[1] == ':') {
        for(int i = 2; value[i] != '\0'; ++i) {
            p->g_param[i-2] = value[i];
            value[i] = '\0';
        }

        dh_set_params(p->p_param, p->g_param);
    } else if(value[0] == 'p' && value[1] == 'u' && value[2] == 'b' && value[3] == ':' ) {
        if(dh_generate_keys() < 0) {
            syslog(LOG_ERR, "Error generating DH key pair");
            exit(EXIT_FAILURE);
        }

        unsigned char *pub_key = calloc(BUFFER_SIZE, sizeof(unsigned char));

        if(dh_get_public_key(pub_key) < 0) {
            syslog(LOG_ERR, "Error getting DH public key");
            exit(EXIT_FAILURE);
        }

        for(int i = 4; i < PUB_KEY_LEN + 4; ++i) {
            peer_key->key[i-4] = value[i];
        }

        return pub_key;
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    openlog(argv[0], LOG_CONS | LOG_PID | LOG_NDELAY, LOG_USER);

    uint16_t port = 0;
    if(argc == 2 || argc == 3) {
        port = atoi(argv[1]);
        if(port < 1025) {
            syslog(LOG_ERR, "Cannot start server on port less than 1024!");
            exit(EXIT_FAILURE);
        }

        if(argc == 3) {
            if(strcmp(argv[2], "-c") == 0) {
                is_crypto = true;
            } else if (strcmp(argv[2], "-cdh") == 0) {
                is_diffie_hellman = true;
            } else if (strcmp(argv[2], "-gost") == 0){
                is_gost = true;
            } else {
                printf("Wrong second passed argument!\nMust be one of the following crypto params: [-c|-cdh|-gost]");
                exit(EXIT_FAILURE);
            }
        }
    } else {
        printf("Unexpected number of arguments!\nShould be passed in form <port> <server_ip> [-c|-cdh|-gost]\n");
        exit(EXIT_FAILURE);
    }

    // Preinitialization step of SEED with specified shared key file
    if(is_crypto) {
        seed_shared_key_read(SEED_SKEY_PATH);
    }

    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr;
    struct sockaddr_in cli_addr;
    pthread_t recv_th;
    pthread_t send_th;

    /* Socket settings */
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);

    /* Ignore pipe signals */
    signal(SIGPIPE, SIG_IGN);

    /* Bind */
    if (bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        syslog(LOG_ERR, "Socket binding failed");
        exit(EXIT_FAILURE);
    }

    /* Listen */
    if (listen(listenfd, 1) < 0) {
        syslog(LOG_ERR, "Socket listening failed");
        exit(EXIT_FAILURE);
    }

    syslog(LOG_INFO, "Server started listening on port %d", port);

    /* Accept clients */
    while (1) {
        socklen_t clilen = sizeof(cli_addr);
        connfd = accept(listenfd, (struct sockaddr*)&cli_addr, &clilen);

        /* Check if max clients is reached */
        if ((cli_count + 1) == MAX_CLIENTS) {
            syslog(LOG_INFO, "Max number of clients reached. Client %d.%d.%d.%d is rejected.",
                        cli_addr.sin_addr.s_addr & 0xff,
                        cli_addr.sin_addr.s_addr & 0xff00 >> 8,
                        cli_addr.sin_addr.s_addr & 0xff0000 >> 16,
                        cli_addr.sin_addr.s_addr & 0xff000000 >> 24);
            close(connfd);
            continue;
        }

        /* Client settings */
        client_t *cli = malloc(sizeof(client_t));
        cli->addr = cli_addr;
        cli->connfd = connfd;
        cli->uid = uid++;
        cli_count++;
        sprintf(cli->name, "%d", cli->uid);

        if(is_diffie_hellman) {
            unsigned char buffer_recv[BUFFER_SIZE] = {};
            int rlen = 0;
            dh_params_t dh_params;
            dh_params.p_param = calloc(BUFFER_SIZE, sizeof(unsigned char));
            dh_params.g_param = calloc(BUFFER_SIZE, sizeof(unsigned char));
            peer_pub_key_t peer_pkey;
            peer_pkey.key = calloc(PUB_KEY_LEN, sizeof(unsigned char));

            while((rlen = read(cli->connfd, buffer_recv, sizeof(buffer_recv) - 1)) > 0) 
            {
                unsigned char *ret = parse_dh_proto_vals(buffer_recv, &dh_params, &peer_pkey);
                if(ret != NULL) {
                    unsigned char pub_key_to_send[BUFFER_SIZE] = "pub:";
                    safe_ucharcat(pub_key_to_send, ret, PUB_KEY_LEN);

                    send_fixed_len_uchar(pub_key_to_send, cli->connfd, PUB_KEY_LEN + 4);

                    free(ret);
                    break;
                }
            }

            dh_derive_shared_key(peer_pkey.key);

            free(peer_pkey.key);
            free(dh_params.p_param);
            free(dh_params.g_param);
        } else if(is_gost) {
            gost_init();

            gost_generate_vko_ukm();

            unsigned char *vko_ukm_to_send = calloc(VKO_UKM_LEN, sizeof(unsigned char));
            gost_get_vko_ukm(vko_ukm_to_send);

            send_fixed_len_uchar(vko_ukm_to_send, cli->connfd, sizeof(vko_ukm_to_send));

            char *pub_key_to_send = NULL;
            gost_get_pub_key(&pub_key_to_send);

            send_fixed_len_uchar(pub_key_to_send, cli->connfd, GOST_MIN_KEY_LEN);

            char buffer_recv[GOST_MIN_KEY_LEN] = {};
            int rlen = 0;
            if(rlen = read(cli->connfd, buffer_recv, sizeof(buffer_recv)) > 0) {
                gost_set_peer_key(buffer_recv);
            }

            gost_derive_vko_key();

            gost_generate_priv_key();

            unsigned char *encoded_priv_key;
            gost_get_encrypted_priv_key(&encoded_priv_key);

            send_fixed_len_uchar(encoded_priv_key, cli->connfd, GOST_MIN_KEY_LEN_BYTE);

            free(pub_key_to_send);
        }

        pthread_create(&send_th, NULL, &send_msg_to_client, (void*)cli);
        pthread_create(&recv_th, NULL, &recv_msg_from_client, (void*)cli);
        pthread_detach(send_th);
        pthread_detach(recv_th);

        /* Reduce CPU usage */
        sleep(1);
    }

    if(is_gost) {
        gost_deinit();
    }

    return EXIT_SUCCESS;
}