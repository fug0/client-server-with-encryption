#include <stdio.h>
#include <unistd.h> 
#include <stdint.h>
#include <syslog.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <libmycrypto.h>

#define _GNU_SOURCE

#define SEED_SKEY_PATH "../shared_key"

static _Atomic bool is_crypto = false;
static _Atomic bool is_diffie_hellman = false;
static _Atomic bool is_gost = false;

static pthread_t recv_th;
static pthread_t send_th;

static void safe_ucharcat(unsigned char *dst, const unsigned char *src, int num) {
    int offset = strlen(dst);
    for(int i = offset; i < num + offset; ++i) {
        dst[i] = src[i - offset];
    }
}

/* Send message to sender */
void send_message_back(const unsigned char *s, int connfd){
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

void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void *send_msg_to_server(void *arg) {
    char message[BUFFER_SIZE + 2] = {};
    int i, c;

    int sockfd = *(int *)(arg);

    while(1) {
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
                    send_fixed_len_uchar(encrypted_message[j], sockfd, SEED_BLOCK_SIZE);
                    usleep(1);
                }
            } else if(is_gost) {
                unsigned char *encrypted_message = calloc(GOST_MIN_KEY_LEN_BYTE * 
                    ((strlen(message) / GOST_KUZNYECHIK_BLOCK_SIZE_BYTE) + 1), sizeof(unsigned char));
                    
                int enc_msg_len;
                gost_kuznyechik_encrypt(message, encrypted_message, &enc_msg_len);
                send_fixed_len_uchar(encrypted_message, sockfd, enc_msg_len);
                free(encrypted_message);
                enc_msg_len = 0;
            } else {
                send_message_back(message, sockfd);
            }
        }
    }

    pthread_detach(pthread_self());

    return NULL;
}

void *recv_msg_from_server(void *arg) {
    unsigned char buffer_recv[BUFFER_SIZE] = {};
    int rlen = 0;
    int sockfd = *(int *)(arg);

    unsigned char seed_decrypted_msg[BUFFER_SIZE] = {};
    /* Receive input from server */
    while((rlen = read(sockfd, buffer_recv, sizeof(buffer_recv) - 1)) > 0) {
        //buffer_recv[rlen] = '\0';

        if(is_crypto || is_diffie_hellman) {
            if(seed_decrypt_with_shared_key(buffer_recv, seed_decrypted_msg)) {
                printf("Message from server: %s", (char *)seed_decrypted_msg);
                memset(seed_decrypted_msg, 0, BUFFER_SIZE);
            };
        } else if(is_gost) {
            if(!gost_kuznyechik_decrypt(buffer_recv, seed_decrypted_msg)) {
                printf("Message from server: %s", (char *)seed_decrypted_msg);
                memset(seed_decrypted_msg, 0, BUFFER_SIZE);
            }
        } else {
            printf("Message from server: %s", (char *)buffer_recv);
        }
    }

    close(sockfd);

    pthread_detach(pthread_self());

    return NULL;
}

int main(int argc, char *argv[]) {
    openlog(argv[0], LOG_CONS | LOG_PID | LOG_NDELAY, LOG_USER);

    // Command-line arguments handling
    uint16_t server_port = 0;
    in_addr_t server_ip = 0;
    if(argc == 3 || argc == 4) {
        server_port = atoi(argv[1]);
        server_ip = inet_addr(argv[2]);

        if(argc == 4) {
            if(strcmp(argv[3], "-c") == 0) {
                is_crypto = true;
            } else if (strcmp(argv[3], "-cdh") == 0) {
                is_diffie_hellman = true;
            } else if (strcmp(argv[3], "-gost") == 0) {
                is_gost = true;
            } else {
                printf("Wrong third passed argument!\nMust be one of the following crypto params: [-c|-cdh|-gost]\n");
                exit(EXIT_FAILURE);
            }
        }
    } else {
        printf("Unexpected number of arguments!\nShould be passed in form <port> <server_ip> [-c|-cdh|-gost]\n");
        exit(EXIT_FAILURE);
    }

    // Networking routines
    int sockfd, numbytes;
    char buf[BUFFER_SIZE];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(argv[2], argv[1], &hints, &servinfo)) != 0) {
        syslog(LOG_ERR, "Error in getaddrinfo: %s\n", gai_strerror(rv));
        exit(EXIT_FAILURE);
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            syslog(LOG_ERR, "Error in socket() syscall");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            syslog(LOG_ERR, "Error in connect() syscall");

            continue;
        }

        break;
    }

    if(p == NULL) {
        syslog(LOG_ERR, "Error connecting to server");
        return(EXIT_FAILURE);
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
    syslog(LOG_INFO, "Client connecting to %s", s);

    freeaddrinfo(servinfo);

    // Preinitialization steps of crypto algos
    if(is_crypto) {
        seed_shared_key_read(SEED_SKEY_PATH);
    } else if(is_diffie_hellman) {
        if(dh_generate_params(PRIME_LENGTH_512, GENERATOR_VALUE_2) < 0) {
            syslog(LOG_ERR, "Error in generating DH parameters");
            exit(EXIT_FAILURE);
        }
        dh_params_t params;
        params.p_param = calloc(BUFFER_SIZE, sizeof(unsigned char));
        params.g_param = calloc(BUFFER_SIZE, sizeof(unsigned char));
        dh_get_params(&params);
        
        unsigned char p_str[BUFFER_SIZE] = "p:";
        safe_ucharcat(p_str, params.p_param, PUB_KEY_LEN);
        send_fixed_len_uchar(p_str, sockfd, PUB_KEY_LEN + 2);
        usleep(1);
        unsigned char g_str[BUFFER_SIZE] = "g:";
        safe_ucharcat(g_str, params.g_param, PUB_KEY_LEN);
        send_message_back(g_str, sockfd);

        if(dh_generate_keys() < 0) {
            syslog(LOG_ERR, "Error generating DH key pair");
            exit(EXIT_FAILURE);
        }

        unsigned char pub_key[BUFFER_SIZE] = {};
        unsigned char pub_key_to_send[BUFFER_SIZE] = "pub:";

        if(dh_get_public_key(pub_key) < 0) {
            syslog(LOG_ERR, "Error getting DH public key");
            exit(EXIT_FAILURE);
        }

        safe_ucharcat(pub_key_to_send, pub_key, PUB_KEY_LEN);

        send_fixed_len_uchar(pub_key_to_send, sockfd, PUB_KEY_LEN + 4);

        unsigned char buffer_recv[BUFFER_SIZE] = {};
        int rlen = 0;
        peer_pub_key_t peer_key;
        peer_key.key = calloc(PUB_KEY_LEN, sizeof(unsigned char));
        while((rlen = read(sockfd, buffer_recv, sizeof(buffer_recv) - 1)) > 0) 
        {
            if(buffer_recv[0] == 'p' && buffer_recv[1] == 'u' && buffer_recv[2] == 'b' && buffer_recv[3] == ':' ) {
                for(int i = 4; i < PUB_KEY_LEN + 4; ++i) {
                    peer_key.key[i-4] = buffer_recv[i];
                }
                break;
            }
        }

        dh_derive_shared_key(peer_key.key);
    } else if(is_gost) {
        gost_init();
    
        unsigned char buffer_recv[VKO_UKM_LEN] = {};
        int rlen = 0;
        
        if((rlen = read(sockfd, buffer_recv, VKO_UKM_LEN)) > 0) {
            gost_set_vko_ukm(buffer_recv);
        }

        char peer_key[GOST_MIN_KEY_LEN] = {};
        if((rlen = read(sockfd, peer_key, GOST_MIN_KEY_LEN)) > 0) {
            gost_set_peer_key(peer_key);
        }

        char *pub_key_to_send = NULL;
        gost_get_pub_key(&pub_key_to_send);

        send_fixed_len_uchar(pub_key_to_send, sockfd, GOST_MIN_KEY_LEN);

        gost_derive_vko_key();
        
        unsigned char encrypted_key[GOST_MIN_KEY_LEN_BYTE] = {};
        if((rlen = read(sockfd, encrypted_key, GOST_MIN_KEY_LEN_BYTE)) > 0) {
            gost_decrypt_and_set_priv_key(encrypted_key);
        }

        free(pub_key_to_send);
    }   

    pthread_create(&send_th, NULL, &send_msg_to_server, (void*)(&sockfd));
    pthread_create(&recv_th, NULL, &recv_msg_from_server, (void*)(&sockfd));
    pthread_join(recv_th, NULL);
    pthread_join(send_th, NULL);

    if(is_gost) {
        gost_deinit();
    }

    return EXIT_SUCCESS;
}