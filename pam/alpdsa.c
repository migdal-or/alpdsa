// alpdsa.c — OpenSSL 3.0 clean API
#include "alpdsa.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

static int recv_exact(int fd, uint8_t *buf, size_t n) {
    size_t received = 0;
    while (received < n) {
        ssize_t r = recv(fd, buf + received, n - received, 0);
        if (r <= 0) return -1;
        received += r;
    }
    return 0;
}

static int send_all(int fd, const uint8_t *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t s = send(fd, buf + sent, n - sent, 0);
        if (s <= 0) return -1;
        sent += s;
    }
    return 0;
}

static int connect_to_target(const alpdsa_target_t *target, int timeout_sec) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(target->port);

    if (inet_pton(AF_INET, target->host, &addr.sin_addr) != 1) {
        struct hostent *he = gethostbyname(target->host);
        if (!he) { close(fd); return -1; }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static EVP_PKEY *load_pubkey(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *der_buf = malloc(len);
    if (!der_buf || fread(der_buf, 1, len, f) != (size_t)len) {
        free(der_buf);
        fclose(f);
        return NULL;
    }
    fclose(f);

    const unsigned char *der = der_buf;
    EVP_PKEY *key = d2i_PUBKEY(NULL, &der, len);
    free(der_buf);

    // Verify it's EC P-256
    if (key && EVP_PKEY_get_id(key) != EVP_PKEY_EC) {
        EVP_PKEY_free(key);
        return NULL;
    }
    return key;
}

int alpdsa_config_load(const char *config_path, alpdsa_target_t *target) {
    FILE *f = fopen(config_path, "r");
    if (!f) return -1;

    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    fclose(f);

    line[strcspn(line, "\r\n")] = '\0';

    char name[256], host[256];
    int port;
    if (sscanf(line, "%255s %255[^:]:%d", name, host, &port) != 3) return -1;

    target->host = strdup(host);
    target->port = port;
    target->key_name = strdup(name);
    return 0;
}

void alpdsa_target_free(alpdsa_target_t *target) {
    free(target->host);
    free(target->key_name);
    target->host = NULL;
    target->key_name = NULL;
}

int alpdsa_authenticate(const alpdsa_target_t *target, const char *pubkey_path) {
    int ret = -1;
    int fd = -1;
    uint8_t nonce[ALPDSA_NONCE_SIZE];
    uint8_t sig_buf[128];
    EVP_PKEY *pubkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;

    pubkey = load_pubkey(pubkey_path);
    if (!pubkey) {
        fprintf(stderr, "alpdsa: failed to load public key\n");
        goto cleanup;
    }

    // Verify curve is P-256 via key params
    char curve_name[64] = {0};
    if (EVP_PKEY_get_utf8_string_param(pubkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                       curve_name, sizeof(curve_name), NULL) != 1 ||
        strcmp(curve_name, SN_X9_62_prime256v1) != 0) {
        // Also try short name
        if (strcmp(curve_name, "prime256v1") != 0) {
            fprintf(stderr, "alpdsa: wrong curve: %s\n", curve_name);
            goto cleanup;
        }
    }

    if (RAND_bytes(nonce, ALPDSA_NONCE_SIZE) != 1) {
        fprintf(stderr, "alpdsa: RAND_bytes failed\n");
        goto cleanup;
    }

    fd = connect_to_target(target, 1);
    if (fd < 0) {
        fprintf(stderr, "alpdsa: connect to %s:%d failed\n", target->host, target->port);
        goto cleanup;
    }

    uint8_t cmd = ALPDSA_CMD_AUTH;
    if (send_all(fd, &cmd, 1) < 0) goto cleanup;
    uint32_t nonce_len_be = htonl(ALPDSA_NONCE_SIZE);
    if (send_all(fd, (uint8_t *)&nonce_len_be, 4) < 0) goto cleanup;
    if (send_all(fd, nonce, ALPDSA_NONCE_SIZE) < 0) goto cleanup;

    uint32_t sig_len_be;
    if (recv_exact(fd, (uint8_t *)&sig_len_be, 4) < 0) goto cleanup;
    int32_t sig_len = ntohl(sig_len_be);
    if (sig_len == -1 || sig_len < 0 || sig_len > (int32_t)sizeof(sig_buf)) goto cleanup;
    if (recv_exact(fd, sig_buf, (size_t)sig_len) < 0) goto cleanup;

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) goto cleanup;

    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pubkey) == 1 &&
        EVP_DigestVerifyUpdate(md_ctx, nonce, ALPDSA_NONCE_SIZE) == 1 &&
        EVP_DigestVerifyFinal(md_ctx, sig_buf, (size_t)sig_len) == 1) {
        ret = 0;
    }

cleanup:
    if (md_ctx) EVP_MD_CTX_free(md_ctx);
    if (fd >= 0) close(fd);
    EVP_PKEY_free(pubkey);
    return ret;
}
