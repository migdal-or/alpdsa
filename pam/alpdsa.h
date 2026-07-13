// alpdsa.h
#ifndef ALPDSA_H
#define ALPDSA_H

#include <stdint.h>
#include <stddef.h>

#define ALPDSA_DEFAULT_PORT 7654
#define ALPDSA_CONFIG_PATH "/etc/alpdsa/alpdsa.config"
#define ALPDSA_NONCE_SIZE 32
#define ALPDSA_CMD_AUTH 0x02

typedef struct {
    char *host;
    int port;
    char *key_name;
} alpdsa_target_t;

/* Parse config, find first available target. Returns 0 on success, -1 on error. */
int alpdsa_config_load(const char *config_path, alpdsa_target_t *target);

/* Free target allocated by alpdsa_config_load */
void alpdsa_target_free(alpdsa_target_t *target);

/* Authenticate against target. Returns 0 on success, -1 on failure/error. */
int alpdsa_authenticate(const alpdsa_target_t *target, const char *pubkey_path);

#endif
