// pam_alpdsa.c — упрощённый, без рытья в конфиге для имени
#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <libgen.h>
#include <sys/stat.h>

#include "alpdsa.h"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *config_path = ALPDSA_CONFIG_PATH;
    const char *user;
    (void)flags;

    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "config=", 7) == 0) {
            config_path = argv[i] + 7;
        }
    }

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user) {
        return PAM_AUTHINFO_UNAVAIL;
    }

    alpdsa_target_t target = {0};
    if (alpdsa_config_load(config_path, &target) != 0) {
        pam_syslog(pamh, LOG_ERR, "alpdsa: bad config %s", config_path);
        return PAM_AUTHINFO_UNAVAIL;
    }

    // pubkey is next to config: /etc/alpdsa/<key_name>.pub
    char pubkey_path[512];
    // Dirname of config
    char *config_copy = strdup(config_path);
    char *dname = dirname(config_copy);
    snprintf(pubkey_path, sizeof(pubkey_path), "%s/%s.pub", dname, target.key_name);
    free(config_copy);

    if (alpdsa_authenticate(&target, pubkey_path) == 0) {
        pam_syslog(pamh, LOG_INFO, "alpdsa: success for %s", user);
        alpdsa_target_free(&target);
        return PAM_SUCCESS;
    }

    alpdsa_target_free(&target);
    return PAM_AUTHINFO_UNAVAIL;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
