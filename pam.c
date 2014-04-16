#include <security/pam_appl.h>

#include <string.h>
#include <stdlib.h>

static int my_conv(int num_msg, const struct pam_message **msg,
	    struct pam_response **resp, void *appdata_ptr) {
    int i = 0;
    struct pam_response *reply;
    reply = (struct pam_response *) calloc(num_msg, sizeof(struct pam_response));
    if (!reply) return PAM_CONV_ERR;
    while (i < num_msg) {
	/* printf("msg[%d]: %d '%s'\n", i, msg[i]->msg_style, msg[i]->msg); */
	reply[i].resp_retcode = 0;
	reply[i].resp = appdata_ptr ? strdup((char*)appdata_ptr) : strdup("");
	i++;
    }
    *resp = reply;
    return PAM_SUCCESS;
}

/* returns 1 if the user has been authenticated, 0 otherwise */
static int check_user_pam(const char *app, const char *user, const char *pwd) {
    pam_handle_t *pamh = NULL;
    int retval, ok = 0;
    struct pam_conv conv = {
	my_conv,
	(void*)pwd
    };

    retval = pam_start(app, user, &conv, &pamh);

    if (retval == PAM_SUCCESS)
        retval = pam_authenticate(pamh, 0);    /* is user really user? */

    if (retval == PAM_SUCCESS)
        retval = pam_acct_mgmt(pamh, 0);       /* permitted access? */

    ok = (retval == PAM_SUCCESS) ? 1 : 0;

    pam_end(pamh, retval);

    return ok;
}

#include <jni.h>

JNIEXPORT jboolean JNICALL Java_com_att_research_RCloud_PAM_PAMchkUser(JNIEnv *, jclass, jstring, jstring, jstring);

jboolean JNICALL Java_com_att_research_RCloud_PAM_PAMchkUser(JNIEnv *env, jclass cls, jstring sApp, jstring sUser, jstring sPwd) {
    const char *app, *usr, *pwd;
    int res = 0;
    if (!env || !sApp || !sUser || !sPwd) return 0;
    app = (*env)->GetStringUTFChars(env, sApp, 0);
    if (app) {
	usr = (*env)->GetStringUTFChars(env, sUser, 0);
	if (usr) {
	    pwd = (*env)->GetStringUTFChars(env, sPwd, 0);
	    if (pwd) {
		res = check_user_pam(app, usr, pwd);
		(*env)->ReleaseStringUTFChars(env, sPwd, pwd);
	    }
	    (*env)->ReleaseStringUTFChars(env, sUser, usr);
	} 
	(*env)->ReleaseStringUTFChars(env, sApp, app);
    }
    return (jboolean) res;
}

