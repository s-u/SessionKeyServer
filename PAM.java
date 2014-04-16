// Verify user credentials against PAM
package com.att.research.RCloud;

public class PAM {
    static boolean pam_loaded = false;
    static {
	try {
	    System.loadLibrary("PAM");
	    pam_loaded = true;
	} catch (UnsatisfiedLinkError e) {
	    System.err.println("WARNING: cannot load PAM library, PAM authentication will be disabled.");
	}
    }

    native static boolean PAMchkUser(String app, String user, String pwd);

    static boolean checkUser(String app, String user, String pwd) {
	return pam_loaded ? PAMchkUser(app, user, pwd) : false;
    }
}
