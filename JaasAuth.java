package com.att.research.RCloud;

// Verify user credentials using JAAS and PAM
import java.io.IOException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/**
 * This JaasAcn application attempts to authenticate a user and reports whether
 * or not the authentication was successful.
 */
public class JaasAuth {
    public static boolean jaasLogin(String user, char[] pass, String jaasModule) {
        LoginContext lc = null;
        try {
            lc = new LoginContext(jaasModule,
                                  new UserNamePasswordCallbackHandler(user, pass));
	    lc.login();
        } catch (LoginException le) {
            System.out.println("jaasLogin: FAILED, LoginException: " + le.getMessage());
            return false;
        } catch (SecurityException se) {
            System.out.println("jaasLogin: FAILED, SecurityException: " + se.getMessage());
            return false;
        }
        return true;
    }

    public static class UserNamePasswordCallbackHandler implements CallbackHandler {
        private String _userName;
        private char[] _password;

        public UserNamePasswordCallbackHandler(String userName, char[] password) {
            _userName = userName;
            _password = password;
        }

        public void handle(Callback[] callbacks) throws IOException,
							UnsupportedCallbackException {
            for (Callback callback : callbacks) {
                if (callback instanceof NameCallback && _userName != null) {
                    ((NameCallback) callback).setName(_userName);
                } else if (callback instanceof PasswordCallback
                           && _password != null) {
                    ((PasswordCallback) callback).setPassword(_password);
                }
            }
        }
    }
}
