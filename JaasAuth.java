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

    static boolean checkUser(String userid, char[] password, String service, String krb5conf) {

        String jaasModule = null;
        // Pre Java7 Switch doesn't support strings
        ValueEnum enumval = ValueEnum.valueOf(service.toUpperCase());

        switch (enumval) {
        case KRB5:
            System.setProperty("java.security.krb5.conf", krb5conf);
            jaasModule = "KerberosModule";
            return (jaasLogin(userid, password, jaasModule));
        case LDAP:
            jaasModule = "LdapModule";
            return (jaasLogin(userid, password, jaasModule));
        case PAM:
            jaasModule = "PAM";
            return (com.att.research.RCloud.PAM.checkUser("login", userid,
                    String.valueOf(password)));
        default:
            return false;
        }

    }

    private static boolean jaasLogin(String user, char[] pass, String jaasModule) {
        System.setProperty("java.security.auth.login.config", "jaas.conf");
        LoginContext lc = null;
        try {
            // System.out.println("try Block of Login LoginContext" +
            // jaasModule);
            lc = new LoginContext(jaasModule,
                                  new UserNamePasswordCallbackHandler(user, pass));
        } catch (LoginException le) {
            System.out.println("Failed creating login context "
                               + le.getMessage());
            return false;
        } catch (SecurityException se) {
            System.out.println("Failed creating login context security "
                               + se.getMessage());
            return false;
        }
        try {
            lc.login();
        } catch (LoginException le) {
            System.out.println("Authentication Failed " + le.getMessage());
            return false;
        }
        return true;

    }

    public enum ValueEnum {
        KRB5, PAM, LDAP
    }

    public static class UserNamePasswordCallbackHandler implements
        CallbackHandler {

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
