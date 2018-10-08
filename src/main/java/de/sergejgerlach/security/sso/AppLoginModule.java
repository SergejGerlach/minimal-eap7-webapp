package de.sergejgerlach.security.sso;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.security.Principal;
import java.security.acl.Group;
import java.util.Iterator;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author sergej
 */
public class AppLoginModule implements LoginModule {

    private static final Logger log = Logger.getLogger(AppLoginModule.class.getName());

    // initial state
    private Subject subject = null;
    private Map<String, ?> sharedState;
    private CallbackHandler callbackHandler;

    // detected loggedin user name
    private String userName = null;

    // configurable test option
    private boolean test = false;
    private String testUser;
    private String roles;

    @Override
    public void initialize(final Subject subject, final CallbackHandler callbackHandler, final Map<String, ?> sharedState, final Map<String, ?> options) {
        log.config("=== initialize ===");
        for (String k : options.keySet()) {
            log.fine("option ".concat(k).concat(" = ").concat((String) options.get(k)));
        }

        this.subject = subject;
        this.sharedState = sharedState;
        this.callbackHandler = callbackHandler;

        test = "true".equalsIgnoreCase((String) options.get("test"));
        testUser = (String) options.get("testUser");
        roles = (String) options.get("roles");
    }

    @Override
    public boolean login() throws LoginException {
        log.config("=== login ===");

        initCredentials();

        log.config("login, userName = " + userName);

        if (userName == null || userName.trim().isEmpty()) {
            String message = "You are not logged in.";
            log.severe(message);
            log.severe(getSubjectAsString());
            log.severe("sharedState : " + sharedState);
            throw new FailedLoginException(message);
        }

        return true;
    }

    @Override
    public boolean commit() throws LoginException {
        log.config("=== commit ===");

        log.fine(getSubjectAsString());

        return true;
    }

    @Override
    public boolean abort() {
        log.config("=== abort ===");
        removeCredentials();
        return true;
    }

    @Override
    public boolean logout() {
        log.config("=== logout ===");
        removeCredentials();
        return true;
    }

    /* ===================================================================== */

    private void removeCredentials() {
        if (!test) return;
        try {
            subject.getPrincipals().clear();
        } catch (Exception e) {
            log.log(Level.SEVERE, "Error in clear Principals", e);
        }
    }

    private void initCredentials() {
        log.config("initCredentials ...");
        if (test) {
            userName = testUser;
            log.fine("set user from config (defined in login-module as module-option name='testUser'), user : '" + userName + "'");
        } else {
            try {
                log.fine("trying to get user from UI dialog ...");
                NameCallback nc = new NameCallback("User name: ");
                Callback[] cb = {nc};
                callbackHandler.handle(cb);
                userName = nc.getName();
                log.fine("set user from UI dialog, user : '" + userName + "'");
            } catch (Exception e) {
                log.log(Level.SEVERE, e.getMessage(), e);
            }
        }
        if (userName != null && !userName.trim().isEmpty()) {
            // add a user principal (authenticated identity) to the Subject
            UserPrincipal userPrincipal = new UserPrincipal(userName);
            subject.getPrincipals().add(userPrincipal);
            log.fine("added user principal '" + userName + "' to the Subject");
        }

        // add a group principal (roles) to the Subject
        Group group = null;
        if (roles != null) {
            String[] roles = this.roles.split(",");
            for (String role : roles) {
                if (group == null) group = new GroupPrincipal("Roles");
                group.addMember(new UserPrincipal(role));
                log.fine("added member '" + role + "' to Group 'Roles'.");
            }
        }
        if (group != null) {
            subject.getPrincipals().add(group);
            log.fine("added group principal 'Roles' to the Subject.");
        }
    }

    /* ===================================================================== */

    private String getSubjectAsString() {
        StringBuilder sb = new StringBuilder("Subject : ");
        if (subject != null) {
            for (Principal principal : subject.getPrincipals()) {
                sb.append("\n === Principal : ").append(principal);
            }

            Iterator<Object> pi = subject.getPublicCredentials().iterator();
            while (pi.hasNext())
                sb.append("\n === Public Credential : ").append(pi.next());

            pi = subject.getPrivateCredentials().iterator();
            while (pi.hasNext()) {
                try {
                    sb.append("\n === Private Credential : ").append(pi.next());
                } catch (Exception e) {
                    sb.append("\n === Private Credential inaccessible. Message : ").append(e.getMessage());
                    break;
                }
            }
        } else {
            sb.append("null");
        }
        return sb.toString();
    }
}
