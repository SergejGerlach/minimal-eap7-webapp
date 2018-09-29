package de.sergejgerlach.sso;

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
    private String testRoles;

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
        testRoles = (String) options.get("testRoles");
    }

    @Override
    public boolean login() throws LoginException {
        log.config("=== login ===");

        initTestUserOrGetCredentials();

        log.config("login, userName = " + userName);

        if (userName == null || userName.trim().isEmpty()) {
            String message = "You are not logged in.";
            log.severe(message + " User name : " + userName);
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
        removeTestUser();
        return true;
    }

    @Override
    public boolean logout() {
        log.config("=== logout ===");
        removeTestUser();
        return true;
    }

    /* ===================================================================== */

    private void removeTestUser() {
        if (!test) return;
        try {
            subject.getPrincipals().clear();
        } catch (Exception e) {
            log.log(Level.SEVERE, "Error in clear Principals", e);
        }
    }

    private void initTestUserOrGetCredentials() {
        if (!test) return;
        log.config("InitTestUser, current user : '" + userName + "'");
        try {
            log.config("trying to get user from UI dialog ...");
            NameCallback nc = new NameCallback("User name: ");
            Callback[] cb = {nc};
            callbackHandler.handle(cb);
            userName = nc.getName();
            log.config("user : '" + userName + "'");

            if (userName == null || userName.trim().isEmpty()) {
                userName = testUser;
                log.config("set to '" + userName + "' (defined in login-module as module-option name='testUser')");
            }
            if (userName == null || userName.trim().isEmpty()) return;

            // add a Principal (authenticated identity) to the Subject
            boolean rv;
            UserPrincipal userPrincipal = new UserPrincipal(userName);
            rv = subject.getPrincipals().add(userPrincipal);
            log.config("added user '" + userName + "' (Principal) to Subject. Return value : " + rv);
            // add a Principal (Roles) to the Subject
            Group group = null;
            if (testRoles != null) {
                String[] roles = testRoles.split(",");
                for (String role : roles) {
                    if (group == null) group = new GroupPrincipal("Roles");
                    rv = group.addMember(new UserPrincipal(role));
                    log.config("added member '" + role + "' (Principal) to Group. Return value : " + rv);
                }
            }
            if (group != null) {
                rv = subject.getPrincipals().add(group);
                log.config("added group 'Roles' (Principal) to Subject. Return value : " + rv);
            }
        } catch (Exception e) {
            log.log(Level.SEVERE, "Error in login as test user : '" + userName + "'", e);
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
