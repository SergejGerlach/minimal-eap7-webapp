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
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author sge
 *
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

  // configurable ldap option
  private static String loginNameAttribute;
  private static String usersLocation;
  private static final Hashtable<String, String> env = new Hashtable<String, String>(16);

  public AppLoginModule() {}

  /* ===================================================================== */

  private static String getOption(final Map<String, ?> options, final String name, final String... args) {
    String option = ((String) options.get(name));
    if(option == null && args != null) {
      if(args.length > 1) {
        log.severe(args[1]);
        throw new RuntimeException(args[1]);
      }
      if(args.length > 0) option = args[0];
    }
    return option;
  }

  @Override
  public void initialize(final Subject subject, final CallbackHandler callbackHandler, final Map<String, ?> sharedState, final Map<String, ?> options) {
    log.info("Begin initialize");
    for(String k : options.keySet()) {
      log.config("option ".concat(k).concat(" = ").concat((String)options.get(k)));
    }

    this.subject = subject;
    this.sharedState = sharedState;
    this.callbackHandler = callbackHandler;

    test = "true".equalsIgnoreCase(getOption(options, "test"));
    testUser = getOption(options, "testUser");
    testRoles = getOption(options, "testRoles");
  }

  @Override
  public boolean login() throws LoginException {
    log.info("Begin login");

    initTestUser();

    log.info("login, userName = " + userName);

    if(userName == null || userName.trim().isEmpty()) {
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
    log.info("Begin commit");

    log.info(getSubjectAsString());

    if(userName == null || userName.trim().isEmpty()) {
      log.log(Level.SEVERE, "userName is null or empty");
      throw new LoginException("Exception caught in commit, Login failed.");
    }

    return true;
  }

  @Override
  public boolean abort() throws LoginException {
    log.info("Begin abort");
    removeTestUser();
    return true;
  }

  @Override
  public boolean logout() throws LoginException {
    log.info("Begin logout");
    removeTestUser();
    return true;
  }

  /* ===================================================================== */

  private void removeTestUser() {
    if(!test) return;
    try {
      subject.getPrincipals().clear();
    } catch (Exception e) {}
  }

  private void initTestUser() {
    if(!test) return;
    log.info("Begin initTestUser, current user : '" + userName + "'");
    try {
      log.info("trying to get user from UI dialog ...");
      NameCallback nc = new NameCallback("User name: ");
      Callback[] cb = { nc };
      callbackHandler.handle(cb);
      userName = nc.getName();
      log.info("user : '" + userName + "'");

      if(userName == null || userName.trim().isEmpty()) {
        userName = testUser;
        log.info("set to '" + userName + "' (defined in login-module as module-option name='testUser')");
      }
        if(userName == null || userName.trim().isEmpty()) return;

      // add a Principal (authenticated identity) to the Subject
      boolean rv = false;
      UserPrincipal userPrincipal = new UserPrincipal(userName);
      rv = subject.getPrincipals().add(userPrincipal);
      log.info("added user '" + userName + "' (Principal) to Subject. Return value : " + rv);
      // add a Principal (Roles) to the Subject
      Group group = null;
      if(testRoles != null) {
        String[] roles = testRoles.split(",");
        for(String role : roles) {
          if(group == null) group = new GroupPrincipal("Roles");
          rv = group.addMember(new UserPrincipal(role));
          log.info("added member '" + role + "' (Principal) to Group. Return value : " + rv);
        }
      }
      if(group != null) {
        rv = subject.getPrincipals().add(group);
        log.info("added group 'Roles' (Principal) to Subject. Return value : " + rv);
      }
    } catch (Exception e) {
      log.log(Level.SEVERE, "Error in login as test user : '" + userName + "'", e);
    }
  }

  /* ===================================================================== */

  private String getSubjectAsString() {
    StringBuilder sb = new StringBuilder("Subject : ");
    if(subject != null) {
      Iterator<Principal> i = subject.getPrincipals().iterator();
      while(i.hasNext())
        sb.append("\n === Principal : ").append(i.next());

      Iterator<Object> pi = subject.getPublicCredentials().iterator();
      while(pi.hasNext())
        sb.append("\n === Public Credential : ").append(pi.next());

      pi = subject.getPrivateCredentials().iterator();
      while(pi.hasNext()) {
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
