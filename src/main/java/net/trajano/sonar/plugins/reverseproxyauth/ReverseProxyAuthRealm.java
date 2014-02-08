package net.trajano.sonar.plugins.reverseproxyauth;

import net.trajano.sonar.plugins.reverseproxyauth.internal.ReverseProxyAuthUsersProvider;
import net.trajano.sonar.plugins.reverseproxyauth.internal.ReverseProxyAuthenticator;

import org.sonar.api.config.Settings;
import org.sonar.api.security.Authenticator;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.security.SecurityRealm;

/**
 * Realm.
 */
public class ReverseProxyAuthRealm extends SecurityRealm {
    /**
     * Authenticator. Constructed on {@link #init()}.
     */
    private Authenticator authenticator;

    /**
     * Settings injected.
     */
    private final Settings settings;

    /**
     * Users provider. Constructed on {@link #init()}.
     */
    private ExternalUsersProvider usersProvider;

    /**
     * @param settings
     *            injected settings
     */
    public ReverseProxyAuthRealm(final Settings settings) {
        super();
        this.settings = settings;
    }

    @Override
    public Authenticator doGetAuthenticator() {
        return authenticator;
    }

    @Override
    public String getName() {
        return "reverseproxyauth";
    }

    @Override
    public ExternalUsersProvider getUsersProvider() {
        return usersProvider;
    }

    @Override
    public void init() {
        authenticator = new ReverseProxyAuthenticator(settings);
        usersProvider = new ReverseProxyAuthUsersProvider(settings);
    }
}
