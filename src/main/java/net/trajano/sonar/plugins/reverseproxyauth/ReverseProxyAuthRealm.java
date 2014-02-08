package net.trajano.sonar.plugins.reverseproxyauth;

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

    /**
     * {@inheritDoc}
     */
    @Override
    public Authenticator doGetAuthenticator() {
        return authenticator;
    }

    /**
     * {@inheritDoc}
     * 
     * @return {@link ReverseProxyAuthPlugin#KEY}
     */
    @Override
    public String getName() {
        return ReverseProxyAuthPlugin.KEY;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ExternalUsersProvider getUsersProvider() {
        return usersProvider;
    }

    /**
     * Instantiates for the {@link Authenticator} and the
     * {@link ExternalUsersProvider}.
     */
    @Override
    public void init() {
        authenticator = new ReverseProxyAuthenticator(settings);
        usersProvider = new ReverseProxyAuthUsersProvider(settings);
    }
}
