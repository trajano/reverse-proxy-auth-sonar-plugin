package net.trajano.sonar.plugins.reverseproxyauth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.config.Settings;
import org.sonar.api.security.Authenticator;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.security.SecurityRealm;

/**
 * Realm.
 */
public class ReverseProxyAuthRealm extends SecurityRealm {
    /**
     * Logger.
     */
    private static final Logger log = LoggerFactory
            .getLogger(ReverseProxyAuthRealm.class);
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
        log.info(usersProvider.toString());
        return usersProvider;
    }

    @Override
    public void init() {
        log.info("init");
        authenticator = new ReverseProxyAuthenticator(settings);
        usersProvider = new ReverseProxyAuthUsersProvider(settings);
    }
}
