package net.trajano.sonar.plugins.reverseproxyauth;

import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.security.SecurityRealm;

/**
 * The security realm. Does nothing for the most part but will allow the use of
 * it in "sonar.security.realm".
 */
public class ReverseProxyAuthRealm extends SecurityRealm {

    /**
     * Settings injected.
     */
    private final ReverseProxyAuthSettings settings;

    /**
     * Users provider. Constructed on {@link #init()}.
     */
    private ExternalUsersProvider usersProvider;

    /**
     * @param settings
     *            injected settings.
     */
    public ReverseProxyAuthRealm(final ReverseProxyAuthSettings settings) {
        super();
        this.settings = settings;
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
     * Instantiates the {@link ExternalUsersProvider}.
     */
    @Override
    public void init() {

        usersProvider = new ReverseProxyAuthUsersProvider(settings);
    }

}
