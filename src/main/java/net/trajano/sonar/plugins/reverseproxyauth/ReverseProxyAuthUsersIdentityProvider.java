package net.trajano.sonar.plugins.reverseproxyauth;

import java.io.IOException;

import org.sonar.api.config.Settings;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.server.authentication.BaseIdentityProvider;
import org.sonar.api.server.authentication.Display;
import org.sonar.api.server.authentication.UserIdentity;

/**
 * This provides the user details. It is called before
 * {@link org.sonar.api.security.Authenticator#doAuthenticate(org.sonar.api.security.Authenticator.Context)}
 * .
 */
public class ReverseProxyAuthUsersIdentityProvider implements
    BaseIdentityProvider {

    /**
     * Settings.
     */
    private final ReverseProxyAuthSettings settings;

    /**
     * Constructs the {@link ExternalUsersProvider} with the specified
     * {@link Settings}.
     *
     * @param settings
     *            injected settings
     */
    public ReverseProxyAuthUsersIdentityProvider(final ReverseProxyAuthSettings settings) {
        super();
        this.settings = settings;
    }

    /**
     * Check if users allow allowed to signup automatically using this provider.
     * It uses the value from "sonar.allowUsersToSignUp". {@inheritDoc}
     */
    @Override
    public boolean allowsUsersToSignUp() {

        return settings.allowsUsersToSignUp();
    }

    /**
     * Since this will never be displayed to the user as an option. This will
     * always return <code>null</code>.
     *
     * @return <code>null</code>
     */
    @Override
    public Display getDisplay() {

        return Display.builder().setIconPath(settings.getBaseUrl() + "/static/reverseproxyauth/proxy.png").build();
    }

    /**
     * {@inheritDoc}
     *
     * @return {@value ReverseProxyAuthPlugin#KEY}
     */
    @Override
    public String getKey() {

        return ReverseProxyAuthPlugin.KEY;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getName() {

        return "Reverse Proxy Authentication Plugin";
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(final Context context) {

        try {
            if (settings.isLocalHost(context.getRequest())) {
                context.getResponse().sendRedirect(settings.getBaseUrl() + "/sessions/unauthorized");
                return;
            }

            final String headerValue = settings.getUserNameFromHeader(context.getRequest());
            if (headerValue == null) {
                context.getResponse().sendRedirect(settings.getBaseUrl() + "/sessions/unauthorized");
                return;
            }
            context.authenticate(UserIdentity.builder().setEmail(headerValue)
                .setProviderLogin(headerValue)
                .setLogin(headerValue)
                .setName(headerValue).build());
            context.getResponse().sendRedirect(settings.getBaseUrl() + "/reverseproxyauth/redirect_back_or_home_url");
        } catch (final IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Checks if the realm was set, due to the nature of how authentications are
     * done with this plugin, it shouldn't be used as an identity provider
     * unless it is the only one. {@inheritDoc}
     *
     * @return <code>true</code> if the realm was set.
     */
    @Override
    public boolean isEnabled() {

        return settings.isRealmReverseProxyAuth();
    }
}
