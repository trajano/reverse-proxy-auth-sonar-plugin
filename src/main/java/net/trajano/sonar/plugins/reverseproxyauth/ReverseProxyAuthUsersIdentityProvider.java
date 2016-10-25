package net.trajano.sonar.plugins.reverseproxyauth;

import java.io.IOException;
import java.net.URI;

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
     * Places an button on the login screen. {@inheritDoc}
     */
    @Override
    public Display getDisplay() {

        return Display.builder().setIconPath("foo.png").build();
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

        if (settings.isLocalHost(context.getRequest())) {
            return;
        }

        final String headerValue = settings.getUserNameFromHeader(context.getRequest());
        if (headerValue == null) {
            return;
        }
        context.authenticate(UserIdentity.builder().setEmail(headerValue)
            .setProviderLogin(headerValue)
            .setLogin(headerValue)
            .setName(headerValue).build());
        try {
            context.getResponse().sendRedirect(URI.create(context.getRequest().getRequestURL().toString()).resolve(context.getRequest().getContextPath()).resolve("/reverseproxyauth/redirect_back_or_home_url").toASCIIString());
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @return <code>true</code>
     */
    @Override
    public boolean isEnabled() {

        return true;
    }
}
