package net.trajano.sonar.plugins.reverseproxyauth;

import org.sonar.api.config.Settings;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.security.UserDetails;

/**
 * This provides the user details. It is called before
 * {@link org.sonar.api.security.Authenticator#doAuthenticate(org.sonar.api.security.Authenticator.Context)}
 * .
 */
public class ReverseProxyAuthUsersProvider extends ExternalUsersProvider {

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
    public ReverseProxyAuthUsersProvider(final ReverseProxyAuthSettings settings) {
        super();
        this.settings = settings;
    }

    /**
     * Obtains the user details from the header. Will return <code>null</code>
     * if it cannot be obtained. However, if it is localhost it will return an
     * empty {@link UserDetails} structure. {@inheritDoc}
     */
    @Override
    public UserDetails doGetUserDetails(final Context context) {

        final UserDetails userDetails = new UserDetails();
        if (!settings.isLocalHost(context.getRequest())) {
            final String headerValue = settings.getUserNameFromHeader(context.getRequest());
            if (headerValue == null) {
                return null;
            }
            userDetails.setEmail(headerValue);
            userDetails.setName(headerValue);
        }
        return userDetails;
    }
}
