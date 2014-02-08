package net.trajano.sonar.plugins.reverseproxyauth.internal;

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
     * HTTP Header name containing the user name.
     */
    private final String headerName;

    /**
     * Host name to allow sonar executions. Authentication will always be
     * accepted when accessing this host name from the
     * {@link javax.servlet.http.HttpServletRequest}.
     */
    private final String localHost;

    /**
     * Constructs the {@link ExternalUsersProvider} with the specified
     * {@link Settings}.
     * 
     * @param settings
     *            settings
     */
    public ReverseProxyAuthUsersProvider(final Settings settings) {
        super();
        headerName = settings.getString("reverseproxyauth.header.name");
        localHost = settings.getString("reverseproxyauth.localhost");
    }

    @Override
    public UserDetails doGetUserDetails(final Context context) {

        final UserDetails userDetails = new UserDetails();
        if (!localHost.equals(context.getRequest().getServerName())) {
            final String headerValue = context.getRequest().getHeader(
                    headerName);
            if (headerValue == null || headerValue.trim().isEmpty()) {
                return null;
            }
            userDetails.setEmail(headerValue);
            userDetails.setName(headerValue);
        }
        return userDetails;
    }
}
