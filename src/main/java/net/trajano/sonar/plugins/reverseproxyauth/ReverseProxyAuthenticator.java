package net.trajano.sonar.plugins.reverseproxyauth;

import org.sonar.api.config.Settings;
import org.sonar.api.security.Authenticator;

/**
 * Implementation of the authenticator that assumes the value in the header is a
 * valid user.
 * 
 * @author Archimedes Trajano
 */
public class ReverseProxyAuthenticator extends Authenticator {
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
     * Constructs the authenticator with the specified {@link Settings}.
     * 
     * @param settings
     *            settings
     */
    public ReverseProxyAuthenticator(final Settings settings) {
        super();
        headerName = settings.getString("reverseproxyauth.header.name");
        localHost = settings.getString("reverseproxyauth.localhost");
    }

    /**
     * Returns <code>true</code> if the header is defined and has a value.
     * {@inheritDoc}
     * 
     * @return <code>true</code> if the header is defined and has a value.
     */
    @Override
    public boolean doAuthenticate(final Context context) {
        if (localHost.equals(context.getRequest().getServerName())) {
            return true;
        }
        final String headerValue = context.getRequest().getHeader(headerName);
        return headerValue != null && !headerValue.trim().isEmpty();
    }
}
