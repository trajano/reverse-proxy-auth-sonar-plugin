package net.trajano.sonar.plugins.reverseproxyauth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
     * Logger.
     */
    private static final Logger log = LoggerFactory
            .getLogger(ReverseProxyAuthenticator.class);

    /**
     * HTTP Header name containing the user name.
     */
    private final String headerName;

    public ReverseProxyAuthenticator(final Settings settings) {
        headerName = settings.getString("reverseproxyauth.header.name");
    }

    /**
     * Returns <code>true</code> if the header is defined and has a value.
     * {@inheritDoc}
     * 
     * @return <code>true</code> if the header is defined and has a value.
     */
    @Override
    public boolean doAuthenticate(final Context context) {
        log.info("doAuthenticate");
        final String headerValue = context.getRequest().getHeader(headerName);
        return headerValue != null && !headerValue.trim().isEmpty();
    }
}
