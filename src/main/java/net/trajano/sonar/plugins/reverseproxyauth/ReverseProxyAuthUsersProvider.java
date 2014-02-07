package net.trajano.sonar.plugins.reverseproxyauth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.config.Settings;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.security.UserDetails;

/**
 * Module object.
 */
public class ReverseProxyAuthUsersProvider extends ExternalUsersProvider {
    /**
     * Logger.
     */
    private static final Logger log = LoggerFactory
            .getLogger(ReverseProxyAuthUsersProvider.class);

    private final String headerName;

    /**
     * @param settings
     */
    public ReverseProxyAuthUsersProvider(final Settings settings) {
        headerName = settings.getString("reverseproxyauth.header.name");
    }

    @Override
    public UserDetails doGetUserDetails(final Context context) {
        log.info("My first log");
        log.info("header name = " + headerName);

        final String headerValue = context.getRequest().getHeader(headerName);
        log.info("header value = " + headerValue);
        if (headerValue == null || headerValue.trim().isEmpty()) {
            return null;
        }
        final UserDetails userDetails = new UserDetails();
        userDetails.setEmail(headerValue);
        userDetails.setName(headerValue);
        return userDetails;
    }
}
