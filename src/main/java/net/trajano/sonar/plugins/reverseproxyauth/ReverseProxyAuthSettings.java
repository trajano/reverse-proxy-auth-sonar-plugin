package net.trajano.sonar.plugins.reverseproxyauth;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

import org.sonar.api.CoreProperties;
import org.sonar.api.config.Settings;
import org.sonar.api.server.ServerSide;

/**
 * Wraps the settings object so it provides a type safe interface rather than
 * using strings. This class also provides the property key constants.
 *
 * @author Archimedes
 */
@ServerSide
public class ReverseProxyAuthSettings {

    /**
     * HTTP Header name containing the user name.
     */
    public static final String HEADER_NAME = "reverseproxyauth.header.name";

    /**
     * Host name to allow sonar executions. Authentication will always be
     * accepted when accessing this host name from the
     * {@link javax.servlet.http.HttpServletRequest}.
     */
    public static final String LOCALHOST = "reverseproxyauth.localhost";

    /**
     * Wrapped settings.
     */
    private final Settings settings;

    /**
     * @param settings
     *            injected settings.
     */
    public ReverseProxyAuthSettings(final Settings settings) {
        this.settings = settings;
    }

    /**
     * Returns the value of sonar.allowUsersToSignUp.
     *
     * @return the value of sonar.allowUsersToSignUp.
     */
    public boolean allowsUsersToSignUp() {

        return settings.getBoolean(CoreProperties.CORE_ALLOW_USERS_TO_SIGNUP_PROPERTY);
    }

    /**
     * Gets the user name from the headers of the request. This may return null,
     * but will never return an empty or blank string.
     *
     * @param request
     *            servlet request
     * @return user name
     */
    public String getUserNameFromHeader(final HttpServletRequest request) {

        final String headerValue = request.getHeader(settings.getString(HEADER_NAME));
        if (headerValue == null || headerValue.trim().isEmpty()) {
            return null;
        } else {
            return headerValue;
        }
    }

    /**
     * Checks if the server name is equal to localhost in the servlet request.
     *
     * @param request
     *            servlet request
     * @return true if the server name is equal to localhost.
     */
    public boolean isLocalHost(final ServletRequest request) {

        return settings.getString(LOCALHOST).equals(request.getServerName());
    }

    /**
     * Returns <code>true</code> if the security realm is set to
     * reverseproxyauth.
     *
     * @return <code>true</code> if the security realm is set to
     *         reverseproxyauth.
     */
    public boolean isRealmReverseProxyAuth() {

        return ReverseProxyAuthPlugin.KEY.equals(settings.getString(CoreProperties.CORE_AUTHENTICATOR_REALM));
    }
}
