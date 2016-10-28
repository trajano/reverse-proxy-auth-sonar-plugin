package net.trajano.sonar.plugins.reverseproxyauth;

import javax.annotation.Nonnull;
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
     * If true, then new users that are not yet registered in the system are
     * automatically registered.
     */
    public static final String ALLOW_NEW_USERS = "reverseproxyauth.allow.new";

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
    public ReverseProxyAuthSettings(@Nonnull final Settings settings) {
        this.settings = settings;
    }

    /**
     * Returns the value of {@link #ALLOW_NEW_USERS}.
     *
     * @return the value of {@link #ALLOW_NEW_USERS}.
     */
    public boolean allowsUsersToSignUp() {

        return settings.getBoolean(ALLOW_NEW_USERS);
    }

    /**
     * Base URL of the server.
     *
     * @return Base URL of the server.
     */
    public String getBaseUrl() {

        return settings.getString(CoreProperties.SERVER_BASE_URL);
    }

    /**
     * Gets the user name from the headers of the request. This may return null,
     * but will never return an empty or blank string.
     *
     * @param request
     *            servlet request
     * @return user name
     */
    public String getUserNameFromHeader(@Nonnull final HttpServletRequest request) {

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
    public boolean isLocalHost(@Nonnull final ServletRequest request) {

        final String localhostValue = settings.getString(LOCALHOST);
        return localhostValue != null && localhostValue.equals(request.getServerName());
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
