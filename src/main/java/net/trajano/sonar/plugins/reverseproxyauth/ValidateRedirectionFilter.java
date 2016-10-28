package net.trajano.sonar.plugins.reverseproxyauth;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.sonar.api.web.ServletFilter;

/**
 * This filter redirects the request for new sessions to
 * <code>/sessions/init/reverseproxyauth</code> automatically if realm is set to
 * "reverseproxyauth" and is not "localhost".
 */
public class ValidateRedirectionFilter extends ServletFilter {

    /**
     * URL Pattern when showing the login screen.
     */
    private static final String URL_PATTERN = "/sessions/new";

    /**
     * Indicates whether the filter is enabled.
     */
    private final boolean filterEnabled;

    /**
     * Settings.
     */
    private final ReverseProxyAuthSettings settings;

    /**
     * @param settings
     *            injected settings
     */
    public ValidateRedirectionFilter(final ReverseProxyAuthSettings settings) {
        super();
        filterEnabled = settings.isRealmReverseProxyAuth();
        this.settings = settings;
    }

    /**
     * Does nothing. {@inheritDoc}
     */
    @Override
    public void destroy() {

        // does nothing.
    }

    /**
     * Redirects automatically to the authenticator. {@inheritDoc}
     */
    @Override
    public void doFilter(final ServletRequest request,
        final ServletResponse response,
        final FilterChain chain)
        throws ServletException,
        IOException {

        if (!filterEnabled || settings.isLocalHost(request)) {
            chain.doFilter(request, response);
            return;
        }

        ((HttpServletResponse) response).sendRedirect(settings.getReverseProxyAuthInitUrl());
    }

    /**
     * Match against <code>/sessions/new</code>. {@inheritDoc}
     */
    @Override
    public UrlPattern doGetPattern() {

        return UrlPattern.create(URL_PATTERN);
    }

    /**
     * Does nothing. {@inheritDoc}
     */
    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {

        // does nothing.
    }
}
