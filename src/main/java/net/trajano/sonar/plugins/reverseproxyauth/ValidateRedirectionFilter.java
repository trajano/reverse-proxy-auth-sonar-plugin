package net.trajano.sonar.plugins.reverseproxyauth;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.sonar.api.web.ServletFilter;

/**
 * This filter redirects the request for new sessions to
 * <code>/sessions/init/reverseproxyauth</code> automatically if realm is set to
 * "reverseproxyauth" and is not "localhost".
 */
public class ValidateRedirectionFilter extends ServletFilter {

    /**
     * URL Pattern.
     */
    private static final String URL_PATTERN = "/sessions/new";

    /**
     * URL Pattern length.
     */
    private static final int URL_PATTERN_LENGTH = URL_PATTERN.length();

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
     * Perform the redirection and handle the <code>X_FORWARDED_PROTO</code>
     * header as needed. Warnings are suppressed as Sonar treats multiple
     * exceptions as technical debt. {@inheritDoc}
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

        final HttpServletRequest req = (HttpServletRequest) request;
        final StringBuilder url = new StringBuilder(req.getRequestURL().toString());
        url.replace(url.length() - URL_PATTERN_LENGTH, url.length(), "/sessions/init/reverseproxyauth");

        final String forwardedProtocol = req.getHeader("X_FORWARDED_PROTO");
        if (forwardedProtocol != null) {
            url.replace(0, url.indexOf(":"), forwardedProtocol);
        }
        ((HttpServletResponse) response).sendRedirect(url.toString());
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
