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
 * This filter redirects the current request to
 * <code>/reverseproxyauth/validate</code>.
 */
public class ValidateRedirectionFilter extends ServletFilter {
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
            final ServletResponse response, final FilterChain chain)
            throws IOException {
        final HttpServletRequest req = (HttpServletRequest) request;
        final StringBuilder url = new StringBuilder(req.getRequestURL()
                .toString());
        url.replace(url.length() - 13, url.length(),
                "/reverseproxyauth/validate");

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
        return UrlPattern.create("/sessions/new");
    }

    /**
     * Does nothing. {@inheritDoc}
     */
    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        // does nothing.
    }
}
