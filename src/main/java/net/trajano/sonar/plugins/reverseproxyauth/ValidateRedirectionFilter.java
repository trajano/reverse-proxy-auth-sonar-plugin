package net.trajano.sonar.plugins.reverseproxyauth;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
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
     * Servlet context.
     */
    private ServletContext servletContext;

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
    @SuppressWarnings("all")
    @Override
    public void doFilter(final ServletRequest request,
            final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {
        final HttpServletRequest req = (HttpServletRequest) request;
        final URI targetUri = URI.create(req.getRequestURI()).resolve(
                servletContext.getContextPath() + "/reverseproxyauth/validate");

        final String forwardedProtocol = req.getHeader("X_FORWARDED_PROTO");
        if (forwardedProtocol == null) {
            ((HttpServletResponse) response).sendRedirect(targetUri
                    .toASCIIString());
        } else {
            URI newT;
            try {
                newT = new URI(forwardedProtocol, targetUri.getHost(),
                        targetUri.getPath(), null);
            } catch (final URISyntaxException e) {
                throw new ServletException(e);
            }
            ((HttpServletResponse) response).sendRedirect(newT.toASCIIString());

        }
    }

    /**
     * Match against <code>/sessions/new</code>. {@inheritDoc}
     */
    @Override
    public UrlPattern doGetPattern() {
        return UrlPattern.create("/sessions/new");
    }

    /**
     * Initializes the {@link ServletContext}. {@inheritDoc}
     */
    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        servletContext = filterConfig.getServletContext();
    }
}
