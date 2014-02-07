package net.trajano.sonar.plugins.reverseproxyauth;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.web.ServletFilter;

/**
 * Plugin definition.
 */
public class ReverseProxyAuthServletFilter extends ServletFilter {
    /**
     * Logger.
     */
    private static final Logger log = LoggerFactory
            .getLogger(ReverseProxyAuthServletFilter.class);

    @Override
    public void destroy() {
        log.info("destroy");
    }

    @Override
    public void doFilter(final ServletRequest request,
            final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {
        // log.info("filter");
        chain.doFilter(request, response);
    }

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {
        log.info("init");
    }
}
