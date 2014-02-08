package net.trajano.sonar.plugins.reverseproxyauth.test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.trajano.sonar.plugins.reverseproxyauth.ValidateRedirectionFilter;

import org.junit.Test;
import org.sonar.api.web.ServletFilter;

/**
 * Tests {@link ValidateRedirectionFilter}.
 */
public class FilterTest {

    /**
     * Tests the typical filtering events.
     */
    @Test
    public void testFilter() throws Exception {
        final ServletContext servletContext = mock(ServletContext.class);
        when(servletContext.getContextPath()).thenReturn("/sonar");
        final FilterConfig filterConfig = mock(FilterConfig.class);
        when(filterConfig.getServletContext()).thenReturn(servletContext);

        final ServletFilter filter = new ValidateRedirectionFilter();
        filter.init(filterConfig);
        filter.doGetPattern();

        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURL()).thenReturn(
                new StringBuffer("http://i.tra.com:8322/sonar/sessions/new"));

        final HttpServletResponse response = mock(HttpServletResponse.class);

        final FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);

        verify(response).sendRedirect(
                "http://i.tra.com:8322/sonar/reverseproxyauth/validate");

        filter.destroy();
    }

    /**
     * Tests the typical filtering events with X_FORWARDED_PROTO
     */
    @Test
    public void testFilterWithProtocol() throws Exception {
        final ServletContext servletContext = mock(ServletContext.class);
        when(servletContext.getContextPath()).thenReturn("/sonar");
        final FilterConfig filterConfig = mock(FilterConfig.class);
        when(filterConfig.getServletContext()).thenReturn(servletContext);

        final ServletFilter filter = new ValidateRedirectionFilter();
        filter.init(filterConfig);
        filter.doGetPattern();

        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURL()).thenReturn(
                new StringBuffer("https://i.tra.com:8322/sonar/sessions/new"));
        when(request.getHeader("X_FORWARDED_PROTO")).thenReturn("https");

        final HttpServletResponse response = mock(HttpServletResponse.class);

        final FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);

        verify(response).sendRedirect(
                "https://i.tra.com:8322/sonar/reverseproxyauth/validate");

        filter.destroy();
    }

    /**
     * Tests the typical filtering events with X_FORWARDED_PROTO and Sonar at
     * root.
     */
    @Test
    public void testFilterWithProtocolAtRoot() throws Exception {
        final ServletContext servletContext = mock(ServletContext.class);
        when(servletContext.getContextPath()).thenReturn("/");
        final FilterConfig filterConfig = mock(FilterConfig.class);
        when(filterConfig.getServletContext()).thenReturn(servletContext);

        final ServletFilter filter = new ValidateRedirectionFilter();
        filter.init(filterConfig);
        filter.doGetPattern();

        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURL()).thenReturn(
                new StringBuffer("https://i.tra.com:8322/sessions/new"));
        when(request.getHeader("X_FORWARDED_PROTO")).thenReturn("https");

        final HttpServletResponse response = mock(HttpServletResponse.class);

        final FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);

        verify(response).sendRedirect(
                "https://i.tra.com:8322/reverseproxyauth/validate");

        filter.destroy();
    }
}