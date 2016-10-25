package net.trajano.sonar.plugins.reverseproxyauth.test;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.sonar.api.config.Settings;
import org.sonar.api.web.ServletFilter;

import net.trajano.sonar.plugins.reverseproxyauth.ReverseProxyAuthPlugin;
import net.trajano.sonar.plugins.reverseproxyauth.ReverseProxyAuthSettings;
import net.trajano.sonar.plugins.reverseproxyauth.ValidateRedirectionFilter;

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

        final Settings settingsMock = mock(Settings.class);
        when(settingsMock.getString("sonar.security.realm")).thenReturn("reverseproxyauth");
        when(settingsMock.getString("reverseproxyauth.localhost")).thenReturn("not.localhost");
        final ServletFilter filter = new ValidateRedirectionFilter(new ReverseProxyAuthSettings(settingsMock));
        filter.init(filterConfig);
        filter.doGetPattern();

        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURL()).thenReturn(
            new StringBuffer("http://i.tra.com:8322/sonar/sessions/new"));
        when(request.getServerName())
            .thenReturn("not.localhost.com");

        final HttpServletResponse response = mock(HttpServletResponse.class);

        final FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);

        verify(response).sendRedirect(
            "http://i.tra.com:8322/sonar/sessions/init/reverseproxyauth");

        filter.destroy();
    }

    /**
     * Tests the typical filtering events.
     */
    @Test
    public void testFilterDisabled() throws Exception {

        final ServletContext servletContext = mock(ServletContext.class);
        when(servletContext.getContextPath()).thenReturn("/sonar");
        final FilterConfig filterConfig = mock(FilterConfig.class);
        when(filterConfig.getServletContext()).thenReturn(servletContext);

        final Settings settingsMock = mock(Settings.class);
        when(settingsMock.getString("sonar.security.realm")).thenReturn(null);
        when(settingsMock.getString("reverseproxyauth.localhost")).thenReturn("not.localhost");
        final ServletFilter filter = new ValidateRedirectionFilter(new ReverseProxyAuthSettings(settingsMock));
        filter.init(filterConfig);
        filter.doGetPattern();

        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURL()).thenReturn(
            new StringBuffer("http://i.tra.com:8322/sonar/sessions/new"));
        when(request.getServerName())
            .thenReturn("not.localhost.com");

        final HttpServletResponse response = mock(HttpServletResponse.class);

        final FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);

        verify(response, never()).sendRedirect(anyString());

        filter.destroy();
    }

    /**
     * Tests the typical filtering events.
     */
    @Test
    public void testFilterDisabledDueToLocalhost() throws Exception {

        final ServletContext servletContext = mock(ServletContext.class);
        when(servletContext.getContextPath()).thenReturn("/sonar");
        final FilterConfig filterConfig = mock(FilterConfig.class);
        when(filterConfig.getServletContext()).thenReturn(servletContext);

        final Settings settingsMock = mock(Settings.class);
        when(settingsMock.getString("sonar.security.realm")).thenReturn(ReverseProxyAuthPlugin.KEY);
        when(settingsMock.getString("reverseproxyauth.localhost")).thenReturn("localhost");
        final ServletFilter filter = new ValidateRedirectionFilter(new ReverseProxyAuthSettings(settingsMock));
        filter.init(filterConfig);
        filter.doGetPattern();

        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURL()).thenReturn(
            new StringBuffer("http://i.tra.com:8322/sonar/sessions/new"));
        when(request.getServerName())
            .thenReturn("localhost");

        final HttpServletResponse response = mock(HttpServletResponse.class);

        final FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);

        verify(response, never()).sendRedirect(anyString());

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

        final Settings settingsMock = mock(Settings.class);
        when(settingsMock.getString("sonar.security.realm")).thenReturn("reverseproxyauth");
        when(settingsMock.getString("reverseproxyauth.localhost")).thenReturn("not.localhost");
        final ServletFilter filter = new ValidateRedirectionFilter(new ReverseProxyAuthSettings(settingsMock));
        filter.init(filterConfig);
        filter.doGetPattern();

        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURL()).thenReturn(
            new StringBuffer("https://i.tra.com:8322/sonar/sessions/new"));
        when(request.getHeader("X_FORWARDED_PROTO")).thenReturn("https");
        when(request.getServerName())
            .thenReturn("not.localhost.com");

        final HttpServletResponse response = mock(HttpServletResponse.class);

        final FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);

        verify(response).sendRedirect(
            "https://i.tra.com:8322/sonar/sessions/init/reverseproxyauth");

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

        final Settings settingsMock = mock(Settings.class);
        when(settingsMock.getString("sonar.security.realm")).thenReturn("reverseproxyauth");
        when(settingsMock.getString("reverseproxyauth.localhost")).thenReturn("not.localhost");
        final ServletFilter filter = new ValidateRedirectionFilter(new ReverseProxyAuthSettings(settingsMock));
        filter.init(filterConfig);
        filter.doGetPattern();

        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURL()).thenReturn(
            new StringBuffer("https://i.tra.com:8322/sessions/new"));
        when(request.getHeader("X_FORWARDED_PROTO")).thenReturn("https");
        when(request.getServerName())
            .thenReturn("not.localhost.com");

        final HttpServletResponse response = mock(HttpServletResponse.class);

        final FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);

        verify(response).sendRedirect(
            "https://i.tra.com:8322/sessions/init/reverseproxyauth");

        filter.destroy();
    }
}
