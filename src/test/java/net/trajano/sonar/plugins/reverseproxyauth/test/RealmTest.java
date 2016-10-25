package net.trajano.sonar.plugins.reverseproxyauth.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.mockito.Matchers;
import org.sonar.api.CoreProperties;
import org.sonar.api.config.Settings;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.security.SecurityRealm;
import org.sonar.api.server.authentication.BaseIdentityProvider.Context;

import net.trajano.sonar.plugins.reverseproxyauth.ReverseProxyAuthPlugin;
import net.trajano.sonar.plugins.reverseproxyauth.ReverseProxyAuthRealm;
import net.trajano.sonar.plugins.reverseproxyauth.ReverseProxyAuthSettings;
import net.trajano.sonar.plugins.reverseproxyauth.ReverseProxyAuthUsersIdentityProvider;

/**
 * Tests the realm.
 */
public class RealmTest {

    /**
     * Tests the typical authentication process.
     *
     * @throws IOException
     */
    @Test
    public void testRealm() throws IOException {

        final Settings settings = new Settings();
        settings.appendProperty("reverseproxyauth.header.name",
            "X-Forwarded-User");
        settings.appendProperty("reverseproxyauth.localhost", "localhost");

        final ReverseProxyAuthSettings reverseProxyAuthSettings = new ReverseProxyAuthSettings(settings);
        final SecurityRealm realm = new ReverseProxyAuthRealm(reverseProxyAuthSettings);
        realm.getName();
        realm.init();

        final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getHeader("X-Forwarded-User")).thenReturn(
            "foo@bar.com");
        when(httpServletRequest.getServerName())
            .thenReturn("not.localhost.com");
        when(httpServletRequest.getRequestURL())
            .thenReturn(new StringBuffer("/"));
        when(httpServletRequest.getContextPath())
            .thenReturn("/");

        final ReverseProxyAuthUsersIdentityProvider provider = new ReverseProxyAuthUsersIdentityProvider(reverseProxyAuthSettings);
        final Context context = mock(Context.class);
        when(context.getRequest()).thenReturn(httpServletRequest);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(context.getResponse()).thenReturn(response);
        provider.init(context);
        verify(context).authenticate(Matchers.any());
        verify(response).sendRedirect("/reverseproxyauth/redirect_back_or_home_url");
    }

    /**
     * Tests when the header is missing.
     */
    @Test
    public void testRealmMissingHeader() {

        final Settings settings = new Settings();
        settings.appendProperty("reverseproxyauth.header.name",
            "X-Forwarded-User");
        settings.appendProperty("reverseproxyauth.localhost", "localhost");

        final ReverseProxyAuthSettings reverseProxyAuthSettings = new ReverseProxyAuthSettings(settings);
        final SecurityRealm realm = new ReverseProxyAuthRealm(reverseProxyAuthSettings);
        realm.getName();
        realm.init();

        final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getHeader("X-Forwarded-User")).thenReturn(null);
        when(httpServletRequest.getServerName())
            .thenReturn("not.localhost.com");

        final ReverseProxyAuthUsersIdentityProvider provider = new ReverseProxyAuthUsersIdentityProvider(reverseProxyAuthSettings);
        final Context context = mock(Context.class);
        when(context.getRequest()).thenReturn(httpServletRequest);
        when(context.getResponse()).thenReturn(mock(HttpServletResponse.class));
        provider.init(context);
    }

    /**
     * Tests when the header has empty header value.
     */
    @Test
    public void testRealmMissingHeaderValue() {

        final Settings settings = new Settings();
        settings.appendProperty("reverseproxyauth.header.name",
            "X-Forwarded-User");
        settings.appendProperty("reverseproxyauth.localhost", "localhost");

        final ReverseProxyAuthSettings reverseProxyAuthSettings = new ReverseProxyAuthSettings(settings);
        final SecurityRealm realm = new ReverseProxyAuthRealm(reverseProxyAuthSettings);
        realm.init();

        final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getHeader("X-Forwarded-User")).thenReturn("");
        when(httpServletRequest.getServerName())
            .thenReturn("not.localhost.com");

        final ReverseProxyAuthUsersIdentityProvider provider = new ReverseProxyAuthUsersIdentityProvider(reverseProxyAuthSettings);
        final Context context = mock(Context.class);
        when(context.getRequest()).thenReturn(httpServletRequest);
        when(context.getResponse()).thenReturn(mock(HttpServletResponse.class));
        provider.init(context);
    }

    /**
     * Tests the typical authentication process when the server request is
     * against localhost.
     */
    @Test
    public void testRealmOnLocalhost() {

        final Settings settings = new Settings();
        settings.appendProperty("reverseproxyauth.header.name",
            "X-Forwarded-User");
        settings.appendProperty("reverseproxyauth.localhost", "localhost");

        final ReverseProxyAuthSettings reverseProxyAuthSettings = new ReverseProxyAuthSettings(settings);
        final SecurityRealm realm = new ReverseProxyAuthRealm(reverseProxyAuthSettings);
        realm.init();

        final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getServerName()).thenReturn("localhost");

        final ReverseProxyAuthUsersIdentityProvider provider = new ReverseProxyAuthUsersIdentityProvider(reverseProxyAuthSettings);
        final Context context = mock(Context.class);
        when(context.getRequest()).thenReturn(httpServletRequest);
        when(context.getResponse()).thenReturn(mock(HttpServletResponse.class));
        provider.init(context);
    }

    @Test
    public void testStaticValues() {

        final Settings settings = new Settings();
        settings.appendProperty(CoreProperties.CORE_ALLOW_USERS_TO_SIGNUP_PROPERTY, "true");
        final ReverseProxyAuthUsersIdentityProvider provider = new ReverseProxyAuthUsersIdentityProvider(new ReverseProxyAuthSettings(settings));
        assertEquals(ReverseProxyAuthPlugin.KEY, provider.getKey());
        assertNotNull(provider.getName());
        assertNotNull(provider.getDisplay());
        assertTrue(provider.isEnabled());
        assertTrue(provider.allowsUsersToSignUp());
    }

    /**
     * Tests terminated response. IOException on sendRedirect().
     *
     * @throws IOException
     */
    @Test
    public void testTerminatedResponse() throws IOException {

        final Settings settings = new Settings();
        settings.appendProperty("reverseproxyauth.header.name",
            "X-Forwarded-User");
        settings.appendProperty("reverseproxyauth.localhost", "localhost");

        final ReverseProxyAuthSettings reverseProxyAuthSettings = new ReverseProxyAuthSettings(settings);
        final SecurityRealm realm = new ReverseProxyAuthRealm(reverseProxyAuthSettings);
        realm.getName();
        realm.init();

        final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getHeader("X-Forwarded-User")).thenReturn(
            "foo@bar.com");
        when(httpServletRequest.getServerName())
            .thenReturn("not.localhost.com");
        when(httpServletRequest.getRequestURL())
            .thenReturn(new StringBuffer("/"));
        when(httpServletRequest.getContextPath())
            .thenReturn("/");

        final ReverseProxyAuthUsersIdentityProvider provider = new ReverseProxyAuthUsersIdentityProvider(reverseProxyAuthSettings);
        final Context context = mock(Context.class);
        when(context.getRequest()).thenReturn(httpServletRequest);

        final HttpServletResponse response = mock(HttpServletResponse.class);
        final IOException ioException = new IOException();
        doThrow(ioException).when(response).sendRedirect(Matchers.anyString());
        when(context.getResponse()).thenReturn(response);

        try {
            provider.init(context);
        } catch (final RuntimeException e) {
            assertEquals(ioException, e.getCause());
        }
        verify(context).authenticate(any());
    }

    @Test
    public void testUserProvider() {

        final Settings settings = new Settings();
        settings.appendProperty(CoreProperties.CORE_ALLOW_USERS_TO_SIGNUP_PROPERTY, "true");
        settings.appendProperty("reverseproxyauth.header.name",
            "X-Forwarded-User");
        settings.appendProperty("reverseproxyauth.localhost", "localhost");

        final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getHeader("X-Forwarded-User")).thenReturn(
            "foo@bar.com");
        when(httpServletRequest.getServerName())
            .thenReturn("not.localhost.com");
        when(httpServletRequest.getRequestURL())
            .thenReturn(new StringBuffer("/"));
        when(httpServletRequest.getContextPath())
            .thenReturn("/");

        final ReverseProxyAuthRealm realm = new ReverseProxyAuthRealm(new ReverseProxyAuthSettings(settings));
        realm.init();
        final ExternalUsersProvider.Context context = new ExternalUsersProvider.Context(null, httpServletRequest);
        realm.getUsersProvider().doGetUserDetails(context);
    }

    @Test
    public void testUserProviderLocalhost() {

        final Settings settings = new Settings();
        settings.appendProperty(CoreProperties.CORE_ALLOW_USERS_TO_SIGNUP_PROPERTY, "true");
        settings.appendProperty("reverseproxyauth.header.name",
            "X-Forwarded-User");
        settings.appendProperty("reverseproxyauth.localhost", "localhost");

        final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getHeader("X-Forwarded-User")).thenReturn(
            "blah");
        when(httpServletRequest.getServerName())
            .thenReturn("localhost");
        when(httpServletRequest.getRequestURL())
            .thenReturn(new StringBuffer("/"));
        when(httpServletRequest.getContextPath())
            .thenReturn("/");

        final ReverseProxyAuthRealm realm = new ReverseProxyAuthRealm(new ReverseProxyAuthSettings(settings));
        realm.init();
        final ExternalUsersProvider.Context context = new ExternalUsersProvider.Context(null, httpServletRequest);
        assertEquals("", realm.getUsersProvider().doGetUserDetails(context).getEmail());
        assertEquals("", realm.getUsersProvider().doGetUserDetails(context).getName());
        assertEquals("", realm.getUsersProvider().doGetUserDetails(context).getUserId());
    }

    @Test
    public void testUserProviderMissingHeader() {

        final Settings settings = new Settings();
        settings.appendProperty(CoreProperties.CORE_ALLOW_USERS_TO_SIGNUP_PROPERTY, "true");
        settings.appendProperty("reverseproxyauth.header.name",
            "X-Forwarded-User");
        settings.appendProperty("reverseproxyauth.localhost", "localhost");

        final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getHeader("X-Forwarded-User")).thenReturn(
            null);
        when(httpServletRequest.getServerName())
            .thenReturn("not.localhost.com");
        when(httpServletRequest.getRequestURL())
            .thenReturn(new StringBuffer("/"));
        when(httpServletRequest.getContextPath())
            .thenReturn("/");

        final ReverseProxyAuthRealm realm = new ReverseProxyAuthRealm(new ReverseProxyAuthSettings(settings));
        realm.init();
        final ExternalUsersProvider.Context context = new ExternalUsersProvider.Context(null, httpServletRequest);
        assertNull(realm.getUsersProvider().doGetUserDetails(context));
    }

}
