package net.trajano.sonar.plugins.reverseproxyauth.test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;

import net.trajano.sonar.plugins.reverseproxyauth.ReverseProxyAuthRealm;

import org.junit.Test;
import org.sonar.api.config.Settings;
import org.sonar.api.security.Authenticator;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.security.SecurityRealm;

/**
 * Tests the realm.
 */
public class RealmTest {

    /**
     * Tests the typical authentication process.
     */
    @Test
    public void testRealm() {
        final Settings settings = new Settings();
        settings.appendProperty("reverseproxyauth.header.name",
                "X-Forwarded-User");
        settings.appendProperty("reverseproxyauth.localhost", "localhost");

        final SecurityRealm realm = new ReverseProxyAuthRealm(settings);
        realm.getName();
        realm.init();

        final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getHeader("X-Forwarded-User")).thenReturn(
                "foo@bar.com");
        when(httpServletRequest.getServerName())
                .thenReturn("not.localhost.com");

        final ExternalUsersProvider.Context usersProviderContext = new ExternalUsersProvider.Context(
                null, httpServletRequest);
        realm.getUsersProvider().doGetUserDetails(usersProviderContext);

        final Authenticator.Context authenticatorContext = new Authenticator.Context(
                null, null, httpServletRequest);
        realm.doGetAuthenticator().doAuthenticate(authenticatorContext);
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

        final SecurityRealm realm = new ReverseProxyAuthRealm(settings);
        realm.getName();
        realm.init();

        final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getHeader("X-Forwarded-User")).thenReturn(null);
        when(httpServletRequest.getServerName())
                .thenReturn("not.localhost.com");

        final ExternalUsersProvider.Context usersProviderContext = new ExternalUsersProvider.Context(
                null, httpServletRequest);
        realm.getUsersProvider().doGetUserDetails(usersProviderContext);

        final Authenticator.Context authenticatorContext = new Authenticator.Context(
                null, null, httpServletRequest);
        realm.doGetAuthenticator().doAuthenticate(authenticatorContext);
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

        final SecurityRealm realm = new ReverseProxyAuthRealm(settings);
        realm.getName();
        realm.init();

        final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getHeader("X-Forwarded-User")).thenReturn("");
        when(httpServletRequest.getServerName())
                .thenReturn("not.localhost.com");

        final ExternalUsersProvider.Context usersProviderContext = new ExternalUsersProvider.Context(
                null, httpServletRequest);
        realm.getUsersProvider().doGetUserDetails(usersProviderContext);

        final Authenticator.Context authenticatorContext = new Authenticator.Context(
                null, null, httpServletRequest);
        realm.doGetAuthenticator().doAuthenticate(authenticatorContext);
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

        final SecurityRealm realm = new ReverseProxyAuthRealm(settings);
        realm.getName();
        realm.init();

        final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getServerName()).thenReturn("localhost");

        final ExternalUsersProvider.Context usersProviderContext = new ExternalUsersProvider.Context(
                null, httpServletRequest);
        realm.getUsersProvider().doGetUserDetails(usersProviderContext);

        final Authenticator.Context authenticatorContext = new Authenticator.Context(
                null, null, httpServletRequest);
        realm.doGetAuthenticator().doAuthenticate(authenticatorContext);
    }
}