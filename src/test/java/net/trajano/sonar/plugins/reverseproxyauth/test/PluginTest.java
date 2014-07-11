package net.trajano.sonar.plugins.reverseproxyauth.test;

import java.util.List;

import net.trajano.sonar.plugins.reverseproxyauth.Extensions;
import net.trajano.sonar.plugins.reverseproxyauth.ReverseProxyAuthPlugin;
import net.trajano.sonar.plugins.reverseproxyauth.ReverseProxyAuthRealm;
import net.trajano.sonar.plugins.reverseproxyauth.ValidateRedirectionFilter;

import org.junit.Assert;
import org.junit.Test;
import org.sonar.api.Extension;
import org.sonar.api.config.Settings;

public class PluginTest {
    @Test
    public void testExtensionProviderWhenRealmIsNotSet() {
        final Settings settings = new Settings();

        final List<?> list = new Extensions(settings).provide();
        Assert.assertTrue(list.isEmpty());
    }

    @Test
    public void testExtensionProviderWhenRealmIsSet() {
        final Settings settings = new Settings();
        settings.appendProperty("sonar.security.realm",
                ReverseProxyAuthPlugin.KEY);

        final List<Class<? extends Extension>> list = new Extensions(settings)
                .provide();
        Assert.assertTrue(list.contains(ReverseProxyAuthRealm.class));
        Assert.assertTrue(list.contains(ValidateRedirectionFilter.class));
    }

    @Test
    public void testListExtensions() {
        new ReverseProxyAuthPlugin().getExtensions();
    }
}
