package net.trajano.sonar.plugins.reverseproxyauth.test;

import static org.mockito.Mockito.mock;

import org.junit.Test;
import org.sonar.api.Plugin;

import net.trajano.sonar.plugins.reverseproxyauth.ReverseProxyAuthPlugin;

public class PluginTest {
    @Test
    public void testListExtensions() {
        final Plugin.Context context = mock(Plugin.Context.class);
        new ReverseProxyAuthPlugin().define(context);
    }
}
